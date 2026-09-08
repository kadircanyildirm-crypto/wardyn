// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wardyn userspace.
//!
//! Usage:
//!   wardyn [OPTIONS] run -- <cmd> [args...]   watch that command's subtree
//!   wardyn [OPTIONS] [--all]                  watch system-wide
//!
//! Renders a live ratatui TUI when stdout is a terminal, else a plain table.
//! Each event is evaluated against the policy (allow/warn/block); violations are
//! coloured and written to the audit log. With `--enforce`, blocked file reads,
//! execs and egress are denied in-kernel for the watched subtree.
//!
//! The feed distinguishes *what the kernel did* from *what the policy predicts*:
//! `BLOCK` = the kernel reported denying it, `block~` = flagged but not
//! kernel-enforceable, `block` = observe-only (no `--enforce`). Denials are
//! reported by the very hook that made them, so an open through a dirfd or a
//! symlink — which the observed `sys_enter` path describes wrongly — still shows
//! up. Under `--enforce` the child is also spawned with `WARDYN_DENIALS=<path>`,
//! a JSONL receipt naming each denied action, so the agent can learn why an
//! operation failed instead of flailing against a bare EPERM.
mod audit;
mod btf;
mod overrides_file;
mod receipt;
mod tui;

use std::collections::VecDeque;
use std::io::IsTerminal as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{bail, Context as _};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm, TracePoint};
use aya::Btf;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};
use wardyn_common::{
    action, fmode, kind, meta, stat, Event, InodeKey, PairKey, PortKey4, PortKey6, ProtoKey4,
    ProtoKey6, ProtoPortKey4, ProtoPortKey6, NAME_LEN, PATH_LEN, PORT_BITS, PROTO_BITS,
};
use wardyn_policy::cli::{self, Format, Mode, Opts, ParseOutcome};
use wardyn_policy::identity::AnchorBase;
use wardyn_policy::policy::{
    self, Action, DenialKey, Exceptions, LifecycleOp, Loader, Policy, Proto, Verdict,
};

use crate::audit::Audit;
use crate::receipt::Receipt;

/// Userspace mirror of `wardyn_common::NameKey` (identical C layout) carrying a
/// `Pod` impl so aya can use it as a hash-map key. The `Pod` impl can't live on
/// the wardyn_common type (orphan rule), hence this local copy.
#[repr(C)]
#[derive(Clone, Copy)]
struct NameKey([u8; NAME_LEN]);
unsafe impl aya::Pod for NameKey {}

/// Userspace mirror of `wardyn_common::PairKey`, `Pod` for the two-component
/// maps. Same orphan-rule story as `NameKey`; layout asserted in the tests.
#[repr(C)]
#[derive(Clone, Copy)]
struct PairKeyPod {
    parent: [u8; NAME_LEN],
    name: [u8; NAME_LEN],
}
unsafe impl aya::Pod for PairKeyPod {}

impl From<PairKey> for PairKeyPod {
    fn from(k: PairKey) -> Self {
        PairKeyPod {
            parent: k.parent,
            name: k.name,
        }
    }
}

/// Userspace mirror of `wardyn_common::Ip6Key` (16-byte v6 address), `Pod` so aya
/// can use it as the v6 LPM-trie key.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ip6Key([u8; 16]);
unsafe impl aya::Pod for Ip6Key {}

/// Userspace mirror of `wardyn_common::InodeKey`, `Pod` for the identity maps.
/// Same story as `NameKey`: the orphan rule keeps the `Pod` impl off the shared
/// type, so the layout is duplicated and asserted equal in the tests below.
#[repr(C)]
#[derive(Clone, Copy)]
struct InoKey {
    dev: u32,
    _pad: u32,
    ino: u64,
}
unsafe impl aya::Pod for InoKey {}

/// Userspace mirrors of the port-qualified LPM keys. Same orphan-rule story as
/// `NameKey` and `InoKey`; the layouts are asserted equal in the tests below.
#[repr(C)]
#[derive(Clone, Copy)]
struct PortKey4Pod {
    port: [u8; 2],
    addr: [u8; 4],
    _pad: [u8; 2],
}
unsafe impl aya::Pod for PortKey4Pod {}

#[repr(C)]
#[derive(Clone, Copy)]
struct PortKey6Pod {
    port: [u8; 2],
    addr: [u8; 16],
    _pad: [u8; 2],
}
unsafe impl aya::Pod for PortKey6Pod {}

/// Userspace mirrors of the protocol-qualified LPM keys.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProtoPortKey4Pod {
    proto: u8,
    port: [u8; 2],
    addr: [u8; 4],
    _pad: [u8; 1],
}
unsafe impl aya::Pod for ProtoPortKey4Pod {}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProtoPortKey6Pod {
    proto: u8,
    port: [u8; 2],
    addr: [u8; 16],
    _pad: [u8; 1],
}
unsafe impl aya::Pod for ProtoPortKey6Pod {}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProtoKey4Pod {
    proto: u8,
    addr: [u8; 4],
    _pad: [u8; 3],
}
unsafe impl aya::Pod for ProtoKey4Pod {}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProtoKey6Pod {
    proto: u8,
    addr: [u8; 16],
    _pad: [u8; 3],
}
unsafe impl aya::Pod for ProtoKey6Pod {}

impl From<ProtoPortKey4> for ProtoPortKey4Pod {
    fn from(k: ProtoPortKey4) -> Self {
        ProtoPortKey4Pod {
            proto: k.proto,
            port: k.port,
            addr: k.addr,
            _pad: [0; 1],
        }
    }
}

impl From<ProtoPortKey6> for ProtoPortKey6Pod {
    fn from(k: ProtoPortKey6) -> Self {
        ProtoPortKey6Pod {
            proto: k.proto,
            port: k.port,
            addr: k.addr,
            _pad: [0; 1],
        }
    }
}

impl From<ProtoKey4> for ProtoKey4Pod {
    fn from(k: ProtoKey4) -> Self {
        ProtoKey4Pod {
            proto: k.proto,
            addr: k.addr,
            _pad: [0; 3],
        }
    }
}

impl From<ProtoKey6> for ProtoKey6Pod {
    fn from(k: ProtoKey6) -> Self {
        ProtoKey6Pod {
            proto: k.proto,
            addr: k.addr,
            _pad: [0; 3],
        }
    }
}

impl From<PortKey4> for PortKey4Pod {
    fn from(k: PortKey4) -> Self {
        PortKey4Pod {
            port: k.port,
            addr: k.addr,
            _pad: [0; 2],
        }
    }
}

impl From<PortKey6> for PortKey6Pod {
    fn from(k: PortKey6) -> Self {
        PortKey6Pod {
            port: k.port,
            addr: k.addr,
            _pad: [0; 2],
        }
    }
}

impl From<InodeKey> for InoKey {
    fn from(k: InodeKey) -> Self {
        InoKey {
            dev: k.dev,
            _pad: 0,
            ino: k.ino,
        }
    }
}

/// AF_INET6, matching the eBPF side.
const AF_INET6: u16 = 10;

/// CONFIG slots shared with the eBPF side (pid-ns handshake, fork offset,
/// deferred eviction, and the BTF-resolved LSM struct offsets). Slot 5 is
/// reserved: it used to carry `sched_process_fork`'s `parent_pid` offset, which
/// the hook no longer needs.
const CFG_HS_NONCE: u32 = 3;
const CFG_HS_TGID: u32 = 4;
const CFG_FORK_CHILD_OFF: u32 = 6;
const CFG_DEFER_EVICT: u32 = 7;
const CFG_FILE_DENTRY_OFF: u32 = 8;
const CFG_DENTRY_NAME_OFF: u32 = 9;
const CFG_DENTRY_PARENT_OFF: u32 = 10;
const CFG_BPRM_FILE_OFF: u32 = 11;
// Identity matching (M6). All zero unless BTF yielded the inode fields AND the
// policy produced at least one anchor; the hooks check `CFG_IDENTITY_ON` first,
// so a kernel that hides these simply keeps name matching.
const CFG_FILE_INODE_OFF: u32 = 12;
const CFG_FILE_MODE_OFF: u32 = 13;
const CFG_INODE_INO_OFF: u32 = 14;
const CFG_INODE_SB_OFF: u32 = 15;
const CFG_SB_DEV_OFF: u32 = 16;
const CFG_DENTRY_INODE_OFF: u32 = 17;
const CFG_EXT_OFFSETS: u32 = 18;
const CFG_IDENTITY_ON: u32 = 19;
const CFG_PORT_RULES_ON: u32 = 20;
const CFG_LIFECYCLE_ON: u32 = 21;
const CFG_PROTO_RULES_ON: u32 = 22;
const CFG_PAIRS_ON: u32 = 23;

/// Feed rows that carry an operator/diagnostic message rather than a syscall.
const KIND_NOTICE: u32 = u32::MAX;

/// The live kernel enforcement maps, held for the whole run (not dropped after
/// population) so the TUI can grant approve-once exceptions while the target
/// is still running: remove a block key, or insert a most-specific allow route.
pub(crate) struct KernelMaps {
    names: BpfHashMap<MapData, NameKey, u8>,
    dirs: BpfHashMap<MapData, NameKey, u8>,
    /// Two-component keys, `(parent, name)`. Held for the same reason as the
    /// single-name maps: an exception must be able to lift one mid-run.
    pairs: BpfHashMap<MapData, PairKeyPod, u8>,
    dir_pairs: BpfHashMap<MapData, PairKeyPod, u8>,
    execs: BpfHashMap<MapData, NameKey, u8>,
    net4: LpmTrie<MapData, u32, u32>,
    net6: LpmTrie<MapData, Ip6Key, u32>,
    /// Port-qualified rules, consulted by the hooks before the address-only
    /// tries above.
    port4: LpmTrie<MapData, PortKey4Pod, u32>,
    port6: LpmTrie<MapData, PortKey6Pod, u32>,
    /// Protocol-qualified rules. Four tries in all now, consulted most-specific
    /// first — an exception has to be written into the one that denied.
    proto_port4: LpmTrie<MapData, ProtoPortKey4Pod, u32>,
    proto_port6: LpmTrie<MapData, ProtoPortKey6Pod, u32>,
    proto4: LpmTrie<MapData, ProtoKey4Pod, u32>,
    proto6: LpmTrie<MapData, ProtoKey6Pod, u32>,
    /// Identity maps (M6). Held for the same reason as the name maps: an
    /// approve-once exception has to be able to drop an inode key mid-run.
    inodes: BpfHashMap<MapData, InoKey, u8>,
    dir_inodes: BpfHashMap<MapData, InoKey, u8>,
    exec_inodes: BpfHashMap<MapData, InoKey, u8>,
}

impl KernelMaps {
    /// Take the enforcement maps from the loaded object and compile the policy
    /// into them. Must run AFTER all program attaches (map relocation).
    fn load(ebpf: &mut aya::Ebpf, policy: &Policy) -> anyhow::Result<KernelMaps> {
        let mut net4: LpmTrie<_, u32, u32> =
            LpmTrie::try_from(ebpf.take_map("NET_RULES").context("NET_RULES")?)?;
        for (plen, data, act) in policy.net_entries() {
            net4.insert(&Key::new(plen, data), act, 0)
                .context("populating NET_RULES")?;
        }
        let mut net6: LpmTrie<_, Ip6Key, u32> =
            LpmTrie::try_from(ebpf.take_map("NET_RULES6").context("NET_RULES6")?)?;
        for (plen, data, act) in policy.net_entries6() {
            net6.insert(&Key::new(plen, Ip6Key(data)), act, 0)
                .context("populating NET_RULES6")?;
        }
        let mut port4: LpmTrie<_, PortKey4Pod, u32> =
            LpmTrie::try_from(ebpf.take_map("NET_PORT_RULES").context("NET_PORT_RULES")?)?;
        for (plen, key, act) in policy.port_entries() {
            port4
                .insert(&Key::new(plen, PortKey4Pod::from(key)), act, 0)
                .context("populating NET_PORT_RULES")?;
        }
        let mut port6: LpmTrie<_, PortKey6Pod, u32> = LpmTrie::try_from(
            ebpf.take_map("NET_PORT_RULES6")
                .context("NET_PORT_RULES6")?,
        )?;
        for (plen, key, act) in policy.port_entries6() {
            port6
                .insert(&Key::new(plen, PortKey6Pod::from(key)), act, 0)
                .context("populating NET_PORT_RULES6")?;
        }

        let mut proto_port4: LpmTrie<_, ProtoPortKey4Pod, u32> = LpmTrie::try_from(
            ebpf.take_map("NET_PROTO_PORT_RULES")
                .context("NET_PROTO_PORT_RULES")?,
        )?;
        for (plen, key, act) in policy.proto_port_entries() {
            proto_port4
                .insert(&Key::new(plen, ProtoPortKey4Pod::from(key)), act, 0)
                .context("populating NET_PROTO_PORT_RULES")?;
        }
        let mut proto_port6: LpmTrie<_, ProtoPortKey6Pod, u32> = LpmTrie::try_from(
            ebpf.take_map("NET_PROTO_PORT_RULES6")
                .context("NET_PROTO_PORT_RULES6")?,
        )?;
        for (plen, key, act) in policy.proto_port_entries6() {
            proto_port6
                .insert(&Key::new(plen, ProtoPortKey6Pod::from(key)), act, 0)
                .context("populating NET_PROTO_PORT_RULES6")?;
        }
        let mut proto4: LpmTrie<_, ProtoKey4Pod, u32> = LpmTrie::try_from(
            ebpf.take_map("NET_PROTO_RULES")
                .context("NET_PROTO_RULES")?,
        )?;
        for (plen, key, act) in policy.proto_entries() {
            proto4
                .insert(&Key::new(plen, ProtoKey4Pod::from(key)), act, 0)
                .context("populating NET_PROTO_RULES")?;
        }
        let mut proto6: LpmTrie<_, ProtoKey6Pod, u32> = LpmTrie::try_from(
            ebpf.take_map("NET_PROTO_RULES6")
                .context("NET_PROTO_RULES6")?,
        )?;
        for (plen, key, act) in policy.proto_entries6() {
            proto6
                .insert(&Key::new(plen, ProtoKey6Pod::from(key)), act, 0)
                .context("populating NET_PROTO_RULES6")?;
        }

        // The map VALUE is the access mask, not a presence flag — see
        // `wardyn_common::fmode`. 0 means "every open"; READ/WRITE narrow it.
        let (name_keys, dir_keys) = policy.file_enforcement();
        let mut names: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_NAMES").context("BLOCK_NAMES")?)?;
        for (k, mask) in name_keys {
            names
                .insert(NameKey(k), mask, 0)
                .context("populating BLOCK_NAMES")?;
        }
        let mut dirs: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_DIRS").context("BLOCK_DIRS")?)?;
        for (k, mask) in dir_keys {
            dirs.insert(NameKey(k), mask, 0)
                .context("populating BLOCK_DIRS")?;
        }
        let (pair_keys, dir_pair_keys) = policy.pair_enforcement();
        let mut pairs: BpfHashMap<_, PairKeyPod, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_PAIRS").context("BLOCK_PAIRS")?)?;
        for (parent, name, mask) in pair_keys {
            pairs
                .insert(PairKeyPod { parent, name }, mask, 0)
                .context("populating BLOCK_PAIRS")?;
        }
        let mut dir_pairs: BpfHashMap<_, PairKeyPod, u8> = BpfHashMap::try_from(
            ebpf.take_map("BLOCK_DIR_PAIRS")
                .context("BLOCK_DIR_PAIRS")?,
        )?;
        for (parent, name, mask) in dir_pair_keys {
            dir_pairs
                .insert(PairKeyPod { parent, name }, mask, 0)
                .context("populating BLOCK_DIR_PAIRS")?;
        }
        let mut execs: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_EXEC").context("BLOCK_EXEC")?)?;
        for (k, mask) in policy.exec_enforcement() {
            execs
                .insert(NameKey(k), mask, 0)
                .context("populating BLOCK_EXEC")?;
        }

        // Identity keys. Populated even when the kernel's identity offsets did
        // not resolve: the hooks gate on CFG_IDENTITY_ON, so a populated map is
        // simply never consulted, and startup has already said so out loud.
        let inode_keys = policy.inode_enforcement();
        let mut take_ino = |name: &str| -> anyhow::Result<BpfHashMap<MapData, InoKey, u8>> {
            Ok(BpfHashMap::try_from(
                ebpf.take_map(name).with_context(|| name.to_string())?,
            )?)
        };
        let mut inodes = take_ino("BLOCK_INODES")?;
        for (k, mask) in inode_keys.files {
            inodes
                .insert(InoKey::from(k), mask, 0)
                .context("populating BLOCK_INODES")?;
        }
        let mut dir_inodes = take_ino("BLOCK_DIR_INODES")?;
        for (k, mask) in inode_keys.dirs {
            dir_inodes
                .insert(InoKey::from(k), mask, 0)
                .context("populating BLOCK_DIR_INODES")?;
        }
        let mut exec_inodes = take_ino("BLOCK_EXEC_INODES")?;
        for (k, mask) in inode_keys.execs {
            exec_inodes
                .insert(InoKey::from(k), mask, 0)
                .context("populating BLOCK_EXEC_INODES")?;
        }

        Ok(KernelMaps {
            names,
            dirs,
            pairs,
            dir_pairs,
            execs,
            net4,
            net6,
            port4,
            port6,
            proto_port4,
            proto_port6,
            proto4,
            proto6,
            inodes,
            dir_inodes,
            exec_inodes,
        })
    }

    /// Make the kernel stop denying `key` for the rest of this run. File/exec
    /// exceptions remove the basename/dir from the block map; network
    /// exceptions insert a most-specific allow (/32 or /128) that outranks any
    /// blocking CIDR in the LPM trie.
    pub(crate) fn apply_exception(&mut self, key: &DenialKey) -> anyhow::Result<()> {
        fn drop_name(map: &mut BpfHashMap<MapData, NameKey, u8>, name: &str) -> anyhow::Result<()> {
            let bytes = policy::name_key(name).context("name not kernel-mappable")?;
            map.remove(&NameKey(bytes)).context("removing block key")
        }
        fn drop_ino(
            map: &mut BpfHashMap<MapData, InoKey, u8>,
            dev: u32,
            ino: u64,
        ) -> anyhow::Result<()> {
            map.remove(&InoKey::from(InodeKey::new(dev, ino)))
                .context("removing identity block key")
        }
        // A lifecycle exception narrows the stored mask instead of removing the
        // key: the operator approved one `rm`, not every read of the file. The
        // key only goes away when clearing the bit leaves nothing to enforce —
        // writing a zero back would mean `MASK_ANY`, i.e. "block every open",
        // which is the opposite of what was granted.
        fn lift_name(
            map: &mut BpfHashMap<MapData, NameKey, u8>,
            name: &str,
            op: u8,
        ) -> anyhow::Result<()> {
            let bytes = policy::name_key(name).context("name not kernel-mappable")?;
            let cur = map.get(&NameKey(bytes), 0).context("reading block key")?;
            match fmode::without(cur, op) {
                Some(next) => map
                    .insert(NameKey(bytes), next, 0)
                    .context("narrowing block key"),
                None => map.remove(&NameKey(bytes)).context("removing block key"),
            }
        }
        fn lift_ino(
            map: &mut BpfHashMap<MapData, InoKey, u8>,
            dev: u32,
            ino: u64,
            op: u8,
        ) -> anyhow::Result<()> {
            let k = InoKey::from(InodeKey::new(dev, ino));
            let cur = map.get(&k, 0).context("reading identity block key")?;
            match fmode::without(cur, op) {
                Some(next) => map
                    .insert(k, next, 0)
                    .context("narrowing identity block key"),
                None => map.remove(&k).context("removing identity block key"),
            }
        }
        fn pair_key(parent: &str, name: &str) -> anyhow::Result<PairKeyPod> {
            Ok(PairKeyPod {
                parent: policy::name_key(parent).context("parent not kernel-mappable")?,
                name: policy::name_key(name).context("name not kernel-mappable")?,
            })
        }
        fn lift_pair(
            map: &mut BpfHashMap<MapData, PairKeyPod, u8>,
            parent: &str,
            name: &str,
            op: u8,
        ) -> anyhow::Result<()> {
            let k = pair_key(parent, name)?;
            let cur = map.get(&k, 0).context("reading pair block key")?;
            match fmode::without(cur, op) {
                Some(next) => map.insert(k, next, 0).context("narrowing pair block key"),
                None => map.remove(&k).context("removing pair block key"),
            }
        }
        match key {
            DenialKey::FileName(n) => drop_name(&mut self.names, n),
            DenialKey::FileDir(d) => drop_name(&mut self.dirs, d),
            DenialKey::FilePair { parent, name } => self
                .pairs
                .remove(&pair_key(parent, name)?)
                .context("removing pair block key"),
            DenialKey::DirPair { parent, name } => self
                .dir_pairs
                .remove(&pair_key(parent, name)?)
                .context("removing dir-pair block key"),
            DenialKey::Exec(n) => drop_name(&mut self.execs, n),
            DenialKey::FileInode { dev, ino } => drop_ino(&mut self.inodes, *dev, *ino),
            DenialKey::DirInode { dev, ino } => drop_ino(&mut self.dir_inodes, *dev, *ino),
            DenialKey::ExecInode { dev, ino } => drop_ino(&mut self.exec_inodes, *dev, *ino),
            // Into the protocol trie that denied, for the same reason a port
            // denial goes into the port trie: the rule that is still there
            // outranks an allow written anywhere less specific.
            DenialKey::NetProto { proto, key } => {
                let n = proto.number();
                match key.as_ref() {
                    DenialKey::Net4(ip) => self
                        .proto4
                        .insert(
                            &Key::new(
                                PROTO_BITS + 32,
                                ProtoKey4Pod::from(ProtoKey4::new(n, ip.octets())),
                            ),
                            action::ALLOW,
                            0,
                        )
                        .context("inserting protocol allow"),
                    DenialKey::Net6(ip) => self
                        .proto6
                        .insert(
                            &Key::new(
                                PROTO_BITS + 128,
                                ProtoKey6Pod::from(ProtoKey6::new(n, ip.octets())),
                            ),
                            action::ALLOW,
                            0,
                        )
                        .context("inserting protocol allow"),
                    DenialKey::Net4Port { ip, port } => self
                        .proto_port4
                        .insert(
                            &Key::new(
                                PROTO_BITS + PORT_BITS + 32,
                                ProtoPortKey4Pod::from(ProtoPortKey4::new(n, *port, ip.octets())),
                            ),
                            action::ALLOW,
                            0,
                        )
                        .context("inserting protocol+port allow"),
                    DenialKey::Net6Port { ip, port } => self
                        .proto_port6
                        .insert(
                            &Key::new(
                                PROTO_BITS + PORT_BITS + 128,
                                ProtoPortKey6Pod::from(ProtoPortKey6::new(n, *port, ip.octets())),
                            ),
                            action::ALLOW,
                            0,
                        )
                        .context("inserting protocol+port allow"),
                    other => anyhow::bail!("`{other}` cannot carry a protocol exception"),
                }
            }
            DenialKey::Lifecycle { op, key } => {
                let bit = op.bit();
                match key.as_ref() {
                    DenialKey::FileName(n) => lift_name(&mut self.names, n, bit),
                    DenialKey::FileDir(d) => lift_name(&mut self.dirs, d, bit),
                    DenialKey::FilePair { parent, name } => {
                        lift_pair(&mut self.pairs, parent, name, bit)
                    }
                    DenialKey::DirPair { parent, name } => {
                        lift_pair(&mut self.dir_pairs, parent, name, bit)
                    }
                    DenialKey::FileInode { dev, ino } => {
                        lift_ino(&mut self.inodes, *dev, *ino, bit)
                    }
                    DenialKey::DirInode { dev, ino } => {
                        lift_ino(&mut self.dir_inodes, *dev, *ino, bit)
                    }
                    // The lifecycle hooks consult only the four file maps, so
                    // nothing else can be wrapped. Refuse rather than silently
                    // do nothing: an exception that quietly failed is worse than
                    // one that never appeared.
                    other => anyhow::bail!("`{other}` cannot carry a lifecycle exception"),
                }
            }
            // `from_ne_bytes`, not `from_le_bytes`: the LPM trie compares key
            // bytes from the most significant end, so the octets must sit in
            // network order in memory on either endianness.
            DenialKey::Net4(ip) => self
                .net4
                .insert(
                    &Key::new(32, u32::from_ne_bytes(ip.octets())),
                    action::ALLOW,
                    0,
                )
                .context("inserting /32 allow"),
            DenialKey::Net6(ip) => self
                .net6
                .insert(&Key::new(128, Ip6Key(ip.octets())), action::ALLOW, 0)
                .context("inserting /128 allow"),
            // Into the PORT trie, because that is the one that denied. The hooks
            // consult it first and take its answer as final, so an allow written
            // anywhere else would be read after the block that is still there.
            DenialKey::Net4Port { ip, port } => self
                .port4
                .insert(
                    &Key::new(
                        PORT_BITS + 32,
                        PortKey4Pod::from(PortKey4::new(*port, ip.octets())),
                    ),
                    action::ALLOW,
                    0,
                )
                .context("inserting port allow"),
            DenialKey::Net6Port { ip, port } => self
                .port6
                .insert(
                    &Key::new(
                        PORT_BITS + 128,
                        PortKey6Pod::from(PortKey6::new(*port, ip.octets())),
                    ),
                    action::ALLOW,
                    0,
                )
                .context("inserting port allow"),
        }
    }
}

/// The kernel's own counters (per-CPU, summed). These are the only numbers in
/// wardyn that are not a userspace guess, which is what makes them worth
/// printing: they say how many events were *lost*, how many children escaped the
/// watch set, and how many denials the hooks really made.
pub(crate) struct KernelStats {
    map: PerCpuArray<MapData, u64>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StatSnapshot {
    pub ring_drops: u64,
    pub watch_full: u64,
    pub denied_file: u64,
    pub denied_exec: u64,
    pub denied_net: u64,
    /// How many of the above matched on `(dev, ino)` rather than a name. A
    /// SUBSET of the denial counters above, never an addition — see
    /// [`stat::DENIED_IDENTITY`].
    pub denied_identity: u64,
    /// Removals refused by the lifecycle hooks.
    pub denied_delete: u64,
    /// New names refused by the lifecycle hooks.
    pub denied_create: u64,
}

impl StatSnapshot {
    pub fn denials(&self) -> u64 {
        self.denied_file
            + self.denied_exec
            + self.denied_net
            + self.denied_delete
            + self.denied_create
    }
}

impl KernelStats {
    fn new(map: PerCpuArray<MapData, u64>) -> Self {
        KernelStats { map }
    }

    fn slot(&self, idx: u32) -> u64 {
        self.map
            .get(&idx, 0)
            .map(|per_cpu| per_cpu.iter().sum())
            .unwrap_or(0)
    }

    pub(crate) fn snapshot(&self) -> StatSnapshot {
        StatSnapshot {
            ring_drops: self.slot(stat::RING_DROPS),
            watch_full: self.slot(stat::WATCH_FULL),
            denied_file: self.slot(stat::DENIED_FILE),
            denied_exec: self.slot(stat::DENIED_EXEC),
            denied_net: self.slot(stat::DENIED_NET),
            denied_identity: self.slot(stat::DENIED_IDENTITY),
            denied_delete: self.slot(stat::DENIED_DELETE),
            denied_create: self.slot(stat::DENIED_CREATE),
        }
    }
}

/// Everything the event loops need to evaluate, record, and (from the TUI)
/// grant exceptions — bundled so signatures stay sane.
pub(crate) struct RunCtx<'a> {
    pub policy: &'a Policy,
    pub audit: &'a mut Audit,
    pub receipt: Option<&'a mut Receipt>,
    pub maps: &'a mut KernelMaps,
    pub stats: Option<KernelStats>,
    pub enforce: bool,
    /// File/exec `block` rules are *predicted* as an enforced `BLOCK` only when
    /// this is true: the LSM attached AND the dentry offsets are trusted.
    /// Otherwise those rows are demoted to `block~`. Either way the kernel's own
    /// `DENY_*` events remain the authority.
    pub enforce_files: bool,
    /// The WATCHED map, held past spawn only when eviction is deferred to userspace
    /// (`prune_watched`); `None` otherwise.
    pub watched: Option<BpfHashMap<MapData, u32, u8>>,
    /// Predicted denials awaiting the kernel's confirming `DENY_*` event, so a
    /// confirmation is not rendered (and audited) a second time. Bounded; the
    /// observe tracepoint always fires before the enforcing hook, so a short
    /// window is enough.
    pending: VecDeque<(u32, u32, String)>,
}

impl RunCtx<'_> {
    fn remember_prediction(&mut self, pid: u32, kind: u32, key: String) {
        if self.pending.len() >= 256 {
            self.pending.pop_front();
        }
        self.pending.push_back((pid, kind, key));
    }

    /// Was this kernel denial already reported by a predicted row? Consumes the
    /// prediction if so.
    fn take_prediction(&mut self, pid: u32, kind: u32, key: &str) -> bool {
        if let Some(i) = self
            .pending
            .iter()
            .rposition(|(p, k, s)| *p == pid && *k == kind && s == key)
        {
            self.pending.remove(i);
            return true;
        }
        false
    }
}

fn load_tracepoint(
    ebpf: &mut aya::Ebpf,
    name: &str,
    category: &str,
    tp: &str,
) -> anyhow::Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` not found"))?
        .try_into()?;
    prog.load()?;
    prog.attach(category, tp)
        .with_context(|| format!("attaching {category}:{tp}"))?;
    Ok(())
}

/// The kernel the LSM struct offsets in wardyn-ebpf were derived for.
const OFFSETS_KERNEL: &str = "6.8";

/// The architecture they were derived ON — `scripts/kernel-offsets.sh` was run
/// against an x86_64 vmlinux, and nothing in the numbers records that.
const OFFSETS_ARCH: &str = "x86_64";

/// Whether the built-in LSM offsets can be trusted on the machine we are on.
///
/// Only consulted when BTF resolution fails, which is rare — wardyn needs BTF
/// to attach the LSM programs at all — but it decides something specific: it is
/// the signal that lets the feed *predict* a file/exec `BLOCK`. Get it wrong and
/// wardyn claims denials the kernel may never make, which is the one thing this
/// codebase refuses to do.
///
/// Both halves have to match.
///
/// **The kernel version**, because `struct file` is reorganised between
/// releases — 6.13 moved `f_path` into an anonymous union, which is what the
/// BTF walker had to learn to descend into.
///
/// **The architecture**, because these numbers came off one. Field offsets
/// within these structs are not guaranteed to agree across arches on the same
/// release: distro configs differ (lock debugging, `CONFIG_FSNOTIFY`, preempt
/// model), and several members inside `struct file` and `struct dentry` are
/// behind `#ifdef`. Assuming aarch64 lays out like x86_64 would be a guess, and
/// a wrong guess reads the wrong words and silently permits.
///
/// So on any architecture but the one they were measured on, the built-ins are
/// never trusted. The cost is nil in practice and the alternative is a number
/// that looks authoritative and is not.
fn kernel_matches_builtin_offsets() -> bool {
    if std::env::consts::ARCH != OFFSETS_ARCH {
        return false;
    }
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mm = release
        .trim()
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    !mm.is_empty() && mm == OFFSETS_KERNEL
}

/// Prune WATCHED of tgids whose process has exited. Only used when eviction is
/// deferred to userspace (no pid-namespace mismatch, so the init-ns tgids in
/// WATCHED equal the pids under our own /proc). This is what makes the deferred
/// leader eviction safe: it removes an entry only once the process is genuinely
/// gone, so a live process that `pthread_exit`'d from its leader thread stays
/// watched. A briefly-reused pid may be re-watched until the next sweep — the
/// intended fail-safe direction (transiently over-watch, never under-watch).
fn prune_watched(map: &mut BpfHashMap<MapData, u32, u8>) {
    let dead: Vec<u32> = map
        .keys()
        .filter_map(Result::ok)
        .filter(|pid| !std::path::Path::new(&format!("/proc/{pid}")).exists())
        .collect();
    for pid in dead {
        let _ = map.remove(&pid);
    }
}

/// Drop the child out of root before it execs the agent. Without this the watched
/// (sandboxed) process inherits wardyn's root and can disable the very enforcement
/// watching it (rewrite the BPF maps, detach the cgroup programs, kill wardyn, or
/// read the raw disk). Target identity: `--as-user uid[:gid]`, else
/// `$SUDO_UID`/`$SUDO_GID` (the documented `sudo wardyn ...` path). Refused under
/// `--enforce` if no non-root target can be found (better to not start than to
/// hand the sandboxed process the keys); `--keep-root` opts out explicitly.
fn apply_privilege_drop(
    cmd: &mut Command,
    opts: &Opts,
    notices: &mut Vec<String>,
) -> anyhow::Result<()> {
    if opts.keep_root {
        if opts.enforce {
            notices.push(
                "--keep-root — the watched agent runs as root and can disable enforcement from \
                 userspace. Only use this for a trusted target."
                    .into(),
            );
        }
        return Ok(());
    }
    let (uid, gid) = match resolve_target_identity(opts) {
        Some(t) => t,
        None => {
            let msg = "could not determine a non-root user to drop the agent to (no --as-user and \
                       no usable $SUDO_UID). Run wardyn via `sudo`, pass --as-user <uid[:gid]>, or \
                       --keep-root to intentionally run the agent as root";
            if opts.enforce {
                bail!("{msg} (refused under --enforce: a root child can disable enforcement)");
            }
            notices.push(msg.into());
            return Ok(());
        }
    };
    // SAFETY: pre_exec runs in the forked child before exec; only async-signal-safe
    // libc calls are used. Order matters — clear supplementary groups and setgid
    // BEFORE setuid, while we still hold the privilege to do so.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // No setuid binary the agent execs can regain privilege. Pass the
            // variadic args as c_ulong so the full 64-bit registers are well-defined.
            libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
            Ok(())
        });
    }
    notices.push(format!(
        "the agent runs as uid={uid} gid={gid}, not root (--keep-root to disable)"
    ));
    Ok(())
}

/// The (uid, gid) to drop the child to: `--as-user uid[:gid]` wins, else
/// `$SUDO_UID`/`$SUDO_GID`. `None` if neither yields a non-root uid.
fn resolve_target_identity(opts: &Opts) -> Option<(u32, u32)> {
    if let Some(spec) = &opts.as_user {
        let mut it = spec.splitn(2, ':');
        let uid: u32 = it.next()?.parse().ok()?;
        let gid: u32 = match it.next() {
            Some(g) => g.parse().ok()?,
            None => uid,
        };
        return Some((uid, gid));
    }
    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    if uid == 0 {
        return None;
    }
    let gid: u32 = std::env::var("SUDO_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(uid);
    Some((uid, gid))
}

/// Where a `path:` rule's relative path and `~` resolve from.
///
/// Both halves are things only this process knows and neither is guessable:
/// - **cwd** is wardyn's working directory, which the agent inherits, so
///   `path: .env` means the `.env` of the project the agent was launched in.
/// - **home** is the *agent's* home, not root's. Wardyn runs under `sudo`, so
///   `$HOME` here is normally `/root`, and a rule saying `~/.ssh` that quietly
///   anchored root's keys instead of the user's would protect the wrong thing
///   while looking correct.
fn anchor_base(opts: &Opts) -> AnchorBase {
    let home = resolve_target_identity(opts)
        .and_then(|(uid, _)| home_for_uid(uid))
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from));
    AnchorBase {
        cwd: std::env::current_dir().ok(),
        home,
    }
}

/// The home directory recorded for `uid` in `/etc/passwd`.
///
/// Read directly rather than through NSS: wardyn has no libc user-database
/// dependency, and a policy that resolves differently depending on whether LDAP
/// answered would be worse than one that only knows local accounts. A miss is
/// reported by the caller as an unresolved rule, never guessed.
fn home_for_uid(uid: u32) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        // name:passwd:uid:gid:gecos:home:shell
        let mut f = line.split(':');
        let (_name, _pw, u) = (f.next()?, f.next()?, f.next()?);
        if u.parse::<u32>().ok()? != uid {
            continue;
        }
        let home = f.nth(2)?; // skip gid, gecos
        if !home.is_empty() {
            return Some(PathBuf::from(home));
        }
    }
    None
}

/// The LSM hooks that carry the `create`/`delete` axis. Attached only when a
/// policy asks for it, and separately from the two core hooks, because they are
/// not equally load-bearing: `file_open` failing to attach means wardyn cannot
/// do its main job, while `inode_mkdir` failing means one axis of one rule is
/// unenforced. Aborting the whole LSM for the second would trade the tool for a
/// feature.
const LIFECYCLE_HOOKS: &[&str] = &[
    "inode_unlink",
    "inode_rmdir",
    "inode_create",
    "inode_mkdir",
    "inode_rename",
    "inode_link",
    "inode_symlink",
];

/// Load + attach the BPF-LSM file/exec deniers. Kept separate so a kernel without
/// BPF LSM degrades gracefully to network-only enforcement instead of aborting.
///
/// `lifecycle` adds the create/delete hooks. Returns the hooks that could NOT be
/// attached, so the caller can name them instead of leaving a policy claiming an
/// axis the kernel is not enforcing.
fn attach_lsm(ebpf: &mut aya::Ebpf, lifecycle: bool) -> anyhow::Result<Vec<String>> {
    let btf = Btf::from_sys_fs().context("loading kernel BTF")?;
    let mut attach = |name: &str, hook: &str| -> anyhow::Result<()> {
        let prog: &mut Lsm = ebpf
            .program_mut(name)
            .with_context(|| format!("{name} program not found"))?
            .try_into()?;
        prog.load(hook, &btf)
            .with_context(|| format!("loading lsm/{hook}"))?;
        prog.attach()
            .with_context(|| format!("attaching lsm/{hook}"))?;
        Ok(())
    };
    // The two that wardyn is not wardyn without.
    attach("file_open", "file_open")?;
    attach("bprm_check", "bprm_check_security")?;

    let mut missing = Vec::new();
    if lifecycle {
        for hook in LIFECYCLE_HOOKS {
            if let Err(e) = attach(hook, hook) {
                missing.push(format!("{hook} ({e:#})"));
            }
        }
    }
    Ok(missing)
}

/// Await the child's exit if there is one; otherwise never resolve.
///
/// A `wait` error is a *result*, not grounds to `process::exit` — doing that
/// skipped the terminal restore, the final ring sweep and the exit summary.
pub(crate) async fn wait_for(child: &mut Option<Child>) -> Option<std::process::ExitStatus> {
    match child {
        Some(c) => c.wait().await.ok(),
        None => std::future::pending().await,
    }
}

/// Stop the watched agent when wardyn stops.
///
/// Wardyn's enforcement lives in programs owned by this process: when it exits,
/// the cgroup and LSM attachments go away. Leaving the agent running would hand
/// it exactly the unsupervised shell the tool exists to prevent, silently, at
/// the moment the operator pressed `q`. So the subtree goes down with the
/// warden: SIGTERM, a short grace period, then SIGKILL.
/// Returns `(status, we_signalled)`. When wardyn had to signal the agent — the
/// operator quit while it was still working — the agent's resulting exit status
/// describes wardyn's own shutdown, not the agent's outcome, so the caller
/// reports success instead of a misleading 143.
async fn stop_child(child: &mut Option<Child>) -> (Option<std::process::ExitStatus>, bool) {
    let Some(c) = child.as_mut() else {
        return (None, false);
    };
    if let Ok(Some(status)) = c.try_wait() {
        return (Some(status), false);
    }
    let Some(pid) = c.id().map(|p| p as i32) else {
        return (None, false);
    };
    eprintln!(
        "wardyn: stopping the watched agent (pid {pid}) — enforcement ends when wardyn does, so \
         it must not keep running unsupervised."
    );
    // Negative pid = the whole process group, so a shell's children go too.
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
        libc::kill(pid, libc::SIGTERM);
    }
    let status = match tokio::time::timeout(std::time::Duration::from_secs(3), c.wait()).await {
        Ok(status) => status.ok(),
        Err(_) => {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
            c.wait().await.ok()
        }
    };
    (status, true)
}

/// The process exit code to report for a finished target: its own code, or
/// 128+signal in the shell convention.
fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let code = match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("wardyn: error: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

async fn run() -> anyhow::Result<i32> {
    let opts = match cli::parse_args()? {
        ParseOutcome::Help => {
            println!("{}", cli::USAGE);
            return Ok(0);
        }
        ParseOutcome::Version => {
            println!("wardyn {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        ParseOutcome::Run(o) => *o,
    };

    // `--dry-run` answers "what would this policy actually do?" without root,
    // eBPF, or a target — the check that used to be impossible before deploying
    // a policy.
    if opts.dry_run {
        // Same anchor base as a real run, so `--dry-run` reports the objects the
        // run would actually pin. Resolving them differently here would make the
        // one command users are told to validate a policy with the one command
        // that cannot see an identity rule pointing at the wrong file.
        let policy = Loader::new()
            .base(anchor_base(&opts))
            .load(opts.policy_path.as_deref())?;
        print!("{}", policy.explain());
        return Ok(0);
    }

    // Enforcement is deliberately scoped to the launched subtree (the kernel
    // deny hooks gate on WATCHED membership, and WATCHED is only ever seeded in
    // `run` mode). Under `--all`/bare invocation WATCHED stays empty, so nothing
    // would actually be denied — refuse rather than claim an enforcement that
    // silently does nothing. (System-wide blocking is out of scope by design.)
    if opts.enforce && matches!(opts.mode, Mode::All) {
        bail!(
            "--enforce requires `run -- <cmd>`: wardyn only enforces on the subtree it launches, \
             not system-wide. Re-run as: wardyn --enforce run -- <cmd>"
        );
    }
    // eBPF load/attach needs privilege; fail early with a clear message.
    if unsafe { libc::geteuid() } != 0 {
        bail!("wardyn must run as root — it loads eBPF programs (try: sudo wardyn ...)");
    }
    // A TUI needs a terminal to draw on: asking for one over a pipe would
    // render escape sequences into whatever is reading. `--format json` never
    // gets one, whether or not stdout is a tty.
    let use_tui = opts.format == Format::Tui && std::io::stdout().is_terminal();
    if !use_tui {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    // Startup diagnostics are collected, not printed: in TUI mode stderr is
    // about to be replaced by the alternate screen, so anything written here
    // would flash past unread. They are shown as feed rows instead, and printed
    // plainly when there is no TUI.
    let mut notices: Vec<String> = Vec::new();

    let policy = Loader::new()
        .base(anchor_base(&opts))
        .load(opts.policy_path.as_deref())?;
    notices.push(format!("policy loaded: {}", policy.summary()));
    if opts.enforce {
        // Identity rules: say which objects they landed on, and which resolved
        // to nothing. A `path:` rule that silently evaporated (wrong working
        // directory, a `~` with no home) looks exactly like coverage in the rule
        // list and is nothing at all in the kernel. Only under `--enforce`,
        // because in observe mode no rule enforces anything anyway.
        for a in policy.anchors() {
            notices.push(format!("{} pins {}", a.rule, a.blast_radius()));
        }
        for u in policy.unresolved_anchors() {
            notices.push(format!(
                "{} resolved to nothing ({} — {}); it pins no object. Any `match:` rule for the \
                 same name still applies.",
                u.rule,
                u.path.display(),
                u.reason
            ));
        }
        // Be honest up front: block rules that can't reduce to a kernel-checkable
        // basename/dir are flagged in the feed but never actually denied.
        for pat in policy.observe_only_blocks() {
            notices.push(format!(
                "policy `{pat}` (block) can't be kernel-enforced (only basename/dir file rules \
                 and CIDRs are) — it will be flagged, not denied"
            ));
        }
        // And the converse: a block glob that reduced to a bare name enforces
        // MORE broadly than written, because the LSM hook matches names.
        for (pat, reach) in policy.overbroad_block_keys() {
            notices.push(format!(
                "policy `{pat}` (block) enforces on {reach} — the kernel matches by name, so it \
                 will also deny paths the glob wouldn't."
            ));
        }
        // Rule ORDER does not exist in the kernel: an allow before a block does
        // not survive the reduction to a set of block keys.
        for (pat, key) in policy.shadowed_by_kernel() {
            notices.push(format!(
                "policy `{pat}` is overridden in the kernel by block key `{key}` — the kernel's \
                 block set is unordered, so this rule does NOT create an exception."
            ));
        }
        for msg in policy.semantic_warnings() {
            notices.push(msg);
        }
    }
    let mut audit = Audit::create(&opts.audit_path)?;

    // Agent-facing denial receipt: only under --enforce (observe mode denies
    // nothing), created before spawn so the child can inherit its path in
    // WARDYN_DENIALS and read back what was denied instead of flailing on a
    // bare EPERM.
    let mut receipt = if opts.enforce {
        let path = opts.denials_path.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("wardyn-denials-{}.jsonl", std::process::id()))
        });
        // The receipt is created root-owned and 0600, then handed to the
        // identity the agent will actually run as — otherwise the privilege
        // drop would leave the agent unable to read its own receipt.
        let owner = if opts.keep_root {
            None
        } else {
            resolve_target_identity(&opts)
        };
        Some(Receipt::create(
            &path,
            &opts.mode.label(),
            &policy.summary(),
            owner,
        )?)
    } else {
        if opts.denials_path.is_some() {
            notices.push(
                "--denials has no effect without --enforce (observe mode denies nothing, so there \
                 is nothing to receipt)"
                    .into(),
            );
        }
        None
    };

    let ebpf_object = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/wardyn"));
    if ebpf_object.is_empty() {
        bail!(
            "this binary was built with WARDYN_SKIP_EBPF_BUILD=1 and contains no eBPF programs — \
             it can only be type-checked. Rebuild with bpf-linker installed."
        );
    }
    let mut ebpf = aya::Ebpf::load(ebpf_object).context("loading eBPF object")?;

    load_tracepoint(&mut ebpf, "wardyn_execve", "syscalls", "sys_enter_execve")?;
    load_tracepoint(&mut ebpf, "wardyn_openat", "syscalls", "sys_enter_openat")?;
    load_tracepoint(&mut ebpf, "wardyn_connect", "syscalls", "sys_enter_connect")?;
    load_tracepoint(&mut ebpf, "wardyn_fork", "sched", "sched_process_fork")?;
    load_tracepoint(&mut ebpf, "wardyn_exit", "sched", "sched_process_exit")?;
    // Cover the syscall variants the LSM/cgroup hooks also enforce on, so a
    // denial can't happen off-feed. Optional: absent on older kernels.
    for (name, tp) in [
        ("wardyn_openat2", "sys_enter_openat2"),
        ("wardyn_execveat", "sys_enter_execveat"),
        ("wardyn_sendto", "sys_enter_sendto"),
    ] {
        if let Err(e) = load_tracepoint(&mut ebpf, name, "syscalls", tp) {
            notices.push(format!(
                "could not attach syscalls:{tp} ({e:#}) — opens/execs/sends via this syscall \
                 variant won't appear in the feed (enforcement is unaffected)."
            ));
        }
    }
    // Pid-ns handshake (see `learn_init_ns_tgid`). Best-effort: without it
    // wardyn still works wherever it shares the kernel's init pid namespace.
    let handshake_attached = match load_tracepoint(
        &mut ebpf,
        "wardyn_handshake",
        "syscalls",
        "sys_enter_personality",
    ) {
        Ok(()) => true,
        Err(e) => {
            notices.push(format!(
                "could not attach the pid-ns handshake tracepoint ({e:#}) — if wardyn runs inside \
                 a container or WSL distro, `run` scoping will silently fail"
            ));
            false
        }
    };

    // Enforcement (opt-in): attach the cgroup/connect4 denier BEFORE taking any
    // map, so map relocation still finds NET_RULES/CONFIG/WATCHED in the object.
    // Kept in `_cgroup` for the program's lifetime.
    let mut _cgroup = None;
    // Whether the BPF-LSM file/exec deniers actually attached. Drives the honest
    // feed: if they didn't, file/exec `block` rows are demoted to `block~`.
    let mut lsm_active = false;
    if opts.enforce {
        let cg = std::fs::File::open("/sys/fs/cgroup")
            .context("open /sys/fs/cgroup (cgroup v2 required for network enforcement)")?;
        for name in ["connect4", "connect6", "sendmsg4", "sendmsg6"] {
            let prog: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .with_context(|| format!("{name} program not found"))?
                .try_into()?;
            prog.load()?;
            // `Single` is what aya calls flags=0; on kernels >= 5.7 this becomes
            // a bpf_link attach, which the kernel itself treats as ALLOW_MULTI,
            // so other cgroup-BPF tools (and a second wardyn) still attach.
            prog.attach(&cg, CgroupAttachMode::Single)
                .with_context(|| format!("attaching {name} to the cgroup"))?;
        }
        _cgroup = Some(cg);

        // Files/exec: BPF-LSM deniers. Non-fatal — if the kernel lacks BPF LSM,
        // keep the (already-attached) network enforcement rather than aborting.
        match attach_lsm(&mut ebpf, policy.has_lifecycle_rules()) {
            Ok(missing) => {
                lsm_active = true;
                let axes = if policy.has_lifecycle_rules() {
                    "enforcement ON — egress (cgroup) + secret-file reads + blocked execs + \
                     create/delete (LSM)"
                } else {
                    "enforcement ON — egress (cgroup) + secret-file reads + blocked execs (LSM)"
                };
                notices.push(axes.into());
                // A create/delete rule that silently did not attach is a rule
                // the policy claims and the kernel does not hold. Name it.
                if !missing.is_empty() {
                    notices.push(format!(
                        "create/delete rules are only PARTLY enforced — this kernel would not \
                         take: {}. Operations reaching the missing hook are ALLOWED.",
                        missing.join(", ")
                    ));
                }
            }
            Err(e) => notices.push(format!(
                "BPF LSM enforcement unavailable ({e:#}) — file/exec blocking is OFF (network \
                 egress blocking is still active). Enable it via scripts/enable-bpf-lsm.sh."
            )),
        }
    }

    let mut config: Array<_, u32> = Array::try_from(ebpf.take_map("CONFIG").context("CONFIG")?)?;
    config.set(0, u32::from(matches!(opts.mode, Mode::All)), 0)?; // watch_all
    config.set(1, u32::from(opts.enforce), 0)?; // enforce
    config.set(2, policy.default_action_code(), 0)?; // net_default

    // sched_process_fork's child_pid offset moved when the kernel made comm
    // dynamic (`__data_loc`): 44→20. Read the running kernel's authoritative
    // layout from tracefs rather than baking in one kernel's number — fork
    // adoption (and with it ALL `run` scoping) silently dies when it is wrong.
    let child_off = match tracefs_field_offset("sched/sched_process_fork", "child_pid") {
        Some(c) => c,
        None => {
            notices.push(
                "could not read the sched_process_fork layout from tracefs — falling back to \
                 kernel-6.8 offsets; child adoption may silently fail"
                    .into(),
            );
            44
        }
    };
    config.set(CFG_FORK_CHILD_OFF, child_off, 0)?;
    // Skip the port-trie lookup per connect for policies that name no ports.
    config.set(CFG_PORT_RULES_ON, u32::from(policy.has_port_rules()), 0)?;
    // The five lifecycle hooks stay inert unless a rule asked for them. This is
    // not only a hot-path saving: it is what guarantees a policy written before
    // the axis existed cannot start refusing an `rm` because wardyn was updated.
    config.set(CFG_LIFECYCLE_ON, u32::from(policy.has_lifecycle_rules()), 0)?;
    config.set(CFG_PROTO_RULES_ON, u32::from(policy.has_proto_rules()), 0)?;
    config.set(CFG_PAIRS_ON, u32::from(policy.has_pair_rules()), 0)?;

    // LSM dentry offsets: resolve them from the running kernel's own BTF so the
    // file/exec matcher adapts to the kernel instead of being pinned to 6.8. On
    // failure the CONFIG slots stay 0 and the eBPF side falls back to the built-in
    // 6.8 constants — strictly a portability win, no regression. `offsets_trusted`
    // drives the honest feed below (file/exec BLOCK is only predicted when we
    // trust the offsets are right; the kernel's own events are unaffected).
    let mut offsets_trusted = false;
    let mut identity_available = false;
    if opts.enforce {
        match btf::resolve_offsets() {
            Ok(o) => {
                config.set(CFG_FILE_DENTRY_OFF, o.lsm.file_dentry, 0)?;
                config.set(CFG_DENTRY_NAME_OFF, o.lsm.dentry_name, 0)?;
                config.set(CFG_DENTRY_PARENT_OFF, o.lsm.dentry_parent, 0)?;
                config.set(CFG_BPRM_FILE_OFF, o.lsm.bprm_file, 0)?;
                offsets_trusted = true;
                match o.identity {
                    Some(i) => {
                        config.set(CFG_FILE_INODE_OFF, i.file_inode, 0)?;
                        config.set(CFG_FILE_MODE_OFF, i.file_mode, 0)?;
                        config.set(CFG_INODE_INO_OFF, i.inode_ino, 0)?;
                        config.set(CFG_INODE_SB_OFF, i.inode_sb, 0)?;
                        config.set(CFG_SB_DEV_OFF, i.sb_dev, 0)?;
                        config.set(CFG_DENTRY_INODE_OFF, i.dentry_inode, 0)?;
                        // The offsets are usable: `access:` narrowing (which only
                        // needs f_mode) is now in force.
                        config.set(CFG_EXT_OFFSETS, 1, 0)?;
                        identity_available = true;
                        // The identity *reads* are switched on separately, only
                        // when the policy has keys for them to match: three extra
                        // kernel reads and a map lookup per open, plus four more
                        // per ancestor level, is not free on the hot path of
                        // every file the watched tree touches.
                        let want = !policy.inode_enforcement().is_empty();
                        config.set(CFG_IDENTITY_ON, u32::from(want), 0)?;
                    }
                    None => notices.push(
                        "this kernel's BTF does not expose the inode fields; identity (dev,ino) \
                         rules cannot be enforced — name rules still are."
                            .to_string(),
                    ),
                }
            }
            Err(why) => {
                // Couldn't read/parse BTF; the built-in 6.8 offsets apply. Only
                // trust them for the honest feed if we're actually on 6.8.
                offsets_trusted = kernel_matches_builtin_offsets();
                if offsets_trusted {
                    notices.push(format!(
                        "BTF offset resolution failed ({why}) — using built-in kernel-\
                         {OFFSETS_KERNEL} LSM offsets (running kernel matches)."
                    ));
                } else {
                    // Say WHICH half failed. "not 6.8" on an aarch64 6.8 box
                    // would send the reader hunting for a version problem that
                    // is not there.
                    let mismatch = if std::env::consts::ARCH != OFFSETS_ARCH {
                        format!(
                            "the built-in offsets were measured on {OFFSETS_ARCH} and this is {}",
                            std::env::consts::ARCH
                        )
                    } else {
                        format!("the running kernel is not {OFFSETS_KERNEL}")
                    };
                    notices.push(format!(
                        "could not resolve LSM struct offsets from BTF ({why}) and {mismatch}; \
                         file/exec blocking may silently fail. Such rows are shown as block~ \
                         until the kernel reports a denial itself."
                    ));
                }
            }
        }
    }

    // `access: read`/`write` needs the kernel to read `f_mode`, which needs an
    // offset we may not have. The rule still fires — it just covers every open,
    // which is broader than written. Broader is the safe direction; saying
    // nothing about it is not.
    if opts.enforce && !identity_available && policy.uses_access_narrowing() {
        notices.push(
            "this policy narrows rules with `access:`, but the kernel offsets needed to read an \
             open's access mode did not resolve — those rules cover EVERY open (broader than \
             written), not just the access named."
                .to_string(),
        );
    }

    // `run` scoping: WATCHED is keyed by tgid as the KERNEL sees it (init pid
    // namespace); std::process::id() is wardyn's pid in its OWN namespace. On a
    // bare host they coincide, but inside a container or WSL2 distro they never
    // do — seeding WATCHED with the local pid would watch (and enforce) nothing
    // while claiming to. Learn the kernel-view tgid instead, and be loud when
    // the namespaces differ.
    let self_pid = std::process::id();
    let mut seed_tgid = self_pid;
    let mut ns_mismatch = false;
    if matches!(opts.mode, Mode::Run(_)) && handshake_attached {
        match learn_init_ns_tgid(&mut config) {
            Some(tgid) => {
                seed_tgid = tgid;
                ns_mismatch = tgid != self_pid;
                if ns_mismatch {
                    notices.push(format!(
                        "pid namespace detected (self {self_pid}, kernel view {tgid}) — relying on \
                         in-kernel fork adoption; the feed shows init-ns pids"
                    ));
                }
            }
            None => notices.push(
                "pid-ns handshake failed — assuming no pid namespace; if wardyn runs inside a \
                 container or WSL distro, `run` scoping will silently fail"
                    .into(),
            ),
        }
    }

    // Deferred WATCHED eviction (see the `wardyn_exit` hook): when there is no
    // pid-namespace mismatch, userspace prunes WATCHED against /proc, so tell the
    // kernel NOT to evict on a leader-thread exit — otherwise a process that ends
    // `main` with `pthread_exit()` while worker threads keep running is silently
    // unwatched. Under a mismatch we can't map init-ns tgids to our own /proc, so
    // the kernel keeps evicting on leader exit (the best available signal there).
    let defer_evict = matches!(opts.mode, Mode::Run(_)) && !ns_mismatch;
    config.set(CFG_DEFER_EVICT, u32::from(defer_evict), 0)?;

    // Kept alive for the whole run so the TUI can grant exceptions into them.
    let mut kernel_maps = KernelMaps::load(&mut ebpf, &policy)?;
    let stats = ebpf
        .take_map("STATS")
        .and_then(|m| PerCpuArray::try_from(m).ok())
        .map(KernelStats::new);
    if stats.is_none() {
        notices.push("STATS map unavailable — dropped events cannot be reported this run".into());
    }

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS")?)?;
    let async_fd = AsyncFd::new(ring)?;

    // Held past spawn only when we prune in userspace, so `prune_watched` can drop
    // tgids whose /proc entry is gone.
    let mut watched_map: Option<BpfHashMap<MapData, u32, u8>> = None;
    let mut child: Option<Child> = None;
    if let Mode::Run(argv) = &opts.mode {
        let mut watched: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(ebpf.take_map("WATCHED").context("WATCHED")?)?;
        watched.insert(seed_tgid, 1u8, 0)?; // seed self so fork adopts child
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        // A denial reaches the agent as a bare EPERM; WARDYN_DENIALS names the
        // receipt explaining it. Env is inherited by the whole subtree.
        if let Some(r) = &receipt {
            cmd.env("WARDYN_DENIALS", r.path());
        }
        // Its own process group, so `stop_child` can take the whole subtree down
        // with one signal when wardyn exits.
        cmd.process_group(0);
        // Drop the watched agent out of root before exec (unless --keep-root): the
        // thing being sandboxed must not run with the privilege that could disable
        // its own warden (bpftool the maps, kill wardyn, read the raw disk).
        apply_privilege_drop(&mut cmd, &opts, &mut notices)?;
        let spawned = cmd
            .spawn()
            .with_context(|| format!("spawning `{}`", argv[0].to_string_lossy()))?;
        if let Some(pid) = spawned.id() {
            // Under a pid namespace the local child pid means nothing to the
            // kernel — worse, it could collide with an unrelated init-ns tgid
            // and watch a stranger. The fork hook already adopted the child
            // (spawn returning means the clone completed); the direct insert
            // is belt-and-braces for the namespace-free case only.
            if !ns_mismatch {
                let _ = watched.insert(pid, 1u8, 0);
            }
            notices.push(format!(
                "watching `{}` (pid {pid}) and its subtree",
                opts.mode.label()
            ));
        }
        // Self was only seeded so the fork hook would adopt the child at spawn
        // time; the child (and its subtree via fork) is tracked in its own right
        // now, so drop wardyn's own pid — otherwise wardyn would police itself
        // (its own opens/execs/connects) under --enforce and add noise to the feed.
        let _ = watched.remove(&seed_tgid);
        child = Some(spawned);
        if defer_evict {
            watched_map = Some(watched);
        }
    } else {
        notices.push("watching exec/open/connect system-wide; Ctrl-C to stop".into());
    }

    let mut ctx = RunCtx {
        policy: &policy,
        audit: &mut audit,
        receipt: receipt.as_mut(),
        maps: &mut kernel_maps,
        stats,
        enforce: opts.enforce,
        // File/exec denials are only PREDICTED as `BLOCK` when the LSM attached
        // and we trust the dentry offsets; otherwise they are demoted to block~.
        // A `DENY_*` event from the kernel overrides either way.
        enforce_files: opts.enforce && lsm_active && offsets_trusted,
        watched: watched_map,
        pending: VecDeque::new(),
    };
    let result = if use_tui {
        tui::run(async_fd, &mut child, opts.mode.label(), &mut ctx, notices).await
    } else {
        for n in &notices {
            eprintln!("wardyn: {n}");
        }
        run_stream(async_fd, &mut child, &mut ctx, opts.format).await
    };

    // Whatever happened above — clean exit, error, or the operator quitting —
    // the agent must not outlive its warden.
    let (status, we_stopped_it) = stop_child(&mut child).await;

    let snapshot = ctx.stats.as_ref().map(|s| s.snapshot()).unwrap_or_default();
    eprintln!(
        "wardyn: {} policy violation(s) logged to {}",
        audit.count(),
        audit.path()
    );
    if let Some(failed) = std::num::NonZeroU64::new(audit.write_failures()) {
        eprintln!(
            "wardyn: WARNING: {failed} audit record(s) could NOT be written — the security record \
             for this run is incomplete."
        );
    }
    if let Some(r) = &receipt {
        eprintln!(
            "wardyn: {} denial(s) receipted to {} (WARDYN_DENIALS in the agent's env)",
            r.count(),
            r.path()
        );
    }
    report_kernel_stats(
        &snapshot,
        opts.enforce,
        receipt.as_ref().map(|r| r.count()).unwrap_or(0),
    );
    result?;
    if we_stopped_it {
        // The agent's status here reports our own SIGTERM, not its outcome.
        return Ok(0);
    }
    Ok(status.map(exit_code_of).unwrap_or(0))
}

/// Print the counters only the kernel could know. Silence here would mean a full
/// ring buffer (lost audit records), a full watch set (unenforced children), or
/// an enforcement path that never fired, all looking exactly like a clean run.
fn report_kernel_stats(s: &StatSnapshot, enforce: bool, claimed: u64) {
    if s.ring_drops > 0 {
        eprintln!(
            "wardyn: WARNING: {} event(s) were dropped by a full ring buffer — those actions have \
             no feed row, no audit record and no receipt line.",
            s.ring_drops
        );
    }
    if s.watch_full > 0 {
        eprintln!(
            "wardyn: WARNING: the watch set filled up {} time(s) — those child processes ran \
             completely unobserved AND unenforced.",
            s.watch_full
        );
    }
    if enforce {
        eprintln!(
            "wardyn: kernel denials — {} file, {} exec, {} network",
            s.denied_file, s.denied_exec, s.denied_net
        );
        // Listed on their own line rather than folded into "file": these came
        // from a different set of hooks, and an operator checking whether the
        // `delete` axis actually fired should not have to subtract.
        if s.denied_delete > 0 || s.denied_create > 0 {
            eprintln!(
                "wardyn: kernel denials — {} delete, {} create (lifecycle hooks)",
                s.denied_delete, s.denied_create
            );
        }
        // Identity denials are the ones a name rule alone would have missed —
        // the renamed secret, the hard link, the moved directory. Reported
        // separately because "the rename didn't help" is a claim, and a counter
        // is the difference between a claim and a measurement.
        if s.denied_identity > 0 {
            eprintln!(
                "wardyn: {} of those matched by identity (dev,ino) — a rename or hard link would \
                 have defeated a name rule.",
                s.denied_identity
            );
        }
        // The one cross-check that cannot be fooled by a wrong struct offset or
        // an LSM that failed to attach: if the receipt told the agent it was
        // denied N times and the kernel counted none, the receipt was fiction.
        if claimed > 0 && s.denials() == 0 {
            eprintln!(
                "wardyn: WARNING: {claimed} denial(s) were reported to the agent but the kernel \
                 counted none — enforcement did NOT fire. Treat this run as observe-only."
            );
        }
    }
}

/// Non-interactive line printer, used when stdout is not a terminal or when a
/// format was asked for. No keyboard, so no exceptions can be granted here.
///
/// `Plain` and `Json` share this loop rather than each having their own: the
/// signal handling, the periodic `/proc` sweep, and the final post-exit drain
/// are the parts that are easy to get subtly wrong, and a second copy of them
/// would be a second place for an event to go missing. Only the rendering
/// differs, which is the last thing that happens to a `Desc`.
async fn run_stream(
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    child: &mut Option<Child>,
    ctx: &mut RunCtx<'_>,
    format: Format,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    // `println!` panics on a closed pipe (`wardyn --plain | head`) and blocks on
    // a slow one. Write through a locked handle and treat a broken pipe as a
    // normal end of output.
    fn line(out: &mut std::io::StdoutLock<'_>, args: std::fmt::Arguments<'_>) -> bool {
        match writeln!(out, "{args}") {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => false,
            Err(_) => false,
        }
    }
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let enforce = ctx.enforce;

    // The header. For the table it is a column legend; for the stream it is a
    // record like any other, so a consumer that starts reading mid-pipe is not
    // required to have seen it — everything it says is repeated per event
    // except `wardyn`, which is there so a mixed log can be filtered.
    let mut open = match format {
        Format::Json => line(
            &mut out,
            format_args!(
                "{}",
                serde_json::json!({
                    "schema_version": audit::SCHEMA_VERSION,
                    "wardyn": "event-stream",
                    "ts": audit::now(),
                    "enforcing": enforce,
                })
            ),
        ),
        _ => line(
            &mut out,
            format_args!(
                "{:<7} {:<15} {:<8} {:<6} DETAIL",
                "PID", "COMM", "EVENT", "ACT"
            ),
        ),
    };

    let exceptions = Exceptions::default();
    let mut sweep = tokio::time::interval(std::time::Duration::from_secs(2));
    // One Ctrl-C future for the whole loop: recreating it every iteration drops
    // any signal that arrives in the gap between iterations.
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => break,
            status = wait_for(child), if child.is_some() => {
                if let Some(s) = status {
                    log::info!("target exited ({s})");
                }
                break;
            }
            _ = sweep.tick() => {
                if let Some(m) = ctx.watched.as_mut() {
                    prune_watched(m);
                }
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                drain(guard.get_inner_mut(), ctx, &exceptions, |d| {
                    if open {
                        open = emit(&mut out, format, enforce, &d);
                    }
                });
                guard.clear_ready();
            }
        }
        if !open {
            break; // the reader went away
        }
    }
    // The exit/signal branch can win the select while events still sit in the
    // ring (e.g. a secret read immediately before the child exits). Sweep once
    // more so those final events are shown and audited, not dropped.
    drain(async_fd.get_mut(), ctx, &exceptions, |d| {
        if open {
            open = emit(&mut out, format, enforce, &d);
        }
    });
    Ok(())
}

/// Render one event in the chosen format. Returns whether the reader is still
/// there — a closed pipe (`wardyn --format json | head`) ends output rather
/// than panicking.
fn emit(out: &mut std::io::StdoutLock<'_>, format: Format, enforce: bool, d: &Desc) -> bool {
    use std::io::Write as _;
    let text = match format {
        Format::Json => stream_json(enforce, d).to_string(),
        _ => format!(
            "{:<7} {:<15} {:<8} {:<6} {}",
            d.pid,
            d.comm_display(),
            d.label,
            d.act(enforce),
            d.shown()
        ),
    };
    match writeln!(out, "{text}") {
        Ok(()) => out.flush().is_ok(),
        Err(_) => false,
    }
}

/// One stream record.
///
/// The observation events (`allow` rows) are the reason this is not just the
/// audit log on stdout: the log deliberately holds only violations, because it
/// is a security record and an operator should not have to grep a million
/// `ld.so.cache` opens to find the one denial. A stream has the opposite job —
/// a SIEM wants the baseline too, and the consumer does the filtering.
///
/// `notice` rows are wardyn talking about itself (an LSM that failed to attach,
/// an exception granted). They are marked rather than dropped, because a
/// consumer reconstructing what the tool was capable of at a given moment needs
/// them, and one that only wants agent behaviour can filter on the field.
fn stream_json(enforce: bool, d: &Desc) -> serde_json::Value {
    if d.notice {
        return serde_json::json!({
            "schema_version": audit::SCHEMA_VERSION,
            "ts": audit::now(),
            "event": "notice",
            "detail": d.detail,
        });
    }
    let mut v = audit::event_json(
        &audit::now(),
        d.pid,
        &d.comm,
        d.label,
        &d.detail,
        d.action,
        &d.rule,
        d.denied(enforce),
        d.kernel,
        d.matched_key().as_deref(),
    );
    // Two fields the audit log has no use for, because it only ever holds
    // violations: whether this row would be enforced if it were a block, and
    // whether an exception is already covering it.
    if let Some(o) = v.as_object_mut() {
        o.insert("enforceable".into(), d.enforceable.into());
        o.insert("excepted".into(), d.excepted.into());
    }
    v
}

// ── shared event decoding / display ─────────────────────────────────────────

pub(crate) struct Desc {
    pub pid: u32,
    pub comm: String,
    pub kind: u32,
    pub label: &'static str,
    pub detail: String,
    pub action: Action,
    pub rule: String,
    pub enforceable: bool,
    /// The kernel key this event was denied on, when it was — the unit an
    /// approve-once exception operates at (offered by the TUI on `a`).
    pub denial_key: Option<DenialKey>,
    /// The operator granted an exception covering this event: the kernel
    /// allowed it even though the policy objects (or used to).
    pub excepted: bool,
    /// The kernel itself reported this row (a `DENY_*` event). Not a prediction.
    pub kernel: bool,
    /// An operator/diagnostic message, not an observed action: never counted as
    /// a policy verdict.
    pub notice: bool,
}

impl Desc {
    /// The kernel key this event was decided on, rendered the way every other
    /// surface renders it (`name=.aws/credentials`, `ip=1.1.1.1:25`) — the same
    /// string `--dry-run` prints and the TUI offers to except.
    ///
    /// `None` for a warn: nothing was denied, so no key fired. That is a
    /// meaningful null rather than a missing field, and consumers should read it
    /// as "this record is a flag, not a decision".
    pub fn matched_key(&self) -> Option<String> {
        self.denial_key.as_ref().map(|k| k.to_string())
    }
}

/// Escape control bytes for terminal display. Paths and `comm` are entirely
/// attacker-controlled: a watched agent that opens a file whose name contains
/// `\r` or an ANSI escape could otherwise repaint the feed, forge rows, or hide
/// its own activity from the operator watching it.
fn sanitize(s: &str) -> String {
    if !s
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}'))
    {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}') {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

impl Desc {
    /// Detail annotated with the matched rule when it's a violation (or an
    /// exception, where the rule string carries the granted key). Safe to print.
    pub fn shown(&self) -> String {
        let detail = sanitize(&self.detail);
        if self.notice || (self.action == Action::Allow && !self.excepted) {
            detail
        } else {
            format!("{detail}  [{}]", self.rule)
        }
    }

    pub fn comm_display(&self) -> String {
        sanitize(&self.comm)
    }

    /// ACT column text, honest about enforcement: `BLOCK` = the kernel denied
    /// it (reported or confidently predicted), `block~` = flagged under
    /// --enforce but not enforceable, `block` = observe-only, `excep` = allowed
    /// by an operator exception.
    pub fn act(&self, enforce: bool) -> &'static str {
        if self.notice {
            return "note";
        }
        if self.excepted {
            return "excep";
        }
        match self.action {
            Action::Allow => "ok",
            Action::Warn => "warn",
            Action::Block if enforce && self.enforceable => "BLOCK",
            Action::Block if enforce => "block~",
            Action::Block => "block",
        }
    }

    /// Whether the kernel actually denied this event.
    pub fn denied(&self, enforce: bool) -> bool {
        !self.notice && self.action == Action::Block && enforce && self.enforceable
    }
}

/// A startup diagnostic rendered as a feed row.
pub(crate) fn notice_row(text: &str) -> Desc {
    Desc {
        pid: 0,
        comm: "wardyn".into(),
        kind: KIND_NOTICE,
        label: "notice",
        detail: text.to_string(),
        action: Action::Allow,
        rule: String::new(),
        enforceable: false,
        denial_key: None,
        excepted: false,
        kernel: false,
        notice: true,
    }
}

/// Process every event currently in the ring: audit each violation, receipt
/// each actual denial for the agent, and hand the decoded [`Desc`] to `sink`
/// for display. Shared by the live loops and their final post-exit sweep.
/// Reads are synchronous — once the child has exited its events are already in
/// the buffer, so a plain `next()` loop drains them.
pub(crate) fn drain(
    ring: &mut RingBuf<MapData>,
    ctx: &mut RunCtx<'_>,
    exceptions: &Exceptions,
    mut sink: impl FnMut(Desc),
) {
    let enforce = ctx.enforce;
    let enforce_files = ctx.enforce_files;
    while let Some(item) = ring.next() {
        let Some(ev) = parse_event(&item) else {
            continue;
        };
        // A kernel `DENY_*` event that merely confirms a row we already reported
        // must not produce a second row, a second audit record or a second
        // receipt line. One that does NOT match a prediction is the interesting
        // case: a denial the observed path never described (dirfd-relative
        // opens, symlinks, sendmsg) and which used to be invisible.
        if let Some(key) = confirmation_key(&ev) {
            let (obs_kind, key_text) = key;
            if ctx.take_prediction(ev.pid, obs_kind, &key_text) {
                continue;
            }
        }
        let Some(d) = describe(&ev, ctx.policy, enforce, enforce_files, exceptions) else {
            continue;
        };
        if !d.notice && d.action != Action::Allow {
            ctx.audit.record(
                d.pid,
                &d.comm,
                d.label,
                &d.detail,
                d.action,
                &d.rule,
                d.denied(enforce),
                d.kernel,
                d.matched_key().as_deref(),
            );
            // The receipt is the agent's view: only what the kernel really
            // denied belongs there — not warns, not unenforced `block~`.
            if d.denied(enforce) {
                if let Some(r) = ctx.receipt.as_deref_mut() {
                    let _ = r.record(d.pid, &d.comm, d.label, &d.detail, &d.rule);
                }
                if !d.kernel {
                    if let Some(k) = &d.denial_key {
                        let text = prediction_key(k);
                        ctx.remember_prediction(d.pid, d.kind, text);
                    }
                }
            }
        }
        sink(d);
    }
}

/// For a kernel `DENY_*` event, the `(observation kind, key)` pair a predicted
/// row would have recorded — used to recognise a confirmation.
fn confirmation_key(ev: &Event) -> Option<(u32, String)> {
    match ev.kind {
        kind::DENY_FILE => Some((kind::OPEN, event_key_name(ev))),
        kind::DENY_EXEC => Some((kind::EXEC, event_key_name(ev))),
        kind::DENY_NET => Some((kind::CONNECT, deny_net_addr(ev).to_string())),
        _ => None,
    }
}

/// The text form of a predicted denial key, matching [`confirmation_key`].
fn prediction_key(k: &DenialKey) -> String {
    match k {
        DenialKey::FileName(n) | DenialKey::FileDir(n) | DenialKey::Exec(n) => n.clone(),
        // Matches `event_key_name` for a pair-keyed kernel event, so a
        // predicted pair denial and the kernel's confirmation of it agree.
        DenialKey::FilePair { parent, name } | DenialKey::DirPair { parent, name } => {
            format!("{parent}/{name}")
        }
        DenialKey::Net4(ip) => ip.to_string(),
        DenialKey::Net6(ip) => ip.to_string(),
        // Matches `confirmation_key`, which keys a network confirmation on the
        // address alone: userspace predicts from the address it observed and
        // cannot know which trie the kernel will use.
        DenialKey::Net4Port { ip, .. } => ip.to_string(),
        DenialKey::Net6Port { ip, .. } => ip.to_string(),
        // Userspace never *predicts* an identity denial — it only has the path
        // string, and the point of an identity rule is that the string is not
        // what decides. These arrive as kernel reports, which is the branch that
        // renders them; a prediction key for one would never be looked up.
        DenialKey::FileInode { dev, ino }
        | DenialKey::DirInode { dev, ino }
        | DenialKey::ExecInode { dev, ino } => format!("{dev}:{ino}"),
        // Also never predicted, and for a sharper reason: there is no
        // observation tracepoint for `unlink`/`rename`/`mkdir` at all, so a
        // lifecycle denial has nothing to confirm — the kernel event IS the
        // first time userspace hears about the operation.
        DenialKey::Lifecycle { op, key } => format!("{}:{}", op.as_str(), prediction_key(key)),
        // Keyed on the address alone, exactly as the port form is: userspace
        // predicts from what the tracepoint saw, and the tracepoint sees a
        // sockaddr, not a socket — it has no protocol to key on.
        DenialKey::NetProto { key, .. } => prediction_key(key),
    }
}

/// Reinterpret ring-buffer bytes as an [`Event`] (bytes aren't guaranteed aligned).
pub(crate) fn parse_event(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < core::mem::size_of::<Event>() {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Event) })
}

/// The destination address a `DENY_NET` event refers to.
fn deny_net_addr(ev: &Event) -> std::net::IpAddr {
    if ev.family == AF_INET6 {
        let ip6 = Ipv6Addr::from(ev.daddr6);
        match ip6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(ip6),
        }
    } else {
        std::net::IpAddr::V4(Ipv4Addr::from(ev.daddr.to_ne_bytes()))
    }
}

pub(crate) fn describe(
    ev: &Event,
    policy: &Policy,
    enforce: bool,
    enforce_files: bool,
    exc: &Exceptions,
) -> Option<Desc> {
    // Kernel-reported denials first: these are decisions, not observations, and
    // they are reported exactly as made.
    match ev.kind {
        kind::DENY_FILE | kind::DENY_EXEC | kind::DENY_DELETE | kind::DENY_CREATE => {
            let name = event_key_name(ev);
            let identity = matches!(ev.meta, meta::KEY_INO | meta::KEY_DIR_INO);
            let key = match (ev.kind, ev.meta) {
                (kind::DENY_EXEC, meta::KEY_INO) => DenialKey::ExecInode {
                    dev: ev.dev,
                    ino: ev.ino,
                },
                (kind::DENY_EXEC, _) => DenialKey::Exec(name.clone()),
                (_, meta::KEY_INO) => DenialKey::FileInode {
                    dev: ev.dev,
                    ino: ev.ino,
                },
                (_, meta::KEY_DIR_INO) => DenialKey::DirInode {
                    dev: ev.dev,
                    ino: ev.ino,
                },
                (_, meta::KEY_DIR) => DenialKey::FileDir(name.clone()),
                (_, meta::KEY_PAIR) => {
                    let (parent, name) = event_pair_names(ev);
                    DenialKey::FilePair { parent, name }
                }
                (_, meta::KEY_DIR_PAIR) => {
                    let (parent, name) = event_pair_names(ev);
                    DenialKey::DirPair { parent, name }
                }
                _ => DenialKey::FileName(name.clone()),
            };
            // A lifecycle denial matched one of the same four file keys, but on
            // a different bit of its mask. Wrapping it keeps the exception
            // honest: approving one `rm` must not also unblock every read.
            let key = match ev.kind {
                kind::DENY_DELETE => DenialKey::Lifecycle {
                    op: LifecycleOp::Delete,
                    key: Box::new(key),
                },
                kind::DENY_CREATE => DenialKey::Lifecycle {
                    op: LifecycleOp::Create,
                    key: Box::new(key),
                },
                _ => key,
            };
            let label = match ev.kind {
                kind::DENY_EXEC => "exec",
                kind::DENY_DELETE => "delete",
                kind::DENY_CREATE => "create",
                _ => "open",
            };
            // An identity denial is the one case where the object's *current*
            // name is the interesting part: the kernel matched the inode, so
            // showing `hidden.txt [was .env]` is what tells the operator the
            // rename did not work. Fall back to the bare key if the policy has
            // no anchor for it (an exception was granted, or the map outlived
            // a reload).
            // There is no `sys_enter` tracepoint for unlink/rename/mkdir, so a
            // lifecycle row is not a *confirmation* of anything the feed already
            // showed — it is the first and only time the operation is reported.
            // Say which, so a reader does not go looking for the missing
            // observation row.
            let why = if matches!(ev.kind, kind::DENY_DELETE | kind::DENY_CREATE) {
                "refused in-kernel; the attempt itself is not observed, only its refusal"
            } else {
                "denied in-kernel; path not observed"
            };
            let detail = if identity {
                match policy.anchor_for(&InodeKey::new(ev.dev, ev.ino)) {
                    Some(a) => format!("{name}  (same object as {})", a.path.display()),
                    None => format!("{key} ({why})"),
                }
            } else {
                format!("{key} ({why})")
            };
            let rule = match (identity, policy.anchor_for(&InodeKey::new(ev.dev, ev.ino))) {
                (true, Some(a)) => a.rule.clone(),
                _ => format!("kernel:{key}"),
            };
            return Some(Desc {
                pid: ev.pid,
                comm: field_str(&ev.comm),
                kind: ev.kind,
                label,
                detail,
                action: Action::Block,
                rule,
                enforceable: true,
                denial_key: Some(key),
                excepted: false,
                kernel: true,
                notice: false,
            });
        }
        kind::DENY_NET => {
            let addr = deny_net_addr(ev);
            // `meta` says which of the four tries decided. Building an address
            // key for a port-trie denial would produce an exception the port
            // rule immediately overrules — and the same is now true one
            // dimension further out.
            let by_port = matches!(ev.meta, meta::KEY_PORT | meta::KEY_PROTO_PORT);
            let key = match (addr, by_port) {
                (std::net::IpAddr::V4(ip), false) => DenialKey::Net4(ip),
                (std::net::IpAddr::V6(ip), false) => DenialKey::Net6(ip),
                (std::net::IpAddr::V4(ip), true) => DenialKey::Net4Port { ip, port: ev.dport },
                (std::net::IpAddr::V6(ip), true) => DenialKey::Net6Port { ip, port: ev.dport },
            };
            let key = match ev.meta {
                meta::KEY_PROTO | meta::KEY_PROTO_PORT => {
                    match Proto::from_number(ev.proto as u8) {
                        Some(proto) => DenialKey::NetProto {
                            proto,
                            key: Box::new(key),
                        },
                        // The kernel says a protocol trie decided but reports a
                        // protocol no rule can name. That should be impossible;
                        // leaving the key unwrapped would silently write the
                        // exception into the wrong trie, so keep the unwrapped key
                        // and let the operator see the denial repeat rather than
                        // watch an approval do nothing.
                        None => key,
                    }
                }
                _ => key,
            };
            return Some(Desc {
                pid: ev.pid,
                comm: field_str(&ev.comm),
                kind: ev.kind,
                label: "connect",
                detail: match Proto::from_number(ev.proto as u8) {
                    Some(p) => format!("{addr}:{} ({})", ev.dport, p.as_str()),
                    None => format!("{addr}:{}", ev.dport),
                },
                action: Action::Block,
                rule: format!("kernel:{key}"),
                enforceable: true,
                denial_key: Some(key),
                excepted: false,
                kernel: true,
                notice: false,
            });
        }
        _ => {}
    }

    // `enforce_files` gates whether a kernel file/exec denial is PREDICTED: when
    // the LSM isn't attached or the offsets aren't trusted, pass `None` so the
    // row is demoted to `block~` instead of a `BLOCK` that may never fire.
    let (label, detail, verdict, denial_key, excepted) = match ev.kind {
        kind::EXEC | kind::OPEN => {
            let is_exec = ev.kind == kind::EXEC;
            let label = if is_exec { "exec" } else { "open" };
            let Some(d) = event_path(ev) else {
                // The path was longer than the event buffer or unreadable. It
                // used to arrive as an empty string and be evaluated against the
                // policy as "" — a silent allow with a blank DETAIL.
                return Some(Desc {
                    pid: ev.pid,
                    comm: field_str(&ev.comm),
                    kind: ev.kind,
                    label,
                    detail: format!("<path over {PATH_LEN} bytes or unreadable — NOT evaluated>"),
                    action: Action::Warn,
                    rule: "unreadable-path".into(),
                    enforceable: false,
                    denial_key: None,
                    excepted: false,
                    kernel: false,
                    notice: false,
                });
            };
            let kd = if enforce_files {
                if is_exec {
                    policy.kernel_exec_denial(&d)
                } else {
                    // `ev.fmode` is what the syscall's flags asked for, so a rule
                    // that only covers reads does not predict a denial for a
                    // write-only open the kernel will let through.
                    policy.kernel_file_denial(&d, ev.fmode)
                }
            } else {
                None
            };
            let base = if is_exec {
                policy.eval_exec(&d)
            } else {
                policy.eval_file(&d)
            };
            let (v, key, ex) = reconcile(base, enforce, kd, exc);
            (label, d, v, key, ex)
        }
        kind::CONNECT => {
            let (d, mut v, ip_key) = if ev.family == AF_INET6 {
                let ip6 = Ipv6Addr::from(ev.daddr6);
                // Mirror the kernel: a v4-mapped v6 destination (`::ffff:a.b.c.d`)
                // is enforced by the v4 trie (connect6 unwraps it), so evaluate it
                // as v4 or the feed would show `ok` for an egress the kernel denies.
                if let Some(v4) = ip6.to_ipv4_mapped() {
                    (
                        format!("[{ip6}]:{}", ev.dport),
                        policy.eval_connect(v4, ev.dport),
                        DenialKey::Net4(v4),
                    )
                } else {
                    (
                        format!("[{ip6}]:{}", ev.dport),
                        policy.eval_connect6(ip6, ev.dport),
                        DenialKey::Net6(ip6),
                    )
                }
            } else {
                let ip = Ipv4Addr::from(ev.daddr.to_ne_bytes());
                (
                    format!("{ip}:{}", ev.dport),
                    policy.eval_connect(ip, ev.dport),
                    DenialKey::Net4(ip),
                )
            };
            // Network exceptions: the /32 (/128) allow the operator granted
            // outranks the blocking CIDR in the kernel trie — mirror that.
            let mut key = None;
            let mut ex = false;
            if v.action == Action::Block {
                if enforce && exc.contains(&ip_key) {
                    ex = true;
                    v = Verdict {
                        action: Action::Allow,
                        rule: format!("{} → excepted {ip_key}", v.rule),
                        enforceable: true,
                    };
                } else {
                    key = Some(ip_key);
                }
            }
            ("connect", d, v, key, ex)
        }
        _ => return None,
    };
    Some(Desc {
        pid: ev.pid,
        comm: field_str(&ev.comm),
        kind: ev.kind,
        label,
        detail,
        action: verdict.action,
        rule: verdict.rule,
        enforceable: verdict.enforceable,
        denial_key,
        excepted,
        kernel: false,
        notice: false,
    })
}

/// Reconcile the glob verdict against what the kernel's coarse name matcher will
/// *actually* do under `--enforce`, so the feed doesn't disagree with the
/// syscall's real outcome. `kernel_denial` is `Some(key)` when the LSM hook would
/// deny this exact path — unless the operator granted that key as an exception,
/// in which case the kernel allows it again.
///
/// Returns `(verdict, denial_key, excepted)`: `denial_key` is the key the TUI
/// can offer to except (only when the kernel really denies), `excepted` marks
/// rows covered by an already-granted exception.
fn reconcile(
    mut v: Verdict,
    enforce: bool,
    kernel_denial: Option<DenialKey>,
    exc: &Exceptions,
) -> (Verdict, Option<DenialKey>, bool) {
    if !enforce {
        return (v, None, false);
    }
    match kernel_denial {
        Some(key) if exc.contains(&key) => {
            if v.action == Action::Block && v.enforceable {
                v.enforceable = false;
            }
            v.rule = format!("{} → excepted {key}", v.rule);
            (v, None, true)
        }
        Some(key) => {
            if !(v.action == Action::Block && v.enforceable) {
                v = Verdict {
                    action: Action::Block,
                    rule: format!("kernel:{key}"),
                    enforceable: true,
                };
            }
            (v, Some(key), false)
        }
        None => {
            if v.action == Action::Block && v.enforceable {
                v.enforceable = false;
            }
            (v, None, false)
        }
    }
}

/// Byte offset of `field` in a tracefs event format file, e.g.
/// `tracefs_field_offset("sched/sched_process_fork", "child_pid")`. The format
/// file is the kernel's own declaration of the event layout — the only source
/// that is correct on every kernel.
fn tracefs_field_offset(event: &str, field: &str) -> Option<u32> {
    let text = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .iter()
        .find_map(|root| std::fs::read_to_string(format!("{root}/events/{event}/format")).ok())?;
    parse_format_offset(&text, field)
}

/// The parsing half of [`tracefs_field_offset`], split out for tests. Format
/// lines look like `\tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;`.
fn parse_format_offset(format: &str, field: &str) -> Option<u32> {
    let marker = format!(" {field};");
    for line in format.lines() {
        if line.contains(&marker) {
            for part in line.split(';') {
                if let Some(v) = part.trim().strip_prefix("offset:") {
                    return v.trim().parse().ok();
                }
            }
        }
    }
    None
}

/// Learn wardyn's tgid as the kernel's init pid namespace sees it.
///
/// Publish a random nonce in CONFIG, call `personality(nonce)` (a per-process
/// flag read/set, restored immediately), and let the `sys_enter_personality`
/// tracepoint write the caller's init-ns tgid back through CONFIG. The nonce
/// gates the write so a concurrent personality() call from another process
/// can't elect itself; the window is closed (nonce = 0) before returning.
fn learn_init_ns_tgid(config: &mut Array<MapData, u32>) -> Option<u32> {
    use std::io::Read as _;
    let mut nb = [0u8; 4];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut nb))
        .ok()?;
    let mut nonce = u32::from_ne_bytes(nb);
    if nonce == 0 || nonce == u32::MAX {
        nonce ^= 0x5ad0_1e55; // 0 disables the hook; -1 is personality's query value
    }
    config.set(CFG_HS_NONCE, nonce, 0).ok()?;
    // personality() returns the previous persona; the nonce persona lives only
    // for the instant between these two calls, in this process.
    let old = unsafe { libc::personality(nonce as libc::c_ulong) };
    if old != -1 {
        unsafe { libc::personality(old as libc::c_ulong) };
    }
    let _ = config.set(CFG_HS_NONCE, 0u32, 0);
    // The tracepoint ran synchronously inside the personality() syscall.
    match config.get(&CFG_HS_TGID, 0) {
        Ok(tgid) if tgid != 0 => Some(tgid),
        _ => None,
    }
}

/// NUL-terminated byte field -> lossy UTF-8 string.
fn field_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// The matched key carried by a `DENY_FILE` / `DENY_EXEC` event.
fn event_key_name(ev: &Event) -> String {
    if matches!(ev.meta, meta::KEY_PAIR | meta::KEY_DIR_PAIR) {
        let (parent, name) = event_pair_names(ev);
        return format!("{parent}/{name}");
    }
    let len = (ev.path_len as usize).min(PATH_LEN);
    field_str(&ev.path[..len])
}

/// The two halves of a pair-keyed denial: parent in the first [`NAME_LEN`]
/// bytes of `path`, name in the next. Fixed widths, so no delimiter parsing.
fn event_pair_names(ev: &Event) -> (String, String) {
    (
        field_str(&ev.path[..NAME_LEN]),
        field_str(&ev.path[NAME_LEN..2 * NAME_LEN]),
    )
}

/// The observed path, or `None` when the kernel could not capture it (a path at
/// or over `PATH_LEN`, or an unreadable user pointer — both arrive as a zeroed
/// buffer, which must not be evaluated as the empty path).
fn event_path(ev: &Event) -> Option<String> {
    let len = (ev.path_len as usize).min(PATH_LEN);
    if len == 0 || ev.path[0] == 0 {
        return None;
    }
    Some(field_str(&ev.path[..len]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardyn_common::COMM_LEN;

    fn block(rule: &str, enforceable: bool) -> Verdict {
        Verdict {
            action: Action::Block,
            rule: rule.into(),
            enforceable,
        }
    }

    #[test]
    fn reconcile_offers_key_then_honours_exception() {
        let mut exc = Exceptions::default();
        let key = DenialKey::FileName(".env".into());
        // Pre-grant: enforced BLOCK, key offered for the TUI to except.
        let (v, k, ex) = reconcile(block("**/.env", true), true, Some(key.clone()), &exc);
        assert_eq!(v.action, Action::Block);
        assert!(v.enforceable && !ex);
        assert_eq!(k, Some(key.clone()));
        // Post-grant: kernel no longer denies — never claim a BLOCK; mark the
        // override and stop offering the key.
        exc.grant(key.clone());
        let (v, k, ex) = reconcile(block("**/.env", true), true, Some(key), &exc);
        assert!(ex && !v.enforceable && k.is_none());
        assert!(v.rule.contains("excepted name=.env"));
    }

    #[test]
    fn reconcile_without_enforce_is_passthrough() {
        let exc = Exceptions::default();
        let key = DenialKey::FileName(".env".into());
        let (v, k, ex) = reconcile(block("**/.env", true), false, Some(key), &exc);
        assert_eq!(v.action, Action::Block);
        assert!(v.enforceable, "observe mode leaves the verdict untouched");
        assert!(k.is_none() && !ex);
    }

    /// Old layout (kernel 6.8): inline `char comm[16]` fields.
    const FORK_6_8: &str = "\
\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;";

    /// New layout (observed on 6.18): comm became `__data_loc` (4 bytes), so
    /// every pid field moved. Captured verbatim from a real format file.
    const FORK_6_18: &str = "\
\tfield:__data_loc char[] parent_comm;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:__data_loc char[] child_comm;\toffset:16;\tsize:4;\tsigned:0;
\tfield:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;";

    #[test]
    fn parses_both_fork_layout_generations() {
        assert_eq!(parse_format_offset(FORK_6_8, "parent_pid"), Some(24));
        assert_eq!(parse_format_offset(FORK_6_8, "child_pid"), Some(44));
        assert_eq!(parse_format_offset(FORK_6_18, "parent_pid"), Some(12));
        assert_eq!(parse_format_offset(FORK_6_18, "child_pid"), Some(20));
    }

    #[test]
    fn field_name_must_match_exactly() {
        // `pid` is a suffix of `parent_pid`/`child_pid` and must not match them.
        assert_eq!(parse_format_offset(FORK_6_18, "pid"), None);
        assert_eq!(parse_format_offset(FORK_6_18, "no_such_field"), None);
    }

    fn ev_with_path(kind_: u32, path: &str, len: u32) -> Event {
        let mut e = Event::zeroed();
        e.kind = kind_;
        e.pid = 7;
        let b = path.as_bytes();
        e.path[..b.len()].copy_from_slice(b);
        e.path_len = len;
        e
    }

    #[test]
    fn an_uncapturable_path_is_flagged_not_silently_allowed() {
        // The kernel reports PATH_LEN with a zeroed buffer when the path did not
        // fit (or could not be read).
        let mut e = Event::zeroed();
        e.kind = kind::OPEN;
        e.path_len = PATH_LEN as u32;
        assert_eq!(event_path(&e), None);

        let p = Policy::from_yaml_str_with(
            "default_action: allow",
            &wardyn_policy::policy::null_resolver,
        )
        .unwrap();
        let d = describe(&e, &p, true, true, &Exceptions::default()).unwrap();
        assert_eq!(d.action, Action::Warn);
        assert!(d.detail.contains("NOT evaluated"));
    }

    #[test]
    fn a_normal_path_still_decodes() {
        let e = ev_with_path(kind::OPEN, "/home/u/.env", 13);
        assert_eq!(event_path(&e).unwrap(), "/home/u/.env");
    }

    #[test]
    fn kernel_denial_events_are_rendered_as_the_kernels_own_verdict() {
        let p = Policy::from_yaml_str_with(
            "default_action: allow",
            &wardyn_policy::policy::null_resolver,
        )
        .unwrap();
        let mut e = ev_with_path(kind::DENY_FILE, ".ssh", 4);
        e.meta = meta::KEY_DIR;
        let d = describe(&e, &p, true, false, &Exceptions::default()).unwrap();
        assert!(d.kernel, "the hook that denied is the one reporting");
        assert_eq!(d.action, Action::Block);
        assert!(d.enforceable, "a reported denial is not a prediction");
        assert_eq!(d.rule, "kernel:dir=.ssh");
        assert_eq!(d.denial_key, Some(DenialKey::FileDir(".ssh".into())));
        // ...even though the policy above blocks nothing at all: the kernel's
        // report is not re-derived from userspace rules.
        assert_eq!(p.eval_file("/home/u/.ssh/id").action, Action::Allow);
    }

    #[test]
    fn a_denied_exec_event_maps_to_the_exec_key() {
        let p = Policy::from_yaml_str_with(
            r#"exec: [{ match: "**/nc", action: block }]"#,
            &wardyn_policy::policy::null_resolver,
        )
        .unwrap();
        let e = ev_with_path(kind::DENY_EXEC, "nc", 2);
        let d = describe(&e, &p, true, true, &Exceptions::default()).unwrap();
        assert_eq!(d.label, "exec");
        assert_eq!(d.denial_key, Some(DenialKey::Exec("nc".into())));
    }

    /// The `Pod` mirror of `InodeKey` must be byte-identical to the shared type.
    /// The orphan rule forces the duplicate, and a duplicate that drifts is a
    /// key the kernel and userspace disagree about — which does not fail, it
    /// just silently matches nothing. Exactly the failure mode the `dev`
    /// encoding already had to be pinned against.
    #[test]
    fn the_inode_key_mirror_has_the_shared_layout() {
        use core::mem::{align_of, size_of};
        assert_eq!(size_of::<InoKey>(), size_of::<InodeKey>());
        assert_eq!(align_of::<InoKey>(), align_of::<InodeKey>());

        let shared = InodeKey::new(0x0080_0001, 0x0102_0304_0506_0708);
        let mirror = InoKey::from(shared);
        let a = unsafe {
            core::slice::from_raw_parts(
                (&shared as *const InodeKey) as *const u8,
                size_of::<InodeKey>(),
            )
        };
        let b = unsafe {
            core::slice::from_raw_parts(
                (&mirror as *const InoKey) as *const u8,
                size_of::<InoKey>(),
            )
        };
        assert_eq!(a, b, "InoKey and InodeKey do not agree byte-for-byte");
    }

    /// And for the two-component key. A drifted mirror here is a rule that
    /// silently matches nothing — the same failure as a drifted `InoKey`.
    #[test]
    fn the_pair_key_mirror_has_the_shared_layout() {
        use core::mem::{align_of, size_of};
        assert_eq!(size_of::<PairKeyPod>(), size_of::<PairKey>());
        assert_eq!(align_of::<PairKeyPod>(), align_of::<PairKey>());
        assert_eq!(
            size_of::<PairKey>(),
            2 * NAME_LEN,
            "two fixed fields, nothing else"
        );

        let mut parent = [0u8; NAME_LEN];
        parent[..4].copy_from_slice(b".aws");
        let mut name = [0u8; NAME_LEN];
        name[..11].copy_from_slice(b"credentials");
        let shared = PairKey { parent, name };
        let mirror = PairKeyPod::from(shared);
        let a = unsafe {
            core::slice::from_raw_parts(
                (&shared as *const PairKey) as *const u8,
                size_of::<PairKey>(),
            )
        };
        let b = unsafe {
            core::slice::from_raw_parts(
                (&mirror as *const PairKeyPod) as *const u8,
                size_of::<PairKeyPod>(),
            )
        };
        assert_eq!(a, b, "PairKeyPod and PairKey do not agree byte-for-byte");
        // Parent first: that is the order the kernel writes the two halves into
        // an event's `path`, and what `event_pair_names` splits on.
        assert_eq!(&a[..4], b".aws");
        assert_eq!(&a[NAME_LEN..NAME_LEN + 11], b"credentials");
    }

    /// A pair-keyed kernel event decodes to the pair, and to the same string
    /// a prediction of it would have recorded — or the kernel's confirmation
    /// never matches the row it confirms.
    #[test]
    fn a_pair_denial_decodes_to_the_pair_and_confirms_its_own_prediction() {
        let mut e = Event::zeroed();
        e.kind = kind::DENY_FILE;
        e.meta = meta::KEY_PAIR;
        e.path[..4].copy_from_slice(b".aws");
        e.path[NAME_LEN..NAME_LEN + 11].copy_from_slice(b"credentials");
        e.path_len = (2 * NAME_LEN) as u32;

        let (parent, name) = event_pair_names(&e);
        assert_eq!((parent.as_str(), name.as_str()), (".aws", "credentials"));
        assert_eq!(event_key_name(&e), ".aws/credentials");

        let predicted = prediction_key(&DenialKey::FilePair {
            parent: ".aws".into(),
            name: "credentials".into(),
        });
        assert_eq!(confirmation_key(&e), Some((kind::OPEN, predicted)));
    }

    /// Same contract for the four protocol keys. A drifted mirror here is a key
    /// the kernel never finds: the trie matches nothing, wardyn fails open, and
    /// the only symptom is a rule that quietly stopped applying.
    #[test]
    fn the_protocol_key_mirrors_have_the_shared_layout() {
        use core::mem::size_of;

        fn same_bytes<A, B>(a: &A, b: &B) -> bool {
            assert_eq!(size_of::<A>(), size_of::<B>(), "size differs");
            let x = unsafe {
                core::slice::from_raw_parts((a as *const A) as *const u8, size_of::<A>())
            };
            let y = unsafe {
                core::slice::from_raw_parts((b as *const B) as *const u8, size_of::<B>())
            };
            x == y
        }

        let pp4 = ProtoPortKey4::new(6, 443, [1, 2, 3, 4]);
        assert!(same_bytes(&pp4, &ProtoPortKey4Pod::from(pp4)));
        let pp6 = ProtoPortKey6::new(17, 53, [9u8; 16]);
        assert!(same_bytes(&pp6, &ProtoPortKey6Pod::from(pp6)));
        let p4 = ProtoKey4::new(17, [10, 0, 0, 1]);
        assert!(same_bytes(&p4, &ProtoKey4Pod::from(p4)));
        let p6 = ProtoKey6::new(6, [7u8; 16]);
        assert!(same_bytes(&p6, &ProtoKey6Pod::from(p6)));

        // The protocol must lead the key, for the same reason the port leads a
        // `PortKey4`: an LPM trie compares from the most significant end, and
        // only what comes first can be pinned without pinning the rest.
        let raw = unsafe {
            core::slice::from_raw_parts(
                (&pp4 as *const ProtoPortKey4) as *const u8,
                size_of::<ProtoPortKey4>(),
            )
        };
        assert_eq!(raw[0], 6, "protocol is not the leading byte");
        assert_eq!(&raw[1..3], &443u16.to_be_bytes(), "port does not follow it");
    }

    /// An identity denial must be rendered as the object's *current* name plus
    /// the path the policy named — that pairing is the whole report: it is how
    /// an operator sees that the rename did not work.
    #[test]
    fn an_identity_denial_names_the_object_the_policy_pinned() {
        use std::path::PathBuf;
        let fake = |p: &std::path::Path| -> Option<(u64, u64, bool)> {
            (p == std::path::Path::new("/proj/.env")).then_some((0x801, 4242, false))
        };
        let p = wardyn_policy::policy::Loader::offline()
            .stat(&fake)
            .base(wardyn_policy::identity::AnchorBase {
                cwd: Some(PathBuf::from("/proj")),
                home: None,
            })
            .from_str("files:\n  - { path: \".env\", action: block }\n")
            .unwrap();

        // The kernel reports the name the file has NOW, plus the key it matched.
        let mut e = ev_with_path(kind::DENY_FILE, "hidden.txt", 10);
        e.meta = meta::KEY_INO;
        e.dev = 0x0080_0001;
        e.ino = 4242;
        let d = describe(&e, &p, true, true, &Exceptions::default()).unwrap();

        assert!(d.kernel);
        assert_eq!(
            d.denial_key,
            Some(DenialKey::FileInode {
                dev: 0x0080_0001,
                ino: 4242
            })
        );
        assert!(d.detail.contains("hidden.txt"), "{}", d.detail);
        assert!(d.detail.contains("/proj/.env"), "{}", d.detail);
        assert_eq!(d.rule, "path:.env");
    }

    /// An identity key the policy no longer knows about (an exception was
    /// granted, or the map outlived a reload) must still render as a denial —
    /// degraded to the bare key, never dropped.
    #[test]
    fn an_identity_denial_with_no_matching_anchor_still_reports() {
        let p = Policy::from_yaml_str_with(
            "default_action: allow",
            &wardyn_policy::policy::null_resolver,
        )
        .unwrap();
        let mut e = ev_with_path(kind::DENY_FILE, "whatever", 8);
        e.meta = meta::KEY_INO;
        e.dev = 0x0080_0001;
        e.ino = 99;
        let d = describe(&e, &p, true, true, &Exceptions::default()).unwrap();
        assert_eq!(d.action, Action::Block);
        assert!(d.detail.contains("ino"), "{}", d.detail);
        assert!(d.detail.contains("99"), "{}", d.detail);
    }

    #[test]
    fn deny_net_unwraps_v4_mapped_addresses_like_the_kernel_hook() {
        let mut e = Event::zeroed();
        e.kind = kind::DENY_NET;
        e.family = AF_INET6;
        e.daddr6 = Ipv6Addr::from([0, 0, 0, 0, 0, 0xffff, 0x0101, 0x0101]).octets();
        e.dport = 443;
        assert_eq!(deny_net_addr(&e).to_string(), "1.1.1.1");
        let p = Policy::from_yaml_str_with(
            "default_action: allow",
            &wardyn_policy::policy::null_resolver,
        )
        .unwrap();
        let d = describe(&e, &p, true, true, &Exceptions::default()).unwrap();
        assert_eq!(d.detail, "1.1.1.1:443");
        assert_eq!(d.rule, "kernel:ip=1.1.1.1");
    }

    #[test]
    fn control_bytes_in_a_path_cannot_forge_feed_rows() {
        let hostile = "/tmp/\x1b[2Kfake\r  99999  root  open   ok   /etc/passwd";
        let out = sanitize(hostile);
        assert!(!out.contains('\x1b') && !out.contains('\r'));
        assert!(out.contains("\\u{1b}") && out.contains("\\u{d}"));
        // Right-to-left overrides can hide a suffix just as effectively.
        assert!(sanitize("evil\u{202e}txt.exe").contains("\\u{202e}"));
        // Ordinary paths are untouched (and not reallocated into escapes).
        assert_eq!(
            sanitize("/home/u/proj/src/main.rs"),
            "/home/u/proj/src/main.rs"
        );
    }

    #[test]
    fn comm_is_sanitised_too() {
        let mut e = Event::zeroed();
        e.kind = kind::OPEN;
        let comm = b"ev\x1b[31mil\0";
        e.comm[..comm.len().min(COMM_LEN)].copy_from_slice(&comm[..comm.len().min(COMM_LEN)]);
        let b = b"/tmp/x";
        e.path[..b.len()].copy_from_slice(b);
        e.path_len = b.len() as u32 + 1;
        let p = Policy::from_yaml_str_with(
            "default_action: allow",
            &wardyn_policy::policy::null_resolver,
        )
        .unwrap();
        let d = describe(&e, &p, false, false, &Exceptions::default()).unwrap();
        assert!(!d.comm_display().contains('\x1b'));
    }

    #[test]
    fn notices_are_never_counted_as_policy_verdicts() {
        let d = notice_row("BPF LSM unavailable");
        assert!(d.notice);
        assert_eq!(d.act(true), "note");
        assert!(!d.denied(true));
    }

    #[test]
    fn exit_code_follows_the_target() {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            exit_code_of(std::process::ExitStatus::from_raw(0)),
            0,
            "a clean target run exits 0"
        );
        // 0x0100 = exited with code 1 in wait(2) encoding.
        assert_eq!(exit_code_of(std::process::ExitStatus::from_raw(0x0100)), 1);
        // 9 = killed by SIGKILL -> 128 + 9.
        assert_eq!(exit_code_of(std::process::ExitStatus::from_raw(9)), 137);
    }

    // ── the JSON event stream (docs/EVENT_SCHEMA.md) ────────────────────────

    fn desc_for_test(action: Action, kernel: bool, key: Option<DenialKey>) -> Desc {
        Desc {
            pid: 42,
            comm: "cat".into(),
            kind: kind::OPEN,
            label: "open",
            detail: "/home/u/.env".into(),
            action,
            rule: "**/.env".into(),
            enforceable: true,
            denial_key: key,
            excepted: false,
            kernel,
            notice: false,
        }
    }

    /// Every field the schema documents, present and of the documented type.
    /// This is the contract; a field disappearing here is a version bump.
    #[test]
    fn a_stream_record_carries_every_documented_field() {
        let d = desc_for_test(
            Action::Block,
            true,
            Some(DenialKey::FileName(".env".into())),
        );
        let v = stream_json(true, &d);

        assert_eq!(v["schema_version"], audit::SCHEMA_VERSION);
        assert!(v["ts"].is_string());
        assert_eq!(v["pid"], 42);
        assert_eq!(v["comm"], "cat");
        assert_eq!(v["event"], "open");
        assert_eq!(v["action"], "block");
        assert_eq!(v["enforced"], true);
        assert_eq!(v["source"], "kernel");
        assert_eq!(v["detail"], "/home/u/.env");
        assert_eq!(v["rule"], "**/.env");
        assert_eq!(v["matched_key"], "name=.env");
        assert_eq!(v["enforceable"], true);
        assert_eq!(v["excepted"], false);
    }

    /// The schema's loudest instruction: count denials with `enforced`, not with
    /// `action == "block"`. A consumer that got this wrong would over-report
    /// denials by every warn and every unenforceable block, so the two fields
    /// have to be demonstrably independent.
    #[test]
    fn action_and_enforced_are_not_the_same_field() {
        // A warn is a flag; nothing was denied and no key fired.
        let warn = stream_json(true, &desc_for_test(Action::Warn, false, None));
        assert_eq!(warn["action"], "warn");
        assert_eq!(warn["enforced"], false);
        assert_eq!(warn["matched_key"], serde_json::Value::Null);

        // A block under observe mode (enforce = false) is also not a denial.
        let observing = stream_json(
            false,
            &desc_for_test(
                Action::Block,
                false,
                Some(DenialKey::FileName(".env".into())),
            ),
        );
        assert_eq!(observing["action"], "block");
        assert_eq!(observing["enforced"], false);

        // Only an enforced block is one.
        let denied = stream_json(
            true,
            &desc_for_test(
                Action::Block,
                false,
                Some(DenialKey::FileName(".env".into())),
            ),
        );
        assert_eq!(denied["enforced"], true);
    }

    /// `source` distinguishes proof from prediction, and the stream must carry
    /// that through — an audit that cannot tell them apart cannot be relied on.
    #[test]
    fn source_reports_whether_the_kernel_or_userspace_said_so() {
        let k = stream_json(true, &desc_for_test(Action::Block, true, None));
        let u = stream_json(true, &desc_for_test(Action::Block, false, None));
        assert_eq!(k["source"], "kernel");
        assert_eq!(u["source"], "observed");
    }

    /// A notice is wardyn talking about itself. It is marked, not dropped, and
    /// it must not look like an agent action: no pid, no verdict, nothing a
    /// consumer counting behaviour would pick up.
    #[test]
    fn a_notice_is_marked_and_carries_no_verdict() {
        let mut d = desc_for_test(Action::Allow, false, None);
        d.notice = true;
        d.detail = "BPF LSM enforcement unavailable".into();
        let v = stream_json(true, &d);

        assert_eq!(v["event"], "notice");
        assert_eq!(v["schema_version"], audit::SCHEMA_VERSION);
        assert_eq!(v["detail"], "BPF LSM enforcement unavailable");
        assert!(v["action"].is_null(), "a notice is not a verdict");
        assert!(v["pid"].is_null(), "a notice is not an agent action");
    }

    /// One object per line is the whole format: a path containing a newline or
    /// an escape sequence must not be able to forge a second record. The feed
    /// already refuses to render control bytes; the stream has to be safe for a
    /// different reason — `jq -c` reads lines.
    #[test]
    fn a_hostile_path_cannot_forge_a_second_stream_record() {
        let mut d = desc_for_test(Action::Block, false, None);
        d.detail = "/tmp/x\n{\"action\":\"allow\",\"enforced\":false}".into();
        let text = stream_json(true, &d).to_string();

        assert_eq!(text.lines().count(), 1, "one record is one line");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        // The newline survives as data inside the field, not as a separator.
        assert!(parsed["detail"].as_str().unwrap().contains('\n'));
    }

    /// The built-in LSM offsets were measured on one kernel *and* one
    /// architecture, and both have to hold before the feed is allowed to
    /// predict a `BLOCK` from them.
    ///
    /// The architecture half has no runtime failure to point at yet — there is
    /// no aarch64 build to have got it wrong on — which is exactly why it is
    /// pinned here: the check exists so that shipping one cannot quietly make
    /// x86_64's numbers authoritative somewhere they were never measured.
    #[test]
    fn builtin_offsets_are_trusted_only_on_the_arch_they_were_measured_on() {
        let trusted = kernel_matches_builtin_offsets();
        if std::env::consts::ARCH != OFFSETS_ARCH {
            assert!(
                !trusted,
                "built-in {OFFSETS_ARCH} offsets were trusted on {} — the feed would predict \
                 denials from numbers nobody measured here",
                std::env::consts::ARCH
            );
        } else {
            // On the arch they came from, the version is what decides, and this
            // machine is whatever CI happens to run. Assert the shape of the
            // answer rather than the answer.
            let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
            let on_that_kernel = release.trim().starts_with(&format!("{OFFSETS_KERNEL}."));
            assert_eq!(trusted, on_that_kernel);
        }
    }
}
