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
use wardyn_common::{action, kind, meta, stat, Event, InodeKey, NAME_LEN, PATH_LEN};
use wardyn_policy::cli::{self, Mode, Opts, ParseOutcome};
use wardyn_policy::identity::AnchorBase;
use wardyn_policy::policy::{self, Action, DenialKey, Exceptions, Loader, Policy, Verdict};

use crate::audit::Audit;
use crate::receipt::Receipt;

/// Userspace mirror of `wardyn_common::NameKey` (identical C layout) carrying a
/// `Pod` impl so aya can use it as a hash-map key. The `Pod` impl can't live on
/// the wardyn_common type (orphan rule), hence this local copy.
#[repr(C)]
#[derive(Clone, Copy)]
struct NameKey([u8; NAME_LEN]);
unsafe impl aya::Pod for NameKey {}

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

/// Feed rows that carry an operator/diagnostic message rather than a syscall.
const KIND_NOTICE: u32 = u32::MAX;

/// The live kernel enforcement maps, held for the whole run (not dropped after
/// population) so the TUI can grant approve-once exceptions while the target
/// is still running: remove a block key, or insert a most-specific allow route.
pub(crate) struct KernelMaps {
    names: BpfHashMap<MapData, NameKey, u8>,
    dirs: BpfHashMap<MapData, NameKey, u8>,
    execs: BpfHashMap<MapData, NameKey, u8>,
    net4: LpmTrie<MapData, u32, u32>,
    net6: LpmTrie<MapData, Ip6Key, u32>,
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
            execs,
            net4,
            net6,
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
        match key {
            DenialKey::FileName(n) => drop_name(&mut self.names, n),
            DenialKey::FileDir(d) => drop_name(&mut self.dirs, d),
            DenialKey::Exec(n) => drop_name(&mut self.execs, n),
            DenialKey::FileInode { dev, ino } => drop_ino(&mut self.inodes, *dev, *ino),
            DenialKey::DirInode { dev, ino } => drop_ino(&mut self.dir_inodes, *dev, *ino),
            DenialKey::ExecInode { dev, ino } => drop_ino(&mut self.exec_inodes, *dev, *ino),
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
    /// SUBSET of `denied_file + denied_exec`, never an addition — see
    /// [`stat::DENIED_IDENTITY`].
    pub denied_identity: u64,
}

impl StatSnapshot {
    pub fn denials(&self) -> u64 {
        self.denied_file + self.denied_exec + self.denied_net
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

/// Whether the running kernel's major.minor matches the built-in LSM offset
/// kernel (`OFFSETS_KERNEL`). Used only as the fallback trust signal when BTF
/// offset resolution is unavailable: on a match the built-in 6.8 offsets are
/// correct, so file/exec `BLOCK` can be predicted honestly.
fn kernel_matches_builtin_offsets() -> bool {
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

/// Load + attach the BPF-LSM file/exec deniers. Kept separate so a kernel without
/// BPF LSM degrades gracefully to network-only enforcement instead of aborting.
fn attach_lsm(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let btf = Btf::from_sys_fs().context("loading kernel BTF")?;
    for (name, hook) in [
        ("file_open", "file_open"),
        ("bprm_check", "bprm_check_security"),
    ] {
        let prog: &mut Lsm = ebpf
            .program_mut(name)
            .with_context(|| format!("{name} program not found"))?
            .try_into()?;
        prog.load(hook, &btf)
            .with_context(|| format!("loading lsm/{hook}"))?;
        prog.attach()
            .with_context(|| format!("attaching lsm/{hook}"))?;
    }
    Ok(())
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
    let use_tui = !opts.plain && std::io::stdout().is_terminal();
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
        match attach_lsm(&mut ebpf) {
            Ok(()) => {
                lsm_active = true;
                notices.push(
                    "enforcement ON — egress (cgroup) + secret-file reads + blocked execs (LSM)"
                        .into(),
                );
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
                    notices.push(format!(
                        "could not resolve LSM struct offsets from BTF ({why}) and the running \
                         kernel is not {OFFSETS_KERNEL}; file/exec blocking may silently fail. \
                         Such rows are shown as block~ until the kernel reports a denial itself."
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
        run_plain(async_fd, &mut child, &mut ctx).await
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

/// Plain line-printer used when stdout is not a terminal (pipes, CI, `--plain`).
/// No interactivity, so no exceptions can be granted here.
async fn run_plain(
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    child: &mut Option<Child>,
    ctx: &mut RunCtx<'_>,
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
    let mut open = line(
        &mut out,
        format_args!(
            "{:<7} {:<15} {:<8} {:<6} DETAIL",
            "PID", "COMM", "EVENT", "ACT"
        ),
    );

    let enforce = ctx.enforce;
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
                        open = line(&mut out, format_args!(
                            "{:<7} {:<15} {:<8} {:<6} {}",
                            d.pid, d.comm_display(), d.label, d.act(enforce), d.shown()
                        ));
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
            open = line(
                &mut out,
                format_args!(
                    "{:<7} {:<15} {:<8} {:<6} {}",
                    d.pid,
                    d.comm_display(),
                    d.label,
                    d.act(enforce),
                    d.shown()
                ),
            );
        }
    });
    Ok(())
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
        DenialKey::Net4(ip) => ip.to_string(),
        DenialKey::Net6(ip) => ip.to_string(),
        // Userspace never *predicts* an identity denial — it only has the path
        // string, and the point of an identity rule is that the string is not
        // what decides. These arrive as kernel reports, which is the branch that
        // renders them; a prediction key for one would never be looked up.
        DenialKey::FileInode { dev, ino }
        | DenialKey::DirInode { dev, ino }
        | DenialKey::ExecInode { dev, ino } => format!("{dev}:{ino}"),
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
        kind::DENY_FILE | kind::DENY_EXEC => {
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
                _ => DenialKey::FileName(name.clone()),
            };
            let label = if ev.kind == kind::DENY_EXEC {
                "exec"
            } else {
                "open"
            };
            // An identity denial is the one case where the object's *current*
            // name is the interesting part: the kernel matched the inode, so
            // showing `hidden.txt [was .env]` is what tells the operator the
            // rename did not work. Fall back to the bare key if the policy has
            // no anchor for it (an exception was granted, or the map outlived
            // a reload).
            let detail = if identity {
                match policy.anchor_for(&InodeKey::new(ev.dev, ev.ino)) {
                    Some(a) => format!("{name}  (same object as {})", a.path.display()),
                    None => format!("{key} (denied in-kernel by identity)"),
                }
            } else {
                format!("{key} (denied in-kernel; path not observed)")
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
            let key = match addr {
                std::net::IpAddr::V4(v4) => DenialKey::Net4(v4),
                std::net::IpAddr::V6(v6) => DenialKey::Net6(v6),
            };
            return Some(Desc {
                pid: ev.pid,
                comm: field_str(&ev.comm),
                kind: ev.kind,
                label: "connect",
                detail: format!("{addr}:{}", ev.dport),
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
                        policy.eval_connect(v4),
                        DenialKey::Net4(v4),
                    )
                } else {
                    (
                        format!("[{ip6}]:{}", ev.dport),
                        policy.eval_connect6(ip6),
                        DenialKey::Net6(ip6),
                    )
                }
            } else {
                let ip = Ipv4Addr::from(ev.daddr.to_ne_bytes());
                (
                    format!("{ip}:{}", ev.dport),
                    policy.eval_connect(ip),
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
    let len = (ev.path_len as usize).min(PATH_LEN);
    field_str(&ev.path[..len])
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
}
