// SPDX-License-Identifier: AGPL-3.0-or-later
//! Types shared between the eBPF programs (`wardyn-ebpf`) and userspace (`wardyn`).
//!
//! `#![no_std]` so it links into the eBPF object; it also compiles under std,
//! so userspace uses the exact same layout. Every type crossing the boundary is
//! `#[repr(C)]` and `Copy` (plain old data) — userspace reads the raw bytes out
//! of the ring buffer and reinterprets them as an [`Event`].
#![no_std]

/// Length of the `comm` (process name) field, matching the kernel's TASK_COMM_LEN.
pub const COMM_LEN: usize = 16;
/// Max bytes we copy for a path/filename in an event (truncated if longer).
pub const PATH_LEN: usize = 256;
/// Fixed key width for the file-enforcement basename / directory maps.
pub const NAME_LEN: usize = 40;

/// A NUL-padded file basename or directory name, used as an exact hash-map key
/// on both sides of the kernel boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NameKey(pub [u8; NAME_LEN]);

/// The last **two** components of a path — `(parent, name)` — as one key.
///
/// A [`NameKey`] alone is what made `/etc/shadow` deny every file called
/// `shadow` and `**/.aws/credentials` deny every `credentials`: the glob was
/// reduced to its last segment because that is all the LSM hook could read
/// cheaply. But the hook already walks `d_parent` to match directory rules, so
/// the parent's name is one probe away — and keying on both is what lets a rule
/// mean what it says. Two components, not N: every rule in the shipped policies
/// fits, and a fixed-width key of `N × NAME_LEN` bytes assembled inside a
/// bounded loop is verifier cost for a case nobody has written yet.
///
/// Used for both files (`**/.aws/credentials` → `(.aws, credentials)`, matched
/// against the opened object and its parent) and directories
/// (`**/.config/gcloud/**` → `(.config, gcloud)`, matched against each ancestor
/// and *its* parent). Same shape, different maps, because a file pair must not
/// match when the child happens to be a directory of that name.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PairKey {
    pub parent: [u8; NAME_LEN],
    pub name: [u8; NAME_LEN],
}

/// The identity of a filesystem object: `(dev, ino)` — the pair `stat(2)`
/// returns and the kernel keeps on the inode itself.
///
/// This is what a *name* is not. A name rule (`**/.env`) describes a label that
/// `mv` detaches in one syscall; an inode rule describes the object, and follows
/// it through renames and hard links because there is nothing to follow — the
/// object never moved. Copying is not an escape either: `cp` has to *read* the
/// source first, and that read is the thing being denied.
///
/// `dev` is the kernel's own `super_block->s_dev` encoding (`major << 20 |
/// minor`), NOT glibc's 64-bit `dev_t`. Userspace converts when it stats a path
/// — see `wardyn_policy::identity::kernel_dev`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct InodeKey {
    pub dev: u32,
    /// Explicit, so the 8-byte alignment of `ino` is not silently satisfied by
    /// compiler padding that the two sides could disagree about.
    pub _pad: u32,
    pub ino: u64,
}

impl InodeKey {
    pub const fn new(dev: u32, ino: u64) -> Self {
        InodeKey { dev, _pad: 0, ino }
    }
}

/// What kind of syscall/LSM event this is.
///
/// `EXEC` / `OPEN` / `CONNECT` are *observations*: a syscall entered the kernel.
/// The `DENY_*` kinds are *decisions*, emitted by the very hook that returned
/// `-EPERM` (or refused the address). The difference matters: an observation is
/// a userspace string read at `sys_enter`, while a decision names the object the
/// kernel actually acted on, so only a `DENY_*` event proves a denial happened.
pub mod kind {
    pub const EXEC: u32 = 0;
    pub const OPEN: u32 = 1;
    pub const CONNECT: u32 = 2;
    pub const FORK: u32 = 3;
    /// LSM `file_open` denied an open. `path` holds the matched key, `meta`
    /// says whether it was a basename ([`meta::KEY_NAME`]) or an ancestor
    /// directory ([`meta::KEY_DIR`]).
    pub const DENY_FILE: u32 = 4;
    /// LSM `bprm_check_security` denied an exec; `path` holds the basename.
    pub const DENY_EXEC: u32 = 5;
    /// A cgroup `connect*`/`sendmsg*` hook refused an address.
    pub const DENY_NET: u32 = 6;
    /// An LSM `inode_unlink`/`inode_rmdir`/`inode_rename` hook refused to let the
    /// object be removed. `path` holds the matched key, `meta` says which map it
    /// came from, exactly as for [`DENY_FILE`].
    pub const DENY_DELETE: u32 = 7;
    /// An LSM `inode_create`/`inode_mkdir`/`inode_rename` hook refused to let a
    /// new name appear. The object does not exist yet, so this can only ever
    /// match on the *name* being created or on an ancestor directory — never on
    /// the new object's own identity, which does not exist to be matched.
    pub const DENY_CREATE: u32 = 8;
}

/// Values of [`Event::meta`], interpreted per `kind`.
pub mod meta {
    /// `DENY_FILE`/`DENY_DELETE`/`DENY_CREATE`: the object's own basename
    /// matched `BLOCK_NAMES` (or `BLOCK_DIRS`, when the object is itself a
    /// directory being made or removed).
    pub const KEY_NAME: u32 = 0;
    /// `DENY_FILE`/`DENY_DELETE`/`DENY_CREATE`: an ancestor directory matched
    /// `BLOCK_DIRS`.
    pub const KEY_DIR: u32 = 1;
    /// `DENY_FILE`/`DENY_EXEC`/`DENY_DELETE`: the object's own `(dev, ino)`
    /// matched `BLOCK_INODES` (or `BLOCK_DIR_INODES`, for a directory being
    /// removed). `Event::dev`/`ino` carry the key; `path` still carries
    /// the basename the file has *right now*, which is the interesting part —
    /// it is how the operator sees that a rename did not help.
    pub const KEY_INO: u32 = 2;
    /// `DENY_FILE`/`DENY_DELETE`/`DENY_CREATE`: an ancestor directory's
    /// `(dev, ino)` matched `BLOCK_DIR_INODES` — the directory rule survived
    /// the directory being renamed.
    pub const KEY_DIR_INO: u32 = 3;
    /// `DENY_NET`: the destination matched a **port-qualified** rule, i.e. the
    /// decision came from `NET_PORT_RULES`, not the address-only trie.
    ///
    /// Which trie decided is not cosmetic: an approve-once exception has to be
    /// written into the same trie that denied, or the operator grants an
    /// allow that the port rule keeps overruling.
    pub const KEY_PORT: u32 = 4;
    /// `DENY_NET`: the decision came from `NET_PROTO_RULES`, i.e. a rule that
    /// named a `proto:` but no `port:`.
    pub const KEY_PROTO: u32 = 5;
    /// `DENY_NET`: the decision came from `NET_PROTO_PORT_RULES` — a rule that
    /// named both. The most specific of the four tries, and the first consulted.
    pub const KEY_PROTO_PORT: u32 = 6;
    /// `DENY_FILE`/`DENY_DELETE`/`DENY_CREATE`: the object's `(parent, name)`
    /// matched `BLOCK_PAIRS`. `path` carries the pair as two fixed
    /// [`NAME_LEN`]-byte fields, parent first.
    pub const KEY_PAIR: u32 = 7;
    /// Same, for an ancestor directory and *its* parent, from
    /// `BLOCK_DIR_PAIRS`.
    pub const KEY_DIR_PAIR: u32 = 8;
}

/// The access mask stored beside every file/exec block key, and the `f_mode`
/// bits it is matched against.
///
/// Two axes live in one byte, and they are **not** symmetric:
///
/// - The **open** axis ([`READ`]/[`WRITE`]/[`OPEN_ANY`]) is matched against the
///   kernel's `FMODE_*` at `file_open`. It exists because `block` on a secret
///   used to mean "cannot be opened at all", which also forbids *writing* it —
///   so a policy could not say "the agent may create `.env`, it just may not
///   read one".
/// - The **lifecycle** axis ([`CREATE`]/[`DELETE`]) is matched at the
///   `inode_create`/`inode_unlink`/… hooks, where there is no `f_mode` at all.
///   It exists because an `rm` is not an open: a policy that guards a secret's
///   *contents* said nothing about deleting it, and `rm -rf` was never a read.
///
/// The asymmetry is deliberate. [`MASK_ANY`] is **zero** and means "every open,
/// no lifecycle operation" — exactly what a rule written before either axis
/// existed did. If zero also covered delete, every `block` rule in every policy
/// already written would silently start refusing `rm`, which is a behaviour
/// change nobody asked for. So lifecycle coverage is only ever explicit, and
/// [`OPEN_ANY`] is the bit that says "every open" out loud, for the masks that
/// need to combine the two.
pub mod fmode {
    /// The open requested read access (kernel `FMODE_READ`).
    pub const READ: u32 = 0x1;
    /// The open requested write access (kernel `FMODE_WRITE`).
    pub const WRITE: u32 = 0x2;
    /// Every open, whatever it asked for — the explicit form of [`MASK_ANY`].
    ///
    /// Needed because `MASK_ANY` is zero, and zero cannot carry a lifecycle bit
    /// alongside it. A rule covering both axes stores `OPEN_ANY | DELETE`.
    pub const OPEN_ANY: u8 = 0x4;
    /// A new name for this object may not be created (`inode_create`,
    /// `inode_mkdir`, and the destination side of `inode_rename`).
    pub const CREATE: u8 = 0x8;
    /// This object may not be removed (`inode_unlink`, `inode_rmdir`, and the
    /// source side of `inode_rename`).
    pub const DELETE: u8 = 0x10;

    /// Every bit the open axis uses.
    pub const OPEN_BITS: u8 = READ as u8 | WRITE as u8 | OPEN_ANY;
    /// Every bit the lifecycle axis uses.
    pub const LIFECYCLE_BITS: u8 = CREATE | DELETE;

    /// The mask stored with a block key that does not care which access was
    /// requested: **zero**, meaning "every open".
    ///
    /// Not `READ | WRITE`, which looks equivalent and is not: an `O_PATH` open
    /// sets neither bit, so a `READ|WRITE` mask would silently stop covering it
    /// and a rule written today would get weaker than the same rule before the
    /// access axis existed. Zero preserves the old behaviour exactly.
    pub const MASK_ANY: u8 = 0;

    /// Does an open requesting `requested` match a key stored with `mask`?
    ///
    /// A lifecycle-only mask (`access: delete`) matches **no** open: it has no
    /// open bits, and the `MASK_ANY` escape hatch is spelled as "the whole mask
    /// is zero", not "the open bits are zero", precisely so that a delete rule
    /// does not accidentally read as "block every open".
    pub const fn matches(mask: u8, requested: u32) -> bool {
        if mask == MASK_ANY || mask & OPEN_ANY != 0 {
            return true;
        }
        requested & (mask & (READ as u8 | WRITE as u8)) as u32 != 0
    }

    /// Does a key stored with `mask` cover the lifecycle operation `op`
    /// ([`CREATE`] or [`DELETE`])?
    ///
    /// No `MASK_ANY` escape hatch, by design — see the module docs.
    pub const fn covers(mask: u8, op: u8) -> bool {
        mask & op != 0
    }

    /// The mask that covers everything either input covers.
    ///
    /// Used when two rules name the same kernel key: the map holds one value, so
    /// the merge must widen rather than narrow — the alternative is a rule that
    /// silently stops applying because an unrelated rule was added next to it.
    /// Returns the canonical [`MASK_ANY`] when the result is "every open and
    /// nothing else", so a policy that never mentions the new axes produces
    /// byte-identical map values to one built before they existed.
    pub const fn widen(a: u8, b: u8) -> u8 {
        let lifecycle = (a | b) & LIFECYCLE_BITS;
        let any_open = a == MASK_ANY || b == MASK_ANY || (a | b) & OPEN_ANY != 0;
        let open = if any_open {
            OPEN_ANY
        } else {
            (a | b) & (READ as u8 | WRITE as u8)
        };
        if lifecycle == 0 && open == OPEN_ANY {
            MASK_ANY
        } else {
            open | lifecycle
        }
    }

    /// The mask left after an approve-once exception lifts `op` from it, or
    /// `None` when nothing is left to enforce and the key should be dropped.
    ///
    /// Clearing a bit cannot go through [`MASK_ANY`]: a `delete`-only mask minus
    /// `DELETE` is zero, and writing zero back would turn an exception for one
    /// `rm` into a block on every open of the file. `None` says "remove the key"
    /// instead.
    pub const fn without(mask: u8, op: u8) -> Option<u8> {
        let next = mask & !op;
        if next == 0 {
            None
        } else {
            Some(next)
        }
    }
}

/// Slots of the per-CPU `STATS` map. Counters the kernel keeps and userspace
/// reports: without them, a full ring buffer or a full watch set is a silent
/// loss of exactly the records the tool exists to produce.
pub mod stat {
    /// Events dropped because the ring buffer was full.
    pub const RING_DROPS: u32 = 0;
    /// Children that could NOT be added to `WATCHED` (map full) — every one is
    /// a process that escaped both observation and enforcement.
    pub const WATCH_FULL: u32 = 1;
    /// Opens denied by the LSM `file_open` hook.
    pub const DENIED_FILE: u32 = 2;
    /// Execs denied by the LSM `bprm_check_security` hook.
    pub const DENIED_EXEC: u32 = 3;
    /// Destinations refused by the cgroup `connect*`/`sendmsg*` hooks.
    pub const DENIED_NET: u32 = 4;
    /// Denials that matched on `(dev, ino)` rather than on a name — a SUBSET of
    /// [`DENIED_FILE`]/[`DENIED_EXEC`], not an addition to them, so it must not
    /// be summed into a denial total. It exists because "the rename didn't help"
    /// is the one claim identity matching makes, and a counter is the only way
    /// to show it fired rather than assume it did.
    pub const DENIED_IDENTITY: u32 = 5;
    /// Removals refused by the `inode_unlink`/`inode_rmdir`/`inode_rename` hooks.
    pub const DENIED_DELETE: u32 = 6;
    /// New names refused by the `inode_create`/`inode_mkdir`/`inode_rename` hooks.
    pub const DENIED_CREATE: u32 = 7;
    /// Number of slots (the map's `max_entries`).
    pub const COUNT: u32 = 8;
}

/// How many ancestor directories the LSM `file_open` hook walks when matching
/// `BLOCK_DIRS`. Bounded so the verifier accepts the loop; userspace mirrors the
/// same bound so the feed never claims a denial from deeper than the hook looks.
pub const MAX_DIR_WALK: usize = 16;

/// The verdict the policy engine reached for this event.
pub mod action {
    pub const ALLOW: u32 = 0;
    pub const WARN: u32 = 1;
    pub const BLOCK: u32 = 2;
}

/// A single observed (and possibly enforced) action from the watched process
/// tree. One fixed-size record is pushed to the ring buffer per event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    /// One of [`kind`].
    pub kind: u32,
    /// One of [`action`] — the verdict applied (M1: always `ALLOW`, observe-only).
    pub action: u32,

    /// PID (tgid) of the process performing the action.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Real UID of the process.
    pub uid: u32,

    /// Process name (`comm`), NUL-padded.
    pub comm: [u8; COMM_LEN],

    /// For EXEC/OPEN: the executable / file path, NUL-padded, truncated to
    /// `PATH_LEN`. Unused for CONNECT.
    pub path: [u8; PATH_LEN],
    /// Number of valid bytes in `path`.
    pub path_len: u32,

    /// For CONNECT: destination IPv4 address, network byte order (family AF_INET).
    pub daddr: u32,
    /// For CONNECT: destination IPv6 address, network byte order (family AF_INET6).
    pub daddr6: [u8; 16],
    /// For CONNECT: destination port, host byte order.
    pub dport: u16,
    /// Address family for CONNECT: AF_INET (2) or AF_INET6 (10); 0 otherwise.
    pub family: u16,

    /// Kind-specific discriminator; see [`meta`]. 0 for observation events.
    pub meta: u32,

    /// For an identity match (`meta` = [`meta::KEY_INO`] / [`meta::KEY_DIR_INO`]):
    /// the inode number of the object that matched. 0 otherwise.
    pub ino: u64,
    /// The device of that same object (kernel `s_dev` encoding). 0 otherwise.
    pub dev: u32,
    /// For `OPEN` observations and `DENY_FILE`: the access the open asked for,
    /// as [`fmode`] bits. 0 when the hook could not read it.
    pub fmode: u32,

    /// For `CONNECT` / `DENY_NET`: the socket's IP protocol number (`IPPROTO_TCP`
    /// = 6, `IPPROTO_UDP` = 17), 0 when unknown.
    ///
    /// Its own field rather than a reuse of [`Self::fmode`], which happens to be
    /// free on network events: an operator reading a raw audit line should not
    /// have to know which kind of event they are looking at before they can say
    /// what a number means.
    pub proto: u32,
}

impl Event {
    /// A zeroed event; fill in the fields the given `kind` needs.
    pub const fn zeroed() -> Self {
        Self {
            kind: 0,
            action: action::ALLOW,
            pid: 0,
            ppid: 0,
            uid: 0,
            comm: [0; COMM_LEN],
            path: [0; PATH_LEN],
            path_len: 0,
            daddr: 0,
            daddr6: [0; 16],
            dport: 0,
            family: 0,
            meta: 0,
            ino: 0,
            dev: 0,
            fmode: 0,
            proto: 0,
        }
    }
}

/// A 16-byte IPv6 address (network byte order), used as the LPM-trie key for v6
/// network rules. Layout-compatible with the userspace mirror.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ip6Key(pub [u8; 16]);

/// Bits of a port-qualified key that precede the address: the 16-bit port.
///
/// **The field order is the semantics.** An LPM trie compares its key as one bit
/// string from the most significant end, so whatever comes first is what a
/// prefix can constrain *without* constraining the rest. Port before address is
/// therefore the only order that lets a rule say "port 25, anywhere" — the most
/// useful port rule there is. Address first would make that inexpressible,
/// because reaching the port bits would mean covering all 32 address bits.
pub const PORT_BITS: u32 = 16;

/// LPM key for a port-qualified IPv4 rule: `[port (network order), address]`.
///
/// The trailing padding is explicit and never covered by a prefix. It is there
/// so the key is exactly 8 bytes: `aya::maps::lpm_trie::Key` places a `u32`
/// prefix length in front of this, and if the total needed alignment padding,
/// the kernel would compare that padding as part of the key data.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortKey4 {
    pub port: [u8; 2],
    pub addr: [u8; 4],
    pub _pad: [u8; 2],
}

impl PortKey4 {
    pub const fn new(port: u16, addr: [u8; 4]) -> Self {
        PortKey4 {
            port: port.to_be_bytes(),
            addr,
            _pad: [0; 2],
        }
    }
}

/// Same, for IPv6: `[port (network order), 16-byte address]`, padded to 20.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortKey6 {
    pub port: [u8; 2],
    pub addr: [u8; 16],
    pub _pad: [u8; 2],
}

impl PortKey6 {
    pub const fn new(port: u16, addr: [u8; 16]) -> Self {
        PortKey6 {
            port: port.to_be_bytes(),
            addr,
            _pad: [0; 2],
        }
    }
}

/// IP protocol numbers a rule can name. Only these two: they are the transports
/// an egress policy can meaningfully talk about, and a policy that could name
/// any of 256 numbers would mostly be able to name ones no socket ever carries.
pub mod proto {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

/// Bits of a protocol-qualified key that precede everything else: the 8-bit
/// protocol number.
///
/// Leading, for the same reason the port leads a [`PortKey4`]: an LPM trie
/// compares its key as one bit string from the most significant end, so only
/// what comes first can be pinned without pinning the rest. A rule in either of
/// the protocol tries *always* names a protocol — that is what put it there — so
/// these bits are never a don't-care, and the fields behind them keep the exact
/// meaning they have in the tries that have no protocol at all.
pub const PROTO_BITS: u32 = 8;

/// LPM key for a rule naming a protocol and a port: `[proto, port, address]`.
///
/// Four tries now answer the same question at different specificities, and the
/// hooks consult them most-specific first — protocol+port, port, protocol,
/// address — because that is the order in which a rule *says more* about the
/// connection in front of it. The alternative is to let prefix length decide
/// across dimensions, which would make `{ proto: udp, action: block }` lose to
/// any `/8` allow and turn "no UDP at all" into a rule that does not mean what
/// it says.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtoPortKey4 {
    pub proto: u8,
    pub port: [u8; 2],
    pub addr: [u8; 4],
    pub _pad: [u8; 1],
}

impl ProtoPortKey4 {
    pub const fn new(proto: u8, port: u16, addr: [u8; 4]) -> Self {
        ProtoPortKey4 {
            proto,
            port: port.to_be_bytes(),
            addr,
            _pad: [0; 1],
        }
    }
}

/// Same, for IPv6.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtoPortKey6 {
    pub proto: u8,
    pub port: [u8; 2],
    pub addr: [u8; 16],
    pub _pad: [u8; 1],
}

impl ProtoPortKey6 {
    pub const fn new(proto: u8, port: u16, addr: [u8; 16]) -> Self {
        ProtoPortKey6 {
            proto,
            port: port.to_be_bytes(),
            addr,
            _pad: [0; 1],
        }
    }
}

/// LPM key for a rule naming a protocol but no port: `[proto, address]`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtoKey4 {
    pub proto: u8,
    pub addr: [u8; 4],
    pub _pad: [u8; 3],
}

impl ProtoKey4 {
    pub const fn new(proto: u8, addr: [u8; 4]) -> Self {
        ProtoKey4 {
            proto,
            addr,
            _pad: [0; 3],
        }
    }
}

/// Same, for IPv6.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtoKey6 {
    pub proto: u8,
    pub addr: [u8; 16],
    pub _pad: [u8; 3],
}

impl ProtoKey6 {
    pub const fn new(proto: u8, addr: [u8; 16]) -> Self {
        ProtoKey6 {
            proto,
            addr,
            _pad: [0; 3],
        }
    }
}
