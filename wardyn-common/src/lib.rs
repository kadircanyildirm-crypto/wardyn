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
}

/// Values of [`Event::meta`], interpreted per `kind`.
pub mod meta {
    /// `DENY_FILE`: the file's own basename matched `BLOCK_NAMES`.
    pub const KEY_NAME: u32 = 0;
    /// `DENY_FILE`: an ancestor directory matched `BLOCK_DIRS`.
    pub const KEY_DIR: u32 = 1;
    /// `DENY_FILE`/`DENY_EXEC`: the object's own `(dev, ino)` matched
    /// `BLOCK_INODES`. `Event::dev`/`ino` carry the key; `path` still carries
    /// the basename the file has *right now*, which is the interesting part —
    /// it is how the operator sees that a rename did not help.
    pub const KEY_INO: u32 = 2;
    /// `DENY_FILE`: an ancestor directory's `(dev, ino)` matched
    /// `BLOCK_DIR_INODES` — the directory rule survived the directory being
    /// renamed.
    pub const KEY_DIR_INO: u32 = 3;
}

/// Bits of [`Event::fmode`], mirroring the kernel's `FMODE_*`. Only the two that
/// a policy can express are carried across.
///
/// The distinction matters because `block` on a secret used to mean "cannot be
/// opened at all", which also forbids *writing* it — so a policy could not say
/// "the agent may create `.env`, it just may not read one".
pub mod fmode {
    /// The open requested read access (kernel `FMODE_READ`).
    pub const READ: u32 = 0x1;
    /// The open requested write access (kernel `FMODE_WRITE`).
    pub const WRITE: u32 = 0x2;
    /// The mask stored with a block key that does not care which access was
    /// requested: **zero**, meaning "every open matches".
    ///
    /// Not `READ | WRITE`, which looks equivalent and is not: an `O_PATH` open
    /// sets neither bit, so a `READ|WRITE` mask would silently stop covering it
    /// and a rule written today would get weaker than the same rule before the
    /// access axis existed. Zero preserves the old behaviour exactly.
    pub const MASK_ANY: u8 = 0;

    /// Does an open requesting `requested` match a key stored with `mask`?
    pub const fn matches(mask: u8, requested: u32) -> bool {
        mask == MASK_ANY || (requested & mask as u32) != 0
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
    /// Number of slots (the map's `max_entries`).
    pub const COUNT: u32 = 6;
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
        }
    }
}

/// A 16-byte IPv6 address (network byte order), used as the LPM-trie key for v6
/// network rules. Layout-compatible with the userspace mirror.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ip6Key(pub [u8; 16]);
