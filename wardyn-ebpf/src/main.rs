// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wardyn eBPF programs.
//!
//! Two kinds of program run here, and the difference is the whole design:
//!
//! - **Observation** (tracepoints) streams a structured [`Event`] per
//!   exec/open/connect for the watched subtree. What it reports is a *userspace
//!   string read at `sys_enter`* — useful, but not proof of anything.
//! - **Enforcement** (`cgroup/connect*`, `lsm/file_open`, `lsm/bprm_check`)
//!   denies inline, and **reports its own decision** as a `DENY_*` event naming
//!   the key it matched. Userspace therefore renders what the kernel did instead
//!   of re-deriving it from the observed string — the two disagree whenever a
//!   path is relative, opened through a dirfd, or reached via a symlink.
//!
//! Everything the kernel silently loses is counted in `STATS` (ring-buffer
//! drops, watch-set saturation, denials) so userspace can say so out loud.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock_addr, lsm, map, tracepoint},
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie, PerCpuArray, RingBuf},
    programs::{LsmContext, SockAddrContext, TracePointContext},
};
use wardyn_common::{
    action, fmode, kind, meta, stat, Event, InodeKey, Ip6Key, NameKey, COMM_LEN, MAX_DIR_WALK,
    NAME_LEN, PATH_LEN,
};

/// The kernel refuses GPL-only helpers (`bpf_probe_read_kernel`, which every
/// matcher here depends on) unless the object carries a GPL-compatible license
/// tag. Declaring it explicitly, rather than relying on a loader default, is
/// also what makes the object's terms visible to anyone inspecting it.
#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

/// 4 MiB. An `Event` is ~324 bytes, so the old 256 KiB ring held only ~800
/// in-flight events — a `cargo build` or `npm install` overruns that in a
/// fraction of a second, and a dropped event means a denial with no feed row, no
/// audit record and no receipt line. One allocation, freed when wardyn exits.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Watched tgids. Sized well above the old 8192 because thread creations also
/// land here transiently (see `handle_fork`): at saturation `insert` fails and
/// new children silently escape *all* enforcement, which is a bypass primitive,
/// not just a leak. `wardyn_exit` now evicts thread ids as they die, and
/// `STATS[WATCH_FULL]` makes any remaining saturation loud.
#[map]
static WATCHED: HashMap<u32, u8> = HashMap::with_max_entries(65536, 0);

/// Config: [0] watch_all, [1] enforce, [2] net_default (action code),
/// [3] pid-ns handshake nonce (userspace→kernel), [4] learned init-ns tgid
/// (kernel→userspace, written by `wardyn_handshake`), [5] RESERVED (was the
/// sched_process_fork parent_pid offset; the hook now takes the parent's tgid
/// from `bpf_get_current_pid_tgid`, which is correct for a fork from any
/// thread), [6] byte offset of sched_process_fork's child_pid field (read from
/// tracefs — the layout moved when comm became `__data_loc`), [7] defer_evict
/// (1 = don't evict a WATCHED leader on exit; userspace prunes against /proc
/// instead — avoids the pthread_exit-from-leader escape), [8]/[9]/[10]/[11] LSM
/// struct offsets (file→dentry, dentry→name, dentry→parent, binprm→file)
/// resolved at runtime from BTF; 0 means "fall back to the built-in kernel-6.8
/// constants". [12]..[17] the identity offsets (file→inode, file→f_mode,
/// inode→i_ino, inode→i_sb, super_block→s_dev, dentry→d_inode), and [18] the
/// flag that says they are all trustworthy — no identity read happens unless it
/// is set, so an unresolved offset can never turn into a wild kernel probe.
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(32, 0);

/// Per-CPU counters; see [`stat`]. Per-CPU because a shared `Array` counter
/// incremented from several CPUs loses exactly the events it is meant to count.
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(stat::COUNT, 0);

/// Blocked-CIDR -> action code (longest-prefix), keyed by IPv4 in network order.
#[map]
static NET_RULES: LpmTrie<u32, u32> = LpmTrie::with_max_entries(1024, 0);

/// Same, for IPv6 (keyed by the 16-byte address in network order).
#[map]
static NET_RULES6: LpmTrie<Ip6Key, u32> = LpmTrie::with_max_entries(1024, 0);

// The three name maps and the three identity maps below all store an **access
// mask** as their value (see `wardyn_common::fmode`), not a presence flag: 0
// means "every open", and READ/WRITE narrow the key to opens that asked for
// that access. A rule protecting a secret should not also forbid writing it.

/// Blocked file basenames (e.g. `.env`, `shadow`) — exact match, NUL-padded.
#[map]
static BLOCK_NAMES: HashMap<NameKey, u8> = HashMap::with_max_entries(256, 0);

/// Blocked directory names (e.g. `.ssh`, `.aws`) — exact match against every
/// ancestor of the opened file, up to [`MAX_DIR_WALK`] levels.
#[map]
static BLOCK_DIRS: HashMap<NameKey, u8> = HashMap::with_max_entries(256, 0);

/// Blocked executable basenames (e.g. `nc`, `ncat`) — exact match.
#[map]
static BLOCK_EXEC: HashMap<NameKey, u8> = HashMap::with_max_entries(256, 0);

// ── identity maps (M6) ──────────────────────────────────────────────────────
//
// Keyed by `(dev, ino)` — the object, not its label. A name key is shaken off by
// a single `mv`; an inode key is not, because nothing about the object changed.
// Nor does a hard link help: two names, one inode, one key. And a copy is not an
// escape either, because copying a file means reading it, and the read is what
// gets denied.
//
// Only `path:` rules land here, and only when userspace could `stat` them at
// load; the hooks consult these maps in addition to the name maps, never
// instead, so a policy that gains identity rules loses no name coverage.

/// Blocked file identities.
#[map]
static BLOCK_INODES: HashMap<InodeKey, u8> = HashMap::with_max_entries(1024, 0);

/// Blocked directory identities — matched against every ancestor of the opened
/// file, in the same bounded walk as `BLOCK_DIRS`.
#[map]
static BLOCK_DIR_INODES: HashMap<InodeKey, u8> = HashMap::with_max_entries(1024, 0);

/// Blocked executable identities, consulted by `bprm_check_security`.
#[map]
static BLOCK_EXEC_INODES: HashMap<InodeKey, u8> = HashMap::with_max_entries(1024, 0);

const CFG_WATCH_ALL: u32 = 0;
const CFG_ENFORCE: u32 = 1;
const CFG_NET_DEFAULT: u32 = 2;
const CFG_HS_NONCE: u32 = 3;
const CFG_HS_TGID: u32 = 4;
const CFG_FORK_CHILD_OFF: u32 = 6;
const CFG_DEFER_EVICT: u32 = 7;
const CFG_FILE_DENTRY_OFF: u32 = 8;
const CFG_DENTRY_NAME_OFF: u32 = 9;
const CFG_DENTRY_PARENT_OFF: u32 = 10;
const CFG_BPRM_FILE_OFF: u32 = 11;
const CFG_FILE_INODE_OFF: u32 = 12;
const CFG_FILE_MODE_OFF: u32 = 13;
const CFG_INODE_INO_OFF: u32 = 14;
const CFG_INODE_SB_OFF: u32 = 15;
const CFG_SB_DEV_OFF: u32 = 16;
const CFG_DENTRY_INODE_OFF: u32 = 17;
/// Set when userspace resolved the extended offsets (`f_mode`, `f_inode`,
/// `i_ino`, `i_sb`, `s_dev`, `d_inode`) from BTF. Nothing below dereferences one
/// unless it is set, so a kernel whose layout we could not read degrades to name
/// matching instead of probing arbitrary addresses.
const CFG_EXT_OFFSETS: u32 = 18;
/// Set when the extended offsets are usable **and** the policy actually has
/// identity keys. Separate from [`CFG_EXT_OFFSETS`] so a policy with no `path:`
/// rules skips the inode reads entirely — three per open plus four per ancestor
/// level is not free on the hot path — while `access:` narrowing, which only
/// needs `f_mode`, keeps working.
const CFG_IDENTITY_ON: u32 = 19;

const EXECVE_FILENAME_OFFSET: usize = 16;
// personality(persona) — persona is the 1st arg, same slot as execve's filename.
const PERSONALITY_ARG_OFFSET: usize = 16;
// execveat(fd, filename, ...) — filename is the 2nd arg, so one slot further in.
const EXECVEAT_FILENAME_OFFSET: usize = 24;
const OPENAT_FILENAME_OFFSET: usize = 24;
// openat(dfd, filename, flags, mode) — flags is the 3rd arg, one slot past the
// filename. Same ABI-stable 16 + 8·n layout as every other syscall tracepoint.
const OPENAT_FLAGS_OFFSET: usize = 32;
const CONNECT_USERVADDR_OFFSET: usize = 24;
// sendto(fd, buf, len, flags, dest_addr, addrlen) — dest_addr is the 5th arg.
const SENDTO_UADDR_OFFSET: usize = 48;
// sched_process_fork's child_pid offset is NOT hardcoded: the sched tracepoint
// layout moved when comm became `__data_loc` (child_pid 44→20). Userspace reads
// the running kernel's format from tracefs and passes the offset via
// CONFIG[CFG_FORK_CHILD_OFF]. Syscall tracepoints (above) keep their ABI-stable
// 16+8·n argument slots.

// Built-in struct offsets for kernel 6.8 (from `pahole`; see
// scripts/kernel-offsets.sh). These are only a FALLBACK now: userspace resolves
// the running kernel's real offsets from BTF and publishes them via CONFIG[8..11]
// (`off()` prefers the CONFIG value and drops to these when it is 0).
// file.f_path(152) + path.dentry(8):
const FILE_DENTRY_OFF: usize = 160;
// dentry.d_name(32) + qstr.name(8):
const DENTRY_NAME_OFF: usize = 40;
// dentry.d_parent(24):
const DENTRY_PARENT_OFF: usize = 24;
// linux_binprm.file (the executable being exec'd):
const BPRM_FILE_OFF: usize = 64;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[repr(C)]
struct SockAddrIn {
    family: u16,
    port: u16, // network byte order
    addr: u32, // network byte order
}

#[repr(C)]
struct SockAddrIn6 {
    family: u16,
    port: u16, // network byte order
    flowinfo: u32,
    addr: [u8; 16], // network byte order
                    // sin6_scope_id omitted — not needed
}

#[inline(always)]
fn cfg(i: u32) -> u32 {
    CONFIG.get(i).copied().unwrap_or(0)
}

/// A byte offset published by userspace in `CONFIG[idx]`, or `default` when it is
/// 0 (userspace could not resolve it from BTF). Used for the LSM `dentry` offsets
/// so the matcher adapts to the running kernel instead of being pinned to 6.8.
#[inline(always)]
fn off(idx: u32, default: usize) -> usize {
    let v = cfg(idx) as usize;
    if v != 0 {
        v
    } else {
        default
    }
}

/// Bump a [`stat`] counter. Best-effort: a counter we failed to increment must
/// never change what the hook decides.
#[inline(always)]
fn bump(slot: u32) {
    if let Some(p) = STATS.get_ptr_mut(slot) {
        unsafe { *p += 1 };
    }
}

#[inline(always)]
fn watch_all() -> bool {
    cfg(CFG_WATCH_ALL) != 0
}

#[inline(always)]
fn is_watched(pid: u32) -> bool {
    unsafe { WATCHED.get(&pid).is_some() }
}

#[inline(always)]
fn in_scope(pid: u32) -> bool {
    watch_all() || is_watched(pid)
}

// ── exec + open observation ─────────────────────────────────────────────────

#[tracepoint]
pub fn wardyn_execve(ctx: TracePointContext) -> u32 {
    let _ = emit_path_event(&ctx, kind::EXEC, EXECVE_FILENAME_OFFSET, NO_FLAGS);
    0
}

#[tracepoint]
pub fn wardyn_openat(ctx: TracePointContext) -> u32 {
    let _ = emit_path_event(
        &ctx,
        kind::OPEN,
        OPENAT_FILENAME_OFFSET,
        OPENAT_FLAGS_OFFSET,
    );
    0
}

// openat2/execveat exist because the LSM file_open / bprm_check hooks fire for
// them too — without these tracepoints the kernel could deny an open/exec that
// never showed up in the feed. Same filename slot as openat (2nd syscall arg).
#[tracepoint]
pub fn wardyn_openat2(ctx: TracePointContext) -> u32 {
    // openat2 hides its flags inside a `struct open_how` behind a pointer, so
    // the access is not readable from the argument slots. Reported as unknown,
    // which makes userspace predict conservatively rather than guess.
    let _ = emit_path_event(&ctx, kind::OPEN, OPENAT_FILENAME_OFFSET, NO_FLAGS);
    0
}

#[tracepoint]
pub fn wardyn_execveat(ctx: TracePointContext) -> u32 {
    let _ = emit_path_event(&ctx, kind::EXEC, EXECVEAT_FILENAME_OFFSET, NO_FLAGS);
    0
}

/// `flags_off` value meaning "this syscall's access mode is not readable here".
const NO_FLAGS: usize = 0;

/// The kernel's `OPEN_FMODE`: `O_RDONLY`/`O_WRONLY`/`O_RDWR` (0/1/2) become
/// `FMODE_READ`/`FMODE_WRITE`/both, which is literally `(flags + 1) & O_ACCMODE`.
/// Doing the same arithmetic here is what lets the feed's prediction agree with
/// the `f_mode` the LSM hook will read.
#[inline(always)]
fn open_fmode(flags: u32) -> u32 {
    (flags + 1) & 0b11
}

fn emit_path_event(
    ctx: &TracePointContext,
    ev_kind: u32,
    filename_off: usize,
    flags_off: usize,
) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !in_scope(pid) {
        return Ok(());
    }
    let filename = unsafe { ctx.read_at::<u64>(filename_off) }? as *const u8;
    // The access the open asked for, so the feed's own verdict can honour a
    // rule that only covers reads. Unknown (no flags slot, or an unreadable
    // one) is reported as "both", the conservative direction: userspace then
    // predicts as it did before rules could name an access.
    let requested = if flags_off == NO_FLAGS {
        if ev_kind == kind::OPEN {
            fmode::READ | fmode::WRITE
        } else {
            0
        }
    } else {
        match unsafe { ctx.read_at::<u64>(flags_off) } {
            Ok(flags) => open_fmode(flags as u32),
            Err(_) => fmode::READ | fmode::WRITE,
        }
    };

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump(stat::RING_DROPS);
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).kind = ev_kind;
        (*e).action = action::ALLOW;
        (*e).meta = 0;
        (*e).pid = pid;
        (*e).ppid = 0;
        (*e).uid = bpf_get_current_uid_gid() as u32;
        (*e).daddr = 0;
        (*e).daddr6 = [0u8; 16];
        (*e).dport = 0;
        (*e).family = 0;
        (*e).dev = 0;
        (*e).ino = 0;
        (*e).fmode = requested;
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
        let dst = core::slice::from_raw_parts_mut((*e).path.as_mut_ptr(), PATH_LEN);
        (*e).path_len = match bpf_probe_read_user_str_bytes(filename, dst) {
            Ok(bytes) => bytes.len() as u32,
            // A path at or over PATH_LEN (or an unreadable one) leaves the
            // helper's zeroed buffer behind. Report it as PATH_LEN rather than
            // 0 so userspace can say "truncated/unreadable" instead of showing
            // an empty DETAIL and evaluating the policy against "".
            Err(_) => PATH_LEN as u32,
        };
    }
    entry.submit(0);
    Ok(())
}

// ── connect observation ─────────────────────────────────────────────────────

#[tracepoint]
pub fn wardyn_connect(ctx: TracePointContext) -> u32 {
    let _ = emit_connect(&ctx, CONNECT_USERVADDR_OFFSET);
    0
}

// UDP egress uses sendto/sendmsg, not connect — and the cgroup sendmsg hooks
// enforce on it — so observe sendto too, or blocked datagrams would be denied
// invisibly. (sendmsg's destination hides behind a msghdr indirection aya-ebpf
// 0.1 can't easily walk; the DENY_NET event from the cgroup hook covers it.)
#[tracepoint]
pub fn wardyn_sendto(ctx: TracePointContext) -> u32 {
    let _ = emit_connect(&ctx, SENDTO_UADDR_OFFSET);
    0
}

fn emit_connect(ctx: &TracePointContext, uaddr_off: usize) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !in_scope(pid) {
        return Ok(());
    }
    let uaddr = unsafe { ctx.read_at::<u64>(uaddr_off) }? as *const u8;
    // The family is the first u16 of any sockaddr. Read the address BEFORE
    // reserving so a failed read can't leak the ring-buffer entry.
    let family: u16 = unsafe { bpf_probe_read_user(uaddr as *const u16) }?;
    let mut daddr = 0u32;
    let mut daddr6 = [0u8; 16];
    let dport;
    if family == AF_INET {
        let sa: SockAddrIn = unsafe { bpf_probe_read_user(uaddr as *const SockAddrIn) }?;
        daddr = sa.addr;
        dport = u16::from_be(sa.port);
    } else if family == AF_INET6 {
        let sa: SockAddrIn6 = unsafe { bpf_probe_read_user(uaddr as *const SockAddrIn6) }?;
        daddr6 = sa.addr;
        dport = u16::from_be(sa.port);
    } else {
        return Ok(()); // not IP (AF_UNIX, etc.)
    }

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump(stat::RING_DROPS);
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).kind = kind::CONNECT;
        (*e).action = action::ALLOW;
        (*e).meta = 0;
        (*e).pid = pid;
        (*e).ppid = 0;
        (*e).uid = bpf_get_current_uid_gid() as u32;
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
        (*e).path_len = 0;
        (*e).daddr = daddr;
        (*e).daddr6 = daddr6;
        (*e).dport = dport;
        (*e).family = family;
        (*e).dev = 0;
        (*e).ino = 0;
        (*e).fmode = 0;
    }
    entry.submit(0);
    Ok(())
}

// ── denial reporting: the hook that decides is the hook that reports ────────

/// Emit a `DENY_FILE` / `DENY_EXEC` event carrying the key that matched. This is
/// the only evidence userspace has that a denial actually happened: the observed
/// `sys_enter` path may be relative, may name a symlink, or may not exist at all
/// (a dirfd-relative open), and the LSM matched the resolved dentry instead.
#[inline(always)]
fn emit_deny_name(ev_kind: u32, key: &[u8; NAME_LEN], meta_val: u32) {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump(stat::RING_DROPS);
        return;
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).kind = ev_kind;
        (*e).action = action::BLOCK;
        (*e).meta = meta_val;
        (*e).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).ppid = 0;
        (*e).uid = bpf_get_current_uid_gid() as u32;
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
        (*e).daddr = 0;
        (*e).daddr6 = [0u8; 16];
        (*e).dport = 0;
        (*e).family = 0;
        (*e).dev = 0;
        (*e).ino = 0;
        (*e).fmode = 0;
        // Fixed-width copy, no data-dependent indexing: the key is already
        // NUL-padded and userspace stops at the NUL, and a constant-length
        // memcpy is what the verifier is happiest with.
        let dst = core::slice::from_raw_parts_mut((*e).path.as_mut_ptr(), PATH_LEN);
        dst[..NAME_LEN].copy_from_slice(key);
        (*e).path_len = NAME_LEN as u32;
    }
    entry.submit(0);
}

/// Emit a `DENY_FILE`/`DENY_EXEC` for an **identity** match.
///
/// Carries the key that matched *and* the name the object has right now. Both
/// halves matter: userspace maps the key back to the path the policy named, and
/// the current name is what shows the operator that the rename did not work —
/// `hidden.txt [ino:/home/me/.env]` reads as a story, `ino 4242` does not.
#[inline(always)]
fn emit_deny_ident(
    ev_kind: u32,
    dentry: *const u8,
    name_off: usize,
    key: &InodeKey,
    meta_val: u32,
) {
    // Read the name BEFORE reserving, so a failed read cannot leak a ring entry.
    let mut name = [0u8; NAME_LEN];
    let _ = read_name(dentry, name_off, &mut name);

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump(stat::RING_DROPS);
        return;
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).kind = ev_kind;
        (*e).action = action::BLOCK;
        (*e).meta = meta_val;
        (*e).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).ppid = 0;
        (*e).uid = bpf_get_current_uid_gid() as u32;
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
        (*e).daddr = 0;
        (*e).daddr6 = [0u8; 16];
        (*e).dport = 0;
        (*e).family = 0;
        (*e).dev = key.dev;
        (*e).ino = key.ino;
        (*e).fmode = 0;
        let dst = core::slice::from_raw_parts_mut((*e).path.as_mut_ptr(), PATH_LEN);
        dst[..NAME_LEN].copy_from_slice(&name);
        (*e).path_len = NAME_LEN as u32;
    }
    entry.submit(0);
}

/// Emit a `DENY_NET` event for a refused destination.
#[inline(always)]
fn emit_deny_net(daddr: u32, daddr6: [u8; 16], dport: u16, family: u16) {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump(stat::RING_DROPS);
        return;
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).kind = kind::DENY_NET;
        (*e).action = action::BLOCK;
        (*e).meta = 0;
        (*e).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).ppid = 0;
        (*e).uid = bpf_get_current_uid_gid() as u32;
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
        (*e).path_len = 0;
        (*e).daddr = daddr;
        (*e).daddr6 = daddr6;
        (*e).dport = dport;
        (*e).family = family;
    }
    entry.submit(0);
}

// ── network enforcement: deny blocked egress ────────────────────────────────

const ALLOW: i32 = 1;
const DENY: i32 = 0;

/// Collapse a hook's result into a verdict the verifier can bound.
///
/// A `cgroup_sock_addr` program must exit with `R0` in `[0, 1]`, and that bound
/// is checked at load. The verifier cannot see through the bpf-to-bpf call:
/// `try_connect*` hands its `Result` back through a caller stack slot, and the
/// slot is marked unknown once the callee has written to it. So the natural
/// `Ok(v) => v` reloads a full-range scalar into `R0` and the program is
/// rejected outright:
///
/// ```text
/// At program exit the register R0 has smin=0 smax=4294967295
/// should have been in [0, 1]
/// ```
///
/// Every arm here yields a literal instead, which is what makes the bound
/// provable. Do not fold this back into `Ok(v) => v` because "it is the same
/// value": it compiles, and then fails at load — and wardyn fails open, so the
/// result is egress silently unenforced behind a feed that still looks healthy.
#[inline(always)]
fn net_verdict(r: Result<i32, i64>) -> i32 {
    match r {
        Ok(DENY) => DENY,
        _ => ALLOW, // allow, and fail open on a read error
    }
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    net_verdict(try_connect4(&ctx))
}

/// Longest-prefix verdict for an IPv4 destination (network byte order, matching
/// how `user_ip4` and the userspace-compiled `NET_RULES` keys are laid out).
/// Shared by `connect4` and by `connect6`'s v4-mapped path.
#[inline(always)]
fn net4_blocked(ip: u32) -> bool {
    let action = NET_RULES
        .get(&Key::new(32, ip))
        .copied()
        .unwrap_or_else(|| cfg(CFG_NET_DEFAULT));
    action == action::BLOCK
}

/// The destination port from `bpf_sock_addr::user_port`, which holds a
/// network-order 16-bit port zero-extended into a `__be32`.
#[inline(always)]
fn dest_port(ctx: &SockAddrContext) -> u16 {
    let raw = unsafe { (*ctx.sock_addr).user_port };
    u16::from_be(raw as u16)
}

fn try_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    if cfg(CFG_ENFORCE) == 0 {
        return Ok(ALLOW);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_watched(pid) {
        return Ok(ALLOW);
    }
    let ip = unsafe { (*ctx.sock_addr).user_ip4 }; // network byte order
    if net4_blocked(ip) {
        bump(stat::DENIED_NET);
        emit_deny_net(ip, [0u8; 16], dest_port(ctx), AF_INET);
        return Ok(DENY);
    }
    Ok(ALLOW)
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    net_verdict(try_connect6(&ctx))
}

fn try_connect6(ctx: &SockAddrContext) -> Result<i32, i64> {
    if cfg(CFG_ENFORCE) == 0 {
        return Ok(ALLOW);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_watched(pid) {
        return Ok(ALLOW);
    }
    // user_ip6 is [u32; 4] in network order. Read each word DIRECTLY from the
    // context; taking &user_ip6 and indexing it is a "modified ctx ptr" the
    // verifier rejects. Combine on the stack, then reinterpret as 16 bytes.
    let sa = ctx.sock_addr;
    let w = unsafe {
        [
            (*sa).user_ip6[0],
            (*sa).user_ip6[1],
            (*sa).user_ip6[2],
            (*sa).user_ip6[3],
        ]
    };
    let ip6: [u8; 16] = unsafe { core::mem::transmute(w) };
    // A dual-stack AF_INET6 socket connecting to an IPv4 host runs THIS hook with
    // a v4-mapped address (`::ffff:a.b.c.d`) — `connect4` never fires for it. If we
    // only consulted the v6 trie, every IPv4 rule (including the `0.0.0.0/0` deny-
    // all) would be silently bypassed. So detect the `::ffff:0:0/96` prefix and run
    // the embedded v4 address through the v4 trie. Explicit byte compares (no loop)
    // keep the verifier happy.
    let v4_mapped = ip6[0] == 0
        && ip6[1] == 0
        && ip6[2] == 0
        && ip6[3] == 0
        && ip6[4] == 0
        && ip6[5] == 0
        && ip6[6] == 0
        && ip6[7] == 0
        && ip6[8] == 0
        && ip6[9] == 0
        && ip6[10] == 0xff
        && ip6[11] == 0xff;
    if v4_mapped {
        // ip6[12..16] are the embedded v4 octets in network order — the same
        // representation `net4_blocked` and `user_ip4` use.
        let ip = u32::from_ne_bytes([ip6[12], ip6[13], ip6[14], ip6[15]]);
        if net4_blocked(ip) {
            bump(stat::DENIED_NET);
            // Report the address the operator will recognise from the feed.
            emit_deny_net(0, ip6, dest_port(ctx), AF_INET6);
            return Ok(DENY);
        }
        return Ok(ALLOW);
    }
    let action = NET_RULES6
        .get(&Key::new(128, Ip6Key(ip6)))
        .copied()
        .unwrap_or_else(|| cfg(CFG_NET_DEFAULT));
    if action == action::BLOCK {
        bump(stat::DENIED_NET);
        emit_deny_net(0, ip6, dest_port(ctx), AF_INET6);
        return Ok(DENY);
    }
    Ok(ALLOW)
}

// UDP is connectionless — connect() may never fire, so gate sendmsg too. The
// destination is in the same bpf_sock_addr fields, so reuse the connect logic.

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    net_verdict(try_connect4(&ctx))
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    net_verdict(try_connect6(&ctx))
}

// ── file enforcement: deny opening blocked secrets ──────────────────────────

const EPERM: i32 = -1;
const OK: i32 = 0;

/// The LSM counterpart of [`net_verdict`] — identical reasoning, different
/// range: an LSM hook must exit with `R0` in `[-4095, 0]`. These two hooks are
/// the ones a `?` can genuinely fail in (they read kernel memory), so the error
/// arm is live here rather than ceremony, and it permits: wardyn fails open by
/// design, and a failed read must not be turned into a denial nobody can explain.
#[inline(always)]
fn lsm_verdict(r: Result<i32, i64>) -> i32 {
    match r {
        Ok(EPERM) => EPERM,
        _ => OK, // permit, and fail open on a read error
    }
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    lsm_verdict(try_file_open(&ctx))
}

fn try_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    if cfg(CFG_ENFORCE) == 0 {
        return Ok(OK);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_watched(pid) {
        return Ok(OK);
    }

    let name_off = off(CFG_DENTRY_NAME_OFF, DENTRY_NAME_OFF);
    let parent_off = off(CFG_DENTRY_PARENT_OFF, DENTRY_PARENT_OFF);
    let ext = cfg(CFG_EXT_OFFSETS) != 0;
    let identity = ext && cfg(CFG_IDENTITY_ON) != 0;

    // struct file* -> f_path.dentry
    let file: *const u8 = unsafe { ctx.arg(0) };
    let dentry = read_ptr(file, off(CFG_FILE_DENTRY_OFF, FILE_DENTRY_OFF))?;

    // What did this open ask for? Only meaningful once `f_mode`'s offset is
    // known; otherwise every mask matches, which is exactly how rules behaved
    // before the access axis existed. Gated on `ext`, NOT on `identity`: a policy
    // can use `access:` without a single `path:` rule, and tying the two would
    // silently stop narrowing such a rule.
    let requested = if ext {
        read_u32(file, cfg(CFG_FILE_MODE_OFF) as usize).unwrap_or(ANY_ACCESS)
    } else {
        ANY_ACCESS
    };

    // Identity first: it is the more specific statement. A file that matches by
    // inode matches whatever it is currently called, and reporting the *name*
    // rule for it would tell the operator the wrong story.
    if identity {
        if let Ok(key) = inode_key_of_file(file) {
            if let Some(&mask) = unsafe { BLOCK_INODES.get(&key) } {
                if access_matches(mask, requested) {
                    bump(stat::DENIED_FILE);
                    bump(stat::DENIED_IDENTITY);
                    emit_deny_ident(kind::DENY_FILE, dentry, name_off, &key, meta::KEY_INO);
                    return Ok(EPERM);
                }
            }
        }
    }

    // basename: dentry->d_name.name
    let mut name = [0u8; NAME_LEN];
    read_name(dentry, name_off, &mut name)?;
    if let Some(&mask) = unsafe { BLOCK_NAMES.get(&NameKey(name)) } {
        if access_matches(mask, requested) {
            bump(stat::DENIED_FILE);
            emit_deny_name(kind::DENY_FILE, &name, meta::KEY_NAME);
            return Ok(EPERM);
        }
    }

    // Ancestor directories: dentry->d_parent->...->d_name.name. Walking the whole
    // chain (not just the immediate parent) is what makes a `**/dir/**` rule mean
    // what it says; matching only the direct parent quietly let `.ssh/sub/key`
    // through while the feed showed the rule as covering it.
    let mut cur = dentry;
    for _ in 0..MAX_DIR_WALK {
        let Ok(parent) = read_ptr(cur, parent_off) else {
            break;
        };
        // The root dentry is its own parent — that is the loop's real terminator.
        if parent.is_null() || parent == cur {
            break;
        }
        // The ancestor's identity, for a `path:` rule naming a directory: this is
        // what keeps `mv .ssh dotssh` from exposing the subtree.
        if identity {
            if let Ok(key) = inode_key_of_dentry(parent) {
                if let Some(&mask) = unsafe { BLOCK_DIR_INODES.get(&key) } {
                    if access_matches(mask, requested) {
                        bump(stat::DENIED_FILE);
                        bump(stat::DENIED_IDENTITY);
                        emit_deny_ident(kind::DENY_FILE, parent, name_off, &key, meta::KEY_DIR_INO);
                        return Ok(EPERM);
                    }
                }
            }
        }
        let mut dir = [0u8; NAME_LEN];
        if read_name(parent, name_off, &mut dir).is_err() {
            break;
        }
        if let Some(&mask) = unsafe { BLOCK_DIRS.get(&NameKey(dir)) } {
            if access_matches(mask, requested) {
                bump(stat::DENIED_FILE);
                emit_deny_name(kind::DENY_FILE, &dir, meta::KEY_DIR);
                return Ok(EPERM);
            }
        }
        cur = parent;
    }

    Ok(OK)
}

/// Every access a rule can name. Used when the hook could not read `f_mode`, so
/// an unresolved offset never turns a rule OFF — it just stops narrowing it.
const ANY_ACCESS: u32 = fmode::READ | fmode::WRITE;

/// Does a key stored with `mask` cover an open that asked for `requested`?
#[inline(always)]
fn access_matches(mask: u8, requested: u32) -> bool {
    fmode::matches(mask, requested)
}

/// `(dev, ino)` of the object a `struct file` refers to.
#[inline(always)]
fn inode_key_of_file(file: *const u8) -> Result<InodeKey, i64> {
    let inode = read_ptr(file, cfg(CFG_FILE_INODE_OFF) as usize)?;
    inode_key(inode)
}

/// Same, reached through a dentry (used for ancestor directories).
#[inline(always)]
fn inode_key_of_dentry(dentry: *const u8) -> Result<InodeKey, i64> {
    let inode = read_ptr(dentry, cfg(CFG_DENTRY_INODE_OFF) as usize)?;
    inode_key(inode)
}

/// `inode->i_ino` plus `inode->i_sb->s_dev`. The device matters: inode numbers
/// are only unique within a filesystem, and without it a rule pinning
/// `/home/agent/.env` would also deny an unrelated file that happens to have the
/// same inode number on another mount.
#[inline(always)]
fn inode_key(inode: *const u8) -> Result<InodeKey, i64> {
    if inode.is_null() {
        return Err(0);
    }
    let ino: u64 = unsafe {
        bpf_probe_read_kernel(inode.wrapping_add(cfg(CFG_INODE_INO_OFF) as usize) as *const u64)
    }?;
    let sb = read_ptr(inode, cfg(CFG_INODE_SB_OFF) as usize)?;
    let dev = read_u32(sb, cfg(CFG_SB_DEV_OFF) as usize)?;
    Ok(InodeKey { dev, _pad: 0, ino })
}

#[inline(always)]
fn read_u32(base: *const u8, off: usize) -> Result<u32, i64> {
    unsafe { bpf_probe_read_kernel(base.wrapping_add(off) as *const u32) }
}

#[inline(always)]
fn read_ptr(base: *const u8, off: usize) -> Result<*const u8, i64> {
    let p = base.wrapping_add(off) as *const *const u8;
    unsafe { bpf_probe_read_kernel(p) }
}

/// Read a NUL-terminated kernel string into a fixed key buffer.
///
/// On truncation (`name` at or over [`NAME_LEN`]) or an unreadable pointer, the
/// helper zeroes `buf`; an all-zero key matches nothing, because userspace
/// refuses to compile a key that long in the first place. That is the safe
/// direction — a name too long to key on is never enforced, and the policy
/// loader reports the rule as observe-only rather than pretending otherwise.
#[inline(always)]
fn read_name(dentry: *const u8, name_off: usize, buf: &mut [u8; NAME_LEN]) -> Result<(), i64> {
    let name_pp = dentry.wrapping_add(name_off) as *const *const u8;
    let name_ptr: *const u8 = unsafe { bpf_probe_read_kernel(name_pp) }?;
    let _ = unsafe { bpf_probe_read_kernel_str_bytes(name_ptr, buf) };
    Ok(())
}

// ── exec enforcement: deny running blocked programs ─────────────────────────

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check(ctx: LsmContext) -> i32 {
    lsm_verdict(try_bprm_check(&ctx))
}

fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i64> {
    if cfg(CFG_ENFORCE) == 0 {
        return Ok(OK);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_watched(pid) {
        return Ok(OK);
    }
    // linux_binprm* -> file -> f_path.dentry -> d_name.name (the exec basename)
    let bprm: *const u8 = unsafe { ctx.arg(0) };
    let file = read_ptr(bprm, off(CFG_BPRM_FILE_OFF, BPRM_FILE_OFF))?;
    let dentry = read_ptr(file, off(CFG_FILE_DENTRY_OFF, FILE_DENTRY_OFF))?;
    let name_off = off(CFG_DENTRY_NAME_OFF, DENTRY_NAME_OFF);

    // Identity first — renaming a blocked binary is the cheapest bypass there is.
    if cfg(CFG_EXT_OFFSETS) != 0 && cfg(CFG_IDENTITY_ON) != 0 {
        if let Ok(key) = inode_key_of_file(file) {
            if unsafe { BLOCK_EXEC_INODES.get(&key).is_some() } {
                bump(stat::DENIED_EXEC);
                bump(stat::DENIED_IDENTITY);
                emit_deny_ident(kind::DENY_EXEC, dentry, name_off, &key, meta::KEY_INO);
                return Ok(EPERM);
            }
        }
    }

    let mut name = [0u8; NAME_LEN];
    read_name(dentry, name_off, &mut name)?;
    if unsafe { BLOCK_EXEC.get(&NameKey(name)).is_some() } {
        bump(stat::DENIED_EXEC);
        emit_deny_name(kind::DENY_EXEC, &name, meta::KEY_NAME);
        return Ok(EPERM);
    }
    Ok(OK)
}

// ── pid-ns handshake: tell userspace its init-ns tgid ───────────────────────
//
// Every hook here keys WATCHED by `bpf_get_current_pid_tgid() >> 32` — the tgid
// in the kernel's INIT pid namespace. Userspace's `std::process::id()` is its
// pid in its OWN namespace; inside a container or WSL2 distro the two never
// match, and a WATCHED seeded with local pids watches (and enforces) nothing.
// So userspace publishes a random nonce in CONFIG and calls personality(nonce);
// this tracepoint sees the call, checks the nonce, and writes the caller's
// init-ns tgid back through CONFIG. The nonce gate keeps a concurrent
// personality() call from an unrelated process from electing itself.

#[tracepoint]
pub fn wardyn_handshake(ctx: TracePointContext) -> u32 {
    let _ = try_handshake(&ctx);
    0
}

fn try_handshake(ctx: &TracePointContext) -> Result<(), i64> {
    let nonce = cfg(CFG_HS_NONCE);
    if nonce == 0 {
        return Ok(());
    }
    let persona: u64 = unsafe { ctx.read_at::<u64>(PERSONALITY_ARG_OFFSET) }?;
    if persona as u32 != nonce {
        return Ok(());
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(slot) = CONFIG.get_ptr_mut(CFG_HS_TGID) {
        unsafe { *slot = tgid };
    }
    Ok(())
}

// ── fork: adopt children of watched processes ───────────────────────────────

#[tracepoint]
pub fn wardyn_fork(ctx: TracePointContext) -> u32 {
    let _ = handle_fork(&ctx);
    0
}

fn handle_fork(ctx: &TracePointContext) -> Result<(), i64> {
    // `sched_process_fork` runs synchronously in the PARENT's context inside
    // kernel_clone(), so the parent's tgid is simply the current one. The
    // tracepoint's `parent_pid` field is `parent->pid` — a *thread* id — and
    // testing that against a tgid-keyed map only ever worked because thread ids
    // were being leaked into the map as well.
    let parent = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_watched(parent) {
        return Ok(());
    }
    let child_off = cfg(CFG_FORK_CHILD_OFF) as usize;
    if child_off == 0 {
        return Ok(()); // offset not published yet — nothing can be watched yet either
    }
    let child = unsafe { ctx.read_at::<i32>(child_off) }? as u32;
    // For a real fork, child_pid IS the new tgid. For a CLONE_THREAD the field is
    // the new thread's tid, which the map does not need (the tgid is already
    // watched) — `wardyn_exit` drops those again as each thread dies, so they
    // cannot accumulate toward saturation.
    if WATCHED.insert(&child, &1u8, 0).is_err() {
        // The watch set is full: this child, and its whole subtree, is about to
        // run completely unobserved and unenforced. Userspace turns this counter
        // into a loud warning — it must never be a silent hole.
        bump(stat::WATCH_FULL);
    }
    Ok(())
}

/// Drop a process from WATCHED when it exits, so the set can't grow unbounded
/// and a reused pid can't be wrongly treated as still-watched.
///
/// `sched_process_exit` fires per-thread, while WATCHED is keyed by tgid:
///
/// - **Thread exit** (`tid != tgid`) always removes the *tid* key. Thread
///   creations transiently insert their tid (see `handle_fork`), and leaving
///   them behind both leaks toward the map cap — at which point new children
///   escape enforcement entirely — and aliases a future process that happens to
///   be given that pid number. Removing by tid is safe: pid numbers are unique
///   across threads and processes, so this can only ever remove that thread's
///   own entry.
/// - **Leader exit** (`tid == tgid`) is the ambiguous one: a leader can exit via
///   `pthread_exit()` while worker threads keep running, so evicting there would
///   silently unwatch a live process. When userspace can prune WATCHED against
///   `/proc` itself (no pid-namespace mismatch), it sets `CFG_DEFER_EVICT` and we
///   leave removal to that sweep, which only drops a tgid once the whole thread
///   group is gone. Under a pid namespace we keep leader-exit eviction as the
///   best available signal.
#[tracepoint]
pub fn wardyn_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    if tid != tgid {
        let _ = WATCHED.remove(&tid);
        return 0;
    }
    if cfg(CFG_DEFER_EVICT) == 0 {
        let _ = WATCHED.remove(&tgid);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
