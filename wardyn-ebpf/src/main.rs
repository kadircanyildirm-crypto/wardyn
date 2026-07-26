// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wardyn eBPF programs.
//!
//! Observation (tracepoints) streams a structured [`Event`] per exec/open/connect
//! for the watched subtree. Enforcement (M3, gated on `CONFIG[ENFORCE]` and only
//! for WATCHED pids) adds:
//!   - `cgroup/connect4` — deny outbound IPv4 to a blocked CIDR (LPM trie).
//!   - `lsm/file_open`   — deny opening a file whose basename or parent directory
//!     is on the block list (exact match; no kernel path-walk needed).
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock_addr, lsm, map, tracepoint},
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie, RingBuf},
    programs::{LsmContext, SockAddrContext, TracePointContext},
};
use wardyn_common::{action, kind, Event, Ip6Key, NameKey, COMM_LEN, NAME_LEN, PATH_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static WATCHED: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

/// Config: [0] watch_all, [1] enforce, [2] net_default (action code),
/// [3] pid-ns handshake nonce (userspace→kernel), [4] learned init-ns tgid
/// (kernel→userspace, written by `wardyn_handshake`), [5]/[6] byte offsets of
/// sched_process_fork's parent_pid/child_pid fields (read from tracefs — the
/// layout moved when comm became `__data_loc` in newer kernels),
/// [7] defer_evict (1 = don't evict WATCHED on leader exit; userspace prunes
/// against /proc instead — avoids the pthread_exit-from-leader escape),
/// [8]/[9]/[10]/[11] LSM struct offsets (file→dentry, dentry→name, dentry→parent,
/// binprm→file) resolved at runtime from BTF; 0 means "fall back to the built-in
/// kernel-6.8 constants".
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(16, 0);

/// Blocked-CIDR -> action code (longest-prefix), keyed by IPv4 in network order.
#[map]
static NET_RULES: LpmTrie<u32, u32> = LpmTrie::with_max_entries(1024, 0);

/// Same, for IPv6 (keyed by the 16-byte address in network order).
#[map]
static NET_RULES6: LpmTrie<Ip6Key, u32> = LpmTrie::with_max_entries(1024, 0);

/// Blocked file basenames (e.g. `.env`, `shadow`) — exact match, NUL-padded.
#[map]
static BLOCK_NAMES: HashMap<NameKey, u8> = HashMap::with_max_entries(256, 0);

/// Blocked parent-directory names (e.g. `.ssh`, `.aws`) — exact match.
#[map]
static BLOCK_DIRS: HashMap<NameKey, u8> = HashMap::with_max_entries(256, 0);

/// Blocked executable basenames (e.g. `nc`, `ncat`) — exact match.
#[map]
static BLOCK_EXEC: HashMap<NameKey, u8> = HashMap::with_max_entries(256, 0);

const CFG_WATCH_ALL: u32 = 0;
const CFG_ENFORCE: u32 = 1;
const CFG_NET_DEFAULT: u32 = 2;
const CFG_HS_NONCE: u32 = 3;
const CFG_HS_TGID: u32 = 4;
const CFG_FORK_PARENT_OFF: u32 = 5;
const CFG_FORK_CHILD_OFF: u32 = 6;
const CFG_DEFER_EVICT: u32 = 7;
const CFG_FILE_DENTRY_OFF: u32 = 8;
const CFG_DENTRY_NAME_OFF: u32 = 9;
const CFG_DENTRY_PARENT_OFF: u32 = 10;
const CFG_BPRM_FILE_OFF: u32 = 11;

const EXECVE_FILENAME_OFFSET: usize = 16;
// personality(persona) — persona is the 1st arg, same slot as execve's filename.
const PERSONALITY_ARG_OFFSET: usize = 16;
// execveat(fd, filename, ...) — filename is the 2nd arg, so one slot further in.
const EXECVEAT_FILENAME_OFFSET: usize = 24;
const OPENAT_FILENAME_OFFSET: usize = 24;
const CONNECT_USERVADDR_OFFSET: usize = 24;
// sendto(fd, buf, len, flags, dest_addr, addrlen) — dest_addr is the 5th arg.
const SENDTO_UADDR_OFFSET: usize = 48;
// sched_process_fork's pid offsets are NOT hardcoded: the sched tracepoint
// layout moved when comm became `__data_loc` (parent_pid 24→12, child_pid
// 44→20). Userspace reads the running kernel's format from tracefs and passes
// the offsets via CONFIG[CFG_FORK_PARENT_OFF]/[CFG_FORK_CHILD_OFF]. Syscall
// tracepoints (above) keep their ABI-stable 16+8·n argument slots.

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
    let _ = emit_path_event(&ctx, kind::EXEC, EXECVE_FILENAME_OFFSET);
    0
}

#[tracepoint]
pub fn wardyn_openat(ctx: TracePointContext) -> u32 {
    let _ = emit_path_event(&ctx, kind::OPEN, OPENAT_FILENAME_OFFSET);
    0
}

// openat2/execveat exist because the LSM file_open / bprm_check hooks fire for
// them too — without these tracepoints the kernel could deny an open/exec that
// never showed up in the feed. Same filename slot as openat (2nd syscall arg).
#[tracepoint]
pub fn wardyn_openat2(ctx: TracePointContext) -> u32 {
    let _ = emit_path_event(&ctx, kind::OPEN, OPENAT_FILENAME_OFFSET);
    0
}

#[tracepoint]
pub fn wardyn_execveat(ctx: TracePointContext) -> u32 {
    let _ = emit_path_event(&ctx, kind::EXEC, EXECVEAT_FILENAME_OFFSET);
    0
}

fn emit_path_event(ctx: &TracePointContext, ev_kind: u32, filename_off: usize) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !in_scope(pid) {
        return Ok(());
    }
    let filename = unsafe { ctx.read_at::<u64>(filename_off) }? as *const u8;

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).kind = ev_kind;
        (*e).action = action::ALLOW;
        (*e).pid = pid;
        (*e).ppid = 0;
        (*e).uid = bpf_get_current_uid_gid() as u32;
        (*e).daddr = 0;
        (*e).daddr6 = [0u8; 16];
        (*e).dport = 0;
        (*e).family = 0;
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
        let dst = core::slice::from_raw_parts_mut((*e).path.as_mut_ptr(), PATH_LEN);
        (*e).path_len = match bpf_probe_read_user_str_bytes(filename, dst) {
            Ok(bytes) => bytes.len() as u32,
            Err(_) => 0,
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
// 0.1 can't easily walk, so that path stays enforce-only for now.)
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
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).kind = kind::CONNECT;
        (*e).action = action::ALLOW;
        (*e).pid = pid;
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
    Ok(())
}

// ── network enforcement: deny blocked egress ────────────────────────────────

const ALLOW: i32 = 1;
const DENY: i32 = 0;

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(v) => v,
        Err(_) => ALLOW, // fail open
    }
}

/// Longest-prefix verdict for an IPv4 destination (network byte order, matching
/// how `user_ip4` and the userspace-compiled `NET_RULES` keys are laid out).
/// Shared by `connect4` and by `connect6`'s v4-mapped path.
#[inline(always)]
fn net4_verdict(ip: u32) -> i32 {
    let action = NET_RULES
        .get(&Key::new(32, ip))
        .copied()
        .unwrap_or_else(|| cfg(CFG_NET_DEFAULT));
    if action == action::BLOCK {
        DENY
    } else {
        ALLOW
    }
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
    Ok(net4_verdict(ip))
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    match try_connect6(&ctx) {
        Ok(v) => v,
        Err(_) => ALLOW,
    }
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
        // representation `net4_verdict` and `user_ip4` use.
        let ip = u32::from_ne_bytes([ip6[12], ip6[13], ip6[14], ip6[15]]);
        return Ok(net4_verdict(ip));
    }
    let action = NET_RULES6
        .get(&Key::new(128, Ip6Key(ip6)))
        .copied()
        .unwrap_or_else(|| cfg(CFG_NET_DEFAULT));
    if action == action::BLOCK {
        Ok(DENY)
    } else {
        Ok(ALLOW)
    }
}

// UDP is connectionless — connect() may never fire, so gate sendmsg too. The
// destination is in the same bpf_sock_addr fields, so reuse the connect logic.

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(v) => v,
        Err(_) => ALLOW,
    }
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    match try_connect6(&ctx) {
        Ok(v) => v,
        Err(_) => ALLOW,
    }
}

// ── file enforcement: deny opening blocked secrets ──────────────────────────

const EPERM: i32 = -1;
const OK: i32 = 0;

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(&ctx) {
        Ok(v) => v,
        Err(_) => OK, // fail open on a read error
    }
}

fn try_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    if cfg(CFG_ENFORCE) == 0 {
        return Ok(OK);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_watched(pid) {
        return Ok(OK);
    }

    // struct file* -> f_path.dentry
    let file: *const u8 = unsafe { ctx.arg(0) };
    let dentry = read_ptr(file, off(CFG_FILE_DENTRY_OFF, FILE_DENTRY_OFF))?;

    // basename: dentry->d_name.name
    let mut name = [0u8; NAME_LEN];
    read_name(dentry, off(CFG_DENTRY_NAME_OFF, DENTRY_NAME_OFF), &mut name)?;
    if unsafe { BLOCK_NAMES.get(&NameKey(name)).is_some() } {
        return Ok(EPERM);
    }

    // parent directory name: dentry->d_parent->d_name.name
    let parent = read_ptr(dentry, off(CFG_DENTRY_PARENT_OFF, DENTRY_PARENT_OFF))?;
    let mut dir = [0u8; NAME_LEN];
    read_name(parent, off(CFG_DENTRY_NAME_OFF, DENTRY_NAME_OFF), &mut dir)?;
    if unsafe { BLOCK_DIRS.get(&NameKey(dir)).is_some() } {
        return Ok(EPERM);
    }

    Ok(OK)
}

#[inline(always)]
fn read_ptr(base: *const u8, off: usize) -> Result<*const u8, i64> {
    let p = base.wrapping_add(off) as *const *const u8;
    unsafe { bpf_probe_read_kernel(p) }
}

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
    match try_bprm_check(&ctx) {
        Ok(v) => v,
        Err(_) => OK,
    }
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
    let mut name = [0u8; NAME_LEN];
    read_name(dentry, off(CFG_DENTRY_NAME_OFF, DENTRY_NAME_OFF), &mut name)?;
    if unsafe { BLOCK_EXEC.get(&NameKey(name)).is_some() } {
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
    let parent_off = cfg(CFG_FORK_PARENT_OFF) as usize;
    let child_off = cfg(CFG_FORK_CHILD_OFF) as usize;
    if parent_off == 0 || child_off == 0 {
        return Ok(()); // offsets not published yet — nothing can be watched yet either
    }
    let parent = unsafe { ctx.read_at::<i32>(parent_off) }? as u32;
    if !is_watched(parent) {
        return Ok(());
    }
    let child = unsafe { ctx.read_at::<i32>(child_off) }? as u32;
    let _ = WATCHED.insert(&child, &1u8, 0);
    Ok(())
}

/// Drop a process from WATCHED when it exits, so the set can't grow unbounded
/// and a reused pid can't be wrongly treated as still-watched.
///
/// `sched_process_exit` fires per-thread, but WATCHED is keyed by tgid. Removing
/// on the leader's exit (`tid == tgid`) is wrong when the leader exits *first*
/// while other threads keep running (`pthread_exit()` from `main`): the process
/// is still alive but silently unwatched. When userspace can prune WATCHED
/// against `/proc` itself (no pid-namespace mismatch), it sets `CFG_DEFER_EVICT`
/// and we skip kernel eviction entirely, leaving removal to that sweep — which
/// only drops a tgid once its whole thread group is actually gone. Under a pid
/// namespace (where userspace can't map init-ns tgids to its own `/proc`), we
/// keep the original leader-exit eviction as the best available signal.
#[tracepoint]
pub fn wardyn_exit(_ctx: TracePointContext) -> u32 {
    if cfg(CFG_DEFER_EVICT) != 0 {
        return 0; // userspace prunes WATCHED against /proc instead
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    if tid == tgid {
        let _ = WATCHED.remove(&tgid);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
