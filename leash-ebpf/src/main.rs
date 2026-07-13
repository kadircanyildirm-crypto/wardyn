//! Leash eBPF programs.
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
use leash_common::{action, kind, Event, Ip6Key, NameKey, COMM_LEN, NAME_LEN, PATH_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static WATCHED: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

/// Config: [0] watch_all, [1] enforce, [2] net_default (action code).
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(4, 0);

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

const EXECVE_FILENAME_OFFSET: usize = 16;
const OPENAT_FILENAME_OFFSET: usize = 24;
const CONNECT_USERVADDR_OFFSET: usize = 24;
const FORK_PARENT_PID_OFFSET: usize = 24;
const FORK_CHILD_PID_OFFSET: usize = 44;

// struct offsets for kernel 6.8 (from `pahole`); see scripts/kernel-offsets.sh.
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
pub fn leash_execve(ctx: TracePointContext) -> u32 {
    let _ = emit_path_event(&ctx, kind::EXEC, EXECVE_FILENAME_OFFSET);
    0
}

#[tracepoint]
pub fn leash_openat(ctx: TracePointContext) -> u32 {
    let _ = emit_path_event(&ctx, kind::OPEN, OPENAT_FILENAME_OFFSET);
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
pub fn leash_connect(ctx: TracePointContext) -> u32 {
    let _ = emit_connect(&ctx);
    0
}

fn emit_connect(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !in_scope(pid) {
        return Ok(());
    }
    let uaddr = unsafe { ctx.read_at::<u64>(CONNECT_USERVADDR_OFFSET) }? as *const u8;
    // The family is the first u16 of any sockaddr. Read the address BEFORE
    // reserving so a failed read can't leak the ring-buffer entry.
    let family: u16 = unsafe { bpf_probe_read_user(uaddr as *const u16) }?;
    let mut daddr = 0u32;
    let mut daddr6 = [0u8; 16];
    let mut dport = 0u16;
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

fn try_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    if cfg(CFG_ENFORCE) == 0 {
        return Ok(ALLOW);
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_watched(pid) {
        return Ok(ALLOW);
    }
    let ip = unsafe { (*ctx.sock_addr).user_ip4 }; // network byte order
    let action = NET_RULES
        .get(&Key::new(32, ip))
        .copied()
        .unwrap_or_else(|| cfg(CFG_NET_DEFAULT));
    if action == action::BLOCK {
        Ok(DENY)
    } else {
        Ok(ALLOW)
    }
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
    let dentry = read_ptr(file, FILE_DENTRY_OFF)?;

    // basename: dentry->d_name.name
    let mut name = [0u8; NAME_LEN];
    read_name(dentry, &mut name)?;
    if unsafe { BLOCK_NAMES.get(&NameKey(name)).is_some() } {
        return Ok(EPERM);
    }

    // parent directory name: dentry->d_parent->d_name.name
    let parent = read_ptr(dentry, DENTRY_PARENT_OFF)?;
    let mut dir = [0u8; NAME_LEN];
    read_name(parent, &mut dir)?;
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
fn read_name(dentry: *const u8, buf: &mut [u8; NAME_LEN]) -> Result<(), i64> {
    let name_pp = dentry.wrapping_add(DENTRY_NAME_OFF) as *const *const u8;
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
    let file = read_ptr(bprm, BPRM_FILE_OFF)?;
    let dentry = read_ptr(file, FILE_DENTRY_OFF)?;
    let mut name = [0u8; NAME_LEN];
    read_name(dentry, &mut name)?;
    if unsafe { BLOCK_EXEC.get(&NameKey(name)).is_some() } {
        return Ok(EPERM);
    }
    Ok(OK)
}

// ── fork: adopt children of watched processes ───────────────────────────────

#[tracepoint]
pub fn leash_fork(ctx: TracePointContext) -> u32 {
    let _ = handle_fork(&ctx);
    0
}

fn handle_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let parent = unsafe { ctx.read_at::<i32>(FORK_PARENT_PID_OFFSET) }? as u32;
    if !is_watched(parent) {
        return Ok(());
    }
    let child = unsafe { ctx.read_at::<i32>(FORK_CHILD_PID_OFFSET) }? as u32;
    let _ = WATCHED.insert(&child, &1u8, 0);
    Ok(())
}

/// Drop a task from WATCHED when it exits, so the set can't grow unbounded and a
/// reused pid can't be wrongly treated as still-watched.
#[tracepoint]
pub fn leash_exit(_ctx: TracePointContext) -> u32 {
    let tid = bpf_get_current_pid_tgid() as u32; // exiting task's tid (== tgid for the leader)
    let _ = WATCHED.remove(&tid);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
