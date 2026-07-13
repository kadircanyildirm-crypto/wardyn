//! Leash eBPF programs.
//!
//! Observation (tracepoints) streams a structured [`Event`] per exec/open/connect
//! for the watched subtree. Enforcement (M3) adds a `cgroup/connect4` program
//! that *denies* outbound IPv4 connections matching a blocked CIDR — but only for
//! watched pids and only when `CONFIG[ENFORCE]` is set, so it can never break the
//! wider system.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{cgroup_sock_addr, map, tracepoint},
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie, RingBuf},
    programs::{SockAddrContext, TracePointContext},
};
use leash_common::{action, kind, Event, COMM_LEN, PATH_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// PIDs in the watched subtree (pid -> 1).
#[map]
static WATCHED: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

/// Config array:
///   [0] watch_all  (1 = observe system-wide, 0 = scoped to WATCHED)
///   [1] enforce    (1 = cgroup/LSM hooks may deny, 0 = observe only)
///   [2] net_default (action code applied to a connect with no CIDR match)
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(4, 0);

/// Compiled network policy: longest-prefix CIDR -> action code. Populated by
/// userspace from `policy.yaml`. Keyed by the IPv4 address in network byte order.
#[map]
static NET_RULES: LpmTrie<u32, u32> = LpmTrie::with_max_entries(1024, 0);

const CFG_WATCH_ALL: u32 = 0;
const CFG_ENFORCE: u32 = 1;
const CFG_NET_DEFAULT: u32 = 2;

const EXECVE_FILENAME_OFFSET: usize = 16;
const OPENAT_FILENAME_OFFSET: usize = 24;
const CONNECT_USERVADDR_OFFSET: usize = 24;
const FORK_PARENT_PID_OFFSET: usize = 24;
const FORK_CHILD_PID_OFFSET: usize = 44;

const AF_INET: u16 = 2;

#[repr(C)]
struct SockAddrIn {
    family: u16,
    port: u16, // network byte order
    addr: u32, // network byte order
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

// ── exec + open: single user-space path pointer ─────────────────────────────

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
        (*e).dport = 0;
        (*e)._pad = 0;
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

// ── connect: observation (IPv4 dest addr:port) ──────────────────────────────

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
    let uaddr = unsafe { ctx.read_at::<u64>(CONNECT_USERVADDR_OFFSET) }? as *const SockAddrIn;
    let sa = unsafe { bpf_probe_read_user(uaddr) }?;
    if sa.family != AF_INET {
        return Ok(());
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
        (*e).daddr = sa.addr;
        (*e).dport = u16::from_be(sa.port);
        (*e)._pad = 0;
    }
    entry.submit(0);
    Ok(())
}

// ── connect: enforcement (deny blocked egress) ──────────────────────────────

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(v) => v,
        Err(_) => 1, // fail open
    }
}

const ALLOW: i32 = 1;
const DENY: i32 = 0;

fn try_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    // Enforcement is opt-in and scoped: never touch unwatched processes.
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
