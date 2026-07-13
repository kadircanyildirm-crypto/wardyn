//! Leash eBPF programs.
//!
//! M1b step 3: watch three actions for the scoped process subtree —
//!   - exec  (sys_enter_execve)  -> executable path
//!   - open  (sys_enter_openat)  -> file path
//!   - connect (sys_enter_connect) -> IPv4 dest addr:port
//! plus sched_process_fork to walk the tree. `CONFIG[0]` = watch_all toggles
//! system-wide vs scoped (WATCHED-set) monitoring.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use leash_common::{action, kind, Event, COMM_LEN, PATH_LEN};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static WATCHED: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

/// index 0 = watch_all (1 = system-wide, 0 = scoped to WATCHED).
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

// tracepoint field offsets (from /sys/kernel/tracing/events/.../format)
const EXECVE_FILENAME_OFFSET: usize = 16;
const OPENAT_FILENAME_OFFSET: usize = 24;
const CONNECT_USERVADDR_OFFSET: usize = 24;
const FORK_PARENT_PID_OFFSET: usize = 24;
const FORK_CHILD_PID_OFFSET: usize = 44;

const AF_INET: u16 = 2;

/// First bytes of a `struct sockaddr_in` (IPv4).
#[repr(C)]
struct SockAddrIn {
    family: u16, // host byte order
    port: u16,   // network byte order
    addr: u32,   // network byte order
}

#[inline(always)]
fn watch_all() -> bool {
    CONFIG.get(0).map(|v| *v != 0).unwrap_or(false)
}

#[inline(always)]
fn is_watched(pid: u32) -> bool {
    unsafe { WATCHED.get(&pid).is_some() }
}

#[inline(always)]
fn in_scope(pid: u32) -> bool {
    watch_all() || is_watched(pid)
}

// ── exec + open: both carry a single user-space path pointer ────────────────

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
    // Fallible read BEFORE reserve, so we can never leak a reserved entry.
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
        // Read straight into the slot (no pre-zero — that unrolls to 256 stores).
        let dst = core::slice::from_raw_parts_mut((*e).path.as_mut_ptr(), PATH_LEN);
        (*e).path_len = match bpf_probe_read_user_str_bytes(filename, dst) {
            Ok(bytes) => bytes.len() as u32,
            Err(_) => 0,
        };
    }
    entry.submit(0);
    Ok(())
}

// ── connect: IPv4 destination address + port ────────────────────────────────

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
        return Ok(()); // only IPv4 for now (AF_INET6/AF_UNIX ignored)
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
        (*e).daddr = sa.addr; // network byte order; userspace formats it
        (*e).dport = u16::from_be(sa.port); // -> host byte order
        (*e)._pad = 0;
    }
    entry.submit(0);
    Ok(())
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
