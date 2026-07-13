//! Leash eBPF programs.
//!
//! M1b step 2: scope monitoring to a process subtree.
//! - `WATCHED` holds the pids we care about; userspace seeds its own pid (so the
//!   fork below adopts the launched child race-free) and the launched pid.
//! - `leash_fork` (sched_process_fork): when a watched process forks, watch the
//!   child too — this walks the whole subtree.
//! - `leash_execve` emits a structured [`Event`] only for watched pids (or for
//!   everything, when `CONFIG[0]` = watch_all = 1).
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};
use leash_common::{action, kind, Event, COMM_LEN, PATH_LEN};

/// Structured events streamed to userspace.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// PIDs in the watched subtree (pid -> 1).
#[map]
static WATCHED: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

/// Single-entry config. index 0 = watch_all (1 = system-wide, 0 = scoped).
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

const EXECVE_FILENAME_OFFSET: usize = 16;
const FORK_PARENT_PID_OFFSET: usize = 24;
const FORK_CHILD_PID_OFFSET: usize = 44;

#[inline(always)]
fn watch_all() -> bool {
    CONFIG.get(0).map(|v| *v != 0).unwrap_or(false)
}

#[inline(always)]
fn is_watched(pid: u32) -> bool {
    unsafe { WATCHED.get(&pid).is_some() }
}

#[tracepoint]
pub fn leash_execve(ctx: TracePointContext) -> u32 {
    let _ = emit_execve(&ctx);
    0
}

fn emit_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !watch_all() && !is_watched(pid) {
        return Ok(());
    }
    // Read the filename pointer before reserving, so an early return can't leak
    // the reserved ring-buffer entry ("Unreleased reference").
    let filename = unsafe { ctx.read_at::<u64>(EXECVE_FILENAME_OFFSET) }? as *const u8;

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).kind = kind::EXEC;
        (*e).action = action::ALLOW;
        (*e).pid = pid;
        (*e).ppid = 0;
        (*e).uid = bpf_get_current_uid_gid() as u32;
        (*e).daddr = 0;
        (*e).dport = 0;
        (*e)._pad = 0;
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
        // Read straight into the slot; don't pre-zero (256-byte memset unrolls
        // and blows the verifier budget). Userspace reads only `path_len` bytes.
        let dst = core::slice::from_raw_parts_mut((*e).path.as_mut_ptr(), PATH_LEN);
        (*e).path_len = match bpf_probe_read_user_str_bytes(filename, dst) {
            Ok(bytes) => bytes.len() as u32,
            Err(_) => 0,
        };
    }
    entry.submit(0);
    Ok(())
}

/// Follow the tree: a watched process's child becomes watched.
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
