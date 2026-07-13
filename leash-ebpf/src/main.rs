//! Leash eBPF programs. M1a: a single tracepoint on `sys_enter_execve` that logs
//! the PID of every exec — just enough to prove the load/attach/BTF pipeline
//! end-to-end. The ring-buffer + process-tree filtering come in M1b.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn leash_execve(ctx: TracePointContext) -> u32 {
    // upper 32 bits of pid_tgid = tgid (the userspace "PID")
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(&ctx, "execve pid={}", pid);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
