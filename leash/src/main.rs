//! Leash userspace. M1a: load the eBPF object, attach the execve tracepoint, and
//! stream its log lines to the terminal. Ctrl-C to stop.
use anyhow::Context as _;
use aya::programs::TracePoint;
use aya_log::EbpfLogger;
use log::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // The eBPF bytecode is baked in at build time by build.rs (aya-build).
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/leash"
    )))
    .context("loading eBPF object")?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        // Non-fatal: we just won't see the in-kernel log lines.
        warn!("failed to init eBPF logger: {e}");
    }

    let prog: &mut TracePoint = ebpf
        .program_mut("leash_execve")
        .context("program `leash_execve` not found")?
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")
        .context("attaching to syscalls:sys_enter_execve")?;

    info!("leash M1a running — watching execve (Ctrl-C to stop)");
    tokio::signal::ctrl_c().await?;
    info!("detaching, bye");
    Ok(())
}
