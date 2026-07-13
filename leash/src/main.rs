//! Leash userspace.
//!
//! Modes:
//!   leash run -- <cmd> [args...]   monitor only that command's process subtree
//!   leash            | leash --all watch execve system-wide
//!
//! Scoped mode is race-free: we seed WATCHED with our *own* pid before spawning,
//! so the in-kernel `sched_process_fork` hook adopts the child the instant it is
//! forked — no userspace window where the child could exec unwatched.
use std::net::Ipv4Addr;

use anyhow::{bail, Context as _};
use aya::maps::{Array, HashMap as BpfHashMap, RingBuf};
use aya::programs::TracePoint;
use leash_common::{kind, Event, PATH_LEN};
use log::info;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};

enum Mode {
    /// Watch execve across the whole system.
    All,
    /// Launch this argv and watch its subtree.
    Run(Vec<String>),
}

fn parse_args() -> anyhow::Result<Mode> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("--all") | Some("watch") => Ok(Mode::All),
        Some("run") => {
            let mut rest: Vec<String> = args.collect();
            if rest.first().is_some_and(|s| s == "--") {
                rest.remove(0);
            }
            if rest.is_empty() {
                bail!("usage: leash run -- <command> [args...]");
            }
            Ok(Mode::Run(rest))
        }
        Some(other) => bail!("unknown argument `{other}`; usage: leash [run -- <cmd> | --all]"),
    }
}

fn load_tracepoint(
    ebpf: &mut aya::Ebpf,
    name: &str,
    category: &str,
    tp: &str,
) -> anyhow::Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` not found"))?
        .try_into()?;
    prog.load()?;
    prog.attach(category, tp)
        .with_context(|| format!("attaching {category}:{tp}"))?;
    Ok(())
}

/// Await the child's exit if there is one; otherwise never resolve.
async fn wait_for(child: &mut Option<Child>) -> std::process::ExitStatus {
    match child {
        Some(c) => c.wait().await.unwrap_or_else(|_| std::process::exit(1)),
        None => std::future::pending().await,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let mode = parse_args()?;

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/leash"
    )))
    .context("loading eBPF object")?;

    load_tracepoint(&mut ebpf, "leash_execve", "syscalls", "sys_enter_execve")?;
    load_tracepoint(&mut ebpf, "leash_openat", "syscalls", "sys_enter_openat")?;
    load_tracepoint(&mut ebpf, "leash_connect", "syscalls", "sys_enter_connect")?;
    load_tracepoint(&mut ebpf, "leash_fork", "sched", "sched_process_fork")?;

    // watch_all flag: 1 for system-wide, 0 for scoped.
    let mut config: Array<_, u32> = Array::try_from(ebpf.take_map("CONFIG").context("CONFIG")?)?;
    config.set(0, u32::from(matches!(mode, Mode::All)), 0)?;

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS")?)?;
    let mut async_fd = AsyncFd::new(ring)?;

    let mut child: Option<Child> = None;
    match &mode {
        Mode::All => info!("watching execve system-wide; Ctrl-C to stop"),
        Mode::Run(argv) => {
            let mut watched: BpfHashMap<_, u32, u8> =
                BpfHashMap::try_from(ebpf.take_map("WATCHED").context("WATCHED")?)?;
            // Seed our own pid BEFORE spawning, so the fork hook adopts the child.
            watched.insert(std::process::id(), 1u8, 0)?;

            let spawned = Command::new(&argv[0])
                .args(&argv[1..])
                .spawn()
                .with_context(|| format!("spawning `{}`", argv[0]))?;
            if let Some(pid) = spawned.id() {
                let _ = watched.insert(pid, 1u8, 0); // belt & suspenders
                info!("watching `{}` (pid {pid}) and its subtree", argv.join(" "));
            }
            child = Some(spawned);
        }
    }

    println!("{:<8} {:<16} {:<8} {}", "PID", "COMM", "EVENT", "DETAIL");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("interrupted");
                break;
            }
            status = wait_for(&mut child), if child.is_some() => {
                info!("target exited ({status})");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() >= core::mem::size_of::<Event>() {
                        // Ring-buffer bytes aren't guaranteed aligned for Event.
                        let ev = unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Event) };
                        print_event(&ev);
                    }
                }
                guard.clear_ready();
            }
        }
    }
    Ok(())
}

/// NUL-terminated byte field -> lossy UTF-8 string.
fn field_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn event_path(ev: &Event) -> String {
    let len = (ev.path_len as usize).min(PATH_LEN);
    field_str(&ev.path[..len])
}

fn print_event(ev: &Event) {
    let comm = field_str(&ev.comm);
    let (kind_str, detail) = match ev.kind {
        kind::EXEC => ("exec", event_path(ev)),
        kind::OPEN => ("open", event_path(ev)),
        kind::CONNECT => (
            "connect",
            format!("{}:{}", Ipv4Addr::from(ev.daddr.to_ne_bytes()), ev.dport),
        ),
        _ => return,
    };
    println!("{:<8} {:<16} {:<8} {}", ev.pid, comm, kind_str, detail);
}
