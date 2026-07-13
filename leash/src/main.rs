//! Leash userspace.
//!
//! Modes:
//!   leash run -- <cmd> [args...]   monitor only that command's process subtree
//!   leash            | leash --all watch system-wide
//!   leash --plain ...              force the plain line printer (no TUI)
//!
//! Renders a live ratatui TUI when stdout is a terminal; otherwise falls back to
//! a plain PID/COMM/EVENT/DETAIL table (so piping and CI capture still work).
mod tui;

use std::io::IsTerminal as _;
use std::net::Ipv4Addr;

use anyhow::{bail, Context as _};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use leash_common::{kind, Event, PATH_LEN};
use log::info;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};

pub(crate) enum Mode {
    /// Watch system-wide.
    All,
    /// Launch this argv and watch its subtree.
    Run(Vec<String>),
}

impl Mode {
    fn label(&self) -> String {
        match self {
            Mode::All => "system-wide".to_string(),
            Mode::Run(argv) => argv.join(" "),
        }
    }
}

fn parse_args() -> anyhow::Result<(Mode, bool)> {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    let mut plain = false;
    if argv.first().is_some_and(|s| s == "--plain") {
        plain = true;
        argv.remove(0);
    }
    let mode = match argv.first().map(String::as_str) {
        None | Some("--all") | Some("watch") => Mode::All,
        Some("run") => {
            let mut rest = argv.split_off(1);
            if rest.first().is_some_and(|s| s == "--") {
                rest.remove(0);
            }
            if rest.is_empty() {
                bail!("usage: leash run -- <command> [args...]");
            }
            Mode::Run(rest)
        }
        Some(other) => bail!("unknown argument `{other}`; usage: leash [--plain] [run -- <cmd> | --all]"),
    };
    Ok((mode, plain))
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
pub(crate) async fn wait_for(child: &mut Option<Child>) -> std::process::ExitStatus {
    match child {
        Some(c) => c.wait().await.unwrap_or_else(|_| std::process::exit(1)),
        None => std::future::pending().await,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let (mode, plain) = parse_args()?;
    let use_tui = !plain && std::io::stdout().is_terminal();
    if !use_tui {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/leash"
    )))
    .context("loading eBPF object")?;

    load_tracepoint(&mut ebpf, "leash_execve", "syscalls", "sys_enter_execve")?;
    load_tracepoint(&mut ebpf, "leash_openat", "syscalls", "sys_enter_openat")?;
    load_tracepoint(&mut ebpf, "leash_connect", "syscalls", "sys_enter_connect")?;
    load_tracepoint(&mut ebpf, "leash_fork", "sched", "sched_process_fork")?;

    // watch_all flag: 1 system-wide, 0 scoped.
    let mut config: Array<_, u32> = Array::try_from(ebpf.take_map("CONFIG").context("CONFIG")?)?;
    config.set(0, u32::from(matches!(mode, Mode::All)), 0)?;

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS")?)?;
    let async_fd = AsyncFd::new(ring)?;

    let mut child: Option<Child> = None;
    if let Mode::Run(argv) = &mode {
        let mut watched: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(ebpf.take_map("WATCHED").context("WATCHED")?)?;
        // Seed our own pid BEFORE spawning so the fork hook adopts the child.
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
    } else {
        info!("watching execve/openat/connect system-wide; Ctrl-C to stop");
    }

    if use_tui {
        tui::run(async_fd, child, mode.label()).await
    } else {
        run_plain(async_fd, child).await
    }
}

/// Plain line-printer used when stdout is not a terminal (pipes, CI, `--plain`).
async fn run_plain(
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    mut child: Option<Child>,
) -> anyhow::Result<()> {
    println!("{:<8} {:<16} {:<8} {}", "PID", "COMM", "EVENT", "DETAIL");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            status = wait_for(&mut child), if child.is_some() => {
                info!("target exited ({status})");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    if let Some(d) = parse_event(&item).as_ref().and_then(describe) {
                        println!("{:<8} {:<16} {:<8} {}", d.pid, d.comm, d.label, d.detail);
                    }
                }
                guard.clear_ready();
            }
        }
    }
    Ok(())
}

// ── shared event decoding / display ─────────────────────────────────────────

/// A displayable view of an [`Event`].
pub(crate) struct Desc {
    pub pid: u32,
    pub comm: String,
    pub kind: u32,
    pub label: &'static str,
    pub detail: String,
}

/// Reinterpret ring-buffer bytes as an [`Event`] (bytes aren't guaranteed aligned).
pub(crate) fn parse_event(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < core::mem::size_of::<Event>() {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Event) })
}

pub(crate) fn describe(ev: &Event) -> Option<Desc> {
    let (label, detail) = match ev.kind {
        kind::EXEC => ("exec", event_path(ev)),
        kind::OPEN => ("open", event_path(ev)),
        kind::CONNECT => (
            "connect",
            format!("{}:{}", Ipv4Addr::from(ev.daddr.to_ne_bytes()), ev.dport),
        ),
        _ => return None,
    };
    Some(Desc {
        pid: ev.pid,
        comm: field_str(&ev.comm),
        kind: ev.kind,
        label,
        detail,
    })
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
