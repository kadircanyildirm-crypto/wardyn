//! Leash userspace.
//!
//! Usage:
//!   leash [OPTIONS] run -- <cmd> [args...]   watch that command's subtree
//!   leash [OPTIONS] [--all]                  watch system-wide
//!
//! Options:
//!   --plain            force the plain line printer (no TUI)
//!   --policy <path>    policy file (default: ./policy.yaml, else embedded)
//!   --audit <path>     JSONL audit log (default: ./leash-audit.jsonl)
//!
//! Renders a live ratatui TUI when stdout is a terminal, else a plain table.
//! Each event is evaluated against the policy (allow/warn/block); violations are
//! coloured and written to the audit log. M2 is warn-only — nothing is blocked
//! yet (that is M3).
mod audit;
mod policy;
mod tui;

use std::io::IsTerminal as _;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Context as _};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm, TracePoint};
use aya::Btf;
use leash_common::{kind, Event, NAME_LEN, PATH_LEN};
use log::info;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};

use crate::audit::Audit;
use crate::policy::{Action, Policy};

/// Userspace mirror of `leash_common::NameKey` (identical C layout) carrying a
/// `Pod` impl so aya can use it as a hash-map key. The `Pod` impl can't live on
/// the leash_common type (orphan rule), hence this local copy.
#[repr(C)]
#[derive(Clone, Copy)]
struct NameKey([u8; NAME_LEN]);
unsafe impl aya::Pod for NameKey {}

pub(crate) enum Mode {
    All,
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

struct Opts {
    plain: bool,
    enforce: bool,
    policy_path: Option<PathBuf>,
    audit_path: PathBuf,
    mode: Mode,
}

fn parse_args() -> anyhow::Result<Opts> {
    let mut it = std::env::args().skip(1).peekable();
    let mut plain = false;
    let mut enforce = false;
    let mut policy_path = None;
    let mut audit_path = PathBuf::from("leash-audit.jsonl");

    while let Some(a) = it.peek() {
        match a.as_str() {
            "--plain" => {
                plain = true;
                it.next();
            }
            "--enforce" => {
                enforce = true;
                it.next();
            }
            "--policy" => {
                it.next();
                policy_path = Some(PathBuf::from(
                    it.next().context("--policy needs a path")?,
                ));
            }
            "--audit" => {
                it.next();
                audit_path = PathBuf::from(it.next().context("--audit needs a path")?);
            }
            _ => break,
        }
    }

    let mode = match it.next().as_deref() {
        None | Some("--all") | Some("watch") => Mode::All,
        Some("run") => {
            let mut rest: Vec<String> = it.collect();
            if rest.first().is_some_and(|s| s == "--") {
                rest.remove(0);
            }
            if rest.is_empty() {
                bail!("usage: leash run -- <command> [args...]");
            }
            Mode::Run(rest)
        }
        Some(other) => {
            bail!("unknown argument `{other}`; usage: leash [--plain] [--policy P] [--audit P] [run -- <cmd> | --all]")
        }
    };

    Ok(Opts {
        plain,
        enforce,
        policy_path,
        audit_path,
        mode,
    })
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
    let opts = parse_args()?;
    let use_tui = !opts.plain && std::io::stdout().is_terminal();
    if !use_tui {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    let policy = Policy::load(opts.policy_path.as_deref())?;
    info!("policy loaded: {}", policy.summary());
    let mut audit = Audit::create(&opts.audit_path)?;

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/leash"
    )))
    .context("loading eBPF object")?;

    load_tracepoint(&mut ebpf, "leash_execve", "syscalls", "sys_enter_execve")?;
    load_tracepoint(&mut ebpf, "leash_openat", "syscalls", "sys_enter_openat")?;
    load_tracepoint(&mut ebpf, "leash_connect", "syscalls", "sys_enter_connect")?;
    load_tracepoint(&mut ebpf, "leash_fork", "sched", "sched_process_fork")?;

    // Enforcement (opt-in): attach the cgroup/connect4 denier BEFORE taking any
    // map, so map relocation still finds NET_RULES/CONFIG/WATCHED in the object.
    // Kept in `_cgroup` for the program's lifetime.
    let mut _cgroup = None;
    if opts.enforce {
        let prog: &mut CgroupSockAddr = ebpf
            .program_mut("connect4")
            .context("connect4 program not found")?
            .try_into()?;
        prog.load()?;
        let cg = std::fs::File::open("/sys/fs/cgroup")
            .context("open /sys/fs/cgroup (cgroup v2 required for network enforcement)")?;
        prog.attach(&cg, CgroupAttachMode::Single)
            .context("attaching connect4 to the cgroup")?;
        _cgroup = Some(cg);

        // Files: LSM file_open denier (needs kernel BTF to resolve the hook).
        let btf = Btf::from_sys_fs().context("loading kernel BTF")?;
        let lprog: &mut Lsm = ebpf
            .program_mut("file_open")
            .context("file_open program not found")?
            .try_into()?;
        lprog.load("file_open", &btf).context("loading lsm/file_open")?;
        lprog.attach().context("attaching lsm/file_open")?;

        let bprog: &mut Lsm = ebpf
            .program_mut("bprm_check")
            .context("bprm_check program not found")?
            .try_into()?;
        bprog
            .load("bprm_check_security", &btf)
            .context("loading lsm/bprm_check_security")?;
        bprog.attach().context("attaching lsm/bprm_check_security")?;

        info!("enforcement ON — deny blocked egress (cgroup) + secret-file opens + blocked execs (LSM)");
    }

    let mut config: Array<_, u32> = Array::try_from(ebpf.take_map("CONFIG").context("CONFIG")?)?;
    config.set(0, u32::from(matches!(opts.mode, Mode::All)), 0)?; // watch_all
    config.set(1, u32::from(opts.enforce), 0)?; // enforce
    config.set(2, policy.default_action_code(), 0)?; // net_default

    {
        let mut net: LpmTrie<_, u32, u32> =
            LpmTrie::try_from(ebpf.take_map("NET_RULES").context("NET_RULES")?)?;
        for (plen, data, act) in policy.net_entries() {
            net.insert(&Key::new(plen, data), act, 0)
                .context("populating NET_RULES")?;
        }
    }

    {
        let (names, dirs) = policy.file_enforcement();
        let mut bn: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_NAMES").context("BLOCK_NAMES")?)?;
        for k in names {
            bn.insert(NameKey(k), 1u8, 0).context("populating BLOCK_NAMES")?;
        }
        let mut bd: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_DIRS").context("BLOCK_DIRS")?)?;
        for k in dirs {
            bd.insert(NameKey(k), 1u8, 0).context("populating BLOCK_DIRS")?;
        }
        let mut be: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_EXEC").context("BLOCK_EXEC")?)?;
        for k in policy.exec_enforcement() {
            be.insert(NameKey(k), 1u8, 0).context("populating BLOCK_EXEC")?;
        }
    }

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS")?)?;
    let async_fd = AsyncFd::new(ring)?;

    let mut child: Option<Child> = None;
    if let Mode::Run(argv) = &opts.mode {
        let mut watched: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(ebpf.take_map("WATCHED").context("WATCHED")?)?;
        watched.insert(std::process::id(), 1u8, 0)?; // seed self so fork adopts child
        let spawned = Command::new(&argv[0])
            .args(&argv[1..])
            .spawn()
            .with_context(|| format!("spawning `{}`", argv[0]))?;
        if let Some(pid) = spawned.id() {
            let _ = watched.insert(pid, 1u8, 0);
            info!("watching `{}` (pid {pid}) and its subtree", argv.join(" "));
        }
        child = Some(spawned);
    } else {
        info!("watching exec/open/connect system-wide; Ctrl-C to stop");
    }

    let result = if use_tui {
        tui::run(async_fd, child, opts.mode.label(), &policy, &mut audit).await
    } else {
        run_plain(async_fd, child, &policy, &mut audit).await
    };

    eprintln!(
        "leash: {} policy violation(s) logged to {}",
        audit.count(),
        audit.path()
    );
    result
}

/// Plain line-printer used when stdout is not a terminal (pipes, CI, `--plain`).
async fn run_plain(
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    mut child: Option<Child>,
    policy: &Policy,
    audit: &mut Audit,
) -> anyhow::Result<()> {
    println!(
        "{:<7} {:<15} {:<8} {:<6} {}",
        "PID", "COMM", "EVENT", "ACT", "DETAIL"
    );
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
                    if let Some(d) = parse_event(&item).as_ref().and_then(|ev| describe(ev, policy)) {
                        if d.action != Action::Allow {
                            let _ = audit.record(d.pid, &d.comm, d.label, &d.detail, d.action, &d.rule);
                        }
                        let act = match d.action {
                            Action::Allow => "ok",
                            Action::Warn => "WARN",
                            Action::Block => "BLOCK",
                        };
                        println!(
                            "{:<7} {:<15} {:<8} {:<6} {}",
                            d.pid, d.comm, d.label, act, d.shown()
                        );
                    }
                }
                guard.clear_ready();
            }
        }
    }
    Ok(())
}

// ── shared event decoding / display ─────────────────────────────────────────

pub(crate) struct Desc {
    pub pid: u32,
    pub comm: String,
    pub kind: u32,
    pub label: &'static str,
    pub detail: String,
    pub action: Action,
    pub rule: String,
}

impl Desc {
    /// Detail annotated with the matched rule when it's a violation.
    pub fn shown(&self) -> String {
        if self.action == Action::Allow {
            self.detail.clone()
        } else {
            format!("{}  [{}]", self.detail, self.rule)
        }
    }
}

/// Reinterpret ring-buffer bytes as an [`Event`] (bytes aren't guaranteed aligned).
pub(crate) fn parse_event(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < core::mem::size_of::<Event>() {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Event) })
}

pub(crate) fn describe(ev: &Event, policy: &Policy) -> Option<Desc> {
    let (label, detail, verdict) = match ev.kind {
        kind::EXEC => {
            let d = event_path(ev);
            let v = policy.eval_exec(&d);
            ("exec", d, v)
        }
        kind::OPEN => {
            let d = event_path(ev);
            let v = policy.eval_file(&d);
            ("open", d, v)
        }
        kind::CONNECT => {
            let ip = Ipv4Addr::from(ev.daddr.to_ne_bytes());
            let d = format!("{}:{}", ip, ev.dport);
            let v = policy.eval_connect(ip);
            ("connect", d, v)
        }
        _ => return None,
    };
    Some(Desc {
        pid: ev.pid,
        comm: field_str(&ev.comm),
        kind: ev.kind,
        label,
        detail,
        action: verdict.action,
        rule: verdict.rule,
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
