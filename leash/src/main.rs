// SPDX-License-Identifier: AGPL-3.0-or-later
//! Leash userspace.
//!
//! Usage:
//!   leash [OPTIONS] run -- <cmd> [args...]   watch that command's subtree
//!   leash [OPTIONS] [--all]                  watch system-wide
//!
//! Options:
//!   --enforce          deny blocked file reads / execs / egress (default: observe)
//!   --plain            force the plain line printer (no TUI)
//!   --policy <path>    policy file (default: ./policy.yaml, else embedded)
//!   --audit <path>     JSONL audit log (default: ./leash-audit.jsonl)
//!
//! Renders a live ratatui TUI when stdout is a terminal, else a plain table.
//! Each event is evaluated against the policy (allow/warn/block); violations are
//! coloured and written to the audit log. With `--enforce`, blocked file reads,
//! execs and egress are denied in-kernel for the watched subtree. The feed is
//! honest about it: `BLOCK` = actually denied, `block~` = flagged but the rule
//! can't be kernel-enforced, `block` = observe-only (no --enforce).
mod audit;
mod policy;
mod tui;

use std::io::IsTerminal as _;
use std::net::{Ipv4Addr, Ipv6Addr};
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
use crate::policy::{Action, Policy, Verdict};

/// Userspace mirror of `leash_common::NameKey` (identical C layout) carrying a
/// `Pod` impl so aya can use it as a hash-map key. The `Pod` impl can't live on
/// the leash_common type (orphan rule), hence this local copy.
#[repr(C)]
#[derive(Clone, Copy)]
struct NameKey([u8; NAME_LEN]);
unsafe impl aya::Pod for NameKey {}

/// Userspace mirror of `leash_common::Ip6Key` (16-byte v6 address), `Pod` so aya
/// can use it as the v6 LPM-trie key.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ip6Key([u8; 16]);
unsafe impl aya::Pod for Ip6Key {}

/// AF_INET6, matching the eBPF side.
const AF_INET6: u16 = 10;

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
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("leash {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
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
                policy_path = Some(PathBuf::from(it.next().context("--policy needs a path")?));
            }
            "--audit" => {
                it.next();
                audit_path = PathBuf::from(it.next().context("--audit needs a path")?);
            }
            _ => break,
        }
    }

    let mode = match it.next().as_deref() {
        None => Mode::All,
        Some("--all") | Some("watch") => {
            // Options are only recognised BEFORE the mode; a flag here (e.g.
            // `leash --all --enforce`) would otherwise be silently dropped and
            // the user would get observe-only despite asking to enforce.
            if let Some(extra) = it.next() {
                bail!(
                    "unexpected argument `{extra}` after `--all` — put options such as \
                     --enforce BEFORE the mode: leash --enforce run -- <cmd>"
                );
            }
            Mode::All
        }
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

/// Attach a tracepoint that may be absent on older kernels (e.g. `openat2`,
/// 5.6+): warn and continue instead of aborting, so we don't lose the core
/// observation feed just because one newer syscall variant isn't traceable.
fn load_tracepoint_optional(ebpf: &mut aya::Ebpf, name: &str, category: &str, tp: &str) {
    if let Err(e) = load_tracepoint(ebpf, name, category, tp) {
        eprintln!(
            "leash: warning: could not attach {category}:{tp} ({e:#}) — opens/execs/sends via \
             this syscall variant won't appear in the feed (enforcement is unaffected)."
        );
    }
}

/// The kernel the LSM struct offsets in leash-ebpf were derived for.
const OFFSETS_KERNEL: &str = "6.8";

fn print_usage() {
    println!(
        "leash — a kernel-level leash for AI coding agents\n\n\
         USAGE:\n  \
         leash [OPTIONS] run -- <cmd> [args...]   watch that command's subtree\n  \
         leash [OPTIONS] [--all]                  watch system-wide\n\n\
         OPTIONS:\n  \
         --enforce         deny blocked file reads / execs / egress (default: observe)\n  \
         --plain           force the plain line printer (no TUI)\n  \
         --policy <path>   policy file (default: ./policy.yaml, else embedded)\n  \
         --audit <path>    JSONL audit log (default: ./leash-audit.jsonl)\n  \
         -h, --help        print this help\n  \
         -V, --version     print version"
    );
}

/// Warn (fail-safe) if the running kernel isn't the one the LSM file/exec byte
/// offsets were derived for — a mismatch means those reads may be wrong and
/// file/exec enforcement could silently fail. Network egress is unaffected.
fn warn_if_untested_kernel() {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mm = release
        .trim()
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    if !mm.is_empty() && mm != OFFSETS_KERNEL {
        eprintln!(
            "leash: warning: kernel {} — the LSM file/exec offsets were derived for {}; file/exec \
             enforcement may silently fail on a different kernel (network egress is unaffected). \
             Regenerate with scripts/kernel-offsets.sh.",
            release.trim(),
            OFFSETS_KERNEL
        );
    }
}

/// Load + attach the BPF-LSM file/exec deniers. Kept separate so a kernel without
/// BPF LSM degrades gracefully to network-only enforcement instead of aborting.
fn attach_lsm(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let btf = Btf::from_sys_fs().context("loading kernel BTF")?;
    for (name, hook) in [
        ("file_open", "file_open"),
        ("bprm_check", "bprm_check_security"),
    ] {
        let prog: &mut Lsm = ebpf
            .program_mut(name)
            .with_context(|| format!("{name} program not found"))?
            .try_into()?;
        prog.load(hook, &btf)
            .with_context(|| format!("loading lsm/{hook}"))?;
        prog.attach()
            .with_context(|| format!("attaching lsm/{hook}"))?;
    }
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
    // Enforcement is deliberately scoped to the launched subtree (the kernel
    // deny hooks gate on WATCHED membership, and WATCHED is only ever seeded in
    // `run` mode). Under `--all`/bare invocation WATCHED stays empty, so nothing
    // would actually be denied — refuse rather than claim an enforcement that
    // silently does nothing. (System-wide blocking is out of scope by design.)
    if opts.enforce && matches!(opts.mode, Mode::All) {
        bail!(
            "--enforce requires `run -- <cmd>`: leash only enforces on the subtree it launches, \
             not system-wide. Re-run as: leash --enforce run -- <cmd>"
        );
    }
    // eBPF load/attach needs privilege; fail early with a clear message.
    if unsafe { libc::geteuid() } != 0 {
        bail!("leash must run as root — it loads eBPF programs (try: sudo leash ...)");
    }
    let use_tui = !opts.plain && std::io::stdout().is_terminal();
    if !use_tui {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    let policy = Policy::load(opts.policy_path.as_deref())?;
    info!("policy loaded: {}", policy.summary());
    if opts.enforce {
        warn_if_untested_kernel();
        // Be honest up front: block rules that can't reduce to a kernel-checkable
        // basename/dir are flagged in the feed but never actually denied.
        for pat in policy.observe_only_blocks() {
            eprintln!(
                "leash: warning: policy `{pat}` (block) can't be kernel-enforced \
                 (only basename/dir file rules and CIDRs are) — it will be flagged, not denied"
            );
        }
        // And the converse: a block glob that reduced to a bare name enforces
        // MORE broadly than written, because the LSM hook only sees a basename +
        // its immediate parent dir. Say so, so the over-reach is intentional.
        for (pat, reach) in policy.overbroad_block_keys() {
            eprintln!(
                "leash: warning: policy `{pat}` (block) enforces on {reach} — the kernel matches \
                 by basename/dir only, so it will also deny paths the glob wouldn't."
            );
        }
    }
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
    load_tracepoint(&mut ebpf, "leash_exit", "sched", "sched_process_exit")?;
    // Cover the syscall variants the LSM/cgroup hooks also enforce on, so a
    // denial can't happen off-feed. Optional: absent on older kernels.
    load_tracepoint_optional(&mut ebpf, "leash_openat2", "syscalls", "sys_enter_openat2");
    load_tracepoint_optional(
        &mut ebpf,
        "leash_execveat",
        "syscalls",
        "sys_enter_execveat",
    );
    load_tracepoint_optional(&mut ebpf, "leash_sendto", "syscalls", "sys_enter_sendto");

    // Enforcement (opt-in): attach the cgroup/connect4 denier BEFORE taking any
    // map, so map relocation still finds NET_RULES/CONFIG/WATCHED in the object.
    // Kept in `_cgroup` for the program's lifetime.
    let mut _cgroup = None;
    if opts.enforce {
        let cg = std::fs::File::open("/sys/fs/cgroup")
            .context("open /sys/fs/cgroup (cgroup v2 required for network enforcement)")?;
        for name in ["connect4", "connect6", "sendmsg4", "sendmsg6"] {
            let prog: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .with_context(|| format!("{name} program not found"))?
                .try_into()?;
            prog.load()?;
            prog.attach(&cg, CgroupAttachMode::Single)
                .with_context(|| format!("attaching {name} to the cgroup"))?;
        }
        _cgroup = Some(cg);

        // Files/exec: BPF-LSM deniers. Non-fatal — if the kernel lacks BPF LSM,
        // keep the (already-attached) network enforcement rather than aborting.
        match attach_lsm(&mut ebpf) {
            Ok(()) => info!(
                "enforcement ON — egress (cgroup) + secret-file reads + blocked execs (LSM) denied"
            ),
            Err(e) => eprintln!(
                "leash: warning: BPF LSM enforcement unavailable ({e:#}) — file/exec blocking is \
                 OFF (network egress blocking is still active). Enable it via scripts/enable-bpf-lsm.sh."
            ),
        }
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
        let mut net6: LpmTrie<_, Ip6Key, u32> =
            LpmTrie::try_from(ebpf.take_map("NET_RULES6").context("NET_RULES6")?)?;
        for (plen, data, act) in policy.net_entries6() {
            net6.insert(&Key::new(plen, Ip6Key(data)), act, 0)
                .context("populating NET_RULES6")?;
        }
    }

    {
        let (names, dirs) = policy.file_enforcement();
        let mut bn: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_NAMES").context("BLOCK_NAMES")?)?;
        for k in names {
            bn.insert(NameKey(k), 1u8, 0)
                .context("populating BLOCK_NAMES")?;
        }
        let mut bd: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_DIRS").context("BLOCK_DIRS")?)?;
        for k in dirs {
            bd.insert(NameKey(k), 1u8, 0)
                .context("populating BLOCK_DIRS")?;
        }
        let mut be: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_EXEC").context("BLOCK_EXEC")?)?;
        for k in policy.exec_enforcement() {
            be.insert(NameKey(k), 1u8, 0)
                .context("populating BLOCK_EXEC")?;
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
        // Self was only seeded so the fork hook would adopt the child at spawn
        // time; the child (and its subtree via fork) is tracked in its own right
        // now, so drop leash's own pid — otherwise leash would police itself
        // (its own opens/execs/connects) under --enforce and add noise to the feed.
        let _ = watched.remove(&std::process::id());
        child = Some(spawned);
    } else {
        info!("watching exec/open/connect system-wide; Ctrl-C to stop");
    }

    let result = if use_tui {
        tui::run(
            async_fd,
            child,
            opts.mode.label(),
            &policy,
            &mut audit,
            opts.enforce,
        )
        .await
    } else {
        run_plain(async_fd, child, &policy, &mut audit, opts.enforce).await
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
    enforce: bool,
) -> anyhow::Result<()> {
    println!(
        "{:<7} {:<15} {:<8} {:<6} DETAIL",
        "PID", "COMM", "EVENT", "ACT"
    );
    fn print(d: Desc, enforce: bool) {
        println!(
            "{:<7} {:<15} {:<8} {:<6} {}",
            d.pid,
            d.comm,
            d.label,
            d.act(enforce),
            d.shown()
        );
    }
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            status = wait_for(&mut child), if child.is_some() => {
                info!("target exited ({status})");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                drain(guard.get_inner_mut(), policy, audit, enforce, |d| print(d, enforce));
                guard.clear_ready();
            }
        }
    }
    // The exit/Ctrl-C branch can win the select while events still sit in the
    // ring (e.g. a secret read immediately before the child exits). Sweep once
    // more so those final events are shown and audited, not dropped.
    drain(async_fd.get_mut(), policy, audit, enforce, |d| {
        print(d, enforce)
    });
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
    pub enforceable: bool,
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

    /// ACT column text, honest about enforcement: `BLOCK` = kernel-denied,
    /// `block~` = flagged under --enforce but the rule can't be enforced,
    /// `block` = observe-only.
    pub fn act(&self, enforce: bool) -> &'static str {
        match self.action {
            Action::Allow => "ok",
            Action::Warn => "warn",
            Action::Block if enforce && self.enforceable => "BLOCK",
            Action::Block if enforce => "block~",
            Action::Block => "block",
        }
    }

    /// Whether the kernel actually denied this event.
    pub fn denied(&self, enforce: bool) -> bool {
        self.action == Action::Block && enforce && self.enforceable
    }
}

/// Process every event currently in the ring: audit each violation and hand the
/// decoded [`Desc`] to `sink` for display. Shared by the live loops and their
/// final post-exit sweep. Reads are synchronous — once the child has exited its
/// events are already in the buffer, so a plain `next()` loop drains them.
pub(crate) fn drain(
    ring: &mut RingBuf<MapData>,
    policy: &Policy,
    audit: &mut Audit,
    enforce: bool,
    mut sink: impl FnMut(Desc),
) {
    while let Some(item) = ring.next() {
        if let Some(d) = parse_event(&item)
            .as_ref()
            .and_then(|ev| describe(ev, policy, enforce))
        {
            if d.action != Action::Allow {
                let _ = audit.record(
                    d.pid,
                    &d.comm,
                    d.label,
                    &d.detail,
                    d.action,
                    &d.rule,
                    d.denied(enforce),
                );
            }
            sink(d);
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

pub(crate) fn describe(ev: &Event, policy: &Policy, enforce: bool) -> Option<Desc> {
    let (label, detail, verdict) = match ev.kind {
        kind::EXEC => {
            let d = event_path(ev);
            let v = reconcile(policy.eval_exec(&d), enforce, policy.kernel_exec_denial(&d));
            ("exec", d, v)
        }
        kind::OPEN => {
            let d = event_path(ev);
            let v = reconcile(policy.eval_file(&d), enforce, policy.kernel_file_denial(&d));
            ("open", d, v)
        }
        kind::CONNECT => {
            let (d, v) = if ev.family == AF_INET6 {
                let ip = Ipv6Addr::from(ev.daddr6);
                (format!("[{ip}]:{}", ev.dport), policy.eval_connect6(ip))
            } else {
                let ip = Ipv4Addr::from(ev.daddr.to_ne_bytes());
                (format!("{ip}:{}", ev.dport), policy.eval_connect(ip))
            };
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
        enforceable: verdict.enforceable,
    })
}

/// Reconcile the glob verdict against what the kernel's coarse basename/dir
/// matcher will *actually* do under `--enforce`, so the feed never disagrees
/// with the syscall's real outcome. `kernel_denial` is `Some(key)` when the LSM
/// hook would return `-EPERM` for this exact path.
///
/// Without enforcement the glob verdict stands (observe-only). With it, two
/// divergences are corrected:
///   - glob said allow/warn but the kernel denies (a `block` glob reduced to a
///     bare basename over-blocks, e.g. `/etc/shadow` → any `shadow`): promote
///     to an enforced block so the row isn't a green `ok` for a denied open.
///   - glob said an *enforceable* block but the kernel won't deny this path
///     (e.g. `**/.ssh/**` matches a deep file whose immediate parent isn't
///     `.ssh`): demote to `block~` so we don't claim a `BLOCK` that never fired.
fn reconcile(mut v: Verdict, enforce: bool, kernel_denial: Option<String>) -> Verdict {
    if !enforce {
        return v;
    }
    match kernel_denial {
        Some(key) => {
            if !(v.action == Action::Block && v.enforceable) {
                v = Verdict {
                    action: Action::Block,
                    rule: format!("kernel:{key}"),
                    enforceable: true,
                };
            }
        }
        None => {
            if v.action == Action::Block && v.enforceable {
                v.enforceable = false;
            }
        }
    }
    v
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
