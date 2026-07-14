// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wardyn userspace.
//!
//! Usage:
//!   wardyn [OPTIONS] run -- <cmd> [args...]   watch that command's subtree
//!   wardyn [OPTIONS] [--all]                  watch system-wide
//!
//! Options:
//!   --enforce          deny blocked file reads / execs / egress (default: observe)
//!   --plain            force the plain line printer (no TUI)
//!   --policy <path>    policy file (default: ./policy.yaml, else embedded)
//!   --audit <path>     JSONL audit log (default: ./wardyn-audit.jsonl)
//!   --denials <path>   agent-readable denial receipt (--enforce only;
//!                      default: <tmp>/wardyn-denials-<pid>.jsonl)
//!
//! Renders a live ratatui TUI when stdout is a terminal, else a plain table.
//! Each event is evaluated against the policy (allow/warn/block); violations are
//! coloured and written to the audit log. With `--enforce`, blocked file reads,
//! execs and egress are denied in-kernel for the watched subtree. The feed is
//! honest about it: `BLOCK` = actually denied, `block~` = flagged but the rule
//! can't be kernel-enforced, `block` = observe-only (no --enforce). Under
//! `--enforce` the child is also spawned with `WARDYN_DENIALS=<receipt>` — a
//! JSONL file naming each kernel-denied action — so the agent can learn why an
//! operation failed instead of flailing against a bare EPERM.
mod audit;
mod policy;
mod receipt;
mod tui;

use std::io::IsTerminal as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{bail, Context as _};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm, TracePoint};
use aya::Btf;
use log::info;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};
use wardyn_common::{action, kind, Event, NAME_LEN, PATH_LEN};

use crate::audit::Audit;
use crate::policy::{Action, DenialKey, Exceptions, Policy, Verdict};
use crate::receipt::Receipt;

/// Userspace mirror of `wardyn_common::NameKey` (identical C layout) carrying a
/// `Pod` impl so aya can use it as a hash-map key. The `Pod` impl can't live on
/// the wardyn_common type (orphan rule), hence this local copy.
#[repr(C)]
#[derive(Clone, Copy)]
struct NameKey([u8; NAME_LEN]);
unsafe impl aya::Pod for NameKey {}

/// Userspace mirror of `wardyn_common::Ip6Key` (16-byte v6 address), `Pod` so aya
/// can use it as the v6 LPM-trie key.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ip6Key([u8; 16]);
unsafe impl aya::Pod for Ip6Key {}

/// AF_INET6, matching the eBPF side.
const AF_INET6: u16 = 10;

/// CONFIG slots shared with the eBPF side (pid-ns handshake, fork offsets).
const CFG_HS_NONCE: u32 = 3;
const CFG_HS_TGID: u32 = 4;
const CFG_FORK_PARENT_OFF: u32 = 5;
const CFG_FORK_CHILD_OFF: u32 = 6;

/// The live kernel enforcement maps, held for the whole run (not dropped after
/// population) so the TUI can grant approve-once exceptions while the target
/// is still running: remove a block key, or insert a most-specific allow route.
pub(crate) struct KernelMaps {
    names: BpfHashMap<MapData, NameKey, u8>,
    dirs: BpfHashMap<MapData, NameKey, u8>,
    execs: BpfHashMap<MapData, NameKey, u8>,
    net4: LpmTrie<MapData, u32, u32>,
    net6: LpmTrie<MapData, Ip6Key, u32>,
}

impl KernelMaps {
    /// Take the enforcement maps from the loaded object and compile the policy
    /// into them. Must run AFTER all program attaches (map relocation).
    fn load(ebpf: &mut aya::Ebpf, policy: &Policy) -> anyhow::Result<KernelMaps> {
        let mut net4: LpmTrie<_, u32, u32> =
            LpmTrie::try_from(ebpf.take_map("NET_RULES").context("NET_RULES")?)?;
        for (plen, data, act) in policy.net_entries() {
            net4.insert(&Key::new(plen, data), act, 0)
                .context("populating NET_RULES")?;
        }
        let mut net6: LpmTrie<_, Ip6Key, u32> =
            LpmTrie::try_from(ebpf.take_map("NET_RULES6").context("NET_RULES6")?)?;
        for (plen, data, act) in policy.net_entries6() {
            net6.insert(&Key::new(plen, Ip6Key(data)), act, 0)
                .context("populating NET_RULES6")?;
        }
        let (name_keys, dir_keys) = policy.file_enforcement();
        let mut names: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_NAMES").context("BLOCK_NAMES")?)?;
        for k in name_keys {
            names
                .insert(NameKey(k), 1u8, 0)
                .context("populating BLOCK_NAMES")?;
        }
        let mut dirs: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_DIRS").context("BLOCK_DIRS")?)?;
        for k in dir_keys {
            dirs.insert(NameKey(k), 1u8, 0)
                .context("populating BLOCK_DIRS")?;
        }
        let mut execs: BpfHashMap<_, NameKey, u8> =
            BpfHashMap::try_from(ebpf.take_map("BLOCK_EXEC").context("BLOCK_EXEC")?)?;
        for k in policy.exec_enforcement() {
            execs
                .insert(NameKey(k), 1u8, 0)
                .context("populating BLOCK_EXEC")?;
        }
        Ok(KernelMaps {
            names,
            dirs,
            execs,
            net4,
            net6,
        })
    }

    /// Make the kernel stop denying `key` for the rest of this run. File/exec
    /// exceptions remove the basename/dir from the block map; network
    /// exceptions insert a most-specific allow (/32 or /128) that outranks any
    /// blocking CIDR in the LPM trie.
    pub(crate) fn apply_exception(&mut self, key: &DenialKey) -> anyhow::Result<()> {
        fn drop_name(map: &mut BpfHashMap<MapData, NameKey, u8>, name: &str) -> anyhow::Result<()> {
            let bytes = policy::name_key(name).context("name not kernel-mappable")?;
            map.remove(&NameKey(bytes)).context("removing block key")
        }
        match key {
            DenialKey::FileName(n) => drop_name(&mut self.names, n),
            DenialKey::FileDir(d) => drop_name(&mut self.dirs, d),
            DenialKey::Exec(n) => drop_name(&mut self.execs, n),
            DenialKey::Net4(ip) => self
                .net4
                .insert(
                    &Key::new(32, u32::from_le_bytes(ip.octets())),
                    action::ALLOW,
                    0,
                )
                .context("inserting /32 allow"),
            DenialKey::Net6(ip) => self
                .net6
                .insert(&Key::new(128, Ip6Key(ip.octets())), action::ALLOW, 0)
                .context("inserting /128 allow"),
        }
    }
}

/// Everything the event loops need to evaluate, record, and (from the TUI)
/// grant exceptions — bundled so signatures stay sane.
pub(crate) struct RunCtx<'a> {
    pub policy: &'a Policy,
    pub audit: &'a mut Audit,
    pub receipt: Option<&'a mut Receipt>,
    pub maps: &'a mut KernelMaps,
    pub enforce: bool,
}

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
    denials_path: Option<PathBuf>,
    mode: Mode,
}

fn parse_args() -> anyhow::Result<Opts> {
    let mut it = std::env::args().skip(1).peekable();
    let mut plain = false;
    let mut enforce = false;
    let mut policy_path = None;
    let mut audit_path = PathBuf::from("wardyn-audit.jsonl");
    let mut denials_path = None;

    while let Some(a) = it.peek() {
        match a.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("wardyn {}", env!("CARGO_PKG_VERSION"));
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
            "--denials" => {
                it.next();
                denials_path = Some(PathBuf::from(it.next().context("--denials needs a path")?));
            }
            _ => break,
        }
    }

    let mode = match it.next().as_deref() {
        None => Mode::All,
        Some("--all") | Some("watch") => {
            // Options are only recognised BEFORE the mode; a flag here (e.g.
            // `wardyn --all --enforce`) would otherwise be silently dropped and
            // the user would get observe-only despite asking to enforce.
            if let Some(extra) = it.next() {
                bail!(
                    "unexpected argument `{extra}` after `--all` — put options such as \
                     --enforce BEFORE the mode: wardyn --enforce run -- <cmd>"
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
                bail!("usage: wardyn run -- <command> [args...]");
            }
            Mode::Run(rest)
        }
        Some(other) => {
            bail!("unknown argument `{other}`; usage: wardyn [--plain] [--policy P] [--audit P] [run -- <cmd> | --all]")
        }
    };

    Ok(Opts {
        plain,
        enforce,
        policy_path,
        audit_path,
        denials_path,
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
            "wardyn: warning: could not attach {category}:{tp} ({e:#}) — opens/execs/sends via \
             this syscall variant won't appear in the feed (enforcement is unaffected)."
        );
    }
}

/// The kernel the LSM struct offsets in wardyn-ebpf were derived for.
const OFFSETS_KERNEL: &str = "6.8";

fn print_usage() {
    println!(
        "wardyn — a kernel-level warden for AI coding agents\n\n\
         USAGE:\n  \
         wardyn [OPTIONS] run -- <cmd> [args...]   watch that command's subtree\n  \
         wardyn [OPTIONS] [--all]                  watch system-wide\n\n\
         OPTIONS:\n  \
         --enforce         deny blocked file reads / execs / egress (default: observe)\n  \
         --plain           force the plain line printer (no TUI)\n  \
         --policy <path>   policy file (default: ./policy.yaml, else embedded)\n  \
         --audit <path>    JSONL audit log (default: ./wardyn-audit.jsonl)\n  \
         --denials <path>  agent-readable denial receipt, exported as WARDYN_DENIALS (--enforce only)\n  \
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
            "wardyn: warning: kernel {} — the LSM file/exec offsets were derived for {}; file/exec \
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
            "--enforce requires `run -- <cmd>`: wardyn only enforces on the subtree it launches, \
             not system-wide. Re-run as: wardyn --enforce run -- <cmd>"
        );
    }
    // eBPF load/attach needs privilege; fail early with a clear message.
    if unsafe { libc::geteuid() } != 0 {
        bail!("wardyn must run as root — it loads eBPF programs (try: sudo wardyn ...)");
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
                "wardyn: warning: policy `{pat}` (block) can't be kernel-enforced \
                 (only basename/dir file rules and CIDRs are) — it will be flagged, not denied"
            );
        }
        // And the converse: a block glob that reduced to a bare name enforces
        // MORE broadly than written, because the LSM hook only sees a basename +
        // its immediate parent dir. Say so, so the over-reach is intentional.
        for (pat, reach) in policy.overbroad_block_keys() {
            eprintln!(
                "wardyn: warning: policy `{pat}` (block) enforces on {reach} — the kernel matches \
                 by basename/dir only, so it will also deny paths the glob wouldn't."
            );
        }
    }
    let mut audit = Audit::create(&opts.audit_path)?;

    // Agent-facing denial receipt: only under --enforce (observe mode denies
    // nothing), created before spawn so the child can inherit its path in
    // WARDYN_DENIALS and read back what was denied instead of flailing on a
    // bare EPERM.
    let mut receipt = if opts.enforce {
        let path = opts.denials_path.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("wardyn-denials-{}.jsonl", std::process::id()))
        });
        Some(Receipt::create(
            &path,
            &opts.mode.label(),
            &policy.summary(),
        )?)
    } else {
        if opts.denials_path.is_some() {
            eprintln!(
                "wardyn: warning: --denials has no effect without --enforce \
                 (observe mode denies nothing, so there is nothing to receipt)"
            );
        }
        None
    };

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/wardyn"
    )))
    .context("loading eBPF object")?;

    load_tracepoint(&mut ebpf, "wardyn_execve", "syscalls", "sys_enter_execve")?;
    load_tracepoint(&mut ebpf, "wardyn_openat", "syscalls", "sys_enter_openat")?;
    load_tracepoint(&mut ebpf, "wardyn_connect", "syscalls", "sys_enter_connect")?;
    load_tracepoint(&mut ebpf, "wardyn_fork", "sched", "sched_process_fork")?;
    load_tracepoint(&mut ebpf, "wardyn_exit", "sched", "sched_process_exit")?;
    // Cover the syscall variants the LSM/cgroup hooks also enforce on, so a
    // denial can't happen off-feed. Optional: absent on older kernels.
    load_tracepoint_optional(&mut ebpf, "wardyn_openat2", "syscalls", "sys_enter_openat2");
    load_tracepoint_optional(
        &mut ebpf,
        "wardyn_execveat",
        "syscalls",
        "sys_enter_execveat",
    );
    load_tracepoint_optional(&mut ebpf, "wardyn_sendto", "syscalls", "sys_enter_sendto");
    // Pid-ns handshake (see `learn_init_ns_tgid`). Best-effort: without it
    // wardyn still works wherever it shares the kernel's init pid namespace.
    let handshake_attached = match load_tracepoint(
        &mut ebpf,
        "wardyn_handshake",
        "syscalls",
        "sys_enter_personality",
    ) {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "wardyn: warning: could not attach the pid-ns handshake tracepoint ({e:#}) — if \
                 wardyn runs inside a container or WSL distro, `run` scoping will silently fail"
            );
            false
        }
    };

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
                "wardyn: warning: BPF LSM enforcement unavailable ({e:#}) — file/exec blocking is \
                 OFF (network egress blocking is still active). Enable it via scripts/enable-bpf-lsm.sh."
            ),
        }
    }

    let mut config: Array<_, u32> = Array::try_from(ebpf.take_map("CONFIG").context("CONFIG")?)?;
    config.set(0, u32::from(matches!(opts.mode, Mode::All)), 0)?; // watch_all
    config.set(1, u32::from(opts.enforce), 0)?; // enforce
    config.set(2, policy.default_action_code(), 0)?; // net_default

    // sched_process_fork's pid field offsets moved when the kernel made comm
    // dynamic (`__data_loc`): parent_pid 24→12, child_pid 44→20. Read the
    // running kernel's authoritative layout from tracefs rather than baking in
    // one kernel's numbers — fork adoption (and with it ALL `run` scoping)
    // silently dies when these are wrong.
    let fork_offs = (
        tracefs_field_offset("sched/sched_process_fork", "parent_pid"),
        tracefs_field_offset("sched/sched_process_fork", "child_pid"),
    );
    let (parent_off, child_off) = match fork_offs {
        (Some(p), Some(c)) => (p, c),
        _ => {
            eprintln!(
                "wardyn: warning: could not read the sched_process_fork layout from tracefs — \
                 falling back to kernel-6.8 offsets; child adoption may silently fail"
            );
            (24, 44)
        }
    };
    config.set(CFG_FORK_PARENT_OFF, parent_off, 0)?;
    config.set(CFG_FORK_CHILD_OFF, child_off, 0)?;

    // `run` scoping: WATCHED is keyed by tgid as the KERNEL sees it (init pid
    // namespace); std::process::id() is wardyn's pid in its OWN namespace. On a
    // bare host they coincide, but inside a container or WSL2 distro they never
    // do — seeding WATCHED with the local pid would watch (and enforce) nothing
    // while claiming to. Learn the kernel-view tgid instead, and be loud when
    // the namespaces differ.
    let self_pid = std::process::id();
    let mut seed_tgid = self_pid;
    let mut ns_mismatch = false;
    if matches!(opts.mode, Mode::Run(_)) && handshake_attached {
        match learn_init_ns_tgid(&mut config) {
            Some(tgid) => {
                seed_tgid = tgid;
                ns_mismatch = tgid != self_pid;
                if ns_mismatch {
                    eprintln!(
                        "wardyn: pid namespace detected (self {self_pid}, kernel view {tgid}) — \
                         relying on in-kernel fork adoption; the feed shows init-ns pids"
                    );
                }
            }
            None => eprintln!(
                "wardyn: warning: pid-ns handshake failed — assuming no pid namespace; if wardyn \
                 runs inside a container or WSL distro, `run` scoping will silently fail"
            ),
        }
    }

    // Kept alive for the whole run so the TUI can grant exceptions into them.
    let mut kernel_maps = KernelMaps::load(&mut ebpf, &policy)?;

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS")?)?;
    let async_fd = AsyncFd::new(ring)?;

    let mut child: Option<Child> = None;
    if let Mode::Run(argv) = &opts.mode {
        let mut watched: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(ebpf.take_map("WATCHED").context("WATCHED")?)?;
        watched.insert(seed_tgid, 1u8, 0)?; // seed self so fork adopts child
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        // A denial reaches the agent as a bare EPERM; WARDYN_DENIALS names the
        // receipt explaining it. Env is inherited by the whole subtree.
        if let Some(r) = &receipt {
            cmd.env("WARDYN_DENIALS", r.path());
        }
        let spawned = cmd
            .spawn()
            .with_context(|| format!("spawning `{}`", argv[0]))?;
        if let Some(pid) = spawned.id() {
            // Under a pid namespace the local child pid means nothing to the
            // kernel — worse, it could collide with an unrelated init-ns tgid
            // and watch a stranger. The fork hook already adopted the child
            // (spawn returning means the clone completed); the direct insert
            // is belt-and-braces for the namespace-free case only.
            if !ns_mismatch {
                let _ = watched.insert(pid, 1u8, 0);
            }
            info!("watching `{}` (pid {pid}) and its subtree", argv.join(" "));
        }
        // Self was only seeded so the fork hook would adopt the child at spawn
        // time; the child (and its subtree via fork) is tracked in its own right
        // now, so drop wardyn's own pid — otherwise wardyn would police itself
        // (its own opens/execs/connects) under --enforce and add noise to the feed.
        let _ = watched.remove(&seed_tgid);
        child = Some(spawned);
    } else {
        info!("watching exec/open/connect system-wide; Ctrl-C to stop");
    }

    let mut ctx = RunCtx {
        policy: &policy,
        audit: &mut audit,
        receipt: receipt.as_mut(),
        maps: &mut kernel_maps,
        enforce: opts.enforce,
    };
    let result = if use_tui {
        tui::run(async_fd, child, opts.mode.label(), &mut ctx).await
    } else {
        run_plain(async_fd, child, &mut ctx).await
    };

    eprintln!(
        "wardyn: {} policy violation(s) logged to {}",
        audit.count(),
        audit.path()
    );
    if let Some(r) = &receipt {
        eprintln!(
            "wardyn: {} denial(s) receipted to {} (WARDYN_DENIALS in the agent's env)",
            r.count(),
            r.path()
        );
    }
    result
}

/// Plain line-printer used when stdout is not a terminal (pipes, CI, `--plain`).
/// No interactivity, so no exceptions can be granted here.
async fn run_plain(
    mut async_fd: AsyncFd<RingBuf<MapData>>,
    mut child: Option<Child>,
    ctx: &mut RunCtx<'_>,
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
    let enforce = ctx.enforce;
    let exceptions = Exceptions::default();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            status = wait_for(&mut child), if child.is_some() => {
                info!("target exited ({status})");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                drain(guard.get_inner_mut(), ctx, &exceptions, |d| print(d, enforce));
                guard.clear_ready();
            }
        }
    }
    // The exit/Ctrl-C branch can win the select while events still sit in the
    // ring (e.g. a secret read immediately before the child exits). Sweep once
    // more so those final events are shown and audited, not dropped.
    drain(async_fd.get_mut(), ctx, &exceptions, |d| print(d, enforce));
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
    /// The kernel key this event was denied on, when it was — the unit an
    /// approve-once exception operates at (offered by the TUI on `a`).
    pub denial_key: Option<DenialKey>,
    /// The operator granted an exception covering this event: the kernel
    /// allowed it even though the policy objects (or used to).
    pub excepted: bool,
}

impl Desc {
    /// Detail annotated with the matched rule when it's a violation (or an
    /// exception, where the rule string carries the granted key).
    pub fn shown(&self) -> String {
        if self.action == Action::Allow && !self.excepted {
            self.detail.clone()
        } else {
            format!("{}  [{}]", self.detail, self.rule)
        }
    }

    /// ACT column text, honest about enforcement: `BLOCK` = kernel-denied,
    /// `block~` = flagged under --enforce but the rule can't be enforced,
    /// `block` = observe-only, `excep` = allowed by an operator exception.
    pub fn act(&self, enforce: bool) -> &'static str {
        if self.excepted {
            return "excep";
        }
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

/// Process every event currently in the ring: audit each violation, receipt
/// each actual denial for the agent, and hand the decoded [`Desc`] to `sink`
/// for display. Shared by the live loops and their final post-exit sweep.
/// Reads are synchronous — once the child has exited its events are already in
/// the buffer, so a plain `next()` loop drains them.
pub(crate) fn drain(
    ring: &mut RingBuf<MapData>,
    ctx: &mut RunCtx<'_>,
    exceptions: &Exceptions,
    mut sink: impl FnMut(Desc),
) {
    let enforce = ctx.enforce;
    while let Some(item) = ring.next() {
        if let Some(d) = parse_event(&item)
            .as_ref()
            .and_then(|ev| describe(ev, ctx.policy, enforce, exceptions))
        {
            if d.action != Action::Allow {
                let _ = ctx.audit.record(
                    d.pid,
                    &d.comm,
                    d.label,
                    &d.detail,
                    d.action,
                    &d.rule,
                    d.denied(enforce),
                );
                // The receipt is the agent's view: only what the kernel really
                // denied belongs there — not warns, not unenforced `block~`.
                if d.denied(enforce) {
                    if let Some(r) = ctx.receipt.as_deref_mut() {
                        let _ = r.record(d.pid, &d.comm, d.label, &d.detail, &d.rule);
                    }
                }
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

pub(crate) fn describe(
    ev: &Event,
    policy: &Policy,
    enforce: bool,
    exc: &Exceptions,
) -> Option<Desc> {
    let (label, detail, verdict, denial_key, excepted) = match ev.kind {
        kind::EXEC => {
            let d = event_path(ev);
            let (v, key, ex) = reconcile(
                policy.eval_exec(&d),
                enforce,
                policy.kernel_exec_denial(&d),
                exc,
            );
            ("exec", d, v, key, ex)
        }
        kind::OPEN => {
            let d = event_path(ev);
            let (v, key, ex) = reconcile(
                policy.eval_file(&d),
                enforce,
                policy.kernel_file_denial(&d),
                exc,
            );
            ("open", d, v, key, ex)
        }
        kind::CONNECT => {
            let (d, mut v, ip_key) = if ev.family == AF_INET6 {
                let ip = Ipv6Addr::from(ev.daddr6);
                (
                    format!("[{ip}]:{}", ev.dport),
                    policy.eval_connect6(ip),
                    DenialKey::Net6(ip),
                )
            } else {
                let ip = Ipv4Addr::from(ev.daddr.to_ne_bytes());
                (
                    format!("{ip}:{}", ev.dport),
                    policy.eval_connect(ip),
                    DenialKey::Net4(ip),
                )
            };
            // Network exceptions: the /32 (/128) allow the operator granted
            // outranks the blocking CIDR in the kernel trie — mirror that.
            let mut key = None;
            let mut ex = false;
            if v.action == Action::Block {
                if enforce && exc.contains(&ip_key) {
                    ex = true;
                    v = Verdict {
                        action: Action::Allow,
                        rule: format!("{} → excepted {ip_key}", v.rule),
                        enforceable: true,
                    };
                } else {
                    key = Some(ip_key);
                }
            }
            ("connect", d, v, key, ex)
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
        denial_key,
        excepted,
    })
}

/// Reconcile the glob verdict against what the kernel's coarse basename/dir
/// matcher will *actually* do under `--enforce`, so the feed never disagrees
/// with the syscall's real outcome. `kernel_denial` is `Some(key)` when the LSM
/// hook would deny this exact path — unless the operator granted that key as an
/// exception, in which case the kernel allows it again.
///
/// Returns `(verdict, denial_key, excepted)`: `denial_key` is the key the TUI
/// can offer to except (only when the kernel really denies), `excepted` marks
/// rows covered by an already-granted exception.
///
/// Without enforcement the glob verdict stands (observe-only). With it, the
/// corrected divergences are:
///   - glob said allow/warn but the kernel denies (a `block` glob reduced to a
///     bare basename over-blocks, e.g. `/etc/shadow` → any `shadow`): promote
///     to an enforced block so the row isn't a green `ok` for a denied open.
///   - glob said an *enforceable* block but the kernel won't deny this path
///     (e.g. `**/.ssh/**` matches a deep file whose immediate parent isn't
///     `.ssh`): demote to `block~` so we don't claim a `BLOCK` that never fired.
///   - the key is excepted: same demotion, but marked `excep` with the granted
///     key in the rule, so the override is visible instead of a confusing
///     `block~`.
fn reconcile(
    mut v: Verdict,
    enforce: bool,
    kernel_denial: Option<DenialKey>,
    exc: &Exceptions,
) -> (Verdict, Option<DenialKey>, bool) {
    if !enforce {
        return (v, None, false);
    }
    match kernel_denial {
        Some(key) if exc.contains(&key) => {
            if v.action == Action::Block && v.enforceable {
                v.enforceable = false;
            }
            v.rule = format!("{} → excepted {key}", v.rule);
            (v, None, true)
        }
        Some(key) => {
            if !(v.action == Action::Block && v.enforceable) {
                v = Verdict {
                    action: Action::Block,
                    rule: format!("kernel:{key}"),
                    enforceable: true,
                };
            }
            (v, Some(key), false)
        }
        None => {
            if v.action == Action::Block && v.enforceable {
                v.enforceable = false;
            }
            (v, None, false)
        }
    }
}

/// Byte offset of `field` in a tracefs event format file, e.g.
/// `tracefs_field_offset("sched/sched_process_fork", "parent_pid")`. The format
/// file is the kernel's own declaration of the event layout — the only source
/// that is correct on every kernel.
fn tracefs_field_offset(event: &str, field: &str) -> Option<u32> {
    let text = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .iter()
        .find_map(|root| std::fs::read_to_string(format!("{root}/events/{event}/format")).ok())?;
    parse_format_offset(&text, field)
}

/// The parsing half of [`tracefs_field_offset`], split out for tests. Format
/// lines look like `\tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;`.
fn parse_format_offset(format: &str, field: &str) -> Option<u32> {
    let marker = format!(" {field};");
    for line in format.lines() {
        if line.contains(&marker) {
            for part in line.split(';') {
                if let Some(v) = part.trim().strip_prefix("offset:") {
                    return v.trim().parse().ok();
                }
            }
        }
    }
    None
}

/// Learn wardyn's tgid as the kernel's init pid namespace sees it.
///
/// Publish a random nonce in CONFIG, call `personality(nonce)` (a per-process
/// flag read/set, restored immediately), and let the `sys_enter_personality`
/// tracepoint write the caller's init-ns tgid back through CONFIG. The nonce
/// gates the write so a concurrent personality() call from another process
/// can't elect itself; the window is closed (nonce = 0) before returning.
fn learn_init_ns_tgid(config: &mut Array<MapData, u32>) -> Option<u32> {
    use std::io::Read as _;
    let mut nb = [0u8; 4];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut nb))
        .ok()?;
    let mut nonce = u32::from_ne_bytes(nb);
    if nonce == 0 || nonce == u32::MAX {
        nonce ^= 0x5ad0_1e55; // 0 disables the hook; -1 is personality's query value
    }
    config.set(CFG_HS_NONCE, nonce, 0).ok()?;
    // personality() returns the previous persona; the nonce persona lives only
    // for the instant between these two calls, in this process.
    let old = unsafe { libc::personality(nonce as libc::c_ulong) };
    if old != -1 {
        unsafe { libc::personality(old as libc::c_ulong) };
    }
    let _ = config.set(CFG_HS_NONCE, 0u32, 0);
    // The tracepoint ran synchronously inside the personality() syscall.
    match config.get(&CFG_HS_TGID, 0) {
        Ok(tgid) if tgid != 0 => Some(tgid),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::{parse_format_offset, reconcile};
    use crate::policy::{Action, DenialKey, Exceptions, Verdict};

    fn block(rule: &str, enforceable: bool) -> Verdict {
        Verdict {
            action: Action::Block,
            rule: rule.into(),
            enforceable,
        }
    }

    #[test]
    fn reconcile_offers_key_then_honours_exception() {
        let mut exc = Exceptions::default();
        let key = DenialKey::FileName(".env".into());
        // Pre-grant: enforced BLOCK, key offered for the TUI to except.
        let (v, k, ex) = reconcile(block("**/.env", true), true, Some(key.clone()), &exc);
        assert_eq!(v.action, Action::Block);
        assert!(v.enforceable && !ex);
        assert_eq!(k, Some(key.clone()));
        // Post-grant: kernel no longer denies — never claim a BLOCK; mark the
        // override and stop offering the key.
        exc.grant(key.clone());
        let (v, k, ex) = reconcile(block("**/.env", true), true, Some(key), &exc);
        assert!(ex && !v.enforceable && k.is_none());
        assert!(v.rule.contains("excepted name=.env"));
    }

    #[test]
    fn reconcile_without_enforce_is_passthrough() {
        let exc = Exceptions::default();
        let key = DenialKey::FileName(".env".into());
        let (v, k, ex) = reconcile(block("**/.env", true), false, Some(key), &exc);
        assert_eq!(v.action, Action::Block);
        assert!(v.enforceable, "observe mode leaves the verdict untouched");
        assert!(k.is_none() && !ex);
    }

    /// Old layout (kernel 6.8): inline `char comm[16]` fields.
    const FORK_6_8: &str = "\
\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;";

    /// New layout (observed on 6.18): comm became `__data_loc` (4 bytes), so
    /// every pid field moved. Captured verbatim from a real format file.
    const FORK_6_18: &str = "\
\tfield:__data_loc char[] parent_comm;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:__data_loc char[] child_comm;\toffset:16;\tsize:4;\tsigned:0;
\tfield:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;";

    #[test]
    fn parses_both_fork_layout_generations() {
        assert_eq!(parse_format_offset(FORK_6_8, "parent_pid"), Some(24));
        assert_eq!(parse_format_offset(FORK_6_8, "child_pid"), Some(44));
        assert_eq!(parse_format_offset(FORK_6_18, "parent_pid"), Some(12));
        assert_eq!(parse_format_offset(FORK_6_18, "child_pid"), Some(20));
    }

    #[test]
    fn field_name_must_match_exactly() {
        // `pid` is a suffix of `parent_pid`/`child_pid` and must not match them.
        assert_eq!(parse_format_offset(FORK_6_18, "pid"), None);
        assert_eq!(parse_format_offset(FORK_6_18, "no_such_field"), None);
    }
}
