# Wardyn — Architecture

**Wardyn** watches an AI coding agent's process tree from the Linux kernel using eBPF,
and enforces a policy on what that tree may read, execute, and connect to — in real time,
at the syscall/LSM boundary, *before* the action completes.

> Threat model: you run an autonomous agent (Claude Code, an MCP tool, a CI job) that can
> execute arbitrary code. You want it to build your project — not read `~/.ssh`, exfiltrate
> `.env` to an unknown IP, or spawn a reverse shell. Wardyn is the seatbelt.

## Why the kernel

Userspace sandboxes (seccomp wrappers, LD_PRELOAD, ptrace) are bypassable and race-prone.
An eBPF program attached to a kernel hook sees **every** syscall from the watched tree,
cannot be unloaded by the watched process, and — via LSM / cgroup hooks — can *deny* the
operation by returning an error to the kernel, not after the fact.

## Hook map

| Capability | Observe hook | Enforce hook | Can block? | Notes |
|---|---|---|---|---|
| **exec** | `tracepoint/syscalls/sys_enter_execve` + `sys_enter_execveat` | LSM `bprm_check_security` | ✅ (LSM) | deny returns `-EPERM` to `execve`; both syscall variants observed so a denial can't happen off-feed |
| **file open** (`.env`, `~/.ssh`) | `tracepoint/syscalls/sys_enter_openat` + `sys_enter_openat2` | LSM `file_open` | ✅ (LSM only) | `bpf_override_return` can't deny `openat` — not on the kernel error-injection allowlist, so blocking *requires* BPF LSM |
| **outbound connect** | `tracepoint/syscalls/sys_enter_connect` + `sys_enter_sendto` | `cgroup/connect4·6` + `cgroup/sendmsg4·6` | ✅ (cgroup v2) | cgroup hook denies `connect()`/`sendmsg()` **without** LSM — works even on stock WSL2. `sendmsg`'s msghdr destination is enforce-only (not yet observed) |
| **fork / child tracking** | `tracepoint/sched/sched_process_fork` (+ `sched_process_exit` to evict) | — | — | maintains the watched PID set; pid field offsets read from tracefs at runtime |

> The observe hooks are the `sys_enter_*` variants (not `sched_process_exec`/`kprobe tcp_connect`) so that **every** syscall the enforce hooks can act on is also surfaced to the feed — otherwise the kernel could deny an `openat2`/`execveat`/`sendto` that never showed up in the UI or audit log.

Two independent enforcement paths on purpose:
- **Network blocking → cgroup/connect** (needs only cgroup v2).
- **File & exec blocking → BPF LSM** (needs `CONFIG_BPF_LSM=y` **and** `lsm=...,bpf` on the kernel cmdline).

## Process-tree tracking

Wardyn is scoped to *one* agent invocation, not the whole host:

1. Userspace launches the target: `wardyn run -- claude ...`, capturing the child PID as the **root**.
2. eBPF keeps a `watched: HashMap<pid, ()>` seeded with the root.
3. On `sched_process_fork`, if the parent is watched, the child is added.
4. Every observe/enforce hook first checks `watched.contains(pid)` — unwatched processes are ignored.

This makes Wardyn safe to run on a shared machine: it only constrains the subtree you launched.

Two portability traps live in that seeding, both handled at startup:

- **Pid namespaces.** The hooks key `WATCHED` by *init-namespace* tgid
  (`bpf_get_current_pid_tgid`), while `std::process::id()` is wardyn's pid in
  its *own* namespace — different numbers inside a container or WSL2 distro, so
  a locally-seeded map would watch (and enforce) nothing while claiming to.
  Wardyn learns its kernel-view tgid via a nonce-gated tracepoint handshake on
  `sys_enter_personality`, seeds that, announces the mismatch, and leaves child
  adoption entirely to the in-kernel fork hook (a local child pid could collide
  with an unrelated init-ns tgid). Under a mismatch the feed shows init-ns pids.
- **Fork tracepoint layout.** `sched_process_fork`'s pid offsets moved when the
  kernel made comm dynamic (`__data_loc`, observed on 6.18: parent_pid 24→12,
  child_pid 44→20). Wardyn reads the running kernel's tracefs `format` file and
  passes the offsets to the hook via `CONFIG` instead of hardcoding one
  kernel's numbers.

## Event flow

```
 kernel (eBPF)                         userspace (aya + tokio)
 ┌─────────────────────┐               ┌──────────────────────────┐
 │ tracepoints / LSM   │  RingBuf      │ event reader             │
 │ + cgroup/connect    ├──────────────▶│  → policy engine (match) │
 │  (enforce inline)   │               │  → ratatui TUI (live)    │
 │  ▲ policy verdict   │  PerCpuArray  │  → JSONL audit log       │
 │  └──── shared maps ◀─┼───────────────┤  → denial receipt → agent│
 └─────────────────────┘               │ compiled policy → maps  │
                                       └──────────────────────────┘
```

- **Fast-path decisions live in kernel maps.** Userspace compiles `policy.yaml` into eBPF maps
  (path-hash → action, CIDR trie → action) so the LSM/cgroup hook decides `allow|block`
  inline without a userspace round-trip. `warn` events are streamed up for display only.
- **RingBuf** carries events to userspace for the TUI, the audit log, and the
  agent-facing denial receipt.

## Policy model

See [`policy.yaml`](./policy.yaml). Three rule lists — `files`, `network`, `exec` — each an
ordered list; **first match wins**; `default_action` is the fallback. Actions: `allow | warn | block`.

## Crate layout

```
wardyn-common/   no_std, #[repr(C)] event & verdict structs shared kernel↔user
wardyn-ebpf/     no_std no_main; the eBPF programs (target bpfel-unknown-none)
wardyn/          userspace: loader, RingBuf reader, policy compiler, ratatui TUI, audit log
```
Built with [aya](https://aya-rs.dev) (pure-Rust eBPF — no libbpf/C toolchain). eBPF crate is
compiled by `wardyn`'s `build.rs` via `aya-build`.

## Platform matrix

| Feature | WSL2 (stock) | Ubuntu VM + BPF LSM | Notes |
|---|---|---|---|
| observe (exec/open/connect) | ✅ | ✅ | needs BTF (`/sys/kernel/btf/vmlinux`) |
| network **block** | ✅ | ✅ | cgroup/connect, no LSM needed |
| file / exec **block** | ❌ | ✅ | needs `lsm=...,bpf` in GRUB |

Dev target: **Ubuntu 24.04 VM with BPF LSM enabled** — full observe + full block in one place.

## Enforcement (implemented)

Gated on `WATCHED` membership + `CONFIG[enforce]`, so it only ever touches the
launched subtree, and only under `--enforce`. Because `WATCHED` is seeded only in
`run` mode, `--enforce` requires `wardyn run -- <cmd>`; `--enforce --all` is refused
(system-wide blocking is out of scope, and would otherwise enforce *nothing* while
claiming to).

- **Network** — `cgroup/connect4` looks the destination IPv4 up in the `NET_RULES`
  LPM trie (compiled from `policy.network`) and returns *deny* for a `block` verdict.
  The trie is **longest-prefix-match**, so the userspace feed evaluates network
  rules most-specific-first (not first-match) to report the same verdict the kernel
  enforces — a broad `block` CIDR before a narrow `allow` no longer disagree.
- **File** — LSM `file_open` reads `file->f_path.dentry->d_name` (basename) and its
  parent-dir name at fixed kernel offsets, and returns `-EPERM` if either is in the
  `BLOCK_NAMES` / `BLOCK_DIRS` set. aya-ebpf 0.1 has no `bpf_d_path`/`bpf_loop`, so
  matching is exact basename/dir rather than full-path glob. Offsets:
  `scripts/kernel-offsets.sh`.
- **Exec** — LSM `bprm_check_security` applies the same basename match to
  `linux_binprm->file` against `BLOCK_EXEC`.

**Feed/kernel reconciliation.** The basename/dir reduction is coarser than the glob
a rule was written as (`/etc/shadow` → deny any file named `shadow`; `**/.ssh/**`
→ only the immediate `.ssh` parent, not deep descendants). Rather than let the feed
disagree with the syscall's real outcome, under `--enforce` userspace reproduces the
kernel matcher for each event: a rule that over-blocks is shown (and audited) as an
enforced `BLOCK`, and an enforceable-looking glob the kernel *won't* actually deny is
demoted to `block~`. Rules whose kernel key is broader than their glob are printed as
a warning at startup so the over-reach is explicit, not silent.

## Agent feedback — denial receipts

A denial reaches the watched agent as a bare `EPERM`, indistinguishable from an
ordinary permission error — so agents retry, reach for `sudo`, or work around the
failure. Wardyn can see everything the agent does; the receipt gives the agent a
way to see Wardyn back.

Under `--enforce`, `run` spawns the child with `WARDYN_DENIALS=<path>` in its
environment: a per-run JSONL file (truncated at start, unlike the append-only
audit log) with a self-describing header line written for an LLM reader, then one
record per kernel-denied event, flushed as it happens. The agent matches its
failed operation against the records, learns which rule fired, and can surface
that to its operator instead of flailing.

Trust model: the receipt is *output to* the watched tree, never input. The agent
can read it — or scribble on its copy of the truth — but the enforcement state
lives in kernel maps and root-owned policy it cannot reach. Denials are receipted
from the same reconciled verdict as the feed and audit log (`Desc::denied`), so
the receipt never claims a denial the kernel didn't make. Known gap: UDP
`sendmsg()` destinations are enforce-only (not observed), so those denials can't
be receipted.

## Roadmap

- [x] **M1 — Observe:** exec + openat + connect for the watched tree → live TUI.
- [x] **M2 — Policy/warn:** `policy.yaml` compiled to matchers, violations coloured, JSONL audit.
- [x] **M3 — Block:** network via cgroup/connect + file & exec via LSM.
- [ ] **M4 — Ship:** demo GIF, presets, `--dry-run`, IPv6 egress, CI devcontainer.
- [ ] **M5 — Agent feedback:** denial receipts ✓ (`WARDYN_DENIALS`); next:
  approve-once exceptions from the TUI, persistent overrides kept outside the
  watched tree's reach.
