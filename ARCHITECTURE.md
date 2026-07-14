# Leash — Architecture

**Leash** watches an AI coding agent's process tree from the Linux kernel using eBPF,
and enforces a policy on what that tree may read, execute, and connect to — in real time,
at the syscall/LSM boundary, *before* the action completes.

> Threat model: you run an autonomous agent (Claude Code, an MCP tool, a CI job) that can
> execute arbitrary code. You want it to build your project — not read `~/.ssh`, exfiltrate
> `.env` to an unknown IP, or spawn a reverse shell. Leash is the seatbelt.

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
| **fork / child tracking** | `tracepoint/sched/sched_process_fork` (+ `sched_process_exit` to evict) | — | — | maintains the watched PID set |

> The observe hooks are the `sys_enter_*` variants (not `sched_process_exec`/`kprobe tcp_connect`) so that **every** syscall the enforce hooks can act on is also surfaced to the feed — otherwise the kernel could deny an `openat2`/`execveat`/`sendto` that never showed up in the UI or audit log.

Two independent enforcement paths on purpose:
- **Network blocking → cgroup/connect** (needs only cgroup v2).
- **File & exec blocking → BPF LSM** (needs `CONFIG_BPF_LSM=y` **and** `lsm=...,bpf` on the kernel cmdline).

## Process-tree tracking

Leash is scoped to *one* agent invocation, not the whole host:

1. Userspace launches the target: `leash run -- claude ...`, capturing the child PID as the **root**.
2. eBPF keeps a `watched: HashMap<pid, ()>` seeded with the root.
3. On `sched_process_fork`, if the parent is watched, the child is added.
4. Every observe/enforce hook first checks `watched.contains(pid)` — unwatched processes are ignored.

This makes Leash safe to run on a shared machine: it only constrains the subtree you launched.

## Event flow

```
 kernel (eBPF)                         userspace (aya + tokio)
 ┌─────────────────────┐               ┌──────────────────────────┐
 │ tracepoints / LSM   │  RingBuf      │ event reader             │
 │ + cgroup/connect    ├──────────────▶│  → policy engine (match) │
 │  (enforce inline)   │               │  → ratatui TUI (live)    │
 │  ▲ policy verdict   │  PerCpuArray  │  → JSONL audit log       │
 │  └──── shared maps ◀─┼───────────────┤ compiled policy → maps  │
 └─────────────────────┘               └──────────────────────────┘
```

- **Fast-path decisions live in kernel maps.** Userspace compiles `policy.yaml` into eBPF maps
  (path-hash → action, CIDR trie → action) so the LSM/cgroup hook decides `allow|block`
  inline without a userspace round-trip. `warn` events are streamed up for display only.
- **RingBuf** carries events to userspace for the TUI + audit log.

## Policy model

See [`policy.yaml`](./policy.yaml). Three rule lists — `files`, `network`, `exec` — each an
ordered list; **first match wins**; `default_action` is the fallback. Actions: `allow | warn | block`.

## Crate layout

```
leash-common/   no_std, #[repr(C)] event & verdict structs shared kernel↔user
leash-ebpf/     no_std no_main; the eBPF programs (target bpfel-unknown-none)
leash/          userspace: loader, RingBuf reader, policy compiler, ratatui TUI, audit log
```
Built with [aya](https://aya-rs.dev) (pure-Rust eBPF — no libbpf/C toolchain). eBPF crate is
compiled by `leash`'s `build.rs` via `aya-build`.

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
`run` mode, `--enforce` requires `leash run -- <cmd>`; `--enforce --all` is refused
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

## Roadmap

- [x] **M1 — Observe:** exec + openat + connect for the watched tree → live TUI.
- [x] **M2 — Policy/warn:** `policy.yaml` compiled to matchers, violations coloured, JSONL audit.
- [x] **M3 — Block:** network via cgroup/connect + file & exec via LSM.
- [ ] **M4 — Ship:** demo GIF, presets, `--dry-run`, IPv6 egress, CI devcontainer.
