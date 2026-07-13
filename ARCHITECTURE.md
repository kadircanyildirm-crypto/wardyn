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
| **exec** | `tracepoint/sched/sched_process_exec` | LSM `bprm_check_security` | ✅ (LSM) | deny returns `-EPERM` to `execve` |
| **file open** (`.env`, `~/.ssh`) | `tracepoint/syscalls/sys_enter_openat` | LSM `file_open` | ✅ (LSM only) | `bpf_override_return` can't deny `openat` — not on the kernel error-injection allowlist, so blocking *requires* BPF LSM |
| **outbound connect** | `kprobe/tcp_connect` | `cgroup/connect4` + `cgroup/connect6` | ✅ (cgroup v2) | cgroup hook denies `connect()` **without** LSM — works even on stock WSL2 |
| **fork / child tracking** | `tracepoint/sched/sched_process_fork` | — | — | maintains the watched PID set |

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

## Roadmap

- **M1 — Observe:** exec + openat + connect for the watched tree → live TUI. (no enforcement)
- **M2 — Policy/warn:** compile `policy.yaml`, flag violations red in the TUI, JSONL audit log.
- **M3 — Block:** network via cgroup/connect; file+exec via LSM. The demo GIF.
- **M4 — Polish:** README + 30s GIF, `--dry-run`, prebuilt policy presets, CI devcontainer.
