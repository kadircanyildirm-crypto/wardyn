# 🐕 Leash

**A kernel-level leash for AI coding agents.** Leash watches an agent's process tree with
eBPF and enforces — in real time, at the syscall boundary — what it may read, run, and
connect to. It catches the agent reading your `.env` or dialing an unknown IP, and can
*block* it before the operation completes.

> ⚠️ **Status: early development.** M1–M3 done: observe + policy + **kernel-level
> enforcement** — blocks secret-file reads (LSM `file_open`) and blocked egress
> (cgroup `connect4`), scoped to the watched subtree and opt-in via `--enforce`.
> M4 (README polish + demo GIF) next. See [Roadmap](#roadmap) — not production-ready yet.

```
$ leash run -- claude "refactor the auth module"

  PID 20481  claude
  ├─ open   /home/me/project/src/auth.rs         allow
  ├─ open   /home/me/.ssh/id_ed25519              ⛔ BLOCK  (files: **/.ssh/**)
  ├─ exec   /usr/bin/curl                         ⚠  warn
  └─ connect 185.220.101.7:443                     ⛔ BLOCK  (network: default deny)
```

## Why

You hand an autonomous agent a shell. It should build your project — not exfiltrate secrets
or open a reverse shell. Userspace guards (seccomp wrappers, `LD_PRELOAD`, ptrace) are
bypassable. Leash runs in the kernel: the watched process cannot see it, cannot unload it,
and Leash can deny the syscall itself.

## How

- **eBPF** (via [aya](https://aya-rs.dev), pure Rust — no C toolchain) attached to
  tracepoints, BPF-LSM, and cgroup hooks.
- Scoped to the process subtree you launch — safe on a shared machine.
- Policy is a simple [`policy.yaml`](./policy.yaml): ordered `allow | warn | block` rules for
  files, network, and exec.

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** for the hook map and enforcement design.

## Requirements

- Linux with BTF (`/sys/kernel/btf/vmlinux`).
- For **network** blocking: cgroup v2 (stock kernels, incl. WSL2).
- For **file/exec** blocking: BPF LSM — `CONFIG_BPF_LSM=y` and `lsm=...,bpf` on the kernel
  cmdline (Ubuntu ships the config; add the cmdline). macOS/Windows: use a Linux VM.

## Roadmap

- [x] **M1 — Observe:** live tree of exec/open/connect events, scoped to a subtree.
- [x] **M2 — Policy:** `policy.yaml` (glob + CIDR), allow/warn/block verdicts, JSONL audit log.
- [x] **M3 — Block:** deny blocked egress (cgroup `connect4`) + secret-file reads
      (LSM `file_open`); scoped to the subtree, opt-in via `--enforce`.
- [ ] **M4 — Ship:** demo GIF, presets, devcontainer, exec blocking (LSM `bprm_check`).

## License

MIT OR Apache-2.0
