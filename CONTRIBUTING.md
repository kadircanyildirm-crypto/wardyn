# Contributing to Leash

Thanks for your interest in Leash! It's an eBPF watchdog for AI coding agents,
written in Rust. Contributions — bug reports, docs, presets, code — are welcome.

By contributing you agree that your work is licensed under the project's
[AGPL-3.0-or-later](./LICENSE) license.

## Ground rules

- Be respectful — see the [Code of Conduct](./CODE_OF_CONDUCT.md).
- Open an issue before a large change so we can agree on the approach.
- Report security issues privately — see [SECURITY.md](./SECURITY.md), not the
  public tracker.

## Development setup

Leash loads eBPF programs, so building and running it needs Linux. On
macOS/Windows, use a Linux VM (see [`scripts/setup-vm.sh`](./scripts/setup-vm.sh)).

Requirements:

- **Rust nightly** + `rust-src` (pinned in [`rust-toolchain.toml`](./rust-toolchain.toml)).
  The eBPF crate is compiled with `-Z build-std=core` for the `bpfel` target.
- **`bpf-linker`** — `cargo install bpf-linker`.
- To *run* enforcement: a kernel with **BTF**, **cgroup v2**, and **BPF LSM**
  (`CONFIG_BPF_LSM=y` + `lsm=...,bpf`; see [`scripts/enable-bpf-lsm.sh`](./scripts/enable-bpf-lsm.sh)).

```bash
./scripts/setup-vm.sh          # toolchain + bpf-linker (one-time)
cargo build                    # builds userspace + the eBPF object (via aya-build)
cargo test                     # policy-engine unit tests (no root needed)
sudo ./target/debug/leash run -- bash    # smoke-test observation
```

## Before you open a PR

CI runs these and they must pass — run them locally first:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build
cargo test
```

Keep the build **warning-free**, including the eBPF crate.

## What to know about the codebase

- `leash/` — userspace: arg parsing, policy loading, map population, ring-buffer
  drain, TUI / plain feed, JSONL audit log.
- `leash-ebpf/` — the eBPF programs (tracepoints for observation; cgroup + LSM
  hooks for enforcement). `#![no_std]`, verifier-constrained — read the comments.
- `leash-common/` — dependency-free types shared across the kernel/user boundary.
- `policy.rs` is the single source of truth for policy semantics and is
  **unit-tested**. If you change how rules resolve, add or update a test there.

**Kernel offsets:** the LSM file/exec matcher reads `dentry` fields at offsets
derived for a specific kernel (currently 6.8). If you build for another kernel,
regenerate them with [`scripts/kernel-offsets.sh`](./scripts/kernel-offsets.sh)
and update the `OFFSETS_KERNEL` constant.

## Commit & PR style

- Small, focused commits with a clear subject line (imperative mood).
- Reference the milestone (M1–M4) or issue where relevant.
- Describe *what changed and why*, and how you tested it (which kernel, enforce
  on/off) — runtime enforcement can't be tested in CI.
