# Contributing to Wardyn

Thanks for your interest in Wardyn! It's an eBPF watchdog for AI coding agents,
written in Rust. Contributions — bug reports, docs, presets, code — are welcome.

By contributing you agree that your work is licensed under the project's
[AGPL-3.0-or-later](./LICENSE) license.

## Ground rules

- Be respectful — see the [Code of Conduct](./CODE_OF_CONDUCT.md).
- Open an issue before a large change so we can agree on the approach.
- Report security issues privately — see [SECURITY.md](./SECURITY.md), not the
  public tracker.

## Development setup

Wardyn loads eBPF programs, so building and running it needs Linux. On
macOS/Windows, use a Linux VM (see [`scripts/setup-vm.sh`](./scripts/setup-vm.sh)).

Requirements:

- **Rust nightly** + `rust-src` (pinned in [`rust-toolchain.toml`](./rust-toolchain.toml)).
  The eBPF crate is compiled with `-Z build-std=core` for the `bpfel` target.
- **`bpf-linker`**, at the version pinned in
  [`BPF_LINKER_VERSION`](./BPF_LINKER_VERSION) — `scripts/setup-vm.sh` installs
  it, or `cargo install bpf-linker --locked --version "$(cat BPF_LINKER_VERSION)"`.
  Pinned for the same reason as the compiler: it emits the bytecode the kernel
  verifies. Bumping it is a deliberate change — re-run `just e2e` afterwards, and
  note that from 0.11 onwards bpf-linker needs a *system* LLVM matching rustc's
  (`rustc -vV` prints the version), not the one bundled with rustc.
- To *run* enforcement: a kernel with **BTF**, **cgroup v2**, and **BPF LSM**
  (`CONFIG_BPF_LSM=y` + `lsm=...,bpf`; see [`scripts/enable-bpf-lsm.sh`](./scripts/enable-bpf-lsm.sh)).

```bash
./scripts/setup-vm.sh          # toolchain + bpf-linker (one-time)
cargo build                    # builds userspace + the eBPF object (via aya-build)
cargo test                     # unit tests (no root needed)
sudo ./target/debug/wardyn run -- bash    # smoke-test observation
```

### Dev container

[`.devcontainer/`](./.devcontainer/) builds the same toolchain in a container, so
"open the repo, run `just build`" works without provisioning a VM. It runs
privileged with seccomp unconfined, because Docker's default profile blocks
`bpf(2)`.

Know what it can and cannot prove: a container shares the **host's** kernel.
Building, unit tests, `--dry-run` and (given cgroup v2) egress enforcement all
work; **file/exec blocking does not**, because BPF LSM is a host boot-time
setting — `lsm=...,bpf` — that nothing inside a container can turn on, and the VM
kernels behind Docker Desktop on macOS/Windows lack it. `post-start.sh` prints
which axes the host supports on every start. For a kernel-side change, the verdict
still comes from `just e2e` on a machine booted with the BPF LSM enabled.
See [`.devcontainer/README.md`](./.devcontainer/README.md).

### Working without a Linux box (or without `bpf-linker`)

The policy engine and CLI live in `wardyn-policy`, deliberately free of
`aya`/`libc`, so the semantics stay testable anywhere:

```bash
just test-portable             # cargo test -p wardyn-policy -p wardyn-common
just check-nolinker            # type-check the userspace crate with no bpf-linker
```

`check-nolinker` sets `WARDYN_SKIP_EBPF_BUILD=1`, which makes `build.rs` emit an
empty placeholder object. The resulting binary refuses to start — it exists to be
type-checked, never shipped.

## Before you open a PR

CI runs these and they must pass — run them locally first (`just lint` does all
of the checks in one go):

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
# the eBPF crate builds for a different target, so a plain clippy never sees it
cargo clippy --locked -p wardyn-ebpf --target bpfel-unknown-none -Zbuild-std=core -- -D warnings
shellcheck scripts/*.sh tests/e2e/run.sh .devcontainer/*.sh
cargo build --locked
cargo test --locked
```

Keep the build **warning-free**, including the eBPF crate.

Changing anything the kernel programs do? CI compiles the eBPF object but cannot
load it (GitHub runners have no BPF LSM). Run `just e2e` on a kernel booted with
`lsm=...,bpf` and say so in the PR — the verifier is the only thing that can
confirm a hook is acceptable, and a rejected program takes the whole tool down.

## What to know about the codebase

- `wardyn/` — userspace: map population, ring-buffer drain, TUI / plain feed,
  JSONL audit log, denial receipt. Linux-only (aya + libc).
- `wardyn-ebpf/` — the eBPF programs (tracepoints for observation; cgroup + LSM
  hooks for enforcement). `#![no_std]`, verifier-constrained — read the comments.
- `wardyn-common/` — dependency-free types shared across the kernel/user boundary.
- `wardyn-policy/` — the policy engine and CLI parsing. Pure logic, no OS
  dependencies, and the **single source of truth for policy semantics**. If you
  change how rules resolve, add or update a test there.

Two invariants worth stating outright, because breaking either turns wardyn into
a tool that lies:

- **The userspace mirror must match the kernel matcher.** `kernel_file_denial`
  reproduces what the LSM hook does (basename, then ancestor directories bounded
  by `MAX_DIR_WALK`). Change one side and you must change the other, or the feed
  will show `ok` for a denied open.
- **Never claim a denial that wasn't made.** A prediction is displayed; only a
  `DENY_*` event from the deciding hook proves anything. If you add an
  enforcement path, make it report itself and bump its `STATS` counter.

**Kernel offsets:** the LSM file/exec matcher reads `dentry` fields at offsets
derived for a specific kernel (currently 6.8). If you build for another kernel,
regenerate them with [`scripts/kernel-offsets.sh`](./scripts/kernel-offsets.sh)
and update the `OFFSETS_KERNEL` constant.

## Commit & PR style

- Small, focused commits with a clear subject line (imperative mood).
- Reference the milestone (M1–M4) or issue where relevant.
- Describe *what changed and why*, and how you tested it (which kernel, enforce
  on/off) — runtime enforcement can't be tested in CI.
