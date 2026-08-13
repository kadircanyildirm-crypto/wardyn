# Wardyn task runner. Install `just`: https://github.com/casey/just
# Run `just` with no args to list recipes.
set shell := ["bash", "-uc"]

_default:
    @just --list

# Build userspace + eBPF (release).
build:
    cargo build --locked --release

# Observe an agent's subtree — no blocking.
run *args:
    sudo ./target/release/wardyn run -- {{ args }}

# Enforce the policy on an agent's subtree (blocks violations).
enforce *args:
    sudo ./target/release/wardyn --enforce run -- {{ args }}

# Run the bundled demo (a clean allow / warn / block mix).
demo:
    sudo ./target/release/wardyn --enforce run -- bash scripts/demo.sh

# What will this policy ACTUALLY do in the kernel? No root, no eBPF, no target.
check-policy policy="policy.yaml":
    cargo run --locked -q -- --dry-run --policy {{ policy }}

# All tests (needs the eBPF toolchain, because the wardyn crate embeds the object).
test:
    cargo test --locked

# Policy-engine + CLI tests only. Pure logic, no eBPF toolchain, no Linux — this
# is the one that runs on a macOS or Windows laptop.
test-portable:
    cargo test --locked -p wardyn-policy -p wardyn-common

# End-to-end enforcement test: load the real eBPF and assert blocks/allows.
# Needs root + a release build (`just build`). BPF-LSM optional (file assertions
# self-skip without it).
e2e:
    sudo bash tests/e2e/run.sh ./target/release/wardyn

# What CI checks: formatting + clippy over EVERY crate, including the eBPF one
# (which a plain `cargo clippy` never sees — it builds for a different target).
lint:
    cargo fmt --all --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo clippy --locked -p wardyn-ebpf --target bpfel-unknown-none -Zbuild-std=core -- -D warnings
    shellcheck scripts/*.sh tests/e2e/run.sh

# Type-check the userspace crate WITHOUT bpf-linker (macOS/Windows laptops).
# The resulting artifacts cannot run — see wardyn/build.rs.
check-nolinker:
    WARDYN_SKIP_EBPF_BUILD=1 cargo clippy --locked -p wardyn --all-targets -- -D warnings

# One-time: install the build toolchain (rustup nightly + bpf-linker).
setup:
    ./scripts/setup-vm.sh

# One-time: enable the BPF LSM (needs a reboot afterwards).
enable-lsm:
    sudo ./scripts/enable-bpf-lsm.sh
