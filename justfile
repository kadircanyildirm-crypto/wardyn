# Wardyn task runner. Install `just`: https://github.com/casey/just
# Run `just` with no args to list recipes.
set shell := ["bash", "-uc"]

_default:
    @just --list

# Build userspace + eBPF (release).
build:
    cargo build --release

# Observe an agent's subtree — no blocking.
run *args:
    sudo ./target/release/wardyn run -- {{ args }}

# Enforce the policy on an agent's subtree (blocks violations).
enforce *args:
    sudo ./target/release/wardyn --enforce run -- {{ args }}

# Run the bundled demo (a clean allow / warn / block mix).
demo:
    sudo ./target/release/wardyn --enforce run -- bash scripts/demo.sh

# Policy unit tests.
test:
    cargo test

# What CI checks: formatting + clippy (deny warnings).
lint:
    cargo fmt --all --check
    cargo clippy -- -D warnings

# One-time: install the build toolchain (rustup nightly + bpf-linker).
setup:
    ./scripts/setup-vm.sh

# One-time: enable the BPF LSM (needs a reboot afterwards).
enable-lsm:
    sudo ./scripts/enable-bpf-lsm.sh
