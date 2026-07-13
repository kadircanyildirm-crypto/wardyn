#!/usr/bin/env bash
# Install the toolchain to build Leash (aya eBPF, pure Rust) on Ubuntu 24.04.
#   ./setup-vm.sh
set -euo pipefail

echo "== apt build deps (LLVM/clang for bpf-linker) =="
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential pkg-config libssl-dev zlib1g-dev git curl \
  clang llvm libclang-dev

echo "== rustup (stable default) =="
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

echo "== nightly + rust-src (eBPF crate is built with -Z build-std) =="
rustup toolchain install nightly --component rust-src

echo "== bpf-linker (links the eBPF object) =="
cargo install bpf-linker

echo
echo "== versions =="
rustc --version
rustc +nightly --version
bpf-linker --version || true
echo "SETUP DONE"
