#!/usr/bin/env bash
# Install the toolchain to build Wardyn (aya eBPF, pure Rust) on Ubuntu 24.04.
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

echo "== pinned nightly + rust-src (eBPF crate is built with -Z build-std) =="
# Install the toolchain rust-toolchain.toml pins, not a floating `nightly`:
# `rustup show` inside the repo reads that file and materialises exactly it,
# with its rust-src component. Installing plain `nightly` here would download a
# second toolchain that nothing then builds with — the BPF bytecode is a
# function of the compiler, which is why the version is pinned at all.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
(cd "$REPO_ROOT" && rustup show)

echo "== bpf-linker (links the eBPF object) =="
# Pinned in BPF_LINKER_VERSION and installed --locked, for the same reason the
# nightly is pinned: this is the tool that emits the bytecode the kernel
# verifies. It is also a moving target — 0.11 swapped rustc's bundled LLVM for a
# system one, so an unpinned install fails outright on a machine without a
# matching llvm-config.
cargo install bpf-linker --locked --version "$(cat "$REPO_ROOT/BPF_LINKER_VERSION")"

echo
echo "== versions =="
# From the repo root, so this reports the pinned toolchain that will actually
# build wardyn — not whatever rustup's global default happens to be.
(cd "$REPO_ROOT" && rustc --version && cargo --version)
bpf-linker --version || true
echo "SETUP DONE"
