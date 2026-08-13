# Wardyn development container.
#
# Mirrors scripts/setup-vm.sh (Ubuntu 24.04 + LLVM + pinned nightly + bpf-linker)
# so `cargo build`, `just lint` and `just test` behave the same here as in a VM.
#
# What this container can and cannot do is a property of the HOST kernel, not of
# this image — see .devcontainer/README.md. Short version: it always *builds*,
# it enforces egress when the host has cgroup v2, and it can only enforce
# file/exec reads when the host kernel was booted with `lsm=...,bpf`.
FROM ubuntu:24.04

# LLVM/clang is bpf-linker's backend. `just` and `shellcheck` are what the
# justfile and CI invoke; iproute2/procps make the container debuggable.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev zlib1g-dev \
      clang llvm libclang-dev \
      ca-certificates curl git sudo \
      just shellcheck \
      iproute2 procps \
 && rm -rf /var/lib/apt/lists/*

# Ubuntu 24.04 ships a uid-1000 `ubuntu` user. Wardyn runs as root and drops the
# watched agent to $SUDO_UID, so developing as a non-root user with sudo is not a
# convention here — it is the code path the tool actually takes.
RUN echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ubuntu \
 && chmod 0440 /etc/sudoers.d/ubuntu

USER ubuntu
ENV HOME=/home/ubuntu
ENV PATH=/home/ubuntu/.cargo/bin:$PATH

# `--default-toolchain none` so rustup installs nothing yet: the toolchain that
# matters is the one pinned in rust-toolchain.toml, and `rustup show` inside a
# directory holding that file installs exactly it (plus its rust-src component).
# Copying the file instead of repeating the nightly date keeps one source of
# truth — a container built from a different compiler than CI would emit
# different BPF bytecode, which is the thing rust-toolchain.toml exists to stop.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --no-modify-path --default-toolchain none
COPY --chown=ubuntu:ubuntu rust-toolchain.toml /tmp/toolchain/
RUN cd /tmp/toolchain && rustup show && rm -rf /tmp/toolchain

# Links the eBPF object — pinned by the same argument as the compiler, and
# copied in rather than repeated for the same reason as rust-toolchain.toml.
COPY --chown=ubuntu:ubuntu BPF_LINKER_VERSION /tmp/
RUN cargo install bpf-linker --locked --version "$(cat /tmp/BPF_LINKER_VERSION)" \
 && rm -f /tmp/BPF_LINKER_VERSION

# `bpfel-unknown-none` needs no rustup target: build.rs builds it with
# -Z build-std=core, which is why rust-src is pinned as a component above.
RUN rustc --version && cargo --version && bpf-linker --version
