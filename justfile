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

# Put EVERY eBPF program in front of the kernel verifier — load only, never
# attach, so it covers the LSM hooks even on a kernel that cannot attach them.
# Needs root and jq. This is the cheap check; `just e2e` is the honest one.
verify-programs:
    bin="$(cargo test --locked --release --test verifier_smoke --no-run --message-format=json | jq -r 'select(.executable != null and .target.name == "verifier_smoke") | .executable')"; sudo "$bin" --nocapture

# What does wardyn cost? Startup, and marginal per-event, on this kernel.
# Needs root (loads eBPF) and a release build. See docs/PERFORMANCE.md.
bench reps="5":
    sudo bash scripts/bench.sh {{ reps }}

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
    shellcheck scripts/*.sh tests/e2e/run.sh .devcontainer/*.sh

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

# Is this kernel actually able to enforce the file/exec axis? A `no` here means
# `just e2e` will SKIP every LSM assertion — which reads as success and is not.
check-lsm:
    @echo "kernel:  $(uname -r)"
    @echo "BTF:     $([ -e /sys/kernel/btf/vmlinux ] && echo present || echo MISSING)"
    @echo "cgroup2: $(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)"
    @if [ ! -e /sys/kernel/security/lsm ]; then \
        echo "LSMs:    securityfs not mounted — try: sudo mount -t securityfs securityfs /sys/kernel/security"; \
     else \
        echo "LSMs:    $(cat /sys/kernel/security/lsm)"; \
     fi
    @if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then \
        echo "BPF-LSM: ACTIVE — file/exec enforcement is testable here"; \
     else \
        echo "BPF-LSM: NOT ACTIVE — file/exec assertions will skip (see docs/WSL2.md or scripts/enable-bpf-lsm.sh)"; \
     fi

# Fuzz the policy parser. The one input an attacker may control: the default
# policy path is `./policy.yaml`, which lands in the directory the watched agent
# works in — so on the next run wardyn parses attacker-chosen bytes, as root.
#
# Needs `cargo install cargo-fuzz` and a nightly toolchain. `just fuzz 300`
# for a five-minute run; the default is short enough to sit in a pre-push check.
fuzz seconds="60":
    cargo fuzz run policy_parse -- -max_total_time={{seconds}} -max_len=4096

# Re-run every input that has ever crashed the fuzzer. Fast, and the thing that
# actually belongs in CI — a corpus regression, not a fresh hunt.
fuzz-regress:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d fuzz/artifacts/policy_parse ] || [ -z "$(ls -A fuzz/artifacts/policy_parse 2>/dev/null)" ]; then
        echo "no crash artifacts — nothing to regress"
        exit 0
    fi
    cargo fuzz run policy_parse fuzz/artifacts/policy_parse/*

# The stress suite: four scenarios that try to break wardyn rather than
# demonstrate it. `just stress` runs all four; `just stress 01-escape` runs one.
# See docs/stress/README.md for what each one proves.
#
# The default is a glob rather than a conditional, so there is no branch here to
# get wrong — `just stress` expands to `0*`, a name expands to itself.
stress name="0*":
    #!/usr/bin/env bash
    set -uo pipefail
    bash scripts/stress/setup.sh
    shopt -s nullglob
    found=0
    for s in scripts/stress/{{name}}.sh; do
        found=1
        printf '\n\033[1m=== %s ===\033[0m\n' "$(basename "$s" .sh)"
        # WARDYN_AUDIT is handed to the AGENT, not to sudo: a NOPASSWD rule names
        # the wardyn binary, and `sudo VAR=x /path/wardyn` does not match it.
        sudo ./target/release/wardyn --plain --enforce \
            --policy scripts/stress/policy.yaml --audit /tmp/wardyn-stress.jsonl \
            run -- env WARDYN_AUDIT=/tmp/wardyn-stress.jsonl bash "$s"
    done
    [ "$found" -eq 1 ] || { echo "no scenario matched: {{name}}"; exit 1; }

# The control for scenario 1: the same attacks against name rules instead of
# (dev, ino). Without it, "8 blocked" says nothing about what did the blocking.
stress-control:
    bash scripts/stress/setup.sh
    sudo ./target/release/wardyn --plain --enforce \
        --policy scripts/stress/control.yaml --audit /tmp/wardyn-stress-c.jsonl \
        run -- bash scripts/stress/01-escape.sh

# Re-record all four stress GIFs. Needs vhs + ttyd + ffmpeg (see RECORDING.md).
stress-record:
    #!/usr/bin/env bash
    set -euo pipefail
    for t in docs/stress/0*.tape; do echo "recording $t"; vhs "$t"; done
