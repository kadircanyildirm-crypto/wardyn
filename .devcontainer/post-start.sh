#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs on every container start. Two jobs:
#
#   1. Mount tracefs if the host did not expose it. Wardyn reads the fork
#      tracepoint's field offsets from /sys/kernel/tracing; without it, it falls
#      back to built-in kernel-6.8 offsets — a documented fail-open path we would
#      rather not take by accident inside a dev container.
#   2. Say plainly which of Wardyn's three enforcement axes this host can
#      actually exercise. A container inherits the host's kernel: no BPF-LSM on
#      the host means file/exec blocking is unavailable here no matter what the
#      policy says, and finding that out from a silently-skipped e2e assertion
#      wastes an afternoon.
set -u

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
no()   { printf '  \033[31m✗\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m∼\033[0m %s\n' "$1"; }

# ── tracefs (best effort; requires the privileged flag in devcontainer.json) ──
if [[ ! -e /sys/kernel/tracing/events ]] && [[ ! -e /sys/kernel/debug/tracing/events ]]; then
  sudo mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null \
    || sudo mount -t debugfs nodev /sys/kernel/debug 2>/dev/null \
    || true
fi

printf '\n\033[36m›\033[0m Wardyn dev container — host kernel capabilities\n'
printf '  kernel: %s\n' "$(uname -sr)"

# ── BTF: required to load anything at all, and to resolve LSM dentry offsets ──
if [[ -e /sys/kernel/btf/vmlinux ]]; then
  ok "BTF present (/sys/kernel/btf/vmlinux) — LSM offsets resolve at runtime"
else
  no "BTF MISSING — wardyn cannot load; needs a kernel built with CONFIG_DEBUG_INFO_BTF"
fi

# ── cgroup v2: the network enforcement hooks attach to /sys/fs/cgroup ─────────
if [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" == "cgroup2fs" ]]; then
  ok "cgroup v2 — egress enforcement (connect4·6 / sendmsg4·6) available"
else
  no "cgroup v2 MISSING — --enforce cannot block network egress"
fi

# ── BPF LSM: a host boot-time setting; nothing inside the container can fix it ─
LSMS="$(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)"
if [[ ",$LSMS," == *",bpf,"* ]]; then
  ok "BPF LSM active — file/exec blocking available (lsm=$LSMS)"
else
  warn "BPF LSM NOT active (lsm=$LSMS)"
  printf '      File/exec blocking is unavailable on this host. Builds, unit tests,\n'
  printf '      --dry-run and egress enforcement all still work; "just e2e" will\n'
  printf '      SKIP its file assertions. To get it, boot the HOST kernel with\n'
  printf '      lsm=...,bpf (scripts/enable-bpf-lsm.sh, in a VM you control).\n'
  printf '      Docker Desktop on macOS/Windows ships a VM kernel without it.\n'
fi

# ── tracefs, after the mount attempt above ───────────────────────────────────
if [[ -e /sys/kernel/tracing/events ]] || [[ -e /sys/kernel/debug/tracing/events ]]; then
  ok "tracefs readable — fork tracepoint offsets resolve from the running kernel"
else
  warn "tracefs unavailable — fork offsets fall back to built-in 6.8 values"
fi

printf '\n  Next: \033[1mjust build\033[0m, then \033[1mjust demo\033[0m (or \033[1mjust --list\033[0m).\n\n'
exit 0
