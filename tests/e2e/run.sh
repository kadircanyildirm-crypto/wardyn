#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# End-to-end enforcement test for Wardyn. Loads the real eBPF, runs an agent
# under `--enforce`, and asserts that the kernel actually blocked what policy
# says to block (and allowed what it allows). This is the missing coverage the
# audit flagged as critical: the unit tests never load the eBPF object, so a
# verifier rejection, a map error, or a broken enforcement path would pass CI.
#
# What it proves without external connectivity:
#   * the eBPF object LOADS and attaches (tracepoints + cgroup/connect),
#   * a blocked public IP (v4, and v6 when available) is denied at connect(),
#   * loopback egress is allowed,
#   * the child is dropped out of root before exec (privilege drop),
#   * (when BPF-LSM is active) a blocked `.env` open is denied and receipted.
#
# Usage:  sudo ./tests/e2e/run.sh [path/to/wardyn]
# Requires: root, a BTF + cgroup-v2 kernel. BPF-LSM is optional (file/exec
# assertions are skipped without it, so this runs on stock GitHub runners).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WARDYN="${1:-$REPO_ROOT/target/release/wardyn}"
POLICY="$SCRIPT_DIR/policy.yaml"

PASS=0
FAIL=0
SKIP=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$1"; FAIL=$((FAIL + 1)); }
skip() { printf '  \033[33m∼ SKIP\033[0m %s\n' "$1"; SKIP=$((SKIP + 1)); }
info() { printf '\033[36m›\033[0m %s\n' "$1"; }

# ── preconditions ───────────────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
  echo "e2e: must run as root (loads eBPF). Try: sudo $0" >&2
  exit 2
fi
if [[ ! -x "$WARDYN" ]]; then
  echo "e2e: wardyn binary not found/executable at '$WARDYN' — build it first:" >&2
  echo "     cargo build --release" >&2
  exit 2
fi
if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
  echo "e2e: no /sys/kernel/btf/vmlinux — this kernel lacks BTF; cannot run." >&2
  exit 2
fi

LSM_ACTIVE=0
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then LSM_ACTIVE=1; fi

# ── workspace ───────────────────────────────────────────────────────────────
WS="$(mktemp -d)"
# Invoked by the EXIT trap below, never by name. ShellCheck renamed this check
# between releases (SC2317 in 0.9, SC2329 in 0.11), so silence both or the lint
# passes locally and fails on whichever version CI happens to ship.
# shellcheck disable=SC2317,SC2329
cleanup() { rm -rf "$WS"; }
trap cleanup EXIT
chmod 777 "$WS" # the agent runs dropped-privilege; let it read/write here

printf 'SECRET_API_KEY=sk-e2e-not-real\n' >"$WS/.env"
printf 'this file is fine to read\n' >"$WS/ok.txt"
chmod 644 "$WS/.env" "$WS/ok.txt"

# A secret buried several levels under a blocked DIRECTORY. The LSM hook used to
# compare only the immediate parent, so this file was readable while the feed
# showed `**/.ssh/**` as covering it.
mkdir -p "$WS/.ssh/sub/deeper"
printf 'PRIVATE KEY\n' >"$WS/.ssh/sub/deeper/id_ed25519"
chmod -R 755 "$WS/.ssh"
chmod 644 "$WS/.ssh/sub/deeper/id_ed25519"

AUDIT="$WS/audit.jsonl"
DENIALS="$WS/denials.jsonl"
WLOG="$WS/wardyn.stderr"

# The agent-under-test: a few actions with known verdicts. Reads its identity so
# the test can confirm privilege drop. `|| true` so one blocked step doesn't abort
# the rest. WS is inherited from wardyn's env (survives the setuid drop).
cat >"$WS/agent.sh" <<'AGENT'
#!/usr/bin/env bash
set -u
id -u >"$WS/uid.txt" 2>/dev/null || echo err >"$WS/uid.txt"
# blocked public v4 — denied at connect(); no real connectivity needed
timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null || true
# allowed loopback
timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' 2>/dev/null || true
# blocked public v6 (only produces an event if the host has IPv6)
timeout 3 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/443' 2>/dev/null || true
# blocked secret (enforced only under BPF-LSM)
if cat "$WS/.env" >/dev/null 2>&1; then echo allowed >"$WS/env_read.txt"; else echo denied >"$WS/env_read.txt"; fi
# blocked secret NESTED under a blocked directory (ancestor walk)
if cat "$WS/.ssh/sub/deeper/id_ed25519" >/dev/null 2>&1; then
  echo allowed >"$WS/deep_read.txt"
else
  echo denied >"$WS/deep_read.txt"
fi
# allowed file
cat "$WS/ok.txt" >/dev/null 2>&1 || true
# a deliberate non-zero exit, so the test can assert wardyn propagates it
exit 7
AGENT
chmod 755 "$WS/agent.sh"

# ── run under enforcement ───────────────────────────────────────────────────
info "wardyn: $WARDYN"
info "policy: $POLICY"
info "BPF-LSM active: $([[ $LSM_ACTIVE -eq 1 ]] && echo yes || echo 'no (file/exec assertions skipped)')"
info "running the agent under --enforce ..."

export WS
# --plain so there is no TUI; wardyn exits when the agent script exits.
"$WARDYN" --enforce --plain --policy "$POLICY" --audit "$AUDIT" --denials "$DENIALS" \
  run -- bash "$WS/agent.sh" >"$WLOG" 2>&1
WARDYN_RC=$?

echo
info "results"

# helper: a JSONL line mentioning $1 that is a block AND enforced
audited_block() { grep -F "$1" "$AUDIT" 2>/dev/null | grep -q '"action":"block"' \
  && grep -F "$1" "$AUDIT" 2>/dev/null | grep -q '"enforced":true'; }

# 1) eBPF loaded and produced an audit trail at all.
if [[ -s "$AUDIT" ]]; then
  pass "eBPF loaded, attached, and produced an audit trail"
else
  fail "no audit output — did the eBPF object load? (wardyn rc=$WARDYN_RC)"
fi

# 2) blocked v4 egress was actually denied and recorded as enforced.
if audited_block "1.1.1.1:443"; then
  pass "IPv4 egress to 1.1.1.1:443 blocked and enforced"
else
  fail "expected an enforced block for 1.1.1.1:443"
fi

# 3) loopback egress allowed (allows are never audited, so it must be absent).
if grep -qF "127.0.0.1:9" "$AUDIT" 2>/dev/null; then
  fail "loopback egress was flagged — expected allow (no audit line)"
else
  pass "loopback egress allowed (not blocked)"
fi

# 4) IPv6 regression guard — only when the host actually attempted v6.
if grep -qF "2606:4700:4700::1111" "$AUDIT" 2>/dev/null; then
  if audited_block "2606:4700:4700::1111]:443"; then
    pass "IPv6 egress blocked and enforced (::/0 rule works)"
  else
    fail "IPv6 destination appeared but was NOT enforced — the v6/::ffff hole is back"
  fi
else
  skip "IPv6 egress (host has no IPv6 route; nothing attempted)"
fi

# 5) privilege drop — the agent must not have run as root when invoked via sudo.
if [[ -n "${SUDO_UID:-}" && "${SUDO_UID}" != "0" ]]; then
  AGENT_UID="$(cat "$WS/uid.txt" 2>/dev/null || echo '?')"
  if [[ "$AGENT_UID" == "$SUDO_UID" ]]; then
    pass "agent dropped to uid=$AGENT_UID (== \$SUDO_UID), not root"
  else
    fail "agent ran as uid=$AGENT_UID, expected \$SUDO_UID=$SUDO_UID (privilege drop failed)"
  fi
else
  skip "privilege drop (no usable \$SUDO_UID — run via sudo to test)"
fi

# 6) file/exec blocking — only when BPF-LSM is active.
if [[ $LSM_ACTIVE -eq 1 ]]; then
  if audited_block "/.env"; then
    pass "LSM: .env open blocked and enforced"
  else
    fail "LSM active but .env open was not enforced-blocked"
  fi
  if [[ "$(cat "$WS/env_read.txt" 2>/dev/null)" == "denied" ]]; then
    pass "LSM: the agent's read of .env actually failed"
  else
    fail "LSM active but the agent read .env successfully"
  fi
  # The ancestor walk: a file three levels under a blocked directory.
  if [[ "$(cat "$WS/deep_read.txt" 2>/dev/null)" == "denied" ]]; then
    pass "LSM: a secret nested under a blocked directory was denied (ancestor walk)"
  else
    fail "a file under .ssh/sub/deeper was READ — the dir rule only covers direct children"
  fi
  if grep -qF '"event":"open"' "$DENIALS" 2>/dev/null && grep -qF '.env' "$DENIALS" 2>/dev/null; then
    pass "denial receipt records the .env denial for the agent"
  else
    fail "the .env denial was not written to the WARDYN_DENIALS receipt"
  fi
  # The receipt must be readable by the agent (it is chowned to the drop
  # target) and by nobody else.
  DPERM="$(stat -c '%a' "$DENIALS" 2>/dev/null || echo '?')"
  if [[ "$DPERM" == "600" ]]; then
    pass "denial receipt is private (0600), not world-readable"
  else
    fail "denial receipt mode is $DPERM, expected 600"
  fi
else
  skip "file/exec blocking (BPF-LSM not active — enable with scripts/enable-bpf-lsm.sh)"
fi

# 7) the kernel's own counters are reported, and agree that denials happened.
if grep -q 'kernel denials —' "$WLOG"; then
  pass "kernel denial counters reported at exit"
else
  fail "no 'kernel denials' line — the STATS map was not read"
fi
if grep -q 'enforcement did NOT fire' "$WLOG"; then
  fail "wardyn reported denials to the agent that the kernel never made"
else
  pass "every denial claimed to the agent is backed by a kernel counter"
fi
if grep -qE 'event\(s\) were dropped|watch set filled up' "$WLOG"; then
  fail "events were lost during the run (ring buffer or watch set overflowed)"
else
  pass "no events dropped and the watch set never filled"
fi

# 8) the target's exit status reaches the caller (the agent exits 7).
if [[ "$WARDYN_RC" -eq 7 ]]; then
  pass "wardyn exits with the target's status (7)"
else
  fail "wardyn exited $WARDYN_RC, expected the agent's 7"
fi

# 9) --dry-run explains the policy without root, eBPF, or a target.
DRY="$("$WARDYN" --dry-run --policy "$POLICY" 2>&1)"
if [[ "$DRY" == *"name=.env"* && "$DRY" == *"dir=.ssh"* && "$DRY" == *"cidr:0.0.0.0/0"* ]]; then
  pass "--dry-run reports every key the kernel will enforce on"
else
  fail "--dry-run did not describe the policy's kernel keys"
fi

# ── summary ─────────────────────────────────────────────────────────────────
echo
if [[ $FAIL -gt 0 ]]; then
  echo "── wardyn stderr ──"
  sed 's/^/  /' "$WLOG"
  echo "── audit.jsonl ──"
  sed 's/^/  /' "$AUDIT" 2>/dev/null | head -40
  echo
  printf '\033[31mE2E FAILED\033[0m — %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
  exit 1
fi
printf '\033[32mE2E PASSED\033[0m — %d passed, %d skipped\n' "$PASS" "$SKIP"
exit 0
