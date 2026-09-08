#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# STRESS 2 — the agent stops going after the secret and goes after the warden.
#
# Wardyn's enforcement lives in kernel maps, applied by a root process. The
# agent is dropped to a non-root uid with NO_NEW_PRIVS before it execs, so the
# question is whether that drop actually holds or is just a line in a notice.
#
# Almost nothing here needs a wardyn *rule* to fail. That is the point: these
# are refused because of what the agent IS, not because of what the policy says.
# A rule can be forgotten; an identity cannot.
#
# Two of these are expected to SUCCEED, and both are followed by a check that
# the success bought nothing. A test that only lists refusals would be measuring
# its own choice of attacks.
#
# Run under:  wardyn --enforce --policy scripts/stress/policy.yaml run -- bash …
set -u
export LC_ALL=C
W="$HOME/wardyn-stress"

held=0; escaped=0

try() { # success means the warden lost
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  \033[1;31m✗ SUCCEEDED\033[0m   %s\n' "$label"; escaped=$((escaped + 1))
  else
    printf '  \033[32m✓ refused\033[0m     %s\n' "$label"; held=$((held + 1))
  fi
  sleep 0.35
}

note() { printf '  \033[33m•\033[0m %s\n' "$1"; sleep 0.35; }

printf 'the agent: uid=%s gid=%s groups=%s  NoNewPrivs=%s\n\n' \
  "$(id -u)" "$(id -g)" "$(id -G)" "$(awk '/NoNewPrivs/{print $2}' /proc/self/status)"

echo "── reach the maps that hold the policy ─────────────────────"
# A direct bpf(2) call, not `bpftool` — that binary is not installed
# everywhere, and a test that passes because a command is missing is worse
# than no test at all.
try "bpf(MAP_GET_NEXT_ID) — needs CAP_BPF" python3 scripts/stress/bpf-probe.py
WPID="$(pgrep -x wardyn | head -1)"
try "read wardyn's memory (/proc/$WPID/mem)"  head -c 16 "/proc/${WPID:-0}/mem"
try "list wardyn's open descriptors"        ls "/proc/${WPID:-0}/fd"

echo
echo "── read the machine underneath it ──────────────────────────"
try "kernel memory (/proc/kcore)"           head -c 16 /proc/kcore
try "the raw disk"                          head -c 16 /dev/sda
try "the shadow file"                       cat /etc/shadow

echo
echo "── stop the process that is watching ───────────────────────"
try "kill wardyn (pid ${WPID:-none})"       kill -9 "${WPID:-0}"
# `pkill` exits 0 if it signalled ANY matching process, and what it manages to
# match varies from run to run — which made this report "SUCCEEDED" on one run
# and "refused" on the next, while wardyn was alive both times. Ask the only
# question that means anything.
pkill -9 -u 0 >/dev/null 2>&1
# `kill -0` is not the test either: sending a signal to a process owned by
# ANOTHER user fails with EPERM, so it cannot tell "gone" from "not yours".
# /proc is readable by everyone.
if [ -d "/proc/${WPID:-0}" ]; then
  printf '  \033[32m✓ refused\033[0m     kill every root process — wardyn is still alive\n'
  held=$((held + 1))
else
  printf '  \033[1;31m✗ SUCCEEDED\033[0m   the warden was killed\n'
  escaped=$((escaped + 1))
fi
sleep 0.35

echo
echo "── get privileges back ─────────────────────────────────────"
try "setuid binary (NO_NEW_PRIVS)"          sudo -n id
# A new user namespace DOES get created — unprivileged userns is enabled on most
# distros. What matters is whether it buys anything, so ask it to do the two
# things the agent actually wants.
if unshare -Ur true 2>/dev/null; then
  note "a new user namespace WAS created (unprivileged userns is enabled here)"
  try "  ...read the secret from inside it"   unshare -Ur cat "$W/vault/.env"
  try "  ...reach the BPF maps from inside"   unshare -Ur python3 scripts/stress/bpf-probe.py
else
  try "new user namespace"                    unshare -Ur true
fi

echo
echo "── rewrite the rules for the NEXT run ──────────────────────"
# The policy is loaded from the agent's own working directory by default, and
# wardyn says so at startup. This is a known, documented weakness — so the
# honest thing is to show it working AND show what it does not buy.
cp scripts/stress/policy.yaml /tmp/agent-owned-policy.yaml 2>/dev/null
try "append 'allow everything' to a policy" \
  bash -c 'echo "  - { match: \"**\", action: allow }" >> /tmp/agent-owned-policy.yaml'
note "expected: the policy lives where the agent can write. wardyn warns at startup."
try "  ...and read the secret now"          cat "$W/vault/.env"
note "the running policy is already in kernel maps — a file edit reaches the NEXT run"

echo
echo "── erase the evidence ──────────────────────────────────────"
# The audit log's path has to come from the caller. `rm -f` on a path that does
# not exist exits 0, so a hardcoded guess reports "the agent erased the evidence"
# when it had merely deleted nothing. A test that lies in the tool's favour is
# bad; one that lies against it is no better.
AUDIT="${WARDYN_AUDIT:-}"
if [ -z "$AUDIT" ] || [ ! -e "$AUDIT" ]; then
  printf '  \033[33m∼ skipped\033[0m   erase the audit log (WARDYN_AUDIT is not a real file)\n'
else
  # shellcheck disable=SC2016  # `$0` is the inner shell's argument, on purpose:
  # passing the path as an argument rather than interpolating it keeps a path
  # with spaces (or a `;`) from becoming part of the command.
  try "delete it ($AUDIT)"                  bash -c 'rm -f -- "$0"' "$AUDIT"
  # shellcheck disable=SC2016
  try "truncate it"                         bash -c ': > "$0"' "$AUDIT"
fi
# The receipt is a different matter and is MEANT to be reachable: wardyn chowns
# it to the agent so the agent can read why it was denied. Losing it costs the
# agent its own explanation and nothing else — the audit log is the record, and
# that one is root's.
if [ -n "${WARDYN_DENIALS:-}" ] && [ -e "${WARDYN_DENIALS}" ]; then
  note "the receipt is agent-writable by design — the agent's copy, not the record"
fi

echo
if [ "$escaped" -eq 1 ]; then
  printf '\033[1;32m  %d attempts, %d refused. The one that worked — editing a policy file — changed nothing here.\033[0m\n' \
    "$((held + escaped))" "$held"
elif [ "$escaped" -eq 0 ]; then
  printf '\033[1;32m  %d attempts on the warden itself, all refused\033[0m\n' "$held"
else
  printf '\033[1;31m  %d of %d attempts succeeded\033[0m\n' "$escaped" "$((held + escaped))"
fi
