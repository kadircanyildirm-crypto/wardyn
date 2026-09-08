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
# Absolute, because wardyn is launched from the workspace directory below and a
# relative `./target/release/wardyn` would not resolve from there.
[[ "$WARDYN" = /* ]] || WARDYN="$(cd "$(dirname "$WARDYN")" && pwd)/$(basename "$WARDYN")"
POLICY="$SCRIPT_DIR/policy.yaml"

PASS=0
FAIL=0
SKIP=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$1"; FAIL=$((FAIL + 1)); }
skip() { printf '  \033[33m∼ SKIP\033[0m %s\n' "$1"; SKIP=$((SKIP + 1)); }
info() { printf '\033[36m›\033[0m %s\n' "$1"; }
# A gap wardyn does NOT close, asserted so it stays a documented limitation
# rather than an assumption. If one of these starts failing, something got
# better and SECURITY.md is now overcautious — which is a fix, not a break, but
# it must be a deliberate one.
limit() { printf '  \033[35m◆ known limit\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }

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
# A second, identical workspace for the control run at the end (name rules only).
WS_CTL="$(mktemp -d)"
# Invoked by the EXIT trap below, never by name. ShellCheck renamed this check
# between releases (SC2317 in 0.9, SC2329 in 0.11), so silence both or the lint
# passes locally and fails on whichever version CI happens to ship.
# shellcheck disable=SC2317,SC2329
cleanup() { rm -rf "$WS" "$WS_CTL"; }
trap cleanup EXIT

# Build the fixture tree the agent script operates on, in $1.
make_fixtures() {
  local d="$1"
  chmod 777 "$d" # the agent runs dropped-privilege; let it read/write here

  printf 'SECRET_API_KEY=sk-e2e-not-real\n' >"$d/.env"
  printf 'this file is fine to read\n' >"$d/ok.txt"
  # For the access axis: writable, but not readable back.
  printf 'existing line\n' >"$d/writable.log"
  chmod 644 "$d/.env" "$d/ok.txt" "$d/writable.log"

  # A secret buried several levels under a blocked DIRECTORY. The LSM hook used
  # to compare only the immediate parent, so this file was readable while the
  # feed showed `**/.ssh/**` as covering it.
  mkdir -p "$d/.ssh/sub/deeper"
  printf 'PRIVATE KEY\n' >"$d/.ssh/sub/deeper/id_ed25519"
  chmod -R 755 "$d/.ssh"
  chmod 644 "$d/.ssh/sub/deeper/id_ed25519"

  # Pair-key fixtures: one of each name where the rule applies, and one where
  # only the old bare-name key would have. The second of each pair is the
  # assertion — a `credentials` that is not under `.aws` must open.
  mkdir -p "$d/.aws" "$d/proj" "$d/.config/gcloud/sub" "$d/other/gcloud"
  printf 'aws_secret_access_key=nope\n' >"$d/.aws/credentials"
  printf 'just a file called credentials\n' >"$d/proj/credentials"
  printf 'gcloud key\n' >"$d/.config/gcloud/sub/key"
  printf 'unrelated gcloud dir\n' >"$d/other/gcloud/key"
  chmod 755 "$d/.aws" "$d/proj" "$d/.config" "$d/.config/gcloud" "$d/.config/gcloud/sub" "$d/other" "$d/other/gcloud"
  chmod 644 "$d/.aws/credentials" "$d/proj/credentials" "$d/.config/gcloud/sub/key" "$d/other/gcloud/key"

  # Lifecycle fixtures. `precious.txt` is protected from removal but not from
  # reading; `vault/` is pinned by identity and protects what is under it.
  printf 'do not delete me\n' >"$d/precious.txt"
  chmod 644 "$d/precious.txt"
  mkdir -p "$d/vault/empty"
  printf 'vaulted\n' >"$d/vault/note.txt"
  chmod 755 "$d/vault" "$d/vault/empty"
  chmod 644 "$d/vault/note.txt"

  # A stand-in for a blocked binary. A shell script is enough:
  # `bprm_check_security` fires for the script itself, so the `**/nc` exec rule
  # denies it exactly as it would deny the real netcat, and the fixture needs
  # nothing installed.
  printf '#!/bin/sh\necho nc-ran\n' >"$d/nc"
  chmod 755 "$d/nc"

  # The agent must OWN the fixtures it is going to rename and hard-link.
  # `fs.protected_hardlinks` (on by default) refuses a link to a file the caller
  # neither owns nor can write, so root-owned fixtures would make the hard-link
  # bypass test pass without wardyn doing anything at all — a green light for a
  # hole that is still open. This also mirrors reality: an agent's secrets are
  # normally its own files.
  if [[ -n "${SUDO_UID:-}" && "${SUDO_UID}" != "0" ]]; then
    chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$d"
  fi
}
make_fixtures "$WS"
make_fixtures "$WS_CTL"

# The control policy: the shipped one with every `path:` (identity) rule stripped.
# Running the *same* agent against it is what turns "the identity tests passed"
# into "identity is what made them pass" — without it, a name rule that happened
# to cover a renamed fixture would look exactly like a working inode match.
CTL_POLICY="$WS_CTL/name-only.yaml"
grep -v '{ *path:' "$POLICY" >"$CTL_POLICY"

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
# ── port rules, all on loopback so nothing depends on external connectivity ──
# blocked by an address rule (/32 beats the /8 allow)
timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.2/8' 2>/dev/null || true
# ...but allowed on port 9, because a port rule is consulted first
timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.2/9' 2>/dev/null || true
# denied on an address the policy otherwise allows in full — the ordering proof
timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/7' 2>/dev/null || true
# ── protocol rules, one dimension further out than ports ─────────────────────
# UDP to a host the /8 allows in full: the protocol rule is consulted first.
timeout 3 bash -c 'exec 3<>/dev/udp/127.0.0.3/9' 2>/dev/null || true
# ...and the same host over TCP, which that rule says nothing about.
timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.3/10' 2>/dev/null || true
# A bare port block, lifted for one protocol by the most specific tier there is.
timeout 3 bash -c 'exec 3<>/dev/udp/127.0.0.1/11' 2>/dev/null || true
# ...while the same port over TCP is still denied by that bare port rule.
timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.4/11' 2>/dev/null || true
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

# ── access axis: `block ... access: read` must still permit writing ──────────
# An O_WRONLY|O_APPEND open asks for FMODE_WRITE and must be allowed; the
# O_RDONLY read that follows asks for FMODE_READ and must not be.
if echo 'appended by the agent' >>"$WS/writable.log" 2>/dev/null; then
  echo allowed >"$WS/log_write.txt"
else
  echo denied >"$WS/log_write.txt"
fi
if cat "$WS/writable.log" >/dev/null 2>&1; then
  echo allowed >"$WS/log_read.txt"
else
  echo denied >"$WS/log_read.txt"
fi

say() { if cat "$1" >/dev/null 2>&1; then echo allowed; else echo denied; fi; }

# ── two-component keys: the parent is part of the name now ───────────────────
# `**/.aws/credentials` used to compile to `credentials` and deny every file so
# called. Two reads per rule: the one it names, and the one it used to catch.
say "$WS/.aws/credentials"       >"$WS/pair_aws.txt"
say "$WS/proj/credentials"       >"$WS/pair_bare.txt"
say "$WS/.config/gcloud/sub/key" >"$WS/pair_gcloud.txt"
say "$WS/other/gcloud/key"       >"$WS/pair_other.txt"

# ── identity bypasses: the same object reached under a different name ────────
# Everything below is one question: does the rule follow the OBJECT, or only the
# label? Name matching answers "only the label", and each of these walks through.
cd "$WS" || exit 9

# 1. rename the secret, then read it under its new name
if mv .env renamed.txt 2>/dev/null; then say renamed.txt >"$WS/rename_read.txt"
else echo mv-failed >"$WS/rename_read.txt"; fi
mv renamed.txt .env 2>/dev/null || true

# 2. hard-link it: one inode, two names, and the rule only knows one of them
if ln .env hardlink.txt 2>/dev/null; then say hardlink.txt >"$WS/link_read.txt"
else echo ln-failed >"$WS/link_read.txt"; fi

# 3. copy it. This one must ALREADY fail, name matching or not: `cp` has to read
#    the source, and that read is the thing being denied. It is the reason
#    identity matching closes the loop instead of just moving the goalposts.
if cp .env copy.txt 2>/dev/null; then echo allowed >"$WS/copy_read.txt"
else echo denied >"$WS/copy_read.txt"; fi

# 4. rename the blocked DIRECTORY and read through the new name
if mv .ssh dotssh 2>/dev/null; then
  say dotssh/sub/deeper/id_ed25519 >"$WS/dirrename_read.txt"
else echo mv-failed >"$WS/dirrename_read.txt"; fi
mv dotssh .ssh 2>/dev/null || true

# 5. rename a blocked BINARY and run it
if mv nc renamed_nc 2>/dev/null; then
  if ./renamed_nc >/dev/null 2>&1; then echo allowed >"$WS/rename_exec.txt"
  else echo denied >"$WS/rename_exec.txt"; fi
else echo mv-failed >"$WS/rename_exec.txt"; fi

# 6. COPY a blocked binary and run it. A copy is a genuinely different object, so
#    no inode rule can catch it — pinned here as a known limitation rather than
#    left for someone to discover.
if cp renamed_nc copied_nc 2>/dev/null; then
  chmod 755 copied_nc
  if ./copied_nc >/dev/null 2>&1; then echo allowed >"$WS/copy_exec.txt"
  else echo denied >"$WS/copy_exec.txt"; fi
else echo cp-failed >"$WS/copy_exec.txt"; fi

# ── lifecycle axis: an `rm` is not an open ───────────────────────────────────
# Every rule exercised above is matched at `file_open`, which does not fire for
# unlink(2) at all — so before the lifecycle hooks existed, a policy could guard
# a secret's contents and still watch the agent delete it.
did() { if "$@" >/dev/null 2>&1; then echo allowed; else echo denied; fi; }

# `access: delete` must refuse the removal...
did rm -f "$WS/precious.txt" >"$WS/rm_precious.txt"
# ...and must NOT refuse reading the very same file. A delete rule that also
# blocks reads is indistinguishable from the old `block`, which is the thing
# the axis exists to stop being.
say "$WS/precious.txt" >"$WS/read_precious.txt"

# An ancestor pinned by identity covers what is under it, for removals exactly
# as it does for opens.
did rm -f "$WS/vault/note.txt" >"$WS/rm_vaulted.txt"
did rmdir "$WS/vault/empty" >"$WS/rmdir_vaulted.txt"

# The create side: a name the policy refuses to let appear at all.
did touch "$WS/forbidden.new" >"$WS/touch_forbidden.txt"
did mkdir "$WS/forbidden.dir" >"$WS/mkdir_forbidden.txt"
# ...including when it appears as the DESTINATION of a rename, which is the
# hole a create rule would have if only `inode_create` were hooked.
did mv "$WS/ok.txt" "$WS/forbidden.new" >"$WS/mv_forbidden.txt"
# ...and as a hard link or a symlink, which are the other two one-word ways to
# make a name exist.
did ln "$WS/ok.txt" "$WS/forbidden.new" >"$WS/ln_forbidden.txt"
did ln -s "$WS/ok.txt" "$WS/forbidden.new" >"$WS/symlink_forbidden.txt"

# COMPATIBILITY. `.env` is blocked with no `access:` at all. That rule said
# nothing about deleting before this axis existed, and must still say nothing —
# otherwise every policy already written changed meaning when wardyn updated.
# Last, because it destroys a fixture the assertions above rely on.
did rm -f "$WS/.env" >"$WS/rm_env.txt"

# a deliberate non-zero exit, so the test can assert wardyn propagates it
exit 7
AGENT
chmod 755 "$WS/agent.sh"
cp "$WS/agent.sh" "$WS_CTL/agent.sh" # same agent, for the control run below

# ── run under enforcement ───────────────────────────────────────────────────
info "wardyn: $WARDYN"
info "policy: $POLICY"
info "BPF-LSM active: $([[ $LSM_ACTIVE -eq 1 ]] && echo yes || echo 'no (file/exec assertions skipped)')"
info "running the agent under --enforce ..."

export WS
# --plain so there is no TUI; wardyn exits when the agent script exits.
#
# Run from inside the workspace: a `path:` rule written relatively (`path: .env`)
# means "the one in the project being watched", so it resolves against wardyn's
# working directory — the same directory the agent is launched in. Running from
# the repo root instead would anchor the rules to the repo, which is not where
# the fixtures are.
( cd "$WS" && "$WARDYN" --enforce --plain --policy "$POLICY" \
  --audit "$AUDIT" --denials "$DENIALS" run -- bash "$WS/agent.sh" ) >"$WLOG" 2>&1
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

# 2c) protocol rules: a rule naming a transport beats a longer address prefix
#     that does not, and naming both beats naming one.
if audited_block "127.0.0.3:9"; then
  pass "proto: UDP denied on a host the address rules allow in full"
else
  fail "127.0.0.3:9 over UDP was not blocked — the protocol trie did not take effect"
fi
if audited_block "127.0.0.3:10"; then
  fail "TCP to 127.0.0.3 was blocked by a rule that names UDP — the protocol is being ignored"
else
  pass "proto: the same host over TCP is untouched by a UDP rule"
fi
if audited_block "127.0.0.1:11"; then
  fail "UDP to port 11 was blocked — a proto+port allow did NOT beat a bare port block"
else
  pass "proto: an allow naming protocol AND port beats a block naming only the port"
fi
if audited_block "127.0.0.4:11"; then
  pass "proto: that same port over TCP is still denied by the bare port rule"
else
  fail "127.0.0.4:11 over TCP was allowed — the proto+port allow leaked into the port trie"
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

# 4b) port rules, and the one thing about them that has to be stated: a rule
#     naming a port is consulted before one that does not, whatever their
#     address prefixes.
if audited_block "127.0.0.2:8"; then
  pass "port: an address rule still blocks a port it says nothing about"
else
  fail "127.0.0.2:8 was not blocked — the /32 address rule did not take effect"
fi
if grep -qF "127.0.0.2:9" "$AUDIT" 2>/dev/null; then
  fail "127.0.0.2:9 was flagged — a port allow must override the address block"
else
  pass "port: an allow on one port overrides a block on the whole address"
fi
if audited_block "127.0.0.1:7"; then
  pass "port: a bare port block denies it on a network the policy otherwise allows"
else
  fail "127.0.0.1:7 was allowed — a port rule did NOT beat the 127.0.0.0/8 allow"
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

  verdict() { cat "$WS/$1" 2>/dev/null || echo "missing"; }

  # ── the access axis: `block` no longer has to mean "cannot be opened" ─────
  case "$(verdict log_write.txt)" in
    allowed) pass "access: a read-only block still permits appending to the file" ;;
    denied)  fail "a rule with access: read also blocked a WRITE — the axis is not narrowing" ;;
    *)       fail "access-write check produced no verdict" ;;
  esac
  case "$(verdict log_read.txt)" in
    denied)  pass "access: reading that same file is denied" ;;
    allowed) fail "a rule with access: read did not block the read" ;;
    *)       fail "access-read check produced no verdict" ;;
  esac

  # ── pairs: `/x/y` denies `y` under `x`, not every `y` ─────────────────────

  case "$(verdict pair_aws.txt)" in
    denied)  pass "pair: .aws/credentials is denied (the file the rule names)" ;;
    allowed) fail "the agent READ .aws/credentials — the pair key did not take effect" ;;
    *)       fail "pair check produced no verdict" ;;
  esac
  case "$(verdict pair_bare.txt)" in
    allowed) pass "pair: a credentials file that is NOT under .aws is readable (the old over-reach is gone)" ;;
    denied)  fail "proj/credentials was denied — the rule still compiles to the bare name" ;;
    *)       fail "pair over-reach check produced no verdict" ;;
  esac
  case "$(verdict pair_gcloud.txt)" in
    denied)  pass "pair: a file deep under .config/gcloud is denied (dir pair, ancestor walk)" ;;
    allowed) fail "the agent READ under .config/gcloud — the dir-pair key did not take effect" ;;
    *)       fail "dir-pair check produced no verdict" ;;
  esac
  case "$(verdict pair_other.txt)" in
    allowed) pass "pair: a gcloud dir that is NOT under .config is untouched" ;;
    denied)  fail "other/gcloud/key was denied — the dir rule still compiles to the bare name" ;;
    *)       fail "dir-pair over-reach check produced no verdict" ;;
  esac

  # ── identity: does the rule follow the object, or only the label? ─────────

  case "$(verdict rename_read.txt)" in
    denied)    pass "identity: renaming the secret did not make it readable" ;;
    allowed)   fail "BYPASS — \`mv .env x\` then reading x succeeded (name matching only)" ;;
    mv-failed) skip "rename bypass (the agent could not rename the fixture)" ;;
    *)         fail "rename bypass check produced no verdict" ;;
  esac

  case "$(verdict link_read.txt)" in
    denied)    pass "identity: a hard link to the secret is denied too" ;;
    allowed)   fail "BYPASS — \`ln .env x\` then reading x succeeded (one inode, two names)" ;;
    ln-failed) skip "hard-link bypass (the kernel refused the link; check file ownership)" ;;
    *)         fail "hard-link bypass check produced no verdict" ;;
  esac

  # This one is expected to hold with or without identity matching, and is the
  # reason identity matching is worth having: you cannot copy what you cannot read.
  case "$(verdict copy_read.txt)" in
    denied)  pass "copying the secret fails, because the copy has to read it first" ;;
    allowed) fail "the agent COPIED a blocked secret — the read side is not enforced" ;;
    *)       fail "copy check produced no verdict" ;;
  esac

  case "$(verdict dirrename_read.txt)" in
    denied)    pass "identity: renaming the blocked directory did not expose its contents" ;;
    allowed)   fail "BYPASS — \`mv .ssh dotssh\` then reading through it succeeded" ;;
    mv-failed) skip "directory rename bypass (the agent could not rename the fixture)" ;;
    *)         fail "directory rename bypass check produced no verdict" ;;
  esac

  case "$(verdict rename_exec.txt)" in
    denied)    pass "identity: renaming a blocked binary did not make it runnable" ;;
    allowed)   fail "BYPASS — \`mv nc x\` then running x succeeded" ;;
    mv-failed) skip "binary rename bypass (the agent could not rename the fixture)" ;;
    *)         fail "binary rename bypass check produced no verdict" ;;
  esac

  # A copy of a binary is a new inode with a new name: nothing in the policy
  # describes it. Unlike a secret, a binary is world-readable, so there is no
  # read to deny either. Closing this needs content or provenance matching, not
  # identity — see SECURITY.md.
  case "$(verdict copy_exec.txt)" in
    allowed) limit "copying a blocked binary to a new name still runs it (SECURITY.md)" ;;
    denied)  fail "copy-then-exec was blocked — better than documented; update SECURITY.md" ;;
    *)       skip "copy-then-exec limitation (the agent could not copy the fixture)" ;;
  esac
  # ── lifecycle: the axis that had to be hooked somewhere else entirely ─────

  case "$(verdict rm_precious.txt)" in
    denied)  pass "delete: a rule with access: delete refused the removal" ;;
    allowed) fail "the agent DELETED a file a delete rule was supposed to protect" ;;
    *)       fail "delete check produced no verdict" ;;
  esac
  case "$(verdict read_precious.txt)" in
    allowed) pass "delete: that same rule still permits READING the file" ;;
    denied)  fail "a rule with access: delete also blocked a read — the axis is not narrowing" ;;
    *)       fail "delete-read check produced no verdict" ;;
  esac
  case "$(verdict rm_vaulted.txt)" in
    denied)  pass "delete: a path: rule on a directory covers removing what is UNDER it" ;;
    allowed) fail "a file under a delete-protected directory was removed" ;;
    *)       fail "vault delete check produced no verdict" ;;
  esac
  case "$(verdict rmdir_vaulted.txt)" in
    denied)  pass "delete: rmdir under that directory is refused too (inode_rmdir)" ;;
    allowed) fail "rmdir under a delete-protected directory succeeded" ;;
    *)       fail "rmdir check produced no verdict" ;;
  esac
  case "$(verdict touch_forbidden.txt)" in
    denied)  pass "create: a create-blocked name could not be brought into existence" ;;
    allowed) fail "a file with a create-blocked name was created" ;;
    *)       fail "create check produced no verdict" ;;
  esac
  case "$(verdict mkdir_forbidden.txt)" in
    denied)  pass "create: mkdir of a create-blocked directory name is refused" ;;
    allowed) fail "a directory with a create-blocked name was created" ;;
    *)       fail "mkdir check produced no verdict" ;;
  esac
  case "$(verdict mv_forbidden.txt)" in
    denied)  pass "create: a rename INTO that name is refused at the destination" ;;
    allowed) fail "mv produced a name the create rule forbids — the rename destination is unhooked" ;;
    *)       fail "rename-destination check produced no verdict" ;;
  esac
  case "$(verdict ln_forbidden.txt)" in
    denied)  pass "create: a hard link cannot bring a blocked name into existence either" ;;
    allowed) fail "ln produced a name the create rule forbids — inode_link is unhooked" ;;
    *)       fail "hard-link create check produced no verdict" ;;
  esac
  case "$(verdict symlink_forbidden.txt)" in
    denied)  pass "create: nor can a symlink (the name is the point, not the target)" ;;
    allowed) fail "ln -s produced a name the create rule forbids — inode_symlink is unhooked" ;;
    *)       fail "symlink create check produced no verdict" ;;
  esac
  # The compatibility guarantee, proved in the kernel instead of asserted in a
  # comment. This is the assertion that fails if `MASK_ANY` ever starts covering
  # the lifecycle axis, and with it every policy anyone has already written.
  case "$(verdict rm_env.txt)" in
    allowed) pass "compat: a plain block rule still says NOTHING about deleting" ;;
    denied)  fail "a plain block rule began refusing rm — existing policies changed meaning" ;;
    *)       fail "compat delete check produced no verdict" ;;
  esac

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
# The lifecycle hooks keep their own counters, so a refusal the agent saw with a
# zero counter here would mean the `rm` failed for some unrelated reason —
# ownership, a read-only mount — and the test would be green for nothing.
if [[ $LSM_ACTIVE -eq 1 ]]; then
  if grep -qE 'kernel denials — [1-9][0-9]* delete, [1-9][0-9]* create' "$WLOG"; then
    pass "kernel counted the delete AND create denials it made"
  else
    fail "no lifecycle denial counters — the create/delete hooks did not fire"
  fi
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
if [[ "$DRY" == *"name=.env"* && "$DRY" == *"dir=.ssh"* && "$DRY" == *"cidr:0.0.0.0/0"* \
   && "$DRY" == *"name=.aws/credentials"* && "$DRY" == *"dir=.config/gcloud"* \
   && "$DRY" == *"DELETING"* && "$DRY" == *"CREATING"* \
   && "$DRY" == *"blocked by protocol"* && "$DRY" == *"MOST SPECIFIC FIRST"* ]]; then
  pass "--dry-run reports every key the kernel will enforce on, and on which axis"
else
  fail "--dry-run did not describe the policy's kernel keys"
fi

# 9b) The JSON event stream, against a real kernel. A separate short run rather
#     than a flag on the main one, so the plain table keeps its coverage too.
#     What matters here is not that JSON came out — a unit test can show that —
#     but that the stream agrees with the kernel about what was denied.
if [[ $LSM_ACTIVE -eq 1 ]] && command -v jq >/dev/null 2>&1; then
  JSON_WS="$(mktemp -d)"
  chmod 777 "$JSON_WS"
  printf 'SECRET=nope\n' >"$JSON_WS/.env"
  printf 'fine\n' >"$JSON_WS/ok.txt"
  chmod 644 "$JSON_WS/.env" "$JSON_WS/ok.txt"
  [[ -n "${SUDO_UID:-}" ]] && chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$JSON_WS"
  cat >"$JSON_WS/agent.sh" <<'JAGENT'
cat "$JW/.env"    >/dev/null 2>&1 || true
cat "$JW/ok.txt"  >/dev/null 2>&1 || true
JAGENT
  JSON_OUT="$JSON_WS/stream.jsonl"
  ( cd "$JSON_WS" && JW="$JSON_WS" "$WARDYN" --enforce --format json --policy "$POLICY" \
      --audit "$JSON_WS/audit.jsonl" run -- bash "$JSON_WS/agent.sh" ) \
      >"$JSON_OUT" 2>"$JSON_WS/stderr"

  # Every line is one complete JSON object. A path containing a newline would
  # break this, which is exactly why the format is one-object-per-line.
  if [[ -s "$JSON_OUT" ]] && jq -e . "$JSON_OUT" >/dev/null 2>&1; then
    pass "json: every line of the stream parses as one JSON object"
  else
    fail "json: the stream was empty or did not parse as JSONL"
  fi
  # The header, and a schema version on every record including it.
  if jq -e 'select(.wardyn == "event-stream")' "$JSON_OUT" >/dev/null 2>&1; then
    pass "json: the stream opens with an event-stream header"
  else
    fail "json: no event-stream header"
  fi
  UNVERSIONED="$(jq -c 'select(.schema_version != 1)' "$JSON_OUT" | wc -l)"
  if [[ "$UNVERSIONED" -eq 0 ]]; then
    pass "json: every record carries schema_version (not just the header)"
  else
    fail "json: $UNVERSIONED record(s) had no schema_version — a consumer reading mid-pipe is blind"
  fi
  # The claim the schema doc leads with: count denials with `enforced`, and the
  # count has to match what the kernel itself reported at exit.
  STREAM_DENIED="$(jq -c 'select(.enforced == true)' "$JSON_OUT" | wc -l)"
  KERNEL_FILE="$(sed -n 's/.*kernel denials — \([0-9]*\) file.*/\1/p' "$JSON_WS/stderr" | head -1)"
  if [[ "$STREAM_DENIED" -ge 1 && "$STREAM_DENIED" == "${KERNEL_FILE:-x}" ]]; then
    pass "json: enforced==true count ($STREAM_DENIED) matches the kernel's own denial counter"
  else
    fail "json: stream said $STREAM_DENIED denial(s), the kernel counted ${KERNEL_FILE:-none}"
  fi
  # matched_key is the field the doc says to aggregate by, and it must name the
  # key that fired — not the policy text, which is in `rule`.
  if jq -e 'select(.enforced == true and .matched_key == "name=.env")' "$JSON_OUT" >/dev/null 2>&1; then
    pass "json: matched_key names the kernel key the denial fired on"
  else
    fail "json: no denial carried matched_key=name=.env"
  fi
  # The allow rows are the reason this is not just the audit log on stdout.
  if jq -e 'select(.action == "allow" and .event == "open")' "$JSON_OUT" >/dev/null 2>&1; then
    pass "json: observations are streamed too, not only violations"
  else
    fail "json: the stream carried no allow rows — it is just the audit log"
  fi
  rm -rf "$JSON_WS"
else
  skip "json event stream (needs BPF-LSM and jq)"
fi

# 10) CONTROL: the same agent, the same fixtures, the same wardyn — but a policy
#     with the `path:` rules stripped out. Every bypass the identity rules closed
#     must reopen. Without this, an identity assertion that passed because some
#     *name* rule happened to cover the renamed file would be indistinguishable
#     from a working inode match, and the feature could rot silently.
if [[ $LSM_ACTIVE -eq 1 ]]; then
  info "control run: name rules only (the bypasses must reopen)"
  CTL_LOG="$WS_CTL/wardyn.stderr"
  ( cd "$WS_CTL" && WS="$WS_CTL" "$WARDYN" --enforce --plain --policy "$CTL_POLICY" \
    --audit "$WS_CTL/audit.jsonl" --denials "$WS_CTL/denials.jsonl" \
    run -- bash "$WS_CTL/agent.sh" ) >"$CTL_LOG" 2>&1

  ctl() { cat "$WS_CTL/$1" 2>/dev/null || echo missing; }
  reopened=0
  for probe in rename_read.txt link_read.txt dirrename_read.txt rename_exec.txt; do
    [[ "$(ctl "$probe")" == "allowed" ]] && reopened=$((reopened + 1))
  done
  if [[ $reopened -eq 4 ]]; then
    pass "control: all 4 bypasses reopen without identity rules (so identity is what closed them)"
  else
    fail "control: only $reopened/4 bypasses reopened — the identity assertions above may be passing for another reason"
  fi
  # The name rules must still work in the control run: this proves the control
  # policy is a real policy and not one that failed to load.
  if [[ "$(ctl env_read.txt)" == "denied" ]]; then
    pass "control: the name rule still blocks the un-renamed secret"
  else
    fail "control: even the plain .env read was allowed — the control policy did not take effect"
  fi

  # And the kernel's own counter must say the main run used identity matching.
  if grep -q 'matched by identity' "$WLOG"; then
    pass "kernel counted identity (dev,ino) denials in the enforcing run"
  else
    fail "no identity denials counted — the inode maps were never consulted"
  fi
else
  skip "control run + identity counters (BPF-LSM not active)"
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
