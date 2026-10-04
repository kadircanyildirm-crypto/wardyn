#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# How much does wardyn actually stop, and what does it cost in false positives?
#
#   sudo bash scripts/bench-coverage.sh [path/to/wardyn]
#
# `scripts/bench.sh` answers "what does it cost". This answers "what does it
# buy", and the two halves below are deliberately weighted the same, because a
# tool that denies everything scores perfectly on the first half and is useless.
#
# Three rules this is built to obey, each learned by getting it wrong:
#
#   * **Score the binary, not the audit log.** Every attempt is judged by what
#     the AGENT observed — did the secret bytes arrive, did the connection
#     open — written to a verdict file by the attempt itself. Grepping wardyn's
#     own output scores wardyn's opinion of itself, and an earlier version of
#     this matched wardyn's echo of its own argv and declared a leak.
#   * **A failed setup step is not a blocked attack.** `cat` failing because
#     the fixture was never created reads exactly like `cat` being denied, so
#     every attempt reports SETUP-FAILED separately from DENIED.
#   * **A missing tool is not a passing grade.** An attempt whose tool is not
#     installed is reported as SKIPPED and excluded from the denominator, never
#     counted as a win.
#
# The percentage is a property of the POLICY as much as of wardyn. This runs
# against `scripts/stress/policy.yaml` — sixteen lines, printed below — so the
# number can be read against rules you can see rather than a preset you have to
# go and find.
set -uo pipefail

WARDYN="${1:-./target/release/wardyn}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STRESS_POLICY="$HERE/stress/policy.yaml"

if [[ ! -x "$WARDYN" ]]; then
  echo "no wardyn binary at $WARDYN (build with: cargo build --release)" >&2
  exit 2
fi
if [[ $EUID -ne 0 ]]; then
  echo "needs root: wardyn loads eBPF (try: sudo bash $0)" >&2
  exit 2
fi
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  echo "BPF-LSM is not active — file and exec enforcement cannot attach, so" >&2
  echo "every attack would 'succeed' and the number would be meaningless." >&2
  echo "Enable it with scripts/enable-bpf-lsm.sh and reboot." >&2
  exit 2
fi

USER_NAME="${SUDO_USER:-$USER}"
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
W="${HOME_DIR:-$HOME}/wardyn-stress"
OUT="$W/bench"

bash "$HERE/stress/setup.sh" >/dev/null 2>&1

# The resolved binary behind `nc`, found out here rather than inside the
# sandbox: on Debian /usr/bin/nc is an alternatives symlink to nc.openbsd, and
# the difference between the two is one of the things being measured.
NC_LINK="$(command -v nc 2>/dev/null || true)"
NC_REAL="$(readlink -f "$NC_LINK" 2>/dev/null || true)"
rm -rf "$OUT"; mkdir -p "$OUT"

# The stress rules, plus an identity rule on the resolved nc. Keeping the
# stress policy itself unchanged matters: the other suites assert against it.
POLICY="$OUT/policy.yaml"
# Insert an identity rule at the TOP of the `exec:` block — first, so it is
# matched before the `**/nc` name rule it is being compared against. Appending
# to the file would land it in `network:`, which is the last section; an
# earlier draft did exactly that and the guard here is what caught it.
if ! grep -q "^exec:" "$STRESS_POLICY"; then
  echo "stress/policy.yaml has no exec: section — the exec rows of this" >&2
  echo "benchmark cannot be set up. Fix the insert below." >&2
  exit 2
fi
# The CR strip is not cosmetic. This repo is developed on Windows and the
# checkout can carry CRLF, which leaves the line as `exec:\r` — an anchored
# /^exec:$/ then never matches, the rule is silently not inserted, and the
# benchmark reports an identity rule as ineffective when it was never loaded.
# That is exactly the kind of quiet wrong number this whole script exists to
# avoid, so normalise first and anchor loosely.
if [[ -n "$NC_REAL" ]]; then
  awk -v nc="$NC_REAL" '
    { sub(/\r$/, "") ; print }
    /^exec:[[:space:]]*$/ { printf "  - { path: \"%s\", action: block }\n", nc }
  ' "$STRESS_POLICY" >"$POLICY"
  if ! grep -q "path: \"$NC_REAL\"" "$POLICY"; then
    echo "could not insert the exec identity rule into $POLICY — the exec rows" >&2
    echo "below would be measuring a rule that was never loaded." >&2
    exit 2
  fi
else
  tr -d '\r' <"$STRESS_POLICY" >"$POLICY"
fi
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$W" 2>/dev/null || true
chmod 755 "$W" "$OUT"

# ── the agent ───────────────────────────────────────────────────────────────
# Runs as the dropped (unprivileged) user, inside the watched tree. Each attempt
# appends one line: "<id>\t<verdict>". Verdicts are the agent's own observation.
cat >"$OUT/agent.sh" <<'AGENT'
#!/usr/bin/env bash
# No `set -e`: every attempt is expected to fail, that is the point.
W="$HOME/wardyn-stress"
V="$W/bench/verdicts.tsv"
: >"$V"

# Attack artefacts go here, never in $W/project. A hard link to a pinned inode
# survives the attempt to remove it — deleting it IS a delete of the blocked
# object, which the policy denies on purpose — so anything left behind would
# still be sitting in the compatibility half's working directory and fail its
# `git add -A` with a denial that is entirely correct.
A="$W/bench/scratch"
mkdir -p "$A"

say() { printf '%s\t%s\n' "$1" "$2" >>"$V"; }

# Did we get the secret? The fixture's first bytes are known, so "the read
# returned the real contents" is checkable rather than inferred from exit code.
got() { grep -q 'sk-stress-not-real\|PRIVATE-KEY-MATERIAL\|sk_live_not_real' <<<"${1:-}"; }

try_read() {           # id, path
  local out; out="$(cat "$2" 2>/dev/null)"
  if got "$out"; then say "$1" LEAKED; else say "$1" DENIED; fi
}

# ── A. reach a secret ──────────────────────────────────────────────────────
try_read direct-read "$W/vault/.env"

if mv "$W/vault/id_ed25519" "$W/vault/renamed.key" 2>/dev/null; then
  try_read rename-then-read "$W/vault/renamed.key"
  mv "$W/vault/renamed.key" "$W/vault/id_ed25519" 2>/dev/null
else
  say rename-then-read DENIED-AT-RENAME
fi

if ln "$W/vault/.env" "$A/linked.env" 2>/dev/null; then
  try_read hardlink-then-read "$A/linked.env"
  rm -f "$A/linked.env" 2>/dev/null   # denied by design; the file stays
else
  say hardlink-then-read DENIED-AT-LINK
fi

if ln -s "$W/vault/.env" "$A/sym.env" 2>/dev/null; then
  try_read symlink-then-read "$A/sym.env"
  rm -f "$A/sym.env"
else
  say symlink-then-read SETUP-FAILED
fi

# A copy is a different inode — but making one requires reading the original,
# which is the operation being denied.
if cp "$W/vault/.env" "$A/copy.env" 2>/dev/null; then
  try_read copy-then-read "$A/copy.env"
  rm -f "$A/copy.env"
else
  say copy-then-read DENIED-AT-COPY
fi

# Renaming the DIRECTORY: a name-based rule has nothing left to match.
if mv "$W/vault" "$W/v2" 2>/dev/null; then
  try_read dir-rename-then-read "$W/v2/.env"
  mv "$W/v2" "$W/vault" 2>/dev/null
else
  say dir-rename-then-read DENIED-AT-RENAME
fi

# The secret whose name gives nothing away — only the directory rule covers it.
try_read unnamed-secret "$W/vault/notes.txt"
# Relative path from inside, and a `..` walk from outside.
( cd "$W/vault" 2>/dev/null && try_read relative-path ".env" ) || say relative-path SETUP-FAILED
( cd "$A" 2>/dev/null && try_read dotdot-traversal "../../vault/.env" ) || say dotdot-traversal SETUP-FAILED

# ── B. destroy ─────────────────────────────────────────────────────────────
if rm -f "$W/vault/.env" 2>/dev/null && [[ ! -e "$W/vault/.env" ]]; then
  say unlink-secret DESTROYED
else
  say unlink-secret DENIED
fi
if : >"$W/vault/.env" 2>/dev/null && [[ ! -s "$W/vault/.env" ]]; then
  say truncate-secret DESTROYED
else
  say truncate-secret DENIED
fi

# ── C. execute ─────────────────────────────────────────────────────────────
# bash reports a kernel-refused exec as 126; anything else means it ran.
ran_or_denied() {        # id, binary
  "$2" -h </dev/null >/dev/null 2>&1
  [[ $? -eq 126 ]] && say "$1" DENIED || say "$1" RAN
}

# $BENCH_NC is the *resolved* binary, computed outside the sandbox and pinned
# by a path: rule in the benchmark policy. $BENCH_NC_LINK is the name a user
# types, which on Debian is an alternatives symlink two hops away from it.
if [[ -n "${BENCH_NC:-}" && -x "${BENCH_NC:-/nonexistent}" ]]; then
  ran_or_denied exec-via-symlink "${BENCH_NC_LINK:-$BENCH_NC}"
  ran_or_denied exec-resolved-binary "$BENCH_NC"
  if cp "$BENCH_NC" "$A/nc2" 2>/dev/null && chmod +x "$A/nc2" 2>/dev/null; then
    ran_or_denied exec-renamed-copy "$A/nc2"
    rm -f "$A/nc2"
  else
    say exec-renamed-copy SETUP-FAILED
  fi
else
  say exec-via-symlink SKIPPED-NO-TOOL
  say exec-resolved-binary         SKIPPED-NO-TOOL
  say exec-renamed-copy          SKIPPED-NO-TOOL
fi

# ── D. egress ──────────────────────────────────────────────────────────────
# bash's /dev/tcp needs no external tool and goes through connect(2).
if timeout 4 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
  say egress-tcp-v4 CONNECTED
else
  say egress-tcp-v4 DENIED
fi
if timeout 4 bash -c 'exec 3<>/dev/udp/1.1.1.1/53 && printf x >&3' 2>/dev/null; then
  say egress-udp-v4 SENT
else
  say egress-udp-v4 DENIED
fi
if ip -6 route get 2606:4700:4700::1111 >/dev/null 2>&1; then
  if timeout 4 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/443' 2>/dev/null; then
    say egress-tcp-v6 CONNECTED
  else
    say egress-tcp-v6 DENIED
  fi
else
  say egress-tcp-v6 SKIPPED-NO-ROUTE
fi

# ── E. ordinary work, which must keep working ──────────────────────────────
ok() { if "$@" >/dev/null 2>&1; then say "$1" WORKS; else say "$1" BROKEN; fi; }

P="$W/project"
grep -q public "$P/README.md" 2>/dev/null && say read-allowed-file WORKS || say read-allowed-file BROKEN
echo "new content" >"$P/new.txt" 2>/dev/null && say create-file WORKS || say create-file BROKEN
rm -f "$P/new.txt" 2>/dev/null && say delete-own-file WORKS || say delete-own-file BROKEN
grep -q deep "$P/a/b/c/d/e/f/g/h/leaf.txt" 2>/dev/null && say read-deep-tree WORKS || say read-deep-tree BROKEN

if command -v git >/dev/null 2>&1; then
  ( cd "$P" && rm -rf .git && git init -q && git add -A && \
    git -c user.email=b@e -c user.name=b commit -qm x ) >/dev/null 2>&1 \
    && say git-init-add-commit WORKS || say git-init-add-commit BROKEN
  rm -rf "$P/.git"
else
  say git-init-add-commit SKIPPED-NO-TOOL
fi

if command -v gcc >/dev/null 2>&1; then
  printf '#include <stdio.h>\nint main(){puts("hi");return 0;}\n' >"$P/t.c"
  ( gcc -O1 -o "$P/t" "$P/t.c" && "$P/t" ) >/dev/null 2>&1 \
    && say gcc-build-and-run WORKS || say gcc-build-and-run BROKEN
  rm -f "$P/t" "$P/t.c"
else
  say gcc-build-and-run SKIPPED-NO-TOOL
fi

if command -v python3 >/dev/null 2>&1; then
  python3 -c "open('$P/py.txt','w').write('x'); open('$P/py.txt').read()" >/dev/null 2>&1 \
    && say python-file-io WORKS || say python-file-io BROKEN
  rm -f "$P/py.txt"
else
  say python-file-io SKIPPED-NO-TOOL
fi

# The policy allows loopback explicitly; a tool that broke it would be unusable
# for anyone running a local dev server.
if timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>/dev/null; then
  say loopback-allowed WORKS
else
  # Nothing listening is not a denial. Only a refused connect to a LISTENING
  # port would be, and we cannot assume one exists.
  say loopback-allowed SKIPPED-NOTHING-LISTENING
fi
AGENT
chmod 755 "$OUT/agent.sh"
chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT/agent.sh" 2>/dev/null || true

# ── run it under enforcement ────────────────────────────────────────────────
echo "wardyn coverage benchmark"
echo "  binary : $WARDYN"
echo "  policy : $POLICY"
echo "  kernel : $(uname -r)  ($(uname -m))"
echo "  LSMs   : $(cat /sys/kernel/security/lsm)"
echo

BENCH_NC="$NC_REAL" BENCH_NC_LINK="$NC_LINK" \
"$WARDYN" --enforce --plain --policy "$POLICY" \
  --audit "$OUT/audit.jsonl" --denials "$OUT/denials.jsonl" \
  run -- bash "$OUT/agent.sh" >"$OUT/run.log" 2>&1

V="$W/bench/verdicts.tsv"
if [[ ! -s "$V" ]]; then
  echo "the agent produced no verdicts — see $OUT/run.log" >&2
  tail -5 "$OUT/run.log" >&2
  exit 1
fi

# ── score ───────────────────────────────────────────────────────────────────
# Anything that is not an unambiguous win for the attacker counts as stopped,
# and the raw verdict is printed either way so the judgement can be checked.
ATTACKS=0; STOPPED=0; COMPAT=0; WORKING=0; SKIPPED=0

row() { printf '  %-22s %-26s %s\n' "$1" "$2" "$3"; }

echo "── attacks ─────────────────────────────────────────────────────────────"
while IFS=$'\t' read -r id verdict; do
  case "$id" in
    read-allowed-file|create-file|delete-own-file|read-deep-tree|\
    git-init-add-commit|gcc-build-and-run|python-file-io|loopback-allowed) continue ;;
  esac
  case "$verdict" in
    SKIPPED-*) row "$id" "$verdict" "— not counted"; SKIPPED=$((SKIPPED+1)); continue ;;
    LEAKED|DESTROYED|RAN|CONNECTED|SENT) row "$id" "$verdict" "NOT STOPPED"; ATTACKS=$((ATTACKS+1)) ;;
    SETUP-FAILED) row "$id" "$verdict" "— not counted"; SKIPPED=$((SKIPPED+1)); continue ;;
    *) row "$id" "$verdict" "stopped"; ATTACKS=$((ATTACKS+1)); STOPPED=$((STOPPED+1)) ;;
  esac
done <"$V"

echo
echo "── ordinary work ───────────────────────────────────────────────────────"
while IFS=$'\t' read -r id verdict; do
  case "$id" in
    read-allowed-file|create-file|delete-own-file|read-deep-tree|\
    git-init-add-commit|gcc-build-and-run|python-file-io|loopback-allowed) ;;
    *) continue ;;
  esac
  case "$verdict" in
    SKIPPED-*) row "$id" "$verdict" "— not counted"; continue ;;
    WORKS) row "$id" "$verdict" "ok"; COMPAT=$((COMPAT+1)); WORKING=$((WORKING+1)) ;;
    *) row "$id" "$verdict" "FALSE POSITIVE"; COMPAT=$((COMPAT+1)) ;;
  esac
done <"$V"

echo
echo "── result ──────────────────────────────────────────────────────────────"
printf '  attacks stopped        %d / %d\n' "$STOPPED" "$ATTACKS"
printf '  ordinary work intact   %d / %d\n' "$WORKING" "$COMPAT"
printf '  not attempted          %d (tool or route missing; excluded)\n' "$SKIPPED"
echo
echo "  kernel-confirmed denials this run:"
grep -aE 'kernel denials|receipted' "$OUT/run.log" | sed 's/^/    /'
echo
echo "  verdicts : $V"
echo "  audit    : $OUT/audit.jsonl"
echo
echo "  Out of scope by design, not attempted above and documented in"
echo "  SECURITY.md: io_uring submissions, AF_UNIX / loopback delegation to an"
echo "  unwatched daemon, and raw sockets (the dropped agent has no CAP_NET_RAW)."

[[ $STOPPED -eq $ATTACKS && $WORKING -eq $COMPAT ]] && exit 0 || exit 1
