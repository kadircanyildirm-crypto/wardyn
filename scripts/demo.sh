#!/usr/bin/env bash
# Generates a clean allow / warn / block mix so the Wardyn TUI (and audit log)
# have something to show. Runs ~9s and exits (Wardyn auto-quits when it does).
#
#   sudo /path/to/wardyn run -- bash scripts/demo.sh
set -u

DEMO="${HOME}/wardyn-demo"
mkdir -p "$DEMO" "${HOME}/.ssh"
echo "SECRET_API_KEY=sk-demo-not-real"      > "$DEMO/.env"
echo "//registry.npmjs.org/:_authToken=xx" > "${HOME}/.npmrc"
[ -f "${HOME}/.ssh/id_ed25519" ] || echo "FAKE-DEMO-KEY" > "${HOME}/.ssh/id_ed25519"

for i in 1 2 3; do
  # ── file reads ──
  cat /etc/hostname            >/dev/null 2>&1   # open  -> allow
  cat "$DEMO/.env"             >/dev/null 2>&1   # open  -> BLOCK  (**/.env)
  cat "${HOME}/.ssh/id_ed25519" >/dev/null 2>&1  # open  -> BLOCK  (**/.ssh/**)
  cat "${HOME}/.npmrc"         >/dev/null 2>&1   # open  -> warn   (**/.npmrc)
  # ── outbound connections (bash /dev/tcp; connect() fires even if refused) ──
  timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22'  2>/dev/null  # connect -> allow (loopback)
  timeout 2 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'   2>/dev/null  # connect -> BLOCK (default deny)
  sleep 1
done
