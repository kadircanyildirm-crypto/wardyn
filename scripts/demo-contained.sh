#!/usr/bin/env bash
# The containment half of the demo: an agent confined to one project directory,
# reaching for things outside it.
#
# Fixtures and the policy come from `scripts/demo-setup.sh`, which must run
# BEFORE wardyn — under `allow_paths:` this script can only read what the policy
# grants, and that includes itself.
#
#   bash scripts/demo-setup.sh
#   sudo wardyn --enforce --policy /tmp/wardyn-demo-contained.yaml \
#        run -- bash <project>/demo-contained.sh
set -u

# Same reason as scripts/demo.sh: every exec calls setlocale, and under a UTF-8
# locale glibc opens ~30 files per process looking for it. In a 15-second
# recording that is all anyone sees.
export LC_ALL=C LANG=C

HOME_DIR="$(getent passwd "$(id -un)" | cut -d: -f6)"
HOME_DIR="${HOME_DIR:-$HOME}"
PROJ="$HOME_DIR/wardyn-demo/project"

for _ in 1 2 3 4; do
  # Inside the boundary: this is the agent's own project, granted read+write.
  cat "$PROJ/main.rs" >/dev/null 2>&1
  echo "// built" >>"$PROJ/out.log" 2>/dev/null

  # Outside it. None of these are denied by a `files:` rule — the policy has
  # none for them. They are denied because they are not in `allow_paths:` at
  # all, which is the difference between a blocklist and a boundary.
  cat "$HOME_DIR/.ssh/id_ed25519" >/dev/null 2>&1 # a secret the policy never mentions
  cat "$HOME_DIR/other-project/notes.md" >/dev/null 2>&1 # a different checkout
  ls "$HOME_DIR" >/dev/null 2>&1                  # even listing home

  # Granted read, not write. The feed names which right was missing.
  #
  # Braced, because the failure message for a REDIRECTION comes from the shell
  # itself and not from `echo` — `echo ... 2>/dev/null` silences the wrong
  # process, and the message lands on the terminal the TUI is drawing on.
  { echo x >/etc/wardyn-probe; } 2>/dev/null

  sleep 2
done
