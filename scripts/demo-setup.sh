#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Fixtures for the demo, created BEFORE wardyn starts.
#
# They have to be: the demo policy blocks creating files under `~/.ssh`, so a
# script that made its own fixtures from inside the watched tree would be denied
# by the very rule it is there to demonstrate — and the demo would show wardyn
# stopping its own setup rather than an agent.
#
#   bash scripts/demo-setup.sh   # then: sudo wardyn --enforce run -- bash scripts/demo.sh
set -u

# The user the demo will actually run as. Under `sudo`, `$HOME` is root's, but
# wardyn drops the agent back to $SUDO_UID — so the fixtures belong in that
# user's home, not root's.
DEMO_USER="${SUDO_USER:-$USER}"
DEMO_HOME="$(getent passwd "$DEMO_USER" | cut -d: -f6)"
DEMO_HOME="${DEMO_HOME:-$HOME}"

mkdir -p "$DEMO_HOME/wardyn-demo" "$DEMO_HOME/.ssh"
echo "SECRET_API_KEY=sk-demo-not-real" > "$DEMO_HOME/wardyn-demo/.env"
echo "//registry.npmjs.org/:_authToken=xx" > "$DEMO_HOME/.npmrc"
[ -f "$DEMO_HOME/.ssh/id_ed25519" ] || echo "FAKE-DEMO-KEY" > "$DEMO_HOME/.ssh/id_ed25519"
chmod 700 "$DEMO_HOME/.ssh"
chmod 600 "$DEMO_HOME/.ssh/id_ed25519" "$DEMO_HOME/.npmrc"

if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ]; then
  chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" \
    "$DEMO_HOME/wardyn-demo" "$DEMO_HOME/.ssh" "$DEMO_HOME/.npmrc"
fi

echo "demo fixtures ready in $DEMO_HOME"
