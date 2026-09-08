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

mkdir -p "$DEMO_HOME/wardyn-demo" "$DEMO_HOME/.ssh" "$DEMO_HOME/.aws"
echo "SECRET_API_KEY=sk-demo-not-real" > "$DEMO_HOME/wardyn-demo/.env"
echo "//registry.npmjs.org/:_authToken=xx" > "$DEMO_HOME/.npmrc"
[ -f "$DEMO_HOME/.ssh/id_ed25519" ] || echo "FAKE-DEMO-KEY" > "$DEMO_HOME/.ssh/id_ed25519"
chmod 700 "$DEMO_HOME/.ssh"
chmod 600 "$DEMO_HOME/.ssh/id_ed25519" "$DEMO_HOME/.npmrc"

# Two files with the SAME basename, in different parents. The demo reads both,
# and only the one the rule names is denied — which is what a two-segment kernel
# key buys, and it does not show at all without the second file to compare.
echo "aws_secret_access_key=demo-not-real" > "$DEMO_HOME/.aws/credentials"
echo "not a secret; just named like one" > "$DEMO_HOME/wardyn-demo/credentials"
chmod 600 "$DEMO_HOME/.aws/credentials"
chmod 644 "$DEMO_HOME/wardyn-demo/credentials"

if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ]; then
  chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" \
    "$DEMO_HOME/wardyn-demo" "$DEMO_HOME/.ssh" "$DEMO_HOME/.aws" "$DEMO_HOME/.npmrc"
fi

echo "demo fixtures ready in $DEMO_HOME"
