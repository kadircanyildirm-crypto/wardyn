#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Fixtures for the stress suite, created BEFORE wardyn starts — the policies
# under test block creating files where these live, so a script that made its
# own from inside the watched tree would be denied by the rule it is there to
# attack.
#
#   bash scripts/stress/setup.sh
set -u

USER_NAME="${SUDO_USER:-$USER}"
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"
HOME_DIR="${HOME_DIR:-$HOME}"
W="$HOME_DIR/wardyn-stress"

rm -rf "$W"
mkdir -p "$W/project" "$W/vault" "$W/elsewhere"

# The thing every scenario is trying to read.
echo "SECRET_API_KEY=sk-stress-not-real" >"$W/vault/.env"
echo "PRIVATE-KEY-MATERIAL"              >"$W/vault/id_ed25519"
# A secret whose NAME gives nothing away. It is what separates "block the
# directory by identity" from "block **/vault/**": rename the directory and the
# glob has nothing left to match, while the inode is unchanged.
echo "STRIPE_LIVE_KEY=sk_live_not_real"  >"$W/vault/notes.txt"
chmod 600 "$W/vault/.env" "$W/vault/id_ed25519" "$W/vault/notes.txt"

# Ordinary files, so "denied" can be told apart from "nothing works".
echo "public, boring"       >"$W/project/README.md"
echo "also fine"            >"$W/project/main.rs"
echo "not a secret at all"  >"$W/elsewhere/notes.txt"

# A deep tree, for the ancestor walk and for load.
mkdir -p "$W/project/a/b/c/d/e/f/g/h"
echo "deep but harmless" >"$W/project/a/b/c/d/e/f/g/h/leaf.txt"

if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ]; then
  chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$W"
fi
echo "fixtures: $W"
