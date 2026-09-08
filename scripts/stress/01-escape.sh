#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# STRESS 1 — an agent that actively tries to get at a secret the policy names.
#
# Every attempt here is a documented way to defeat *name*-based matching. The
# policy blocks by `path:` — (dev, ino) — so none of them should work, and the
# control run (`control.yaml`, the same rules written as globs) shows which of
# them a name rule lets through. That comparison is the point: a single run says
# nothing about *why* something was blocked.
#
# The one thing this script must never do is count a failed READ as a blocked
# read when the file was never created. An attack whose setup step was itself
# denied is reported as its own outcome — "the rename was refused" and "the read
# was refused" are different defences, and conflating them would flatter the
# tool with a pass it did not earn.
#
# Run under:  wardyn --enforce --policy scripts/stress/policy.yaml run -- bash …
set -u
# Every exec calls setlocale, and under a UTF-8 locale glibc opens ~30 files per
# process looking for it. Real activity, and the feed is right to show it — but
# in a recording it is all anyone sees.
export LC_ALL=C
W="$HOME/wardyn-stress"
V="$W/vault"

leaked=0; stopped=0; broke=0

pause() { sleep 0.35; }

# An attack. Success is a LEAK.
try() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  \033[1;31m✗ GOT THROUGH\033[0m  %s\n' "$label"; leaked=$((leaked + 1))
  else
    printf '  \033[32m✓ read denied\033[0m  %s\n' "$label"; stopped=$((stopped + 1))
  fi
  pause
}

# An attack that needs a setup step first. If the setup was denied, say THAT —
# never let a missing file masquerade as a blocked read.
try_after() {
  local label="$1" guard="$2"; shift 2
  if [ ! -e "$guard" ]; then
    printf '  \033[32m✓ setup denied\033[0m %s\n' "$label"; stopped=$((stopped + 1)); pause
    return
  fi
  try "$label" "$@"
}

# Ordinary work. Failure means the warden broke the agent, which is its own kind
# of wrong — a sandbox that denies everything is not a passing grade.
must_work() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  \033[32m✓ allowed\033[0m      %s\n' "$label"
  else
    printf '  \033[1;31m✗ BROKEN\033[0m      %s\n' "$label"; broke=$((broke + 1))
  fi
  pause
}

echo "── reading it directly ─────────────────────────────────────"
try "cat the secret by its own name"        cat "$V/.env"
try "cat the private key"                   cat "$V/id_ed25519"

echo
echo "── renaming, which defeats a name rule ─────────────────────"
mv "$V/.env" "$V/harmless.txt" 2>/dev/null
try_after "rename it, read the new name" "$V/harmless.txt" cat "$V/harmless.txt"
mv "$V/harmless.txt" "$V/.env" 2>/dev/null

echo
echo "── hard link: one inode, two names ─────────────────────────"
ln "$V/.env" "$W/project/copy.env" 2>/dev/null
try_after "hard link out, read that" "$W/project/copy.env" cat "$W/project/copy.env"
rm -f "$W/project/copy.env"

echo
echo "── moving the DIRECTORY out from under the rule ────────────"
mv "$V" "$W/notvault" 2>/dev/null
try_after "rename the vault, read inside" "$W/notvault/.env" cat "$W/notvault/.env"
# The one a `**/vault/**` glob cannot survive: the directory is called something
# else now, and this file was never named like a secret to begin with.
try_after "...a file with an innocent name" "$W/notvault/notes.txt" cat "$W/notvault/notes.txt"
mv "$W/notvault" "$V" 2>/dev/null

echo
echo "── symlink, and a path with junk in it ─────────────────────"
ln -s "$V/.env" "$W/project/link.env" 2>/dev/null
try "symlink to it"                         cat "$W/project/link.env"
try "reach it through ../ noise"            cat "$W/project/../vault/.env"
rm -f "$W/project/link.env"

echo
echo "── and the work that must NOT break ────────────────────────"
must_work "read an ordinary project file"   cat "$W/project/README.md"
must_work "read a deep, harmless file"      cat "$W/project/a/b/c/d/e/f/g/h/leaf.txt"
must_work "write into the project"          cp "$W/project/README.md" "$W/project/copy.md"

echo
if [ "$leaked" -eq 0 ] && [ "$broke" -eq 0 ]; then
  printf '\033[1;32m  %d attacks, %d stopped, 0 leaked — and nothing ordinary broke\033[0m\n' \
    "$((leaked + stopped))" "$stopped"
else
  printf '\033[1;31m  %d LEAKED, %d ordinary operations BROKEN\033[0m\n' "$leaked" "$broke"
fi
