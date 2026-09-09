#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# A long-running agent for the kernel view: a loop of ordinary work with the
# occasional reach for something the policy pins, so the scene has both colours
# in it. Nothing here is staged for the camera — every row the page draws is a
# real event the kernel reported.
set -u
export LC_ALL=C
W="$HOME/wardyn-stress"
for i in $(seq 1 400); do
  cat "$W/project/README.md" >/dev/null 2>&1
  cat "$W/project/main.rs"   >/dev/null 2>&1
  cat "$W/project/a/b/c/d/e/f/g/h/leaf.txt" >/dev/null 2>&1
  # every few rounds, try the thing the policy names
  if [ $((i % 4)) -eq 0 ]; then
    cat "$W/vault/.env"       >/dev/null 2>&1
    cat "$W/vault/id_ed25519" >/dev/null 2>&1
  fi
  # and once in a while, a subprocess, so the tree grows
  if [ $((i % 9)) -eq 0 ]; then ( head -c 1 "$W/project/README.md" >/dev/null 2>&1 ) & fi
  sleep 0.45
done
wait
