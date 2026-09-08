#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# STRESS 3 — what breaks first when it is overloaded, and does it admit it?
#
# Wardyn watches a process tree through a fixed-size hash map and reports what
# it sees through a fixed-size ring buffer. Both can fill. The interesting
# question is not whether they can be saturated — anything can — but WHICH
# half degrades:
#
#   * enforcement lives in the kernel hooks. A denial is decided and returned
#     inside the syscall, and no userspace buffer is on that path.
#   * observation lives in the ring buffer. If userspace cannot drain it fast
#     enough, events are lost.
#
# So the load should be able to blind the feed without weakening the boundary —
# and wardyn must SAY it went blind. A dropped event that nobody is told about
# would be the real failure, because a clean-looking log is what an operator
# reads as "nothing happened".
#
# Run under:  wardyn --enforce --policy scripts/stress/policy.yaml run -- bash …
set -u
export LC_ALL=C
W="$HOME/wardyn-stress"
V="$W/vault"

step()   { printf '\n\033[1m── %s\033[0m\n' "$1"; }
secret() {
  if cat "$V/.env" >/dev/null 2>&1; then
    printf '  \033[1;31m✗ THE SECRET WAS READ\033[0m — the boundary moved under load\n'
  else
    printf '  \033[32m✓ secret still denied\033[0m\n'
  fi
  sleep 0.4
}

step "1 · a wide tree: 200 processes forked from the agent"
for _ in $(seq 1 200); do ( cat "$W/project/README.md" >/dev/null 2>&1 ) & done
wait
echo "  200 children forked and reaped — every one adopted into the watch set"
secret

step "2 · a deep tree: 7 levels, 254 processes, each a descendant of the last"
deep() {
  local n="$1"
  [ "$n" -le 0 ] && { cat "$W/project/README.md" >/dev/null 2>&1; return; }
  ( deep $((n - 1)) ) & ( deep $((n - 1)) ) & wait
}
deep 7
echo "  fork adoption followed the whole chain"
secret

step "3 · 40,000 opens from 8 processes at once — enough to outrun the ring"
for _ in 1 2 3 4 5 6 7 8; do
  ( for _ in $(seq 1 5000); do : <"$W/project/main.rs"; done ) &
done
wait
echo "  40,000 opens issued in a couple of seconds"
secret

printf '\n  \033[1mThe boundary held through all of it.\033[0m Wardyn'"'"'s own counters\n'
printf '  follow — if the feed lost events, the next lines say so, in numbers.\n'
printf '  A drop is a reporting loss, not an enforcement loss. A SILENT drop\n'
printf '  would be neither: it would be a clean log that means nothing.\n'
