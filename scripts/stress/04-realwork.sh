#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# STRESS 4 — the other half of the question.
#
# Scenarios 1–3 ask whether the boundary holds. This one asks the thing that
# decides whether anyone keeps it switched on: does ordinary work still happen?
#
# A sandbox that denies everything passes every attack test and gets removed on
# the second day. So this runs a real toolchain — git, a C compiler, python,
# node — through a normal edit/build/commit loop, under the same `--enforce`
# policy the attack scenarios ran against, and counts anything that breaks.
#
# The two rules from that policy that could plausibly get in the way are still
# there: the vault is blocked by inode, and egress to anything off-loopback is
# denied. Both are exercised at the end, on purpose.
#
# Run under:  wardyn --enforce --policy scripts/stress/policy.yaml run -- bash …
set -u
export LC_ALL=C
W="$HOME/wardyn-stress"
R="$W/realwork"
rm -rf "$R"; mkdir -p "$R"; cd "$R" || exit 1

worked=0; broke=0; skipped=0
step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }
ok() { # ok <label> <command...>
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  \033[32m✓\033[0m %s\n' "$label"; worked=$((worked + 1))
  else
    printf '  \033[1;31m✗ BROKE\033[0m %s\n' "$label"; broke=$((broke + 1))
  fi
  sleep 0.3
}

# A tool that is not installed is not a sandbox failure. Counting it as one
# would let whatever happens to be on the box decide whether wardyn passes.
need() { # need <tool> <label> <command...>
  local tool="$1" label="$2"; shift 2
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '  \033[33m∼ skipped\033[0m %s (%s is not installed)\n' "$label" "$tool"
    skipped=$((skipped + 1)); sleep 0.2; return
  fi
  ok "$label" "$@"
}

step "git — the thing every agent touches first"
ok "git init"                git init -q .
ok "write a source file"     bash -c 'printf "int main(void){return 0;}\n" > main.c'
ok "git add"                 git add main.c
ok "git -c user commit"      git -c user.email=a@b -c user.name=agent commit -qm "first"
ok "edit and diff"           bash -c 'printf "int main(void){return 1;}\n" > main.c; git diff --quiet; [ $? -eq 1 ]'
ok "git log"                 git log --oneline
ok "branch and checkout"     bash -c 'git checkout -qb feature && git checkout -q -'

step "a compiler — a real toolchain, hundreds of file opens per invocation"
ok "gcc compiles"            gcc -O2 -o prog main.c
ok "the binary runs"         bash -c './prog; [ $? -eq 1 ]'
ok "make from a Makefile"    bash -c 'printf "all:\n\tgcc -o prog2 main.c\n" > Makefile && make -s'

step "interpreters — they read a lot of their own runtime"
need python3 "python3 runs a script" python3 -c "import json,os; json.dumps({'ok': os.getpid()})"
need node    "node runs a script"    node -e "process.exit(0)"

step "the ordinary filesystem churn of a build"
# shellcheck disable=SC2016  # the loop belongs to the inner shell; expanding
# `$i` out here would write the same filename 300 times.
ok "create 300 files"        bash -c 'mkdir -p src && for i in $(seq 1 300); do echo "// $i" > "src/f$i.c"; done'
ok "read them all back"      bash -c 'cat src/*.c > /dev/null'
ok "tar them up"             tar -czf src.tgz src
ok "delete them again"       bash -c 'rm -rf src'

step "and the two rules that are still in force"
if cat "$W/vault/.env" >/dev/null 2>&1; then
  printf '  \033[1;31m✗ the vault was readable\033[0m\n'; broke=$((broke + 1))
else
  printf '  \033[32m✓\033[0m the vault is still blocked — real work did not widen it\n'
fi
sleep 0.3
if timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
  printf '  \033[1;31m✗ egress to 1.1.1.1 succeeded\033[0m\n'; broke=$((broke + 1))
else
  printf '  \033[32m✓\033[0m egress off-loopback still denied\n'
fi
sleep 0.3

echo
if [ "$broke" -eq 0 ]; then
  printf '\033[1;32m  %d ordinary operations, none broken — and the boundary is where it was\033[0m\n' "$worked"
  [ "$skipped" -gt 0 ] && printf '  (%d skipped: not installed on this machine)\n' "$skipped"
else
  printf '\033[1;31m  %d of %d ordinary operations BROKE under enforcement\033[0m\n' \
    "$broke" "$((worked + broke))"
fi
