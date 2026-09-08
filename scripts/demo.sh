#!/usr/bin/env bash
# Generates a clean allow / warn / block mix so the Wardyn TUI (and audit log)
# have something to show. Runs ~8s and exits (Wardyn auto-quits when it does).
#
# Fixtures come from `scripts/demo-setup.sh`, which must run BEFORE wardyn: the
# policy blocks creating files under `~/.ssh`, so making them from in here would
# be denied by the rule they exist to demonstrate.
#
#   bash scripts/demo-setup.sh
#   sudo /path/to/wardyn --enforce run -- bash scripts/demo.sh
set -u

# Every exec here (cat, timeout, rm, touch, sleep) calls setlocale, and under a
# UTF-8 locale glibc opens ~30 files per process to find it. That is real
# activity and wardyn is right to show it — but in a 20-second demo it is all
# anyone sees. The C locale is built in and needs no files, so the feed shows
# what the demo is about instead of scrolling `LC_MEASUREMENT` past the viewer.
export LC_ALL=C LANG=C

# NOT $HOME. `wardyn run` drops the agent to $SUDO_UID before exec but leaves the
# environment alone, so $HOME is still root's — and the demo would read paths
# that do not exist, showing rules firing on names with nothing behind them.
# Ask the passwd database who this process actually is.
HOME_DIR="$(getent passwd "$(id -un)" | cut -d: -f6)"
HOME_DIR="${HOME_DIR:-$HOME}"
DEMO="$HOME_DIR/wardyn-demo"

for _ in 1 2 3 4 5; do
  # ── file reads ──
  cat /etc/hostname            >/dev/null 2>&1   # open  -> allow
  cat "$DEMO/.env"             >/dev/null 2>&1   # open  -> BLOCK  (**/.env)
  cat "$HOME_DIR/.ssh/id_ed25519" >/dev/null 2>&1  # open  -> BLOCK  (**/.ssh/**)
  cat "$HOME_DIR/.npmrc"         >/dev/null 2>&1   # open  -> warn   (**/.npmrc)
  # ── destroying files, which is not a read ──
  # `file_open` never fires for unlink(2), so these are the lifecycle hooks:
  # the `access: all` rule on ~/.ssh covers removing what is under it, and
  # creating anything new in it.
  rm -f "$HOME_DIR/.ssh/id_ed25519"      2>/dev/null   # unlink -> BLOCK
  touch "$HOME_DIR/.ssh/authorized_keys" 2>/dev/null   # create -> BLOCK
  # ── outbound connections (bash /dev/tcp; connect() fires even if refused) ──
  timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22'  2>/dev/null  # connect -> allow (loopback)
  timeout 2 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'   2>/dev/null  # connect -> BLOCK (default deny)

  # ── the same filename, twice: the rule names a parent, so only one is denied ──
  # `**/.aws/credentials` used to compile to the bare name `credentials` and would
  # have denied both of these. The kernel key is `(.aws, credentials)` now, so an
  # `ok` row sits directly under a BLOCK row for an identically named file.
  #
  # Deliberately LAST in the loop, right before the pause: every `cat` and
  # `timeout` above spawns a process that opens ld.so.cache and libc, and those
  # rows are real — wardyn is right to show them — but they scroll a two-line
  # story off the screen in well under a second. Here the pair is what the feed
  # is resting on while the viewer reads it.
  cat "$HOME_DIR/.aws/credentials" >/dev/null 2>&1  # open  -> BLOCK  (**/.aws/credentials)
  cat "$DEMO/credentials"          >/dev/null 2>&1  # open  -> allow  (same name, other parent)
  sleep 2
done
