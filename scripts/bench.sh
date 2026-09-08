#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# What does wardyn cost? Separates the two costs that a single percentage
# conflates, because they behave completely differently:
#
#   * a FIXED startup cost — compiling the policy, loading and attaching the
#     eBPF programs — paid once per run whatever the agent then does;
#   * a MARGINAL per-event cost — one ring-buffer record parsed, evaluated and
#     rendered, plus the in-kernel matcher under --enforce.
#
# A percentage over a short workload is mostly the first, which is why one
# number would be misleading in both directions: alarming for a quick command,
# far too rosy for a long one.
#
# The marginal cost is measured as a SLOPE — the same workload at N and 2N
# events, and the difference divided by N. Subtracting a separately-measured
# startup instead looks simpler and is wrong: startup here varies by a factor of
# five (BTF parsing is I/O that caches), and subtracting a noisy constant from a
# measurement amplifies its noise rather than removing it. The first attempt at
# this script did exactly that and reported --enforce as CHEAPER than observing,
# which is impossible and was the clue.
#
#   sudo bash scripts/bench.sh [reps]
#
# Reports MEDIANS. A mean over a handful of runs on a shared machine reports the
# noise as if it were the measurement.
set -uo pipefail

REPS="${1:-5}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WARDYN="${WARDYN:-$HERE/target/release/wardyn}"
POLICY="${POLICY:-$HERE/policy.yaml}"

# The smaller of the two sizes each workload is run at; the larger is 2×. The
# difference between them is one N's worth of events with the fixed cost
# cancelled out.
OPENS=20000
EXECS=2000

if [[ "$(id -u)" -ne 0 ]]; then
  echo "bench: must run as root (loads eBPF). Try: sudo $0" >&2
  exit 2
fi
if [[ ! -x "$WARDYN" ]]; then
  echo "bench: no binary at $WARDYN — run: cargo build --release" >&2
  exit 2
fi

WS="$(mktemp -d)"
cleanup() { rm -rf "$WS"; }
trap cleanup EXIT
chmod 777 "$WS"
[[ -n "${SUDO_UID:-}" ]] && chown -R "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$WS"

# ── the workloads ───────────────────────────────────────────────────────────
# Deliberately synthetic and deliberately extreme: they do almost nothing but
# the syscall being measured, so nothing dilutes the overhead. A real agent
# spends most of its time waiting on a model, and will see a far smaller
# fraction than anything here.

for mult in 1 2; do
  # shellcheck disable=SC2016  # `$n` is the generated script's variable, not ours
  printf 'n=0\nwhile [ $n -lt %d ]; do read -r _ < /etc/hostname; n=$((n + 1)); done\n' \
    "$((OPENS * mult))" >"$WS/opens.$mult.sh"
  # shellcheck disable=SC2016
  printf 'n=0\nwhile [ $n -lt %d ]; do /bin/true; n=$((n + 1)); done\n' \
    "$((EXECS * mult))" >"$WS/execs.$mult.sh"
done
# The fixed cost on its own: start wardyn, run nothing, stop.
echo ':' >"$WS/nothing.sh"

# ── timing ──────────────────────────────────────────────────────────────────
run_ms() {
  local start end
  start=$(date +%s%N)
  "$@" >/dev/null 2>&1
  end=$(date +%s%N)
  echo $(((end - start) / 1000000))
}

median() {
  local -a v
  mapfile -t v < <(printf '%s\n' "$@" | sort -n)
  echo "${v[$((${#v[@]} / 2))]}"
}

# Run REPS times; print `median (min–max)` to STDERR for the reader and the
# median alone to stdout for the caller. Two streams, because a function that
# both reports and returns has to keep them apart or the report ends up inside
# the return value.
measure() {
  local label="$1"
  shift
  local -a samples=()
  for _ in $(seq "$REPS"); do
    samples+=("$(run_ms "$@")")
  done
  local med min max
  med="$(median "${samples[@]}")"
  min="$(printf '%s\n' "${samples[@]}" | sort -n | head -1)"
  max="$(printf '%s\n' "${samples[@]}" | sort -n | tail -1)"
  printf '  %-32s %6s ms   (%s–%s)\n' "$label" "$med" "$min" "$max" >&2
  # The caller needs the spread as well: a difference smaller than the
  # run-to-run variation is not a measurement, and saying `0 µs/event` for it
  # would be a claim this machine cannot support.
  echo "$med $((max - min))"
}

under_wardyn() {
  local mode="$1" script="$2"
  if [[ "$mode" == enforce ]]; then
    "$WARDYN" --enforce --plain --policy "$POLICY" --audit "$WS/a.jsonl" run -- bash "$script"
  else
    "$WARDYN" --plain --policy "$POLICY" --audit "$WS/a.jsonl" run -- bash "$script"
  fi
}

echo "wardyn benchmark"
echo "  kernel:   $(uname -r) $(uname -m)"
echo "  BPF-LSM:  $(grep -qw bpf /sys/kernel/security/lsm 2>/dev/null && echo active || echo INACTIVE)"
echo "  policy:   $POLICY"
echo "  reps:     $REPS (median reported)"
echo

echo "── fixed cost: start, supervise nothing, stop"
read -r BARE _ < <(measure "bash -c ':'" bash "$WS/nothing.sh")
read -r START_OBS _ < <(measure "wardyn (observe)" under_wardyn observe "$WS/nothing.sh")
read -r START_ENF _ < <(measure "wardyn --enforce" under_wardyn enforce "$WS/nothing.sh")
STARTUP_OBS=$((START_OBS - BARE))
STARTUP_ENF=$((START_ENF - BARE))
printf '  → startup: %d ms observing, %d ms enforcing\n\n' "$STARTUP_OBS" "$STARTUP_ENF"

# ── marginal cost, as a slope ───────────────────────────────────────────────
# (t at 2N − t at N) / N. Whatever the run costs before the first event —
# startup, teardown, the shell — appears in both terms and cancels.
slope_us() {
  local t1="$1" t2="$2" n="$3" spread="$4"
  local delta=$((t2 - t1))
  # A slope smaller than the run-to-run spread is not a measurement. Reporting
  # it as a number would be false precision; reporting it as 0 would read as
  # "free", which is a stronger claim than "not resolvable on this machine".
  if [[ "$delta" -lt "$spread" ]]; then
    echo "under the ${spread}ms noise"
    return
  fi
  echo "$((delta * 1000 / n)) µs/event"
}

for workload in opens execs; do
  n=$([[ "$workload" == opens ]] && echo "$OPENS" || echo "$EXECS")
  echo "── $workload — slope between $n and $((n * 2)) events"
  read -r b1 bs < <(measure "unsupervised @${n}" bash "$WS/$workload.1.sh")
  read -r b2 _ < <(measure "unsupervised @$((n * 2))" bash "$WS/$workload.2.sh")
  read -r o1 os < <(measure "observe @${n}" under_wardyn observe "$WS/$workload.1.sh")
  read -r o2 _ < <(measure "observe @$((n * 2))" under_wardyn observe "$WS/$workload.2.sh")
  read -r e1 es < <(measure "enforce @${n}" under_wardyn enforce "$WS/$workload.1.sh")
  read -r e2 _ < <(measure "enforce @$((n * 2))" under_wardyn enforce "$WS/$workload.2.sh")
  printf '  → %-28s %s\n' "unsupervised" "$(slope_us "$b1" "$b2" "$n" "$bs")"
  printf '  → %-28s %s\n' "observe" "$(slope_us "$o1" "$o2" "$n" "$os")"
  printf '  → %-28s %s\n' "enforce" "$(slope_us "$e1" "$e2" "$n" "$es")"
  echo
done

# The number that says whether the numbers above mean anything: wardyn reports
# ring-buffer drops at exit, and a fast run that lost events is not a fast run.
echo "── event loss under the heaviest workload"
LOSS="$(under_wardyn enforce "$WS/opens.2.sh" 2>&1 >/dev/null | grep -E 'dropped|watch set filled' || true)"
if [[ -z "$LOSS" ]]; then
  echo "  no events dropped, watch set never filled"
else
  echo "  $LOSS"
fi
