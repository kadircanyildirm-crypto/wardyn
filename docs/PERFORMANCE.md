<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# What wardyn costs

Wardyn sits in the path of every `open`, `exec` and `connect` a watched subtree
makes. That is not free, and a security tool that has never published a number
is asking to be trusted about the one thing users can measure themselves.

Reproduce with `sudo bash scripts/bench.sh [reps]`. The script is checked in;
run it on your own kernel rather than trusting the table below.

## Two costs, not one

They behave completely differently, and a single percentage hides that:

| | what it is | when you feel it |
| --- | --- | --- |
| **startup** | compiling the policy, loading and attaching ~21 eBPF programs, parsing kernel BTF | once per run, whatever the agent then does |
| **marginal** | one ring-buffer record parsed, evaluated against the policy and rendered — plus the in-kernel matcher under `--enforce` | per event, forever |

A percentage over a short command is almost entirely the first. Over a long
session it is almost entirely the second.

## Measured

Kernel 6.18 x86_64 (WSL2), BPF-LSM active, the shipped `policy.yaml`, medians of
5 runs.

### Startup

| | |
| --- | --- |
| observing | **~0.9 s** |
| `--enforce` | **~2.2 s** |

Enforcing costs more because it additionally loads and attaches the seven
lifecycle LSM programs, `file_open` and `bprm_check_security`, and resolves
struct offsets out of `/sys/kernel/btf/vmlinux`.

**This is the number that should change what you do.** Wrapping a 100 ms command
in wardyn makes it a 2.3 s command. Wardyn is for supervising a session, not for
wrapping individual commands in a loop.

It is also the noisiest measurement here — it ranged 1.4–2.7 s across runs,
because BTF parsing is I/O that the page cache absorbs after the first run.

### Marginal

Measured as a **slope**: the same workload at N and at 2N events, difference
divided by N. Whatever the run costs before the first event cancels out.

| workload | unsupervised | observing | `--enforce` |
| --- | --- | --- | --- |
| `open` (20k → 40k) | 5 µs | 20 µs | 22 µs |
| `exec` (2k → 4k) | 534 µs | 561 µs | 702 µs |

So roughly **+15 µs per file open** observing, **+17 µs enforcing**. An exec is
not one event — the loader opens ~20 files — so the per-exec figure includes
those.

No events were dropped and the watch set never filled at 40 000 opens, which is
the check that makes the rest of the table mean anything: a fast run that lost
events is not a fast run, and wardyn counts drops in the kernel and reports them
at exit.

## What these numbers are not

- **They are not from a quiet machine.** WSL2 under a desktop is noisy; the
  `exec` workload varied by ±30 % run to run, which is why the script reports the
  spread and refuses to print a slope smaller than it. Treat the table as an
  order of magnitude.
- **The workloads are deliberately extreme.** A tight `while` loop doing nothing
  but reopening one file is the worst case by construction — nothing dilutes the
  overhead. A real agent spends most of its wall clock waiting on a model, and
  will see a far smaller fraction.
- **The split between kernel and userspace is unmeasured.** The marginal cost
  covers the eBPF hook, the ring buffer, the userspace policy mirror (which
  glob-matches the path) and rendering the feed row. Which of those dominates
  has not been isolated, so no conclusion is offered about where to optimise.
- **Enforcement adds less than observation does.** +15 µs to observe, +2 µs more
  to also enforce. That ordering is worth stating because it is the opposite of
  the intuition that blocking is the expensive part: the in-kernel matcher is a
  handful of hash lookups, while shipping an event to userspace and evaluating a
  policy against it is the bulk of the cost.

## A methodology note

The first version of this benchmark measured startup separately and subtracted
it from the workload time. That reported `--enforce` as **cheaper** than
observing — impossible, and the clue that the method was wrong: subtracting a
constant that itself varies by a factor of five amplifies its noise instead of
removing it. The slope method has no such term.
