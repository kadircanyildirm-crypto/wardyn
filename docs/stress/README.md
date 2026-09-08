<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# The stress suite — how real is it?

Four scenarios that try to break wardyn rather than demonstrate it, each
recorded separately. The scripts are in [`scripts/stress/`](../../scripts/stress);
`just stress` runs all four, `just stress-record` re-records them.

Everything here runs against the same policy —
[`scripts/stress/policy.yaml`](../../scripts/stress/policy.yaml), sixteen lines —
so nothing is stopped by a rule you cannot see.

Two rules the suite holds itself to, learned by getting them wrong first:

- **A failed setup step is not a blocked attack.** `cat` failing because the
  file was never created reads exactly like `cat` being denied. Scenario 1
  reports `setup denied` and `read denied` separately for that reason.
- **A missing tool is not a passing grade.** `bpftool` is not installed
  everywhere, and "command not found" would have counted as "the kernel refused
  you". Scenario 2 issues `bpf(2)` directly; scenario 4 skips tools that are
  absent instead of scoring them.

---

## 1 · Every known way around a secret-file rule

![escape](wardyn-stress-escape.gif)

Eight attacks: read it directly, rename it and read the new name, hard link it
into the project, rename the *directory* it lives in, symlink to it, walk to it
through `../`. Then three ordinary operations that must keep working.

**8 attacks, 8 stopped, nothing ordinary broken.**

The second half of the recording is the control: the same attacks, the same
fixtures, the same binary — with `path:` (dev, ino) rules rewritten as globs.
The hard link goes straight through. That comparison is the point; without it,
"8 blocked" says nothing about *why*.

## 2 · The agent attacks the warden instead of the secret

![self-defence](wardyn-stress-selfdefence.gif)

Fifteen attempts to disable the thing watching: reach the BPF maps, read
wardyn's memory and descriptors, read `/proc/kcore` and the raw disk, kill
wardyn, kill every root process, regain privilege through a setuid binary,
escape into a new user namespace, rewrite the policy, delete the audit log.

**14 refused.** The one that worked — appending to a policy file — is the
documented weakness wardyn warns about at startup, and the very next line shows
the secret still denied: the running policy is already in kernel maps, so a file
edit reaches the *next* run.

The user namespace is created (unprivileged userns is enabled on most distros),
and then asked to do the two things the agent actually wants. It can do neither.

## 3 · 450 processes and 40,000 opens: what breaks first?

![load](wardyn-stress-load.gif)

Enforcement lives in the kernel hooks; observation lives in a ring buffer. Only
one of those can be outrun, and the suite exists to show which.

**The secret stayed denied through all three loads. ~13,000 events were dropped
— and wardyn said so, in numbers.**

A drop is a reporting loss, not an enforcement loss. A *silent* drop would be
neither: it would be a clean log that means nothing.

## 4 · Does real work still happen?

![real work](wardyn-stress-realwork.gif)

The other half of the question. A sandbox that denies everything passes every
attack test and gets switched off on the second day.

git init/add/commit/diff/branch, gcc, make, python3, 300 files created, read,
tarred and deleted — under the same `--enforce` policy the attacks ran against.

**15 operations, none broken**, and the vault is still blocked and egress still
denied at the end.

---

## Running them

```console
$ bash scripts/stress/setup.sh          # fixtures, off-camera
$ just stress                           # all four, against the same policy
$ just stress 01-escape                 # or one
```

Needs a BPF-LSM kernel (`just check-lsm`). Without one the file and lifecycle
hooks never attach, every attack "succeeds", and the suite reports that rather
than passing quietly.
