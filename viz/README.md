<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Kernel view

A 3-D view of a real wardyn run, served locally. Every mark on the scene comes
from wardyn's own `--format json` stream or from the kernel keys `--dry-run`
reports — the keys actually loaded into the BPF maps. **Nothing here is
simulated.** If the run denies nothing, nothing turns red.

```console
# live: wardyn runs the command, the page watches
$ sudo python3 viz/serve.py --policy scripts/stress/policy.yaml -- bash viz/demo-agent.sh

# capture a run once...
$ sudo ./target/release/wardyn --format json --enforce \
      --policy scripts/stress/policy.yaml \
      run -- bash scripts/stress/01-escape.sh > /tmp/capture.jsonl

# ...then replay it as often as you like, with no root and no eBPF
$ python3 viz/serve.py --replay /tmp/capture.jsonl --speed 4
```

Replay wants a captured **`--format json` stream**, not the audit log: the log
deliberately holds only violations, because it is a security record and an
operator should not have to grep a million `ld.so.cache` opens to find the one
denial. The stream carries the allow rows too, which is what the scene needs.
The audit log is also root-owned and `0600` on purpose, so replaying it needs
`sudo` — the server says so rather than dumping a traceback.

Then open **http://localhost:8787**. From Windows this works as-is: WSL2 forwards
localhost.

## The world

| stratum | what it is |
|---|---|
| **userspace** | one tower per *program*, grown by its own traffic. A tower turns red the moment that program is denied something. |
| **syscall boundary** | the grid plane. Past it the agent has no say — it cannot see wardyn, unload it, or race it. |
| **tracepoint** | the outer ring. Observes and reports; it has no verdict to give. |
| **LSM / cgroup hook** | the inner ring. Returns the verdict *inside* the syscall. It flashes red when it refuses. |
| **block keys** | one tile per real kernel key. The tile that matched lifts and lights. |

A syscall is a particle. It falls from its tower, crosses the boundary, and
either passes the hook and sinks through the map layer (allowed) or is turned
around at the hook and thrown back up in red (denied). **The turn is the
denial** — that is the whole picture.

## Choices worth knowing about

**Towers are per program, not per pid.** A shell loop spawns a fresh `cat` every
iteration; a tower per pid gave four hundred of them in a minute and hid the
kernel behind a forest. The live pid count rides on the label (`cat ×51`), so
nothing about the tree is lost.

**Events can outrun the page, and it says so.** A real run pushes ~110 events a
second. Particles come from a fixed pool of 260; when events arrive faster than
that, the surplus is *counted* in a `COALESCED` readout rather than quietly
dropped. That is the same bargain wardyn makes with its ring buffer, and it
should be visible for the same reason.

**Only one wardyn can run at a time.** The cgroup egress programs attach with
`CgroupAttachMode::Single`, so a second instance cannot attach and fails in a way
that reads as an unrelated error. The server checks for a running wardyn and says
so before starting.

## Files

| | |
|---|---|
| `serve.py` | spawns wardyn, parses `--dry-run` for the real map keys, streams events over SSE. Standard library only. |
| `app.js` | the scene. Pooled particles, shared materials, batched DOM. |
| `index.html` | the HUD: counters, feed, key list, startup notices. |
| `demo-agent.sh` | a long-running agent for the live mode — ordinary work with the occasional reach for something the policy pins. |
| `vendor/three.module.min.js` | three.js r160, MIT, vendored so the page works offline. |
