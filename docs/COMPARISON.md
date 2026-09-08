<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Wardyn vs. the field — an honest comparison

Wardyn is often mistaken for a *sandbox*. It isn't one, and it shouldn't try to
be. This page places it honestly next to the tools it is compared to, says
plainly what Wardyn does **not** do, and explains why the right posture is
usually **Wardyn *alongside* a sandbox, not instead of one**.

> ⚠️ **Verify before you cite.** The capability notes about third-party tools
> below reflect our best understanding at the time of writing and can change
> release to release. Confirm the current behaviour of any tool before relying
> on this table in a security decision.

## What Wardyn actually is

A **process-subtree supervisor**: you launch a command, Wardyn scopes an eBPF
policy to *that* subtree (followed across `fork`), observes every `exec` / `open`
/ `connect`, and — under `--enforce` — denies blocked file opens and execs (BPF
LSM), blocked removals and creations (seven more LSM hooks), and blocked egress
(cgroup `connect`/`sendmsg`). It leaves a durable JSONL **audit trail** and hands
the watched agent a machine-readable **denial receipt** so an LLM can learn *why*
an operation failed instead of retrying blindly.

It is a **detective + partial-preventive + feedback** layer. It does not remove
the subtree's ambient authority the way an isolator does.

## Where Wardyn genuinely differs

These are the four things the vendor agent sandboxes and the node-scoped eBPF
tools do **not** give you together:

1. **No user namespaces required.** bubblewrap-based sandboxes need unprivileged
   `user_namespaces`, which are disabled by default on several hardened distros,
   in many CI runners, and inside nested containers. Wardyn needs root + BPF, not
   userns.
2. **Agent-agnostic and retrofit.** Works on *any* process tree — closed-source
   agent CLIs, MCP servers, CI jobs — with zero cooperation from the target. You
   do not have to be the one who wrote the agent.
3. **IP/CIDR egress without a TLS-terminating proxy.** Hostname-allowlisting
   proxies do not see direct-IP connections or non-HTTP protocols. Wardyn denies
   at `connect()`/`sendmsg()` by destination address (IPv4 + IPv6), optionally
   narrowed by `port:` and `proto:`, catching direct-IP exfiltration a hostname
   proxy never inspects.
4. **A forensic record + an agent-facing feedback loop.** An isolator that
   refuses an operation tells you nothing about *what the agent tried*. Wardyn's
   feed and audit log are that record, and `WARDYN_DENIALS` is a channel back
   into the agent's own reasoning.

## What Wardyn does NOT do

Being explicit here is the point — a security tool that oversells is worse than
one that is modest and honest.

- **No allowlist shape — and that is the real limitation.** A rule names what is
  *forbidden*. `access:` can narrow a rule to reads, writes, creations or
  removals, so "may append to this log, may not read it back" and "may not `rm`
  anything under `~/.ssh`" are both expressible. What is *not* expressible is
  "everything is read-only except these three directories": there is no
  read-only-root, and anything a policy forgot to name stays fully writable. An
  isolator inverts that default, which is why the two belong together.
- **No filesystem namespace / containment.** No mount namespace, no chroot, no
  overlay. The whole real filesystem is visible.
- **Name-based rules are still dodgeable by a rename.** The LSM matcher keys a
  `match:` glob on its last two literal segments and on its ancestor directory
  names, which stops *accidental and naive* access and nothing more: `mv .env x` detaches the
  label and the rule stops applying. The fix is to pair it with a `path:` rule,
  which pins `(dev, ino)` and survives rename, hard link and copy — but that is
  something the policy author has to actually do, and a `path:` rule cannot cover
  a file that does not exist yet. Copying a blocked *binary* to a new name still
  runs it, whichever form is used. See [`SECURITY.md`](../SECURITY.md).
- **No content or provenance matching.** Rules describe names and objects, never
  bytes. Wardyn cannot tell a secret from a lookalike, or a trusted binary from a
  copy of one.
- **No defence against a root child (as shipped).** If the watched process runs
  with the same (root) privilege as Wardyn, it can reach the enforcement state.
  Dropping the child to `SUDO_UID` (privilege-drop) is the mitigation — see the
  `run` options.
- **Only partly the agent's protection from itself.** `access: delete` does let a
  policy stop an agent destroying its own work, but Wardyn's centre of gravity is
  still what the subtree reaches *out* to.

## The landscape

| Tool | Category | Scope | Files | Egress | Root? | userns? | Agent feedback | Audit trail |
|---|---|---|---|---|---|---|---|---|
| **Wardyn** | Supervisor (observe + deny + receipt) | One launched subtree | LSM, by name **or** `(dev, ino)` identity; read/write + create/delete | cgroup CIDR, v4/v6, TCP+UDP, `port:` + `proto:` | needs root to load | not required | **yes** (`WARDYN_DENIALS`) | **yes** (JSONL + versioned `--format json` stream) |
| Claude Code sandbox | Isolator | The agent it ships with | bubblewrap FS isolation | allowlisting HTTP(S) proxy | no | typically yes | n/a | limited |
| Codex CLI sandbox | Isolator | The agent it ships with | bubblewrap + Landlock | seccomp net restriction | no | typically yes | n/a | limited |
| Linux **Landlock** | Isolator (kernel LSM) | Inherited across fork/exec | resolved-path hierarchy, ~15 rights: **read/write/exec, remove, make** | TCP bind/connect **by port only** (no CIDR, no UDP) | **no root** | not required | no | ABI≥7 audit (node-wide) |
| bubblewrap / firejail | Isolator | Launched process | mount ns, RO roots | via net ns | no (userns) | needs userns | no | no |
| gVisor | Syscall-interposing runtime | Container | full re-implemented VFS | full | no | no | no | limited |
| sysbox | Container runtime | Container | container rootfs | full | no | no | no | no |
| **Tetragon** | Node/cluster observer+enforcer | Whole node, k8s selectors | kprobe/LSM, TracingPolicy | kprobe | yes (node) | n/a | no | yes (node) |
| **Tracee** / **Falco** | Node runtime detection | Whole node | eBPF events + rules | eBPF events | yes (node) | n/a | no | yes (alerts) |
| seccomp-notify | Syscall broker | Process | syscall-argument level | syscall level | no | needs a supervisor | no | via supervisor |

**Reading the table.** Landlock remains the better file engine wherever the
policy can be written as an allowlist: it is maintained in-tree, needs no struct
offsets, matches on resolved paths rather than basenames, carries read/write/exec
and remove/make rights, and needs no root at all. Its shape is also what makes it
immune to the rename dodge by construction — a sandboxed process reaches only
what was granted, so moving a file cannot grant anything. What it *cannot* do is
express CIDR egress, and it cannot express a blocklist: "everything except these
objects", on a machine whose allowlist you could not enumerate if you tried, is
the case Wardyn's `path:` identity rules exist for.

That is not a scoreboard with a winner. Allowlist and blocklist answer different
questions, and the honest reading of these two rows is that both engines belong
in the same deployment — see the posture below.

Tetragon/Tracee/Falco are *node/cluster-scoped daemons* with no notion of "scope
to this one subtree I just launched from my laptop shell" — Wardyn's whole
premise. The vendor sandboxes are *isolators* that need userns and only work for
the agent they ship with.

## The recommended posture

Use Wardyn **with** an isolator, each doing what it is best at:

- **Filesystem containment** → an isolator (a vendor sandbox, or Landlock via the
  planned `--isolate` mode when the policy is allowlist-shaped). A read-only root
  is theirs to give; Wardyn can deny writes to things a policy *names*, which is
  not the same guarantee.
- **Specific objects that must survive being renamed** → Wardyn. `path:` rules
  pin `(dev, ino)`, so `mv` and `ln` do not shake them off and `access: delete`
  stops the object being removed at all.
- **Egress by address/CIDR (v4+v6, TCP+UDP)** → Wardyn. This is the one axis the
  vendor proxies and Landlock cannot express.
- **Forensic audit + agent-facing denial feedback** → Wardyn. Isolators do not
  produce this, and it is what lets an LLM course-correct instead of retrying.

Being first to say *"use both"* is more credible than claiming to replace either.

## Roadmap implied by this comparison

- **Hybrid engine.** Adopt Landlock for hard filesystem containment when the
  policy is allowlist-shaped (a new `allow_paths:` shape with per-hierarchy
  read/write/exec rights); keep eBPF LSM for blocklist-shaped rules and for the
  observability isolators cannot provide; keep eBPF as the **sole** egress engine.
- **Anchored file matching.** Globs now keep their last *two* literal segments,
  which is what every shipped rule needed; `path:` identity rules cover objects
  the policy can name today. What is left is the difference between a suffix
  and an anchor — `/etc/shadow` still means `etc/shadow` at any depth — and
  objects that do not exist when the policy loads. Landlock's resolved-path
  hierarchies have neither problem, which is one more reason for the hybrid
  above.
- **Metrics.** The structured JSON event stream landed (`--format json`, one
  object per line, versioned per record — see
  [`EVENT_SCHEMA.md`](./EVENT_SCHEMA.md)), so wardyn can be shipped into the
  SIEM layer the node-scoped tools already own. What is still missing is a
  `--metrics-addr` exposing Prometheus counters. Every counter is derivable from
  the stream, so this is convenience rather than capability — and it would mean
  putting an HTTP listener inside a process that runs as root, which is a
  decision worth making deliberately rather than by reflex.

See [`docs/AUDIT.md`](./AUDIT.md) for the full findings this positioning is drawn
from, and [`ARCHITECTURE.md`](../ARCHITECTURE.md) for how enforcement works today.
