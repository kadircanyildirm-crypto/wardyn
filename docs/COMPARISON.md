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
/ `connect`, and — under `--enforce` — denies blocked file opens & execs (BPF
LSM) and blocked egress (cgroup `connect`/`sendmsg`). It leaves a durable JSONL
**audit trail** and hands the watched agent a machine-readable **denial receipt**
so an LLM can learn *why* an operation failed instead of retrying blindly.

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
   at `connect()`/`sendmsg()` by destination address (IPv4 + IPv6, TCP + UDP),
   catching direct-IP exfiltration a hostname proxy never inspects.
4. **A forensic record + an agent-facing feedback loop.** An isolator that
   refuses an operation tells you nothing about *what the agent tried*. Wardyn's
   feed and audit log are that record, and `WARDYN_DENIALS` is a channel back
   into the agent's own reasoning.

## What Wardyn does NOT do

Being explicit here is the point — a security tool that oversells is worse than
one that is modest and honest.

- **No filesystem write protection.** Rules match on *open*, not on the read/
  write intent; the watched tree keeps full write access to everything it can
  reach. There is no read-only-root, no per-path write policy.
- **No filesystem namespace / containment.** No mount namespace, no chroot, no
  overlay. The whole real filesystem is visible.
- **Name-based file/exec blocking is content-blind.** The LSM matcher keys on a
  file's basename and immediate parent-dir name, so it stops *accidental and
  naive* access; it is bypassable by renaming/hard-linking the target (`mv`,
  `link()` are not hooked) and by copying a blocked binary to a new name. See
  [`SECURITY.md`](../SECURITY.md).
- **No defence against a root child (as shipped).** If the watched process runs
  with the same (root) privilege as Wardyn, it can reach the enforcement state.
  Dropping the child to `SUDO_UID` (privilege-drop) is the mitigation — see the
  `run` options.
- **Not the agent's protection from itself.** Wardyn constrains what the agent
  reaches *out* to; it does not prevent the agent from corrupting its own project.

## The landscape

| Tool | Category | Scope | Files | Egress | Root? | userns? | Agent feedback | Audit trail |
|---|---|---|---|---|---|---|---|---|
| **Wardyn** | Supervisor (observe + deny + receipt) | One launched subtree | LSM, name-match (→ full-path planned) | cgroup CIDR, v4/v6, TCP+UDP | needs root to load | not required | **yes** (`WARDYN_DENIALS`) | **yes** (JSONL) |
| Claude Code sandbox | Isolator | The agent it ships with | bubblewrap FS isolation | allowlisting HTTP(S) proxy | no | typically yes | n/a | limited |
| Codex CLI sandbox | Isolator | The agent it ships with | bubblewrap + Landlock | seccomp net restriction | no | typically yes | n/a | limited |
| Linux **Landlock** | Isolator (kernel LSM) | Inherited across fork/exec | resolved-path hierarchy, ~15 rights, **read/write/exec** | TCP bind/connect **by port only** (no CIDR, no UDP) | **no root** | not required | no | ABI≥7 audit (node-wide) |
| bubblewrap / firejail | Isolator | Launched process | mount ns, RO roots | via net ns | no (userns) | needs userns | no | no |
| gVisor | Syscall-interposing runtime | Container | full re-implemented VFS | full | no | no | no | limited |
| sysbox | Container runtime | Container | container rootfs | full | no | no | no | no |
| **Tetragon** | Node/cluster observer+enforcer | Whole node, k8s selectors | kprobe/LSM, TracingPolicy | kprobe | yes (node) | n/a | no | yes (node) |
| **Tracee** / **Falco** | Node runtime detection | Whole node | eBPF events + rules | eBPF events | yes (node) | n/a | no | yes (alerts) |
| seccomp-notify | Syscall broker | Process | syscall-argument level | syscall level | no | needs a supervisor | no | via supervisor |

**Reading the table.** Landlock is *strictly better than Wardyn on the file
axis* (maintained in-tree, no offsets, resolved-path, read/write/exec rights, no
root) but *cannot express CIDR egress at all*. Tetragon/Tracee/Falco are
*node/cluster-scoped daemons* with no notion of "scope to this one subtree I just
launched from my laptop shell" — Wardyn's whole premise. The vendor sandboxes are
*isolators* that need userns and only work for the agent they ship with.

## The recommended posture

Use Wardyn **with** an isolator, each doing what it is best at:

- **Filesystem containment** → an isolator (a vendor sandbox, or Landlock via the
  planned `--isolate` mode when the policy is allowlist-shaped). Hard write
  protection is theirs to give.
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
- **Full-path file matching** (removing the basename limitation) so the file axis
  is competitive even without Landlock.
- **Structured JSON event stream + metrics** so Wardyn plugs into the SIEM/alerting
  layer the node-scoped tools already own.

See [`docs/AUDIT.md`](./AUDIT.md) for the full findings this positioning is drawn
from, and [`ARCHITECTURE.md`](../ARCHITECTURE.md) for how enforcement works today.
