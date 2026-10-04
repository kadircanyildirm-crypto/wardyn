<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Wardyn vs. the field — an honest comparison

Wardyn is often mistaken for a *sandbox*. It isn't one, and it shouldn't try to
be. This page places it honestly next to the tools it is compared to, says
plainly what Wardyn does **not** do, and names the project that is closest to
it — which, since this page was first written, turns out to be very close
indeed.

> ⚠️ **Verify before you cite.** Every capability note about a third-party tool
> below was checked against that project's own documentation on the date in the
> heading, and tools change release to release. Where a project's docs are
> silent on something, this page says *"not documented"* rather than *"does not
> have"* — the difference matters and is easy to get wrong in your own favour.
>
> **Last checked: 2026-10-04.**

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

## The closest project: the eunomia stack

This section did not exist when the page was written, and it is the most
important one on it.

[**ActPlane**](https://github.com/eunomia-bpf/ActPlane)
([arXiv:2606.25189](https://arxiv.org/abs/2606.25189), UC Santa Cruz / Virginia
Tech / HKUST / Alibaba) is, to a first approximation, the same product as
Wardyn: eBPF plus BPF-LSM, a hook set its README gives as
`fork / exec / exit / open / unlink / rename / connect`, a YAML policy compiled
into the kernel, scoped to the agent's process tree, and a human-readable reason
fed back to the agent when a rule fires. MIT licensed, written in Rust with C
for the kernel side, installable with `cargo install actplane`, and shipping
**pre-compiled CO-RE objects**. 103 stars, 10 forks.

[**AgentSight**](https://github.com/eunomia-bpf/agentsight)
([arXiv:2508.02736](https://arxiv.org/abs/2508.02736), published at ACM) is the
observability half: eBPF boundary tracing that reads TLS traffic with uprobes to
recover what the agent *intended* and correlates it with kernel events, at a
stated overhead below 3%. [**actime**](https://github.com/eunomia-bpf/actime)
packages both plus session backup behind `actime run -- claude` — the same
command shape as `wardyn run -- claude`.

Being honest about what that means for this project:

- **"Agent-agnostic, retrofit, no cooperation required" is no longer
  distinctive.** ActPlane does it too.
- **"A feedback loop into the agent's reasoning" is no longer distinctive.**
  ActPlane feeds its `because` clause through the harness's hook system.
  Wardyn's `wardyn hook` does the same thing; it is parity, not a lead.
- **They measured the thing this project asserts.** ActPlane's paper reports a
  dangerous-command refusal rate against a baseline, and a recovery rate with
  and without feedback. Wardyn has, as of this writing, a coverage benchmark of
  its own (see the README) but no comparable agent-behaviour study.
- **Their portability story is better.** CO-RE is a real advantage over runtime
  BTF offset resolution with a baked-in fallback, which has silently failed open
  on this project once already.

What Wardyn still has that their documentation does not describe, checked on the
date above — stated as *not documented*, because absence from a README is not
absence from a tool:

| | Wardyn | ActPlane (per its README) |
| --- | --- | --- |
| egress by **CIDR**, v4+v6, TCP+UDP, with `port:`/`proto:` | yes, cgroup `connect4/6` + `sendmsg4/6` | `connect` hook listed; CIDR/port syntax not documented |
| filesystem **allowlist** (Landlock `allow_paths:` / `allow_ports:`) | yes, in the same tool | not documented |
| rules keyed on **`(dev, ino)`**, surviving rename/hard link | yes | not documented |
| **privilege drop** of the watched process before `exec` | yes, default | not documented |
| **policy decision separated from kernel-confirmed denial** | yes — `action` vs `enforced`, `block~`, exit cross-check | not documented |

That last row is the one to defend. Everything else on this list is a feature
someone could add in a sprint; a tool that refuses to claim a denial the kernel
did not make is a different posture, and it is the reason this project publishes
[its own audit of its own bypasses](./AUDIT.md) and attaches an enforcement
transcript to every release.

## Where Wardyn genuinely differs

Narrower than this list used to be, deliberately:

1. **No user namespaces required.** bubblewrap-based sandboxes need unprivileged
   `user_namespaces`, which are disabled by default on several hardened distros,
   in many CI runners, and inside nested containers. Wardyn needs root + BPF, not
   userns.
2. **It watches the whole subtree, not just the shell tool.** Claude Code's
   sandbox, by its own documentation, "wraps shell commands" — file tools, local
   MCP servers, command hooks, LSP servers and `excludedCommands` run outside it.
   Wardyn's scope is the process tree, so an MCP server the agent starts is
   inside it.
3. **IP/CIDR egress without a TLS-terminating proxy.** The vendor sandboxes
   allowlist *hostnames* through a local proxy. A hostname allowlist does not see
   a direct-IP connection or a non-HTTP protocol. Wardyn denies at
   `connect()`/`sendmsg()` by destination address.
4. **A forensic record that distinguishes prediction from fact.** `source:
   kernel` versus `source: observed`, `enforced` versus `action`, and a run that
   cross-checks its own claimed denials against the hooks at exit.

## What Wardyn does NOT do

Being explicit here is the point — a security tool that oversells is worse than
one that is modest and honest.

- **The allowlist shape is Landlock's, and it is opt-in.** `allow_paths:` gives
  the inverted default — the agent reaches the listed hierarchies and nothing
  else — but a policy that does not use it is still pure blocklist, and anything
  it forgot to name stays reachable and writable.
- **Containment restricts the filesystem; it does not replace it.** No mount
  namespace, no chroot, no overlay. A denied path still exists and its name
  still appears in the error. If the agent must not learn a path exists, that is
  still somebody else's job.
- **Name-based rules are still dodgeable by a rename**, and by a symlink: the
  LSM hook sees the *resolved* binary, so a `match:` exec rule does not fire for
  a binary reached through an `alternatives` symlink. The fix is a `path:` rule
  pinning `(dev, ino)` — which the policy author has to actually write, and
  which cannot cover a file that does not exist yet. Copying a blocked *binary*
  to a new name still runs it.
- **No content or provenance matching.** Rules describe names and objects, never
  bytes.
- **No information-flow policy.** "Read from a secret directory, then wrote to
  the network" is one rule in ActPlane's labelled model. In Wardyn's it is not
  expressible at all.
- **No defence against a root child (as shipped).** Dropping the child to
  `SUDO_UID` is the mitigation, and the default.
- **No CO-RE.** Struct offsets are resolved at runtime from the kernel's own
  BTF, with a baked-in 6.8 fallback. This is a `rustc`/LLVM limitation, not an
  aya one — but it is a weaker guarantee than a relocatable object, and it has
  failed open once (kernel 6.13 moved `f_path` into an anonymous union).

## The landscape

Capability notes reflect each project's own documentation as of **2026-10-04**.

| Tool | Category | Scope | Files | Egress | Root? | userns? | Agent feedback | Audit trail |
|---|---|---|---|---|---|---|---|---|
| **Wardyn** | Supervisor (observe + deny + receipt) + isolator | One launched subtree | Landlock allowlist **plus** eBPF LSM blocklist by name or `(dev, ino)`; read/write + create/delete | cgroup CIDR, v4/v6, TCP+UDP, `port:` + `proto:` | needs root to load | not required | **yes** (receipt + `wardyn hook`) | **yes** (JSONL + versioned stream) |
| **ActPlane** | Supervisor (observe + deny + feedback) | Agent process tree, by label propagation | BPF-LSM, labelled information-flow policy | `connect` hook; CIDR/port not documented | root or `CAP_BPF`+`CAP_SYS_ADMIN` | not required | **yes** (harness hook, MCP server) | yes |
| **AgentSight** | Observer | Agent process tree | eBPF events | eBPF events | yes | n/a | n/a (observes) | yes, plus TLS-recovered intent |
| Claude Code sandbox | Isolator | **Shell commands only** — file tools, MCP servers, hooks and LSP run outside | bubblewrap (Linux/WSL2), Seatbelt (macOS); unsandboxed on native Windows | local proxy against `network.allowedDomains`, hostname-based | no | needs userns | n/a | limited |
| Codex CLI sandbox | Isolator | The agent it ships with | bubblewrap + Landlock; Seatbelt on macOS | seccomp net restriction, no network by default | no | typically yes | n/a | limited |
| Linux **Landlock** | Isolator (kernel LSM) | Inherited across fork/exec | resolved-path hierarchy, ~15 rights | TCP bind/connect **by port only** | **no root** | not required | no | ABI≥7 audit (node-wide) |
| bubblewrap / firejail | Isolator | Launched process | mount ns, RO roots | via net ns | no (userns) | needs userns | no | no |
| gVisor | Syscall-interposing runtime | Container | full re-implemented VFS | full | no | no | no | limited |
| **Tetragon** | Node/cluster observer+enforcer | Whole node, k8s selectors | kprobe/LSM, TracingPolicy | kprobe | yes (node) | n/a | no | yes (node) |
| **Tracee** / **Falco** | Node runtime detection | Whole node | eBPF events + rules | eBPF events | yes (node) | n/a | no | yes (alerts) |
| seccomp-notify | Syscall broker | Process | syscall-argument level | syscall level | no | needs a supervisor | no | via supervisor |

**Reading the table.** Landlock remains the better file engine wherever the
policy can be written as an allowlist: in-tree, no struct offsets, resolved
paths rather than basenames, and no root at all. What it cannot express is CIDR
egress, or a blocklist on a machine whose allowlist you could not enumerate if
you tried — which is what Wardyn's `path:` identity rules exist for.

Tetragon/Tracee/Falco are *node/cluster-scoped daemons* with no notion of "scope
to this one subtree I just launched from my laptop shell". The vendor sandboxes
are *isolators* that wrap the agent's shell tool, which is a smaller boundary
than their reputation suggests — read the row above, and then their own docs.

## The recommended posture

Use Wardyn **with** an isolator, each doing what it is best at:

- **Filesystem containment** → Wardyn's own `allow_paths:`, which is Landlock.
  What a vendor sandbox still adds is a mount namespace — a *different*
  filesystem view rather than a restricted one.
- **Specific objects that must survive being renamed** → Wardyn. `path:` rules
  pin `(dev, ino)`, and `access: delete` stops the object being removed at all.
- **Egress by address/CIDR (v4+v6, TCP+UDP)** → Wardyn. The one axis the vendor
  proxies and Landlock cannot express.
- **Everything the vendor sandbox leaves outside it** — MCP servers, command
  hooks, LSP servers → Wardyn, because its boundary is the process tree.

Being first to say *"use both"* is more credible than claiming to replace either.
If you are choosing between Wardyn and ActPlane rather than between Wardyn and a
sandbox: they are close enough that the honest advice is to try both, and the
honest reasons to pick ActPlane are its CO-RE object, its MIT licence and its
published evaluation.

## Roadmap implied by this comparison

- ~~**Hybrid engine.**~~ **Done.** `allow_paths:` applies Landlock before
  `exec`; eBPF LSM keeps the blocklist and the observability; eBPF remains the
  sole egress engine. What is left is Landlock's network rights (ABI 4+) and its
  scoping of signals and abstract unix sockets (ABI 6+).
- ~~**An agent-facing feedback channel that does not depend on the agent
  reading a file.**~~ **Done** — `wardyn hook`.
- ~~**A number for what it stops.**~~ **Done** — the coverage benchmark in the
  README, with its one miss in the table.
- **An agent-behaviour evaluation.** The coverage benchmark measures techniques,
  not agents. What is still missing is ActPlane's shape of result: does the
  feedback actually change what a model does next, measured over real tasks?
- **CO-RE, or an honest substitute.** Runtime BTF resolution works and is
  tested, but it is the weakest link in portability.
- **Information-flow rules.** The read-then-send shape is not expressible today.
- **Metrics.** `--metrics-addr` with Prometheus counters, still absent — and it
  would mean an HTTP listener inside a process running as root, which is a
  decision worth making deliberately.

Overhead numbers are in [`PERFORMANCE.md`](./PERFORMANCE.md); what it actually
stops is in the README's **What it stops**, reproducible with
`scripts/bench-coverage.sh`. See [`docs/AUDIT.md`](./AUDIT.md) for every finding
this positioning is drawn from, and [`ARCHITECTURE.md`](../ARCHITECTURE.md) for
how enforcement works today.
