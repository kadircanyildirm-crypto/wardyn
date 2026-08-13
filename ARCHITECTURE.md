# Wardyn — Architecture

**Wardyn** watches an AI coding agent's process tree from the Linux kernel using eBPF,
and enforces a policy on what that tree may read, execute, and connect to — in real time,
at the syscall/LSM boundary, *before* the action completes.

> Threat model: you run an autonomous agent (Claude Code, an MCP tool, a CI job) that can
> execute arbitrary code. You want it to build your project — not read `~/.ssh`, exfiltrate
> `.env` to an unknown IP, or spawn a reverse shell. Wardyn is the seatbelt.

## Why the kernel

Userspace sandboxes (seccomp wrappers, LD_PRELOAD, ptrace) are bypassable and race-prone.
An eBPF program attached to a kernel hook sees **every** syscall from the watched tree,
cannot be unloaded by the watched process, and — via LSM / cgroup hooks — can *deny* the
operation by returning an error to the kernel, not after the fact.

## Hook map

| Capability | Observe hook | Enforce hook | Can block? | Notes |
|---|---|---|---|---|
| **exec** | `tracepoint/syscalls/sys_enter_execve` + `sys_enter_execveat` | LSM `bprm_check_security` | ✅ (LSM) | deny returns `-EPERM` to `execve`; both syscall variants observed so a denial can't happen off-feed |
| **file open** (`.env`, `~/.ssh`) | `tracepoint/syscalls/sys_enter_openat` + `sys_enter_openat2` | LSM `file_open` | ✅ (LSM only) | `bpf_override_return` can't deny `openat` — not on the kernel error-injection allowlist, so blocking *requires* BPF LSM. Matches the basename, then **every ancestor directory** (bounded walk) |
| **outbound connect** | `tracepoint/syscalls/sys_enter_connect` + `sys_enter_sendto` | `cgroup/connect4·6` + `cgroup/sendmsg4·6` | ✅ (cgroup v2) | cgroup hook denies `connect()`/`sendmsg()` **without** LSM — works even on stock WSL2. `sendmsg`'s msghdr destination is enforce-only (not observed), but a denial there still reports itself |
| **fork / child tracking** | `tracepoint/sched/sched_process_fork` (+ `sched_process_exit` to evict) | — | — | maintains the watched PID set; the parent's tgid comes from `bpf_get_current_pid_tgid` (the hook runs in the parent), the child's pid offset from tracefs at runtime |

> **Observation is not proof; the deciding hook reports its own decision.** The
> `sys_enter_*` tracepoints exist so the common syscalls also appear in the feed,
> but that coverage is *not* total: the LSM/cgroup hooks fire for a strictly
> larger set of entry points (legacy `open(2)`/`creat(2)`, `sendmsg(2)`, io_uring
> `IORING_OP_*`, a script interpreter reached via `execve`), and the observed path
> is a *userspace string read at `sys_enter`* — relative, symlinked, or
> dirfd-relative paths describe a different object than the dentry the LSM
> matched. So every enforcement hook emits its own `DENY_*` event naming the key
> it matched. Userspace renders that instead of re-deriving a verdict; where a
> denial confirms a row the feed already showed, the duplicate is folded away,
> and where it doesn't, the off-feed denial appears on its own.

> **Losses are counted, not swallowed.** A `PerCpuArray` (`STATS`) counts
> ring-buffer drops, failed `WATCHED` inserts, and denials per class. A full ring
> means events with no feed row, no audit record and no receipt line; a full
> watch set means child processes running *unobserved and unenforced*. Both are
> surfaced in the TUI header and at exit, and the denial counters are the
> cross-check that catches a receipt claiming denials the kernel never made.

Two independent enforcement paths on purpose:
- **Network blocking → cgroup/connect** (needs only cgroup v2).
- **File & exec blocking → BPF LSM** (needs `CONFIG_BPF_LSM=y` **and** `lsm=...,bpf` on the kernel cmdline).

## Process-tree tracking

Wardyn is scoped to *one* agent invocation, not the whole host:

1. Userspace launches the target: `wardyn run -- claude ...`, capturing the child PID as the **root**.
2. eBPF keeps a `watched: HashMap<pid, ()>` seeded with the root.
3. On `sched_process_fork`, if the parent is watched, the child is added.
4. Every observe/enforce hook first checks `watched.contains(pid)` — unwatched processes are ignored.

This makes Wardyn safe to run on a shared machine: it only constrains the subtree you launched.

Two portability traps live in that seeding, both handled at startup:

- **Pid namespaces.** The hooks key `WATCHED` by *init-namespace* tgid
  (`bpf_get_current_pid_tgid`), while `std::process::id()` is wardyn's pid in
  its *own* namespace — different numbers inside a container or WSL2 distro, so
  a locally-seeded map would watch (and enforce) nothing while claiming to.
  Wardyn learns its kernel-view tgid via a nonce-gated tracepoint handshake on
  `sys_enter_personality`, seeds that, announces the mismatch, and leaves child
  adoption entirely to the in-kernel fork hook (a local child pid could collide
  with an unrelated init-ns tgid). Under a mismatch the feed shows init-ns pids.
- **Fork tracepoint layout.** `sched_process_fork`'s pid offsets moved when the
  kernel made comm dynamic (`__data_loc`, observed on 6.18: child_pid 44→20).
  Wardyn reads the running kernel's tracefs `format` file and passes the offset
  to the hook via `CONFIG` instead of hardcoding one kernel's number. The
  *parent* is not read from the tracepoint at all: its `parent_pid` field is a
  thread id, and `WATCHED` is keyed by tgid, so the hook takes the parent's tgid
  from `bpf_get_current_pid_tgid` — it runs synchronously in the parent's
  context inside `kernel_clone()`.
- **Threads are not processes.** `sched_process_fork` also fires for
  `CLONE_THREAD`, and its `child_pid` is then a *thread* id landing in a
  tgid-keyed map. Left there, a thread-heavy agent fills the map — after which
  `insert` fails and every subsequently forked child runs completely unwatched,
  which is a bypass primitive, not merely a leak. `sched_process_exit` therefore
  removes a thread's own tid as it dies (pid numbers are unique, so this can
  never remove a live process's entry), the map is sized well above the old
  8192, and any failed insert increments `STATS[WATCH_FULL]` so saturation is
  loud rather than silent.

## Event flow

```
 kernel (eBPF)                         userspace (aya + tokio)
 ┌─────────────────────┐               ┌──────────────────────────┐
 │ tracepoints / LSM   │  RingBuf      │ event reader             │
 │ + cgroup/connect    ├──────────────▶│  → policy engine (match) │
 │  (enforce inline)   │               │  → ratatui TUI (live)    │
 │  ▲ policy verdict   │  PerCpuArray  │  → JSONL audit log       │
 │  └──── shared maps ◀─┼───────────────┤  → denial receipt → agent│
 └─────────────────────┘               │ compiled policy → maps  │
                                       └──────────────────────────┘
```

- **Fast-path decisions live in kernel maps.** Userspace compiles `policy.yaml` into eBPF maps
  (path-hash → action, CIDR trie → action) so the LSM/cgroup hook decides `allow|block`
  inline without a userspace round-trip. `warn` events are streamed up for display only.
- **RingBuf** carries events to userspace for the TUI, the audit log, and the
  agent-facing denial receipt.

## Policy model

See [`policy.yaml`](./policy.yaml). Three rule lists — `files`, `network`, `exec` —
with `default_action` as the fallback. Actions: `allow | warn | block`.

Matching order is **not** uniform, and the docs used to claim it was:

| Axis | Order | Why |
|---|---|---|
| files / exec | first match wins | ordinary rule-list semantics |
| network | **longest prefix wins** | the kernel decides egress with an LPM trie; CIDRs covering one address are always nested |
| files / exec **under `--enforce`** | **no order at all** | the LSM hook holds a *set* of block keys; an `allow` listed before a `block` does not protect what that block's key covers |

`wardyn --dry-run` prints exactly which keys the kernel will hold, which rules
are flagged-but-never-denied, which enforce more broadly than written, and which
allow rules the kernel's unordered set overrides.

## Crate layout

```
wardyn-common/   no_std, #[repr(C)] event & verdict structs shared kernel↔user
wardyn-ebpf/     no_std no_main; the eBPF programs (target bpfel-unknown-none)
wardyn-policy/   the policy engine + CLI parsing — pure logic, no aya/libc, so
                 `cargo test -p wardyn-policy` runs on any OS
wardyn/          userspace: loader, RingBuf reader, map population, ratatui TUI,
                 audit log, denial receipt
```
Built with [aya](https://aya-rs.dev) (pure-Rust eBPF — no libbpf/C toolchain). eBPF crate is
compiled by `wardyn`'s `build.rs` via `aya-build`.

## Platform matrix

| Feature | WSL2 (stock) | Ubuntu VM + BPF LSM | Notes |
|---|---|---|---|
| observe (exec/open/connect) | ✅ | ✅ | needs BTF (`/sys/kernel/btf/vmlinux`) |
| network **block** | ✅ | ✅ | cgroup/connect, no LSM needed |
| file / exec **block** | ❌ | ✅ | needs `lsm=...,bpf` in GRUB |

Dev target: **Ubuntu 24.04 VM with BPF LSM enabled** — full observe + full block in one place.

## Enforcement (implemented)

Gated on `WATCHED` membership + `CONFIG[enforce]`, so it only ever touches the
launched subtree, and only under `--enforce`. Because `WATCHED` is seeded only in
`run` mode, `--enforce` requires `wardyn run -- <cmd>`; `--enforce --all` is refused
(system-wide blocking is out of scope, and would otherwise enforce *nothing* while
claiming to).

- **Network** — `cgroup/connect4` looks the destination IPv4 up in the `NET_RULES`
  LPM trie (compiled from `policy.network`) and returns *deny* for a `block` verdict.
  The trie is **longest-prefix-match**, so the userspace feed evaluates network
  rules most-specific-first (not first-match) to report the same verdict the kernel
  enforces — a broad `block` CIDR before a narrow `allow` no longer disagree.
- **File** — LSM `file_open` reads `file->f_path.dentry->d_name` (basename) and its
  parent-dir name and returns `-EPERM` if either is in the `BLOCK_NAMES` /
  `BLOCK_DIRS` set. Matching is **exact basename/dir**, not full-path glob (so it
  stops accidental/naive access but is bypassable by renaming or hard-linking the
  target — see `SECURITY.md`). Full-path matching via `bpf_d_path` is on the
  roadmap. The `dentry`-field offsets are resolved **at runtime from the kernel's
  BTF** (`/sys/kernel/btf/vmlinux`) and passed via `CONFIG`, falling back to the
  built-in kernel-6.8 offsets if BTF resolution fails. (Compiler-emitted CO-RE
  relocations are unavailable for the Rust BPF target — a `rustc`/LLVM limitation —
  so userspace-side BTF resolution is the portable substitute.) `scripts/kernel-offsets.sh`
  remains a manual cross-check.
- **Exec** — LSM `bprm_check_security` applies the same basename match to
  `linux_binprm->file` against `BLOCK_EXEC`.

**Feed/kernel reconciliation.** The basename/dir reduction is coarser than the glob
a rule was written as (`/etc/shadow` → deny any file named `shadow`; `**/.ssh/**`
→ only the immediate `.ssh` parent, not deep descendants). Rather than let the feed
disagree with the syscall's real outcome, under `--enforce` userspace reproduces the
kernel matcher for each event: a rule that over-blocks is shown (and audited) as an
enforced `BLOCK`, and an enforceable-looking glob the kernel *won't* actually deny is
demoted to `block~`. Rules whose kernel key is broader than their glob are printed as
a warning at startup so the over-reach is explicit, not silent.

## Agent feedback — denial receipts

A denial reaches the watched agent as a bare `EPERM`, indistinguishable from an
ordinary permission error — so agents retry, reach for `sudo`, or work around the
failure. Wardyn can see everything the agent does; the receipt gives the agent a
way to see Wardyn back.

Under `--enforce`, `run` spawns the child with `WARDYN_DENIALS=<path>` in its
environment: a per-run JSONL file (truncated at start, unlike the append-only
audit log) with a self-describing header line written for an LLM reader, then one
record per kernel-denied event, flushed as it happens. The agent matches its
failed operation against the records, learns which rule fired, and can surface
that to its operator instead of flailing.

Trust model: the receipt is *output to* the watched tree, never input. The agent
can read it — or scribble on its copy of the truth — but the enforcement state
lives in kernel maps and root-owned policy it cannot reach. Denials are receipted
from the same reconciled verdict as the feed and audit log (`Desc::denied`).

That verdict is currently a userspace **inference** (the deciding hook does not
report its own decision — see the hook-map note above), so it can diverge from
what the kernel really did. Two known ways it lies, both now guarded but not
eliminated: (1) when the BPF LSM does not attach or the `dentry` offsets are not
trustworthy, file/exec `block` rules are demoted to `block~` and are **not**
receipted, rather than claiming a `BLOCK` that never fired; (2) UDP `sendmsg()`
destinations are enforce-only (not observed), and dirfd-relative / symlink opens
can be denied by the kernel yet under-reported by the mirror. The durable fix —
emitting the verdict from the enforcement hook itself — is tracked in
`docs/AUDIT.md` (`no-kernel-verdict-channel`).

### Approve-once exceptions (TUI)

Under `--enforce`, `a` in the TUI offers to allow the most recent kernel denial.
The confirm prompt states the TRUE blast radius — the kernel matches bare
basenames / addresses, so the honest unit is "ANY file named `.env`" or "ALL
egress to 1.1.1.1", never "just this file" — and `y` applies the exception to
the kernel map (remove the block key / insert a most-specific LPM allow) and to
the userspace mirror in the same breath, so the feed never keeps claiming a
denial the kernel stopped making (such rows show `excep`, with the granted key
in the rule column). The grant lands in the audit log (an override is part of
the security record) and in the agent's receipt as an `exception` record ("you
may retry"), closing the deny → report → approve → retry loop without
restarting the agent. The trust boundary is the keyboard: only a human at the
terminal can grant. Exceptions live for this run only; nothing is persisted.

## Roadmap

- [x] **M1 — Observe:** exec + openat + connect for the watched tree → live TUI.
- [x] **M2 — Policy/warn:** `policy.yaml` compiled to matchers, violations coloured, JSONL audit.
- [x] **M3 — Block:** network via cgroup/connect + file & exec via LSM.
- [ ] **M4 — Ship:** demo GIF, presets, `--dry-run`, IPv6 egress, CI devcontainer.
- [ ] **M5 — Agent feedback:** denial receipts ✓ (`WARDYN_DENIALS`);
  approve-once exceptions from the TUI ✓; next: persistent overrides kept
  outside the watched tree's reach.
