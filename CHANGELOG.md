# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Denial receipts — the agent learns what was denied (M5).** Under `--enforce`,
  the watched command is spawned with `WARDYN_DENIALS=<path>`: a per-run JSONL
  receipt with a self-describing header and one record per kernel-denied action.
  An agent that just got a bare `EPERM` or a refused connect can read back which
  rule fired and report it to its operator instead of retrying, reaching for
  `sudo`, or coding around the block. `--denials <path>` overrides the location;
  only real kernel denials are receipted (never warns or observe-only `block~`).
- UDP egress enforcement: `sendmsg4` / `sendmsg6` cgroup hooks gate connectionless
  traffic alongside `connect4` / `connect6`, reusing the same policy logic.
- Observation for the syscall variants the enforce hooks also act on:
  `openat2`, `execveat`, and `sendto` tracepoints (best-effort — absent on older
  kernels), so a kernel denial can no longer happen off-feed.
- Community & security infrastructure: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates, Dependabot, and a `cargo-deny`
  supply-chain audit workflow.

### Changed

- Network rules are now evaluated most-specific-first in userspace to match the
  kernel's longest-prefix-match LPM trie; the feed no longer reports a `block`
  the kernel actually allows (or vice-versa) when a broad CIDR precedes a narrow one.
- Audit log is opened for **append** instead of truncated on each run, so the
  security record survives across invocations.
- README and roadmap updated to reflect completed IPv6 egress and UDP gating.

### Fixed

- **`run` scoping silently watched nothing inside pid namespaces** (docker
  containers, WSL2 distros — including `--enforce`, which then denied nothing
  while claiming to). The kernel hooks key `WATCHED` by init-namespace tgid,
  but userspace seeded it with its own-namespace pids, which never match from
  inside a namespace. Wardyn now learns its kernel-view tgid at startup via a
  nonce-gated `sys_enter_personality` handshake, announces a detected
  namespace, and relies on in-kernel fork adoption for the launched child (a
  local child pid could collide with an unrelated init-ns tgid). The feed shows
  init-ns pids under a mismatch.
- **Child adoption broke on kernels with dynamic sched-tracepoint comm fields**
  (`__data_loc`, observed on 6.18: `parent_pid` 24→12, `child_pid` 44→20; the
  hardcoded offsets were for 6.8's inline `char[16]`). The fork hook now gets
  the offsets from the running kernel's tracefs `format` file via `CONFIG`, so
  adoption — and with it all of `run` scoping — survives layout changes.
- **Feed/kernel divergence on file & exec blocks.** The coarse basename/dir
  matcher the LSM hook uses could deny an open/exec the UI reported as `ok`/`warn`
  (e.g. `/etc/shadow` → any file named `shadow`), and could show `BLOCK` for a
  deep `**/.ssh/**` path the kernel never denies. Under `--enforce` userspace now
  reproduces the kernel matcher per event and reports its true outcome, and startup
  warns about rules whose kernel key is broader than their glob.
- **`--enforce --all` claimed enforcement but denied nothing** (the deny hooks gate
  on `WATCHED`, which is empty outside `run` mode). `--enforce` now requires
  `run -- <cmd>`; the combination is refused instead of silently no-op.
- **Options after the mode keyword were silently dropped** (`wardyn --all --enforce`
  ran observe-only). A flag following `--all` is now a hard error.
- **Trailing ring-buffer events were lost** when the child exited: both the TUI and
  plain loops now drain the ring one final time, so a secret read immediately before
  exit is still shown and audited.
- **`wardyn_exit` used the thread id, not the tgid**, so a worker thread's exit could
  evict an unrelated watched process (pid/tgid share one number space). It now acts
  only on the leader's exit and removes by tgid.
- **wardyn policed itself** under `--enforce`: its own pid was seeded into `WATCHED`
  to bootstrap fork-adoption and never removed. It is now dropped once the child is
  tracked, keeping enforcement scoped to the agent subtree.
- Corrected the `ARCHITECTURE.md` hook map (observe hooks are the `sys_enter_*`
  tracepoints, not `sched_process_exec` / `kprobe tcp_connect`).
- Silenced an unused-assignment warning in the connect-observation path so the
  eBPF crate builds warning-free.

## [0.1.0] — unreleased (development)

First working milestones (M1–M3):

### Added

- **M1 — Observe:** live process-tree view of `exec` / `open` / `connect`,
  scoped to a launched subtree and followed across `fork`. Structured
  ring-buffer events; live ratatui TUI + plain fallback.
- **M2 — Policy:** `policy.yaml` engine (glob file/exec rules + CIDR/domain
  network rules), `allow` / `warn` / `block` verdicts, JSONL audit log.
- **M3 — Enforce:** in-kernel denial for the watched subtree under `--enforce`:
  - network egress via `cgroup/connect4` + `connect6` (LPM trie),
  - secret-file reads via BPF-LSM `file_open`,
  - blocked executables via BPF-LSM `bprm_check_security`.
- Fail-safe guards: root check, kernel-offset warning, graceful degradation to
  network-only enforcement when BPF LSM is unavailable.
- Ready-made policy presets (`policies/permissive.yaml`, `policies/strict.yaml`).

[Unreleased]: https://github.com/kadircanyildirm-crypto/wardyn/compare/main...HEAD
