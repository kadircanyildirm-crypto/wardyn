# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **File and exec enforcement was silently off on every kernel newer than 6.12.**
  The LSM matcher reads `struct file` / `dentry` fields by byte offset, resolved
  at runtime from the kernel's BTF. Linux 6.13 reorganised `struct file` and moved
  `f_path` inside an **anonymous union**; the BTF walker only inspected direct
  members, so it reported "no such member", resolution failed, wardyn fell back to
  offsets baked in for 6.8, the hook read the wrong words, every read returned
  `EFAULT`, and the hook failed open. Nothing looked wrong from the outside: the
  feed still rendered, egress was still enforced, and file/exec rows were quietly
  demoted to `block~`. The walker now descends into anonymous members, and
  `resolve_offsets` returns the *reason* it failed instead of a bare `None`.

  Two tests exist so this cannot come back quietly: one reconstructs the 6.13
  shape from a synthetic BTF blob, and one resolves against
  `/sys/kernel/btf/vmlinux` on whatever kernel the tests are running on — the
  check that was missing, since every previous test used a blob the test itself
  had written.

- **The pinned nightly did not pin the eBPF bytecode.** `rust-toolchain.toml`
  governs the userspace build, but `build.rs` passed `Toolchain::default()` to
  aya-build, which is the *floating* `nightly` — so the one artifact the pin
  exists to protect, the bytecode that goes into the kernel and gets verified, was
  built by whatever `rustup` had that day. `build.rs` now reads the channel out of
  `rust-toolchain.toml`, keeping one source of truth.

### Added

- **Identity matching — `path:` rules (M6).** A file or exec rule can now name one
  concrete object instead of a glob over names:

  ```yaml
  files:
    - { match: "**/.env", action: block }   # names: covers files not created yet
    - { path:  "~/.ssh",  action: block }   # identity: survives rename and hard-link
  ```

  A `path:` rule is resolved to `(dev, ino)` when the policy loads and enforced by
  new `BLOCK_INODES` / `BLOCK_DIR_INODES` / `BLOCK_EXEC_INODES` maps, consulted by
  the same LSM hooks. `mv` does not shake it off, `ln` gives a second name to the
  same key, and `cp` is not an escape either — copying a secret means reading it,
  and the read is what gets denied. `~` expands to the *agent's* home (read from
  `/etc/passwd` for the drop-target uid, not `$HOME`, which under `sudo` is
  root's); a bare name is relative to the directory wardyn was launched in.

  Identity is **additive**: name maps are unchanged, so no policy loses coverage.
  A `path:` that resolves to nothing pins nothing, and says so at startup and in
  `--dry-run` rather than looking like protection.

  Proven end-to-end, not asserted: `tests/e2e/run.sh` renames the secret, hard-links
  it, copies it, renames the blocked directory and renames the blocked binary — and
  then re-runs the *same agent* against the *same policy with the `path:` rules
  stripped out*, requiring all four bypasses to reopen. Without that control run, an
  identity assertion that passed because some name rule happened to cover the
  renamed file would be indistinguishable from a working inode match.

- **A read/write axis for file rules.** `access: read | write | any` (default
  `any`). `block` used to mean "cannot be opened at all", which also forbade
  *writing* the file, so a policy could not say "the agent may create a `.env`, it
  just may not read one". The kernel always knew the difference (`f_mode` at
  `file_open`); the policy had no way to ask. The access mask is stored beside each
  key in the kernel maps, and the `openat` tracepoint now carries the requested
  access so the feed's own prediction agrees with what the hook will decide.

  `any` is stored as a zero mask, not `READ|WRITE`: an `O_PATH` open requests
  neither, and the obvious encoding would have quietly narrowed every existing rule.

- **`DENIED_IDENTITY` counter.** Denials that matched on `(dev, ino)` rather than a
  name are counted separately and reported at exit — "the rename didn't help" is a
  claim, and a counter is the difference between a claim and a measurement. It is a
  subset of the file/exec totals, never added to them.

- **Identity denials read as a story.** A kernel denial that matched an inode is
  rendered with the name the object has *now* and the path the policy named:
  `hidden.txt (same object as /home/me/project/.env)`.

- **`docs/WSL2.md` — Windows is a first-class dev environment.** The WSL2 kernel
  already ships BTF, cgroup v2 and `CONFIG_BPF_LSM=y`; one `kernelCommandLine` line
  in `.wslconfig` activates the LSM, and mounting `securityfs` makes it visible.
  The full e2e suite passes there with **0 skipped** — the README previously told
  Windows users to provision a VM. The document also explains why a *skip* in that
  suite is the dangerous result: it looks like success and means the file/exec
  assertions never ran.

- **The kernel reports its own denials.** Every enforcement hook
  (`lsm/file_open`, `lsm/bprm_check_security`, `cgroup/connect4·6`,
  `cgroup/sendmsg4·6`) now emits an event naming the key it matched, and
  userspace *renders* that instead of re-deriving a verdict from the observed
  `sys_enter` path. The two describe different objects whenever a path is
  relative, opened through a directory fd, or reached via a symlink — in all of
  which the feed used to show a green `ok` for a syscall the kernel had turned
  into `-EPERM`, with no audit record and no receipt line. Denials on paths with
  no observe hook at all (`sendmsg`, legacy `open(2)`) are now reported too. A
  kernel report that merely confirms a row already shown is folded away, so the
  common case still renders as one line.
- **Kernel-side loss counters (`STATS`).** Ring-buffer drops, failed `WATCHED`
  inserts and per-class denial counts are counted in a per-CPU map, shown in the
  TUI header, and printed at exit. A dropped event for a denied action means no
  feed row, no audit record and no receipt line; that is now impossible to
  mistake for a clean run. At exit the kernel's denial counters are compared
  against what the receipt told the agent — if the receipt claimed denials the
  kernel never made, the run says so.
- **`--dry-run`.** Loads and explains a policy without root, eBPF, or a target:
  every key the kernel will hold, every `block` rule that is flagged but never
  denied, every rule that enforces more broadly than written, and every `allow`
  the kernel's unordered block set overrides. CI now dry-runs all four shipped
  policies.
- **`wardyn-policy` crate.** The policy engine and CLI parsing moved into a
  portable crate with no `aya`/`libc` dependency, so `cargo test -p wardyn-policy`
  runs on Linux, macOS and Windows — CI now does exactly that on all three. The
  semantics that decide what an agent may read, run and reach were previously
  trapped inside a Linux-only binary crate.
- `WARDYN_SKIP_EBPF_BUILD=1` for `build.rs`: type-check the userspace crate
  without `bpf-linker` (`just check-nolinker`). The resulting binary refuses to
  start rather than pretending to enforce anything.
- The eBPF object now declares its license section explicitly instead of relying
  on a loader default. It must be GPL-compatible for the GPL-only helpers the
  matchers depend on (`bpf_probe_read_kernel`).

- **Runtime BTF offset resolution for the LSM matcher.** The `dentry` field offsets
  the file/exec hooks read are now resolved from the running kernel's own BTF
  (`/sys/kernel/btf/vmlinux`) and passed via `CONFIG`, so the matcher adapts to the
  kernel instead of being pinned to 6.8; it falls back to the built-in offsets (and
  demotes file/exec rows to `block~`) when BTF is unavailable and the kernel isn't
  6.8. (True CO-RE is unavailable for the Rust BPF target — a `rustc`/LLVM
  limitation — so userspace-side resolution is the portable substitute.)
- **Privilege drop for the watched agent.** Under `run`, the child is dropped to
  `$SUDO_UID`/`$SUDO_GID` (or `--as-user uid[:gid]`) with `PR_SET_NO_NEW_PRIVS`
  before `exec`, so the sandboxed process no longer inherits the root that could
  disable its own warden. `--keep-root` opts out; the drop is required under
  `--enforce` unless a target identity is available.
- Startup warning for IPv6 egress coverage gaps (`net_coverage_gaps`): a v4
  `0.0.0.0/0` deny-all with no `::/0` counterpart is now flagged, not silent.
- `docs/AUDIT.md` (adversarially-verified full audit) and `docs/COMPARISON.md`
  (honest positioning vs sandboxes, Landlock, Tetragon/Tracee).

- **Denial receipts — the agent learns what was denied (M5).** Under `--enforce`,
  the watched command is spawned with `WARDYN_DENIALS=<path>`: a per-run JSONL
  receipt with a self-describing header and one record per kernel-denied action.
  An agent that just got a bare `EPERM` or a refused connect can read back which
  rule fired and report it to its operator instead of retrying, reaching for
  `sudo`, or coding around the block. `--denials <path>` overrides the location;
  only real kernel denials are receipted (never warns or observe-only `block~`).
- **Approve-once exceptions from the TUI (M5).** Under `--enforce`, `a` offers
  to allow the most recent kernel denial; the confirm prompt states the true
  blast radius (the kernel matches bare basenames/addresses — "ANY file named
  `.env`", "ALL egress to 1.1.1.1" — never "just this file"). `y` updates the
  kernel map and the feed's userspace mirror together (such rows then show
  `excep` instead of a false `BLOCK`), records the override in the audit log,
  and appends an `exception` record to the agent's receipt so it knows it may
  retry. The trust boundary is the keyboard; exceptions last for the run only.
- UDP egress enforcement: `sendmsg4` / `sendmsg6` cgroup hooks gate connectionless
  traffic alongside `connect4` / `connect6`, reusing the same policy logic.
- Observation for the syscall variants the enforce hooks also act on:
  `openat2`, `execveat`, and `sendto` tracepoints (best-effort — absent on older
  kernels), so a kernel denial can no longer happen off-feed.
- Community & security infrastructure: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates, Dependabot, and a `cargo-deny`
  supply-chain audit workflow.
- **Release builds (`.github/workflows/release.yml`).** A `v*` tag builds a
  statically linked `x86_64-unknown-linux-musl` binary, refuses to publish if
  the tag disagrees with the workspace version, *runs the artifact* (`--help`
  plus `--dry-run` over every shipped policy) before packaging it, and attaches
  the tarball with a SHA-256 next to it. Static because wardyn runs as root on
  whatever machine hosts the agent and a glibc binary built on the newest runner
  will not start on an older one; the eBPF object is already compiled in, so the
  download is one self-contained file. `workflow_dispatch` runs everything
  except the publish, so the path can be exercised before a tag depends on it.
- **Dev container (`.devcontainer/`).** The toolchain from `scripts/setup-vm.sh`
  — Ubuntu 24.04, LLVM, the pinned nightly with `rust-src`, `bpf-linker`, `just`,
  `shellcheck` — without provisioning a VM. It is privileged with seccomp
  unconfined, because Docker's default profile blocks `bpf(2)` outright. On
  start it reports which of the three enforcement axes the *host* kernel can
  actually exercise: a container cannot turn on the BPF LSM (a kernel
  command-line setting), so file/exec blocking is normally unavailable there and
  now says so instead of surfacing as skipped e2e assertions an hour later.
- **Verifier smoke test (`wardyn/tests/verifier_smoke.rs`, `just verify-programs`).**
  Hands every one of the fourteen eBPF programs to the kernel verifier. Loading
  needs only `CAP_BPF` while attaching is what needs cgroup v2 and an active BPF
  LSM, so this covers the file/exec LSM hooks on a stock runner that could never
  attach them — the half of enforcement CI had no way to judge. A verifier
  rejection fails the test; anything else (no BTF, no BPF LSM) is reported as an
  environment skip, so it stays honest about what it actually proved. Runs as
  root in the Enforcement E2E workflow.
- Checked-in VHS tapes for the README demo (`docs/demo.tape` for the live TUI,
  `docs/demo-plain.tape` for the `--plain` fallback).

### Changed

- **Quitting the TUI now stops the agent.** Wardyn's enforcement lives in
  programs this process owns, so `q` used to tear down every hook and leave the
  watched agent running unsupervised — silently, at the moment the operator
  pressed a key. The subtree is now signalled (SIGTERM, then SIGKILL after a
  grace period) whenever wardyn exits, however it exits.
- **Wardyn exits with the target's exit status** (128+signal when it was killed),
  instead of always 0.
- Unknown keys in `policy.yaml` and unsupported `version:` values are now hard
  errors. A typo'd section (`file:` for `files:`) silently disabled an entire
  rule class while the policy looked correct.
- Startup diagnostics are shown as feed rows instead of being written to stderr
  milliseconds before the TUI replaced the screen with an alternate one.
- The denial receipt is created `O_EXCL|O_NOFOLLOW`, mode `0600`, and chowned to
  the identity the agent runs as: it lives at a predictable path in a
  world-writable directory and is opened by root.
- The pinned nightly in `rust-toolchain.toml` is now an exact dated toolchain.
  The bytecode loaded into the kernel is a function of the compiler, so a
  floating channel meant two builds of the same commit could differ in what the
  verifier sees.
- The ring buffer grew from 256 KiB (~800 in-flight events) to 4 MiB, and
  `WATCHED` from 8192 to 65536 entries.
- Network rules are now evaluated most-specific-first in userspace to match the
  kernel's longest-prefix-match LPM trie; the feed no longer reports a `block`
  the kernel actually allows (or vice-versa) when a broad CIDR precedes a narrow one.
- Audit log is opened for **append** instead of truncated on each run, so the
  security record survives across invocations.
- README and roadmap updated to reflect completed IPv6 egress and UDP gating.
- **`bpf-linker` is pinned** in `BPF_LINKER_VERSION` and installed `--locked`
  everywhere it is installed (both CI workflows, the release workflow,
  `setup-vm.sh`, the dev container). Pinning the nightly while leaving the linker
  floating covered half the problem: the linker is what emits the bytecode the
  verifier sees, so two builds of the same commit could still differ. It is also
  what actually broke — bpf-linker 0.11 stopped using the LLVM bundled with rustc
  and now requires a matching system LLVM, so every unpinned install started
  failing with `could not find llvm-config`, on a tool whose failure mode is to
  fail open.
- `scripts/setup-vm.sh` installs the toolchain `rust-toolchain.toml` pins
  (via `rustup show` from the repo root) instead of a floating `nightly`. It was
  downloading a second toolchain that nothing then built with, and reporting its
  version as if it were the one in use — which defeats the point of pinning.
  `bpf-linker` is installed `--locked`, as CI does.
- ShellCheck (CI and `just lint`) also covers `.devcontainer/*.sh`.
- **CI and the Enforcement E2E run on every branch**, not only `main` and pull
  requests. A branch could otherwise carry days of work with nothing ever
  compiling it — which is exactly how an eBPF object no kernel would load was
  merged, and how three unrelated CI breakages surfaced at once when it was.
- `rust-toolchain.toml` also pins `rustfmt` and `clippy`. Pinning the channel
  moved cargo onto a toolchain that had neither, so `cargo fmt` failed with
  "'cargo-fmt' is not installed" — the components CI installs go to the
  toolchain the action selects, and this file then overrides which one runs.

### Fixed

- **Egress enforcement never loaded: the verifier rejected every
  `cgroup_sock_addr` program.** `connect4`, `connect6`, `sendmsg4` and
  `sendmsg6` must exit with `R0` in `[0, 1]`, and each returned the value its
  `try_*` helper had produced. The verifier cannot see through a bpf-to-bpf
  call — the `Result` comes back through a caller stack slot that is marked
  unknown once the callee has written to it — so the reload put a full-range
  scalar in `R0` and `BPF_PROG_LOAD` failed with *"should have been in
  `[0, 1]`"*. Wardyn fails open, so this presented as a startup error and no
  network enforcement at all. The entry points now collapse the result to a
  literal (`net_verdict`), which is what makes the bound provable; the LSM
  hooks return through the same construct (`lsm_verdict`) for the same reason.
  Caught by the enforcement E2E workflow on its first ever run — it was added
  alongside the audit fixes but, like everything else on that branch, had never
  been triggered, because CI only runs on `main` and on pull requests.

- **A thread-heavy agent could switch enforcement off for every future child.**
  `sched_process_fork` also fires for `CLONE_THREAD`, and its `child_pid` is then
  a *thread* id, inserted into a tgid-keyed `WATCHED` and never removed. Roughly
  8192 `pthread_create` calls filled the map, after which every `insert` failed
  with `-E2BIG` — the error was discarded — and each newly forked child ran with
  no observation and no enforcement at all. Thread ids are now evicted as their
  threads exit, failed inserts increment `STATS[WATCH_FULL]` and are reported
  loudly, and the map is eight times larger. Stale thread ids also used to alias
  a later, unrelated process that happened to get that pid number, denying *its*
  file opens and egress.
- **`**/dir/**` rules only covered a directory's immediate children.** The LSM
  hook compared just `d_parent`, so `~/.ssh/sub/deeper/id_ed25519` was readable
  while the feed and the docs both presented the rule as covering the subtree.
  The hook now walks every ancestor (bounded, and the userspace mirror uses the
  same bound so it cannot claim a denial from deeper than the hook looks).
- **Fork adoption compared a thread id against a tgid-keyed map.** The hook now
  takes the parent's tgid from `bpf_get_current_pid_tgid` — it runs in the
  parent's context — which is correct for a fork from any thread, and no longer
  depends on thread ids polluting the map to work at all.
- **An option could swallow the next flag as its value.**
  `wardyn --audit --enforce run -- x` ran in observe mode with an audit log named
  `--enforce`, while the operator believed enforcement was on.
- **A non-UTF-8 argument aborted wardyn before it started.** Arguments are
  `OsString` end to end now, so the agent's command line can name any file.
- **Every `?` in the TUI returned before the terminal restore**, leaving the
  operator in raw mode inside the alternate screen. Restoration is a guard now.
  A `wait` error no longer calls `process::exit(1)`, which skipped the restore,
  the final ring sweep and the exit summary.
- **A pre-typed `a`+`y` could grant an exception whose confirm prompt was never
  drawn** — the TUI drained all buffered keystrokes in one tick. `y` is only
  accepted after the blast-radius prompt has actually been rendered.
- **Attacker-controlled path bytes were printed raw**, so a file name containing
  `\r` or an ANSI escape could forge feed rows or hide activity from the operator
  watching. Control characters and bidirectional overrides are escaped for
  display.
- **A path at or over the 256-byte event buffer arrived as the empty string** and
  was evaluated against the policy as `""` — a silent allow with a blank DETAIL.
  Such events are now flagged as not-evaluated.
- **Audit write failures were discarded.** A full disk turned the security record
  into a partial one with no indication; failures are counted and reported.
- **`run_plain` panicked on a closed pipe** (`wardyn --plain | head`).
- SIGTERM and SIGHUP are handled, and the Ctrl-C future is created once instead
  of being recreated every loop iteration (which dropped signals arriving in the
  gap between iterations).
- A failed exception grant was rendered as a policy `warn`, inflating the warn
  counter with an internal error.
- LPM-trie keys are built with `from_ne_bytes`, not `from_le_bytes`, which was
  correct only on a little-endian host.
- `resolve_domain` no longer runs inside the policy parser: the resolver is
  injectable, so the documented `domain:` rule form is testable and policy tests
  are not network-dependent. Domains that resolve to nothing are reported instead
  of silently enforcing nothing.
- **IPv6 egress was not enforced.** Both presets expressed "deny all other egress"
  only as `0.0.0.0/0` (IPv4), leaving every IPv6 destination — and IPv4-mapped
  `::ffff:a.b.c.d` from dual-stack sockets, which run the `connect6` hook — allowed
  while the feed showed `ok`. The presets now carry `::/0` (and v6 loopback/private
  allows), `connect6` unwraps v4-mapped addresses into the v4 trie, and the
  userspace feed mirrors both.
- **`pthread_exit()` from a thread-group leader silently unwatched a live process.**
  `wardyn_exit` evicted on leader exit, but a leader can exit while worker threads
  keep running. When there is no pid-namespace mismatch, eviction is now deferred to
  a userspace `/proc` sweep that only drops a tgid once its whole thread group is
  gone (`CFG_DEFER_EVICT`); the kernel keeps leader-exit eviction under a mismatch.
- **The feed/receipt claimed file/exec `BLOCK` when the LSM wasn't actually
  enforcing.** When the BPF LSM fails to attach, or the `dentry` offsets aren't
  trusted on a non-6.8 kernel, file/exec `block` rows are now demoted to `block~`
  and are **not** receipted, instead of asserting a denial that never fired.
- **`strict.yaml` blocked any file named `config`/`config.json`** (from
  `**/.kube/config` and `**/.docker/config.json` reducing to bare basenames, which
  also broke `.git/config`). These are now directory-form rules (`**/.kube/**`,
  `**/.docker/**`).

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

### Security

- **`lru` advisory closed.** It reached the build through ratatui, pinned at
  0.12.5 — below 0.16.3, the lowest version without the advisory — so Dependabot
  could only report `security_update_not_possible` and fail, once per push.
  Nothing could move it without moving ratatui, which is why the fix is the 0.30
  bump below rather than a lockfile edit; `lru` now resolves at 0.18.2 through
  `ratatui-core`.

### Dependencies

- **ratatui 0.29 → 0.30, with `default-features = false`.** The default feature
  set drags in 79 extra crates — the termwiz and image backends this tool never
  renders with — on a binary that runs as root and ships a `cargo-deny` audit.
  Narrowed to `crossterm`, `layout-cache` and `underline-color`, the real cost is
  12 crates, all of them ratatui's own 0.30 split (`ratatui-core` / `-crossterm`
  / `-widgets`), its new layout solver `kasuari` (replacing `cassowary`), and
  proc-macro helpers. crossterm moves 0.28 → 0.29 underneath; none of 0.30's
  breaking changes reach this code (no custom `Backend`, no `block::Title`, no
  crossterm colour conversions).
- `actions/checkout` v4 → v7, `actions/upload-artifact` v4 → v7,
  `actions/download-artifact` v4 → v8 — also ending the Node 20 deprecation
  warning printed on every run.
- Lockfile refreshed within semver (anyhow, globset, ipnet, libc, serde,
  serde_json, tokio and the rest of the compatible space).
- `cargo-deny` (`audit.yml`) runs on every branch, so a dependency change is
  reviewed before it lands rather than after.

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
