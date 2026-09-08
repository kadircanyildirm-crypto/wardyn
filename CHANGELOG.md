# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`--as-user 0` ran the agent as root while reporting that it had not.**
  `$SUDO_UID=0` was rejected, but the explicit flag was not: the drop went
  through `setuid(0)` — a successful no-op — past the `--enforce` refusal that
  exists to stop a root child, and printed *"the agent runs as uid=0 gid=0, not
  root"*. It was `--keep-root` without the warning, spelled as its opposite.
  Root is now refused as a target identity however it is requested, and the
  refusal names what was asked for.

- **A `~` rule could silently anchor to root's home.** `--as-user <uid>` for a
  uid with no `/etc/passwd` entry fell back to `$HOME`, which under `sudo` is
  root's — so `path: ~/.ssh` pinned `/root/.ssh` and protected the wrong
  directory while reading as correct. When the agent's identity is known, `~`
  now resolves from that identity or not at all; unresolved rules were already
  reported.

- **One odd line in `/etc/passwd` ended the home lookup instead of skipping an
  entry.** An NIS compat line (`+::::::`) has an empty uid field, so a single
  one above the target user unanchored every `~` rule on that machine.

- **A failed `PR_SET_NO_NEW_PRIVS` was silent.** The privilege drop is three
  things — a non-root uid, cleared supplementary groups, and no route back — and
  only the third could fail while the other two still looked successful, leaving
  an agent that could regain root through a setuid exec. Its return value is now
  checked like the other two, so the spawn fails loudly instead.

- **`run` could watch — and enforce against — an unrelated process.** Wardyn
  identifies the agent to the kernel by tgid *as the kernel sees it*, learned
  through an in-kernel handshake. When that handshake produced nothing, wardyn
  fell back to its own pid, which inside a pid namespace names a different
  init-namespace process or none. The feed then attributed a stranger's syscalls
  to the agent, `--enforce` denied them, and the agent itself ran unwatched —
  with only a conditional warning that did not know whether it applied.

  Wardyn now determines whether it is namespaced without eBPF (the initial pid
  namespace has a fixed inode, so `/proc/self/ns/pid` answers it), and `run`
  refuses to start unless it can identify the agent honestly. The error names
  the ways out. This is the Landlock precedent rather than the fail-open one: a
  watch set pointed at the wrong process is not a weakened watch, it is a false
  report.

  Reachable wherever a container seccomp profile restricts `personality()` to a
  fixed argument list, which is what the handshake rides on.

### Fixed

- **The policy's source was never reported, and the default is inside the
  agent's reach.** `--policy`, `./policy.yaml` and the embedded default fell
  back to each other silently, so `policy loaded: 11 file rule(s)` read
  identically whether those rules were the operator's or the built-in default
  that applied because they ran from a different directory. Startup now names
  the source.

  It also warns when the policy file is writable by the agent's uid. Unlike the
  audit log, the policy is not evidence — it *is* the enforcement, so an agent
  that can rewrite it chooses what constrains it next time. A warning rather
  than a refusal: a policy checked into the project it governs is a legitimate
  setup, and that is the operator's call to weigh.

- **An agent could get root to append to any file, through the audit log.** The
  default `--audit` path is *relative*, so it lands in the directory wardyn was
  launched in — which for the documented `cd project && sudo wardyn run --
  agent` is a directory the **watched agent can write**. The log was opened
  without `O_NOFOLLOW`, so an agent that dropped a symlink named
  `wardyn-audit.jsonl` before wardyn started got root to append JSON — whose
  `detail` and `comm` fields it partly controls — to whatever it pointed at.

  Demonstrated before it was fixed, and a regression test now performs the same
  attack and asserts the target is untouched.

  The log is now opened `O_NOFOLLOW` and, on the resulting **descriptor** rather
  than the path, checked for being a regular file, owned by wardyn, and not
  writable by group or others. Any of those failing is a refusal, matching the
  standard `overrides_file` already held. New logs are created `0600`: the file
  names every path the agent touched, which is the map of a project an attacker
  would want.

  The remaining exposure is the *directory*, which cannot be fixed from here —
  records written during the run are safe, since appends follow the descriptor,
  but the finished file can be swapped afterwards. Startup now says so when the
  audit directory is writable by the agent's uid.

### Changed

- **The kernel-side crates are dual-licensed `GPL-2.0-only OR
  AGPL-3.0-or-later`.** `wardyn-ebpf` and `wardyn-common` compile into the eBPF
  object the kernel loads, and that object declares `GPL` in its ELF license
  section — which it must, since BPF LSM programs are required to be
  GPL-compatible and `bpf_probe_read_kernel` is a GPL-only helper.

  `GPL` means GPLv2 to the kernel. AGPL-3.0 is not on its
  `license_is_gpl_compatible()` list and would be rejected if declared honestly,
  so an AGPL-only crate was shipping an object under terms its source did not
  grant. The GPL-2.0 arm makes the declaration true and the AGPL arm keeps the
  crates usable exactly as before — nobody loses a right, and the ambiguity is
  gone.

  Userspace (`wardyn`, `wardyn-policy`) is unchanged: AGPL-3.0-or-later.

## [0.2.0] — 2026-09-08

Wardyn gained the shape it was missing, and lost three ways of being wrong about
itself.

### The shape: containment

Everything in 0.1.0 was a **blocklist** — name what is forbidden, and whatever
the policy forgot stays reachable. `allow_paths:` is the other half, and it is a
different kernel mechanism:

```yaml
allow_paths:
  - { path: "/usr", rights: [read, exec] }
  - { path: "/etc", rights: [read] }
  - { path: ".",    rights: [read, write, exec] }   # the project
```

The agent reaches those hierarchies and nothing else. Landlock enforces it,
which means it needs no privilege, is inherited by every descendant, and cannot
be undone — it holds even where the eBPF half would not. Containment removes
everything outside; the block rules still deny specific objects inside what is
left; egress stays eBPF's alone.

### Three ways it had been wrong about itself

A tool that reports on a kernel has one job it cannot fail at: saying what
actually happened. Three places where it did not, all found and fixed here.

- **The feed said `ok` for opens Landlock had just refused.** Different LSM, its
  denials never reach wardyn's hooks. Found while recording the demo — the video
  would have shown the tool lying.
- **`domain:` rules were frozen at load.** Every name in the default policy is
  CDN-fronted, so a long session watched allowlisted traffic start hitting the
  deny-all. Users read that as flakiness, and flakiness is how a security tool
  gets switched off.
- **A `match:` glob was reduced to its last segment**, so `/etc/shadow` denied
  every file called `shadow`. A rule whose kernel key is broader than its text
  is the failure this project exists to refuse.

### Reach

`--format json` makes wardyn pipeable into anything that reads a log, with a
schema documented as a versioned interface. arm64 builds ship beside x86_64,
each built *and started* on its own architecture. And there are finally
published overhead numbers, measured as a slope so startup cancels out.

### Upgrading from 0.1.0

Policies keep working. Two changes are visible:

- A `match:` glob now keeps its last **two** literal segments, so
  `**/.aws/credentials` stops denying every file named `credentials`. Rules get
  narrower, never wider — check `--dry-run` if you were relying on the
  over-reach.
- The audit log gained `schema_version` and `matched_key` on every record.
  Existing fields are unchanged.

### Added

- **`allow_paths:` — filesystem containment, via Landlock.** Everything wardyn
  enforced until now was a blocklist: name what is forbidden, and anything the
  policy forgot stays reachable. That is the right shape for "this machine,
  minus these secrets" and the wrong one for "only this project directory".

  ```yaml
  allow_paths:
    - { path: "/usr", rights: [read, exec] }
    - { path: "/etc", rights: [read] }
    - { path: ".",    rights: [read, write, exec] }
  ```

  The agent reaches those hierarchies and nothing else. Applied to the child
  before `exec`, inherited by every descendant, impossible to undo — and it
  needs no privilege, so it holds even for a root agent, unlike the eBPF half.
  This closes the "hybrid engine" item `COMPARISON.md` carried as the largest
  remaining capability gap.

  Three decisions worth the words:

  **The ruleset is built in the parent, while still root.** Adding a hierarchy
  means opening a descriptor for it, and the child has already dropped
  privileges by the time it could try. The child inherits the descriptor and
  makes one syscall, which is what keeps it safe inside `pre_exec`.

  **Every right the kernel knows is *handled*; the policy chooses what is
  *granted*.** A right left out of `handled_access_fs` is not denied, it is
  ignored — so handling only the rights that appear in `rights:` would build a
  ruleset that looks restrictive and silently permits everything nobody
  mentioned. `REFER` is handled from ABI 2 up for the same reason: without it,
  containment would have a hole shaped exactly like `mv`.

  **This one refuses instead of degrading.** Everywhere else wardyn fails open
  and says so, because a broken matcher costs one axis while bricking a working
  machine would be worse. An allowlist is the whole boundary, so failing open
  does not weaken it — it removes it. `allow_paths:` present with Landlock
  unusable, or a granted path that will not resolve, is a startup error.

  Three rights (`read`/`write`/`exec`) rather than Landlock's sixteen bits:
  policy authors have opinions about reading, changing and running, not about
  FIFOs versus sockets. `write` covers creating, removing, renaming and
  truncating — a project directory an agent cannot save a new file into is not
  one it can work in.

  Proven on a real kernel by eight e2e assertions: the granted hierarchy is
  readable and writable, a file outside it is neither, a read-only grant refuses
  writes, and `mv` out of the allowlist is refused.
  [`policies/contained.yaml`](policies/contained.yaml) is a starting preset, and
  `--dry-run` lists the boundary before the rules inside it and says in as many
  words that an unlisted path is denied.

- **Published overhead numbers, and `scripts/bench.sh` to reproduce them.** A
  tool in the path of every `open` in a subtree had never published a figure,
  which asks users to trust it about the one thing they can measure themselves.

  Two costs, kept apart because they behave differently: **startup** (~0.9 s
  observing, ~2.2 s enforcing — loading ~21 eBPF programs and parsing BTF) and
  **marginal** (~+15 µs per file open observing, ~+17 µs enforcing). The startup
  figure is the one that should change behaviour: wardyn supervises a session,
  it is not for wrapping individual commands in a loop.

  The marginal cost is measured as a **slope** — the same workload at N and 2N
  events — so whatever the run costs before the first event cancels out. The
  first attempt subtracted a separately measured startup instead, and reported
  `--enforce` as *cheaper* than observing: impossible, and the clue that
  subtracting a constant which itself varies fivefold amplifies noise rather
  than removing it. [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) says so, along
  with what the numbers are not.

- **arm64 builds.** Releases now ship `aarch64-unknown-linux-musl` beside
  x86_64. Each is built **and started** on its own architecture — GitHub's arm64
  runners are free for public repositories — because the release job verifies
  its artifact by running `--dry-run` against every shipped policy, and a
  cross-built binary could not be started on the builder. That would have
  reduced "we ran it" to "it linked".

- **`--format json`: a structured event stream, and a schema to hold it to.**
  One JSON object per line on stdout — **every** event, allow rows included,
  because a SIEM wants the baseline and the audit log deliberately holds only
  violations. Documented in [`docs/EVENT_SCHEMA.md`](docs/EVENT_SCHEMA.md) as a
  versioned interface with explicit compatibility rules.

  ```console
  $ wardyn --enforce --format json run -- npm install | jq -c 'select(.enforced)'
  ```

  `schema_version` rides on **every record**, not on a header. An audit log is
  appended to across runs and read with `grep`, `tail -f` and `jq -c`, so a
  consumer routinely holds one line with no idea what came before it; a header
  is correct exactly once per file and useless downstream of a pipe.

  Two fields carry the meaning the tool has always had and never exposed
  machine-readably. **`enforced`** is what the kernel did, as distinct from
  `action`, which is what the policy says — they differ for a `warn`, for an
  unenforceable `block~`, and for every row in observe mode, and the doc says in
  as many words to count denials with the former. **`matched_key`** is the
  kernel key the decision fired on (`name=.aws/credentials`, `ip=1.1.1.1:25`),
  which is the right thing to aggregate by: `rule` is policy text and several
  rules can share a key. It is `null` for a warn, which denies nothing and so
  matches no key.

  The stream and the audit log share one record builder, so the fields they have
  in common cannot drift; a test asserts a log line is byte-identical to what
  that builder produces. `Plain` and `Json` also share one output loop — the
  signal handling, the periodic prune and the post-exit drain are where an event
  goes missing, and a second copy of them would be a second place for that.

  Proven against a real kernel: an e2e run asserts the stream parses as JSONL,
  that every record is versioned, that `matched_key` names the key that fired,
  that allow rows are present — and that the count of `enforced == true` records
  **equals the kernel's own denial counter**, which is the claim the whole
  format rests on.

  `--plain` still means what it did. `--format` wins where both are given, since
  `--plain --format json` is a request for machine output and not an ambiguity.

### Fixed

- **The feed showed `ok` for opens Landlock had just refused.** Containment is a
  second, independent boundary, and Landlock reports nothing back to wardyn — it
  is a different LSM and its refusals are invisible to our hooks. So an agent
  that read outside its `allow_paths:` got `Permission denied` while the feed
  printed an `ok` row for the same open. Feed and reality disagreeing is the one
  failure this codebase is built around not having; it arrived with
  `allow_paths:` in the same release, and is fixed before anything shipped with
  it.

  The mirror now consults the containment boundary and reports the denial,
  naming which grant fell short:

      open  BLOCK  /tmp/x/outside.txt  [allow_paths: outside every allow_paths hierarchy]
      open  BLOCK  /etc/wardyn-probe   [allow_paths: `/etc` is granted without `write`]

  This is a **prediction, and a weaker one than the rest**: every other mirror
  here can be corrected by the kernel reporting its own decision, and Landlock
  never will. So it is conservative — a relative path is not judged at all
  (resolving it would mean guessing the agent's working directory) and a symlink
  is judged on the name the syscall passed. Both err toward saying nothing,
  never toward announcing a denial that did not happen.

- **`domain:` rules were resolved once and then frozen for the life of the run.**
  A `{ domain: "registry.npmjs.org", action: allow }` was expanded at load into
  one host rule per address the resolver happened to return, and nothing ever
  re-resolved. CDN-fronted names rotate within minutes — and all three names in
  the shipped default policy are CDN-fronted — so a long agent session would
  start seeing legitimate traffic to an allowlisted host fall through to the
  `0.0.0.0/0` deny-all. Users experience that as wardyn being flaky, and
  flakiness is how a security tool gets switched off.

  Domain rules are now kept as *specs* and re-resolved every 60 seconds, with
  the difference pushed into the live kernel tries — the maps are held for the
  whole run precisely so they can be mutated, which the approve-once path
  already proved. The userspace mirror reads the same live set, so the feed
  cannot disagree with what is enforced.

  A refresh **replaces** the address set rather than growing it. Accumulating
  every address a name has ever had would never break a working agent, which is
  what makes it tempting — and it would let an `allow` drift steadily more
  permissive than what the operator wrote. A policy may not loosen itself.

  Changes are feed rows, including failures: a name that stops resolving stops
  enforcing, and that has to reach the operator while it is happening. It
  previously went to a `log::warn!` that nothing printed, since the logger is
  not initialised under the TUI at all.

  Precedence survives the split. Domain rules live in their own collection now,
  so a tie with a `cidr:` rule on the same `/32` can no longer be decided by
  position in one vector; every rule carries its position in the file instead,
  and a test pins both orderings.

- **The built-in LSM offsets were trusted on any architecture.** When BTF
  resolution fails, wardyn falls back to struct offsets measured with `pahole`
  on kernel 6.8 — and the check guarding that fallback compared only the kernel
  *version*. On an aarch64 machine running 6.8 it would have trusted numbers
  measured on x86_64, and predicted `BLOCK` for rows the kernel might never
  deny. Field offsets are not guaranteed to agree across architectures on one
  release: distro configs differ, and members of `struct file` and
  `struct dentry` sit behind `#ifdef`.

  Harmless until now only because there was no arm64 build to be wrong on —
  which is exactly why it is fixed in the same change that adds one. The
  fallback is now refused on any architecture but the one the numbers came from,
  and the startup notice says which half failed rather than reporting a version
  problem that is not there.

### Changed

- **A `match:` glob keeps its last two literal segments as the kernel key.**
  `/etc/shadow` used to compile to the bare name `shadow` and deny every file so
  called, anywhere; `**/.aws/credentials` denied every `credentials`; and
  `strict.yaml` had to make `**/.git/config` a `warn` because it and
  `**/.kube/config` both reduced to `config`. `--dry-run` printed all three as
  warnings on the shipped policies.

  The LSM hook already walks `d_parent` to match directory rules, so the
  parent's name is one probe away. Two new maps key on `(parent, name)` —
  `BLOCK_PAIRS` for files, `BLOCK_DIR_PAIRS` for a subtree and *its* parent —
  and are consulted before the single-name maps, because a key that says more
  is the more specific one and the exception it offers is the smaller one.
  `**/.env` still compiles to `.env` alone (the segment before it is `**`), so a
  policy written without a literal parent is unchanged.

  Two segments, not N: every rule in the shipped policies fits, and a
  `N × NAME_LEN` key assembled inside a bounded loop is verifier cost for rules
  nobody has written. It is still a **suffix** match — `/etc/shadow` means
  `etc/shadow` at any depth, and `/etc/ssl/private/key.pem` drops its first
  segment — and `overbroad_block_keys` now reports exactly that remainder
  instead of the old, much larger one.

  The userspace mirror consults the same keys in the same order, so a predicted
  pair denial and the kernel's confirmation of it agree; an approve-once
  exception lifts the pair, not the bare name. Proven end-to-end: the fixtures
  include a `credentials` that is *not* under `.aws` and a `gcloud` that is
  *not* under `.config`, and both must open. Seven portable tests pin the
  reduction, the ordering, the `.git`/`.kube` de-collision, and what
  `--dry-run` reports as still dropped.

## [0.1.0] — 2026-09-07

The first release. Wardyn watches one process subtree — an agent and everything
it spawns — and, under `--enforce`, denies what the policy forbids *at the
syscall boundary*, before the action completes.

What it can deny, in the kernel:

| axis | rule | hooks |
| --- | --- | --- |
| **network egress** | `cidr:` / `domain:`, narrowed by `port:` and `proto:` | `cgroup/connect4·6`, `cgroup/sendmsg4·6` |
| **secret reads** | `match:` (a glob over names) or `path:` (one object, by `(dev, ino)`), narrowed by `access: read \| write` | LSM `file_open` |
| **blocked programs** | the same two forms | LSM `bprm_check_security` |
| **deletion and creation** | `access: create \| delete \| all` | LSM `inode_unlink` / `rmdir` / `rename` / `create` / `mkdir` / `link` / `symlink` |

Three properties are worth stating plainly, because they are what the design
spends itself on:

- **The hook that decides is the hook that reports.** An observed `sys_enter`
  path can be relative, symlinked, or reached through a dirfd — so every denial
  is reported by the enforcement hook itself, naming the key it matched, and
  userspace renders that rather than re-deriving it. At exit the kernel's own
  counters are compared against everything the agent was told.
- **Wardyn fails open, and says so.** A verifier rejection, a failed attach, an
  unresolvable struct offset — each degrades to allowing the operation, names the
  reason at startup, and stops predicting `BLOCK` for the rows it can no longer
  promise. A security tool that silently enforces nothing is worse than one that
  admits it.
- **A rule means one thing before and after an upgrade.** `access:` defaults to
  covering opens only, and the create/delete axis is opt-in, so no policy written
  against an earlier build changed meaning when this one shipped. The end-to-end
  suite asserts that in the kernel rather than in a comment.

Requires a Linux kernel with BTF and cgroup v2; file, exec and lifecycle
enforcement additionally require the BPF LSM (`lsm=...,bpf`). Without it, network
egress blocking still works and startup says the rest is off.

Known limits are documented in [SECURITY.md](SECURITY.md) and pinned by the e2e
suite so they cannot quietly start being claimed as fixed — most notably that
copying a *blocked binary* to a new name still runs it.

### Fixed

- **A rejected eBPF program could pass the verifier smoke test as an environment
  skip.** The test tells "this kernel cannot host the program" from "the kernel
  read the program and refused it" by looking for aya's `Verifier output` marker
  — but it looked in `{err:?}` only, and aya renders the log through `Display`.
  So a real rejection was filed as a skip and the test went green, which is
  exactly the outcome it exists to make impossible. It now searches both forms.
  Two genuinely rejected programs went by that way before it was noticed (both
  dereferencing a context pointer at a non-constant offset — legal Rust, and
  `dereference of modified ctx ptr` at load).

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

- **`proto: tcp | udp` on network rules (M6).** A rule can now name the transport,
  and rules are consulted in four tiers, most specific first — protocol+port,
  port, protocol, address:

  ```yaml
  network:
    - { port: 53, proto: udp, action: allow }   # the resolver works...
    - { port: 53,             action: block }   # ...but 53/tcp is a tunnel
    - { proto: udp,           action: block }   # no other UDP, anywhere
  ```

  Each tier is its own LPM trie, keyed with the protocol leading and the port
  behind it, so a rule that names a dimension beats one that does not whatever
  their address prefixes — the same guarantee `port:` already made, extended one
  dimension. Letting prefix length decide *across* dimensions instead would make
  `{ proto: udp, action: block }` a `/0` rule that any `/8` allow outranks, and
  "no UDP at all" would quietly not mean that.

  The protocol comes from `bpf_sock_addr->protocol`, not from which hook fired:
  `connect(2)` runs on UDP sockets too, so "connect means TCP" would file every
  connected datagram under the wrong rule — including the DNS a program is most
  likely to send.

  ## The feed cannot see a protocol, and now says so

  The `sys_enter_connect` tracepoint sees a `sockaddr`, not a socket. Where a
  policy makes the outcome depend on the transport, the userspace mirror reports
  the *lenient* of the two verdicts and marks it unenforceable, rather than
  asserting a denial the kernel may not make. `--dry-run` says the same thing in
  words.

  The first attempt simply skipped the protocol tiers when the protocol was
  unknown, which looks like the safe direction and is not: a proto-qualified
  *allow* outranks a lower-tier block, so ignoring it made the audit record
  `block, enforced: true` for a connection the kernel had just permitted. The
  e2e suite caught it, and a unit test now pins the behaviour that replaced it.

- **A create/delete axis — `access: create` / `delete` / `all` (M6).** `rm` is not
  an open. Every file rule wardyn had was matched at `file_open`, and that hook
  does not fire for `unlink(2)` at all — so a policy could guard a secret's
  contents and still watch the agent delete it, and `rm -rf` was never a read.

  ```yaml
  files:
    - { match: "**/*.sqlite", action: block, access: delete }  # may edit, may not remove
    - { path:  "~/.ssh",      action: block, access: all }     # no reads, no rm, no new files
  ```

  Seven LSM hooks carry it — `inode_unlink`, `inode_rmdir`, `inode_rename`,
  `inode_create`, `inode_mkdir`, `inode_link`, `inode_symlink` — running the same
  three-step match as `file_open` (identity, own name, bounded ancestor walk)
  against the same four maps. Only the test differs: a bit of the stored mask
  instead of the `f_mode` an open requested. Sharing the maps is what keeps
  `{ path: "~/.ssh", access: all }` one rule rather than two, and what lets an
  approve-once exception land on a key the operator already recognises.

  ## `any` still means opens only, and always will

  The default is `access: any`, and it covers **no** lifecycle operation. That is
  not an oversight to be tidied up later: `MASK_ANY` is the mask every `block`
  rule ever written already carries, so widening it would mean every deployed
  policy silently started refusing `rm` the day wardyn was updated — a change of
  meaning on the rules people re-read least. `fmode::covers` therefore has no
  zero escape hatch, and the e2e suite asserts the guarantee *in the kernel*:
  a plain `block` on `.env`, and the agent deletes it.

  Making the two axes coexist in one byte is why `OPEN_ANY` exists. `MASK_ANY` is
  zero and zero cannot also carry a `DELETE` bit, so a mask that covers both
  spells "every open" explicitly — and `fmode::widen` returns the canonical zero
  whenever the result is opens-and-nothing-else, keeping map bytes identical to a
  build that predates the axis.

  ## A rename is two operations, and both ends are checked

  `inode_rename` checks its **source** for `DELETE` — without it, `mv secret
  /tmp/x` empties a protected directory one file at a time — and its
  **destination** for `CREATE|DELETE`, without which `mv evil
  ~/.ssh/authorized_keys` writes into one and `mv junk protected` destroys it.
  `link` and `symlink` are hooked for the same reason: they are the other two
  one-word ways to make a name exist.

  ## The rest of the honesty budget

  An approve-once exception on a lifecycle denial **narrows the stored mask**
  rather than dropping the key — approving one `rm` must not also unblock every
  read of the file — and the key is removed only when clearing the bit leaves
  nothing, because writing zero back would mean `MASK_ANY`, the opposite of what
  was granted. The hooks are gated on a `CONFIG` flag and attached only when a
  policy asks for the axis; they attach individually, and any hook a kernel
  refuses is named at startup instead of leaving the policy claiming something
  the kernel is not holding. An `exec:` rule that names `create`/`delete` is
  refused at load, because exec rules compile into maps these hooks never read.

  There is no observation tracepoint for these syscalls: a removal appears in the
  feed only when it is refused, and the row says so rather than implying a
  missing observation.

  Proven end-to-end on a BPF-LSM kernel, not asserted: the agent's `rm`, `rmdir`,
  `touch`, `mkdir`, `mv`, `ln` and `ln -s` are each refused where a rule covers
  them, its read of the delete-protected file still succeeds, and its `rm` of a
  plainly-blocked `.env` still succeeds — that last one being the compatibility
  guarantee, checked by the kernel rather than by a comment.

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

  The suite is now 29 assertions with **0 skips** on a BPF-LSM kernel. It was 10
  with 1 skip, and that one skip was the entire file/exec axis.

- **`port:` in network rules.** A network rule may name a destination port:

  ```yaml
  network:
    - { cidr: "10.0.0.0/8", action: allow }              # the whole LAN
    - { port: 25,           action: block }              # ...but never SMTP
    - { cidr: "10.0.0.5/32", port: 25, action: allow }   # except this relay
  ```

  Port-qualified rules live in their own LPM trie (`NET_PORT_RULES`), keyed
  `[port, address]` and consulted **before** the address-only one. So a rule that
  names a port beats one that does not, whatever their address prefixes — which
  is both what the kernel does and what people mean by "never SMTP". Within the
  port trie it is longest-prefix as usual, so a specific host can be allowed back.
  A bare `port:` with no `cidr:` covers **both** address families; a v4-only
  reading would leave the same port open over IPv6, which is the exact shape of
  the hole the `::/0` rule had to be added for.

  Port before address in the key is forced, not stylistic: an LPM trie compares
  from the most significant end, so address-first would put the port bits out of
  reach of any rule that did not also fix all 32 address bits — making "port 25,
  anywhere" inexpressible.

  Protocol is deliberately not a third dimension. Behind the port it would make
  "this protocol to this address, any port" inexpressible, and that restriction
  is harder to explain than the expressiveness is worth. `port:` alone covers the
  policies people actually write.

  The kernel now reports **which trie decided** (`meta = KEY_PORT`), because an
  approve-once exception must be written into the trie that denied — an allow in
  the address trie would be overruled by the port rule on the very next connect,
  and the operator would watch their approval do nothing. The confirm prompt is
  also narrower for a port denial: "egress to 1.1.1.1 on port 25 only" rather
  than "ALL egress to 1.1.1.1".

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

### The three milestones underneath all of the above (M1–M3)

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

[Unreleased]: https://github.com/kadircanyildirm-crypto/wardyn/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kadircanyildirm-crypto/wardyn/releases/tag/v0.2.0
[0.1.0]: https://github.com/kadircanyildirm-crypto/wardyn/releases/tag/v0.1.0
