# Security Policy

Wardyn is a security tool that runs privileged (root) and loads eBPF programs into
the kernel. We take vulnerabilities in it seriously and appreciate responsible
disclosure.

> ⚠️ **Status: early development (0.1.x).** Wardyn is not yet production-ready.
> Enforcement is best-effort and depends on kernel configuration (BTF, cgroup v2,
> BPF LSM) and kernel-version-specific struct offsets. Do not rely on it as your
> only line of defense.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ (current release, and latest `main`) |
| < 0.3   | ❌ |

Only the latest commit on `main` and the most recent tagged release receive
security fixes while the project is pre-1.0. There is no backport window, and
no version has a support end-date to plan around — see
[GOVERNANCE.md](GOVERNANCE.md), which says what this project does and does not
promise.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's **[Private vulnerability reporting](https://github.com/kadircanyildirm-crypto/wardyn/security/advisories/new)**
(Security → Advisories → *Report a vulnerability*). This keeps the report
confidential until a fix is available.

If you cannot use GitHub advisories, email the maintainer at
**kadir.can.yildirm@gmail.com** with `[wardyn security]` in the subject.

Please include:

- affected version / commit,
- kernel version and distro (`uname -a`), and whether BPF LSM was enabled,
- a description of the issue and its impact,
- reproduction steps or a proof of concept if you have one.

### What to expect

- **Acknowledgement:** within 5 business days.
- **Assessment & fix timeline:** we aim to confirm and triage within 10 business
  days and to ship a fix as fast as the severity warrants.
- **Credit:** we're happy to credit you in the advisory and changelog unless you
  prefer to remain anonymous.

## Threat model & scope

In scope — issues that let a **watched** process:

- read a file, run a binary, or open a network connection that policy marks
  `block`, while `--enforce` is active and the rule is kernel-enforceable;
- delete, rename away, or create a file that a rule marks `block` with
  `access: create`, `delete` or `all`, under the same conditions;
- reach a path outside the `allow_paths:` hierarchies when a policy sets them —
  reading, writing, executing, or renaming across the boundary;
- escape the watched subtree so its children are no longer followed;
- crash, hang, or otherwise disable Wardyn from userspace.

Out of scope (known limitations, documented, not vulnerabilities):

- **Fail-open by design.** On a kernel read error or a verifier/attach failure,
  Wardyn allows the operation rather than denying it. This is deliberate: Wardyn
  must never brick an otherwise-working system.
- **Observe-only rules.** File/exec `block` rules whose last segment is not a
  literal name (`**/*.key`, `**/.env.*`), and default-deny on files/exec, are
  flagged in the feed but **not** kernel-enforced. The feed labels these honestly
  (`block~`).
- **Kernel-offset drift.** File/exec enforcement reads `struct file`, `dentry` and
  `inode` fields by byte offset. Wardyn resolves them from the running kernel's
  BTF, including through anonymous members (Linux 6.13 moved `f_path` into an
  anonymous union — a resolver that missed that failed open on every kernel since,
  which is why the resolution is now tested against the kernel the tests run on).
  If resolution fails, Wardyn falls back to built-in kernel-6.8 offsets, names the
  reason at startup, and stops predicting `BLOCK` for file/exec rows unless the
  running kernel really is 6.8 **and the machine is x86_64**, which is where
  those numbers were measured. Field offsets are not guaranteed to agree across
  architectures on one release — distro configs differ and several members of
  `struct file` sit behind `#ifdef` — so on arm64 the built-ins are never
  trusted and BTF resolution is effectively required. `scripts/kernel-offsets.sh` is a manual
  cross-check.
- **Requires privilege you already granted.** Wardyn needs root to load eBPF; it
  does not defend against an attacker who is already root outside the watched
  subtree. To keep the watched subtree from being that attacker, `run` now drops
  the child to `$SUDO_UID`/`$SUDO_GID` before `exec` by default (with
  `PR_SET_NO_NEW_PRIVS`); pass `--keep-root` to disable this or `--as-user` to
  choose the target identity. A child kept at root can still reach the enforcement
  maps and disable itself — do not run untrusted agents with `--keep-root`.

- **`match:` rules are name-based, and a name comes off with one `mv`.** The LSM
  matcher keys a glob rule on its last two literal segments — `(parent, name)`
  when the parent is literal, the bare name when it is not — and on the names of
  its ancestor directories (a bounded walk, so a `**/dir/**` rule does cover the
  whole subtree). Two segments is still a suffix match: `/etc/shadow` denies
  `etc/shadow` at any depth, and `--dry-run` says so.
  That stops *accidental and naive* access, and is **bypassable** by renaming or
  hard-linking the target before opening it: a rule that does not name
  `access: delete` permits the `mv`, and `link()` is only consulted for the name
  it creates, never the object it aliases. Write a `path:` rule alongside it for
  anything that matters: those are pinned to `(dev, ino)` at load and follow the
  object through renames and hard links, so the bypass buys nothing.

- **What identity matching still does not cover.**
  - **Objects that do not exist when the policy loads** cannot be pinned. A `path:`
    rule for a file created later resolves to nothing and says so at startup and
    in `--dry-run`; only the `match:` rule covers it. Keep both.
  - **Copying a blocked *binary*** to a new name still runs it: the copy is a
    different inode with a different name, and — unlike a secret — a binary is
    world-readable, so there is no read to deny. Closing this needs content or
    provenance matching, not identity. The e2e suite pins this as a known limit,
    so it cannot quietly start being claimed as fixed.
  - **Copying a blocked *secret*** is not a bypass: `cp` has to read the source,
    and that read is denied. This is asserted end-to-end.
  - **Filesystems that report a different `(dev, ino)` to userspace than the
    inode carries** — overlayfs without `xino`, most visibly inside containers —
    can make an anchor fail to match. It fails *open*, degrading to the name rule,
    and never denies the wrong object: the key simply matches nothing.

- **A `proto:` rule is enforced but not predicted.** The kernel reads the
  socket's protocol; the connect tracepoint cannot, because it sees a `sockaddr`
  and not a socket. Where a policy makes a destination's verdict depend on the
  transport, the observed feed row reports the lenient verdict and does **not**
  claim enforcement — the kernel's own `DENY_NET` row is what reports a denial.
  A row that says `ok` followed by a kernel `⛔BLOCK` for the same destination is
  this, working as intended.

- **`proto:` names a transport, not a payload.** `{ proto: udp, action: block }`
  refuses UDP sockets; it says nothing about what is tunnelled over the transports
  that remain, and DNS-over-HTTPS or a shell over 443/tcp are not protocol-level
  events. Rules are matched at `connect`/`sendmsg`, so a raw socket
  (`SOCK_RAW`, `AF_PACKET`) or an already-established connection is outside what
  these hooks see at all.

- **`domain:` rules are only as sound as DNS.** They are re-resolved every 60
  seconds and the kernel tries are updated in place, so an allowlisted CDN that
  rotates is followed rather than silently falling through to a deny-all. What
  that does **not** fix: between two refreshes the answer can be stale; wardyn
  resolves through the *system* resolver, which is not necessarily the one the
  agent uses; and a `block` by name is defeated by anyone who controls the name,
  since they choose what it answers. A domain block is a convenience, not a
  boundary — use `cidr:` where it has to hold.

- **Containment is opt-in, and restricts rather than replaces.** With
  `allow_paths:` the agent reaches the listed hierarchies and nothing else,
  enforced by Landlock: inherited across `exec`, impossible to undo, and needing
  no privilege, so it holds even for a root agent. Without `allow_paths:` there
  is no containment at all and wardyn is purely a blocklist — it will not invent
  an allowlist, since an empty one denies the agent its own loader.

  What it does not do: there is no mount namespace, so a denied path still
  exists and its name still shows up in the error. And Landlock does not govern
  mounting, so an agent left at root (`--keep-root`) can work around it — one
  more reason the privilege drop is the default.

- **Rules are matched, not the intent behind them.** `access: read` narrows a rule
  to opens requesting `FMODE_READ`. An `O_PATH` open requests neither read nor
  write and is covered only by a rule with no `access:` (the default), or by
  `access: all`.

- **A `block` rule on its own says nothing about deleting.** `file_open` does not
  fire for `unlink(2)`, so an ordinary `block` protects a file's *contents* and
  leaves `rm` untouched. That is deliberate and permanent: making the default
  cover removals would change the meaning of every policy already written. Use
  `access: delete` (or `all`), and check `wardyn --dry-run`, which prints
  `DELETING` beside the keys that really have it.

- **What the `delete` axis does not protect.** It protects the *name*, not the
  bytes. An agent that may still write the file can empty it (`> secret`,
  `truncate`, or an in-place rewrite) without ever unlinking anything, and no
  lifecycle hook fires. If the contents matter, deny the write as well —
  `access: all` does both. Similarly, `create` governs which names may appear
  (`open(O_CREAT)`, `mkdir`, `link`, `symlink`, and a rename's destination); it
  cannot govern what is written into a name that already exists.

- **`create` rules can only match names and ancestors, never identity.** At
  `inode_create` the object does not exist, so there is no `(dev, ino)` to pin.
  A `path:` rule therefore contributes nothing to the create axis for the file
  itself — only for the directory it would appear in, which is the useful case
  (`{ path: "~/.ssh", access: all }` refuses a new `authorized_keys` however it
  is spelled).

- **The lifecycle hooks are attached best-effort.** `file_open` and
  `bprm_check_security` are load-bearing and a failure to attach either disables
  LSM enforcement outright. The seven create/delete hooks are attached
  individually, and any that a kernel refuses are **named at startup** while the
  rest keep working — a policy is never left quietly claiming an axis the kernel
  is not holding. They are attached only when a policy asks for the axis.

- **Rule *order* does not survive into the kernel.** Under `--enforce` the LSM hook
  holds an unordered set of block keys, so an `allow` rule listed before a `block`
  does not create an exception for anything that block's key covers. Startup names
  every rule this affects, and `--dry-run` lists them without running anything.

- **Denials are reported by the hook that makes them** — each enforcement hook
  emits an event naming the key it matched, so a dirfd-relative open, a symlinked
  path, a `sendmsg()` destination or an off-feed syscall path is reported even
  though the observed path described something else. What userspace still *infers*
  is the prediction shown before the kernel answers; when the LSM does not attach
  or `dentry` offsets are untrustworthy, those predictions are demoted to `block~`
  rather than asserting a denial that did not fire, and at exit the kernel's own
  denial counters are compared against everything the receipt claimed.

- **The policy must live somewhere the agent cannot write.** It is not evidence
  like the audit log — it *is* the enforcement, so an agent that can edit it
  decides what wardyn does on the next run. The default is `./policy.yaml`,
  which in the documented `cd project && sudo wardyn run -- agent` is inside the
  tree the agent works in.

  Wardyn cannot refuse that: a policy checked into the project it governs is a
  legitimate and common setup. What it does is name the source at startup — the
  three of them (`--policy`, `./policy.yaml`, the built-in default) used to fall
  back to each other silently, so running from the wrong directory changed the
  policy with nothing said — and warn when the file is writable by the agent's
  uid. Keep the policy outside the agent's reach where that matters.

- **The audit log must live somewhere only root can write.** Wardyn refuses to
  open it through a symlink, refuses a file it does not own, and refuses one
  writable by group or others — a security record a second party can redirect or
  rewrite is not one. It creates the log `0600`, because the log names every
  path the agent touched.

  What it cannot fix is the *directory*. The default `--audit` path is relative,
  so it usually lands in the project the agent is working in. Records written
  during the run are safe (appends follow the open descriptor, so a rename
  cannot redirect them), but the finished file can be moved aside and replaced
  once wardyn exits, and nobody reading it later could tell. Startup says so
  when it detects that. If the log has to be evidence, put it somewhere the
  agent cannot write.

- **Events can still be lost under load.** The ring buffer is finite; a burst that
  overruns it drops events, and a dropped event for a denied action means no feed
  row, no audit record and no receipt line. Wardyn counts drops in the kernel and
  reports them in the header and at exit — it does not silently pretend the run was
  clean.

The complete, adversarially-verified list of gaps and escapes — including several
not yet fixed — is in [`docs/AUDIT.md`](./docs/AUDIT.md). It is required reading
before depending on Wardyn.
