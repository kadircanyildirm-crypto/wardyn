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
| 0.1.x   | ✅ (latest `main`) |
| < 0.1   | ❌        |

Only the latest commit on `main` and the most recent tagged release receive
security fixes while the project is pre-1.0.

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
- escape the watched subtree so its children are no longer followed;
- crash, hang, or otherwise disable Wardyn from userspace.

Out of scope (known limitations, documented, not vulnerabilities):

- **Fail-open by design.** On a kernel read error or a verifier/attach failure,
  Wardyn allows the operation rather than denying it. This is deliberate: Wardyn
  must never brick an otherwise-working system.
- **Observe-only rules.** File/exec `block` rules that don't reduce to an exact
  basename or parent-directory name, and default-deny on files/exec, are flagged
  in the feed but **not** kernel-enforced. The feed labels these honestly
  (`block~`).
- **Kernel-offset drift.** File/exec enforcement reads `struct file`, `dentry` and
  `inode` fields by byte offset. Wardyn resolves them from the running kernel's
  BTF, including through anonymous members (Linux 6.13 moved `f_path` into an
  anonymous union — a resolver that missed that failed open on every kernel since,
  which is why the resolution is now tested against the kernel the tests run on).
  If resolution fails, Wardyn falls back to built-in kernel-6.8 offsets, names the
  reason at startup, and stops predicting `BLOCK` for file/exec rows unless the
  running kernel really is 6.8. `scripts/kernel-offsets.sh` is a manual
  cross-check.
- **Requires privilege you already granted.** Wardyn needs root to load eBPF; it
  does not defend against an attacker who is already root outside the watched
  subtree. To keep the watched subtree from being that attacker, `run` now drops
  the child to `$SUDO_UID`/`$SUDO_GID` before `exec` by default (with
  `PR_SET_NO_NEW_PRIVS`); pass `--keep-root` to disable this or `--as-user` to
  choose the target identity. A child kept at root can still reach the enforcement
  maps and disable itself — do not run untrusted agents with `--keep-root`.

- **`match:` rules are name-based, and a name comes off with one `mv`.** The LSM
  matcher keys a glob rule on the file's basename and on the names of its ancestor
  directories (a bounded walk, so a `**/dir/**` rule does cover the whole subtree).
  That stops *accidental and naive* access, and is **bypassable** by renaming or
  hard-linking the target before opening it — `mv` and `link()` are not hooked.
  Write a `path:` rule alongside it for anything that matters: those are pinned to
  `(dev, ino)` at load and follow the object through renames and hard links.

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

- **Rules are matched, not the intent behind them.** `access: read` narrows a rule
  to opens requesting `FMODE_READ`. An `O_PATH` open requests neither read nor
  write and is covered only by a rule with no `access:` (the default).

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

- **Events can still be lost under load.** The ring buffer is finite; a burst that
  overruns it drops events, and a dropped event for a denied action means no feed
  row, no audit record and no receipt line. Wardyn counts drops in the kernel and
  reports them in the header and at exit — it does not silently pretend the run was
  clean.

The complete, adversarially-verified list of gaps and escapes — including several
not yet fixed — is in [`docs/AUDIT.md`](./docs/AUDIT.md). It is required reading
before depending on Wardyn.
