# Security Policy

Leash is a security tool that runs privileged (root) and loads eBPF programs into
the kernel. We take vulnerabilities in it seriously and appreciate responsible
disclosure.

> ⚠️ **Status: early development (0.1.x).** Leash is not yet production-ready.
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

Report privately via GitHub's **[Private vulnerability reporting](https://github.com/kadircanyildirm-crypto/leash/security/advisories/new)**
(Security → Advisories → *Report a vulnerability*). This keeps the report
confidential until a fix is available.

If you cannot use GitHub advisories, email the maintainer at
**kadir.can.yildirm@gmail.com** with `[leash security]` in the subject.

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
- crash, hang, or otherwise disable Leash from userspace.

Out of scope (known limitations, documented, not vulnerabilities):

- **Fail-open by design.** On a kernel read error or a verifier/attach failure,
  Leash allows the operation rather than denying it. This is deliberate: Leash
  must never brick an otherwise-working system.
- **Observe-only rules.** File/exec `block` rules that don't reduce to an exact
  basename or parent-directory name, and default-deny on files/exec, are flagged
  in the feed but **not** kernel-enforced. The feed labels these honestly
  (`block~`).
- **Kernel-offset drift.** File/exec enforcement reads `dentry` fields at offsets
  derived for a specific kernel. On a mismatched kernel these reads may silently
  fail; Leash warns at startup. Regenerate with `scripts/kernel-offsets.sh`.
- **Requires privilege you already granted.** Leash needs root to load eBPF; it
  does not defend against an attacker who is already root outside the watched
  subtree.
