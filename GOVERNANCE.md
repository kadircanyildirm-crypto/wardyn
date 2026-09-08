<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Governance

What you can rely on from this project, and what you cannot. Written plainly
because the alternative — leaving it unsaid — lets a reader assume more than is
true, and wardyn is a tool people put between an autonomous agent and their
filesystem.

## Who decides

Wardyn is maintained by one person: [@kadircanyildirm-crypto][owner]. There is
no committee, no vote, and no second maintainer with merge rights. Decisions
about scope, the threat model, and what ships are the maintainer's.

That is a real limitation and worth stating in the form it will actually reach
you: **there is a bus factor of one.** If you are considering wardyn for
something you cannot afford to have go unmaintained, weigh that. The AGPL
guarantees you can fork it; it does not guarantee anyone will be here.

[owner]: https://github.com/kadircanyildirm-crypto

## What gets accepted

Contributions are welcome and are judged on whether they make the tool *more
honest*, not only more capable. The rules that decide most reviews are in
[CONTRIBUTING.md](CONTRIBUTING.md); the two that decide the hard ones are:

1. **A claim the tool makes must be true.** A feature that enforces less than
   its output says is not a partial feature, it is a defect. Most of this
   project's fixed bugs were of that shape — see
   [CHANGELOG.md](CHANGELOG.md) and [docs/AUDIT.md](docs/AUDIT.md).
2. **Fail open, and say so** — except where failing open removes a boundary
   rather than weakening one. Landlock containment and `run` pid-scoping refuse
   to start instead; the reasoning is in the code at both sites.

A change to the kernel side must be verified on a machine with BPF-LSM active.
`cargo build` passing is not evidence. See CONTRIBUTING.md for the loop.

## Releases

Semantic versioning, pre-1.0: minor versions may change behaviour, and the
CHANGELOG has an **Upgrading** section whenever they do. There is no fixed
cadence — releases happen when there is something worth releasing, which so far
has meant every few days rather than every few months. Tagged releases build
`x86_64` and `aarch64` musl binaries with checksums.

**No release is on a schedule, and no version has a support window.** Only the
latest tagged release and `main` receive fixes. See
[SECURITY.md](SECURITY.md#supported-versions).

## Security reports

[SECURITY.md](SECURITY.md) has the process and the threat model. In short:
report privately, expect an acknowledgement, and expect the fix and the
disclosure to be one commit with the reasoning written down — that is how the
audit-log symlink hole and the pid-namespace misattribution were handled, and
both are described in the CHANGELOG in enough detail to reproduce them.

## Licensing

The workspace is **AGPL-3.0-or-later**. Two crates are dual-licensed
`GPL-2.0-only OR AGPL-3.0-or-later` — `wardyn-ebpf` and `wardyn-common` — because
they compile into the object the kernel loads, and that object must declare a
GPLv2-compatible licence to use the helpers it needs. The reasoning is in
`wardyn-ebpf/src/main.rs` beside the declaration.

Relicensing the userspace side is not planned. If you need different terms, open
a discussion rather than assuming; the answer may be no, but it will be a real
answer.

## What this project is not

- **Not a compliance product.** There is no certification, no attestation, and
  no auditor behind the audit report — [docs/AUDIT.md](docs/AUDIT.md) says so at
  the top.
- **Not a complete sandbox.** io_uring, AF_UNIX delegation to a local daemon,
  and several other paths are outside what the hooks see. They are listed in
  SECURITY.md rather than left for you to discover.
- **Not a substitute for not running untrusted code.** Wardyn narrows what an
  agent can reach and records what it tried. It is a warden, not a proof.
