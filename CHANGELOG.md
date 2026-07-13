# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- UDP egress enforcement: `sendmsg4` / `sendmsg6` cgroup hooks gate connectionless
  traffic alongside `connect4` / `connect6`, reusing the same policy logic.
- Community & security infrastructure: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates, Dependabot, and a `cargo-deny`
  supply-chain audit workflow.

### Changed

- README and roadmap updated to reflect completed IPv6 egress and UDP gating.

### Fixed

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

[Unreleased]: https://github.com/kadircanyildirm-crypto/leash/compare/main...HEAD
