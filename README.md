# 🐕 Wardyn

**A kernel-level warden for AI coding agents.** Wardyn watches an agent's process
tree with eBPF and enforces — in real time, at the syscall boundary — what it may
**read**, **run**, and **connect to**. It catches the agent reading your `.env`
or dialing an unknown IP, and can *block* it before the operation completes.

[![CI](https://github.com/kadircanyildirm-crypto/wardyn/actions/workflows/ci.yml/badge.svg)](https://github.com/kadircanyildirm-crypto/wardyn/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-AGPL--3.0-blue)
![built with Rust + aya](https://img.shields.io/badge/built%20with-Rust%20%2B%20aya-orange?logo=rust)
![eBPF](https://img.shields.io/badge/eBPF-tracepoints%20%C2%B7%20cgroup%20%C2%B7%20LSM-6f42c1)
![status](https://img.shields.io/badge/status-early%20development-yellow)

<!-- Demo GIF: record with docs/RECORDING.md, drop it at docs/wardyn-demo.gif, then
     uncomment this:
<p align="center"><img src="docs/wardyn-demo.gif" width="820"
  alt="Wardyn blocking an agent from reading .env and dialing an unknown IP"></p>
-->

```console
$ sudo wardyn --enforce run -- claude "refactor the auth module"

  PID    COMM     EVENT    ACT     DETAIL
  40218  claude   exec     ok      /usr/bin/node
  40231  node     open     ok      /home/me/project/src/auth.rs
  40231  node     open     ⛔BLOCK  /home/me/.ssh/id_ed25519   [**/.ssh/**]
  40244  node     exec     ⚠ warn  /usr/bin/curl
  40244  curl     connect  ⛔BLOCK  185.220.101.7:443          [cidr:0.0.0.0/0]
  40250  node     open     ⛔BLOCK  /home/me/project/.env      [**/.env]

  wardyn: 3 policy violation(s) logged to wardyn-audit.jsonl
```

> ⚠️ **Status: early development.** M1–M3 done: observe + policy + **kernel-level
> enforcement** for files, execs and network (TCP + UDP, IPv4 + IPv6). M4 (demo
> GIF, devcontainer, packaging) in progress. Not production-ready — see
> [Roadmap](#roadmap).

## Why

You hand an autonomous agent a shell. It should build your project — not exfiltrate
`~/.ssh`, POST your `.env` to an unknown host, or spawn a reverse shell. Userspace
guards (seccomp wrappers, `LD_PRELOAD`, ptrace) are bypassable and race-prone.

Wardyn runs in the **kernel**: the watched process can't see it, can't unload it,
and Wardyn denies the syscall itself — synchronously, before it completes.

## What it does

For the process subtree you launch (`wardyn run -- <cmd>`, followed across `fork`):

| Axis | Observe | Enforce (`--enforce`) | eBPF hook |
|---|---|---|---|
| **exec** — programs run | ✅ path + comm | ⛔ deny blocked binaries | `tracepoint/execve` + LSM `bprm_check_security` |
| **file** — files opened | ✅ path | ⛔ deny secret reads (`.env`, `.ssh/*`) | `tracepoint/openat` + LSM `file_open` |
| **network** — egress | ✅ dest ip:port | ⛔ deny blocked CIDRs (TCP + UDP, IPv4/IPv6) | `tracepoint/connect` + `cgroup/connect4·6` + `sendmsg4·6` |

Every action is checked against a [`policy.yaml`](#policy) → `allow` / `warn` /
`block`, shown live (coloured) and written to a JSONL audit log.

**Surgically scoped & safe:** enforcement only ever touches the subtree you
launched, and only with `--enforce`. The rest of the system is never affected —
`wardyn --enforce run -- agent` can block the agent from `8.8.8.8` while every other
process on the host reaches it fine.

## Quickstart

Wardyn needs Linux with **BTF**, **cgroup v2**, and — for file/exec blocking —
**BPF LSM** enabled. On macOS/Windows, run it in a Linux VM.

```bash
# 1. one-time: enable BPF LSM (adds `lsm=...,bpf` to the kernel cmdline) + reboot
sudo ./scripts/enable-bpf-lsm.sh && sudo reboot

# 2. one-time: toolchain (rustup nightly + rust-src, bpf-linker)
./scripts/setup-vm.sh

# 3. build
cargo build --release      # userspace + eBPF, via aya-build

# 4. observe (no blocking) — watch an agent's whole subtree
sudo ./target/release/wardyn run -- bash

# 5. enforce — actually block policy violations
sudo ./target/release/wardyn --enforce run -- bash scripts/demo.sh
```

Renders a live TUI when attached to a terminal; pipe it (or pass `--plain`) for a
plain table. `--policy <file>` and `--audit <file>` override the defaults.

## Policy

[`policy.yaml`](./policy.yaml) — three ordered rule lists; **first match wins**;
`default_action` is the fallback. Actions: `allow | warn | block`.

```yaml
default_action: allow

files:                                   # glob against the opened path (** spans dirs)
  - { match: "**/.env",      action: block }
  - { match: "**/.ssh/**",   action: block }
  - { match: "/etc/shadow",  action: block }
  - { match: "**",           action: allow }

network:                                 # cidr, or domain (resolved at load)
  - { cidr: "127.0.0.0/8",   action: allow }
  - { domain: "github.com",  action: allow }
  - { cidr: "0.0.0.0/0",     action: block }   # deny all other egress

exec:                                    # glob against the executable path
  - { match: "**/nc",        action: block }   # netcat / reverse shells
  - { match: "**",           action: allow }
```

Ready-made presets live in [`policies/`](./policies).

## How it works

```
   wardyn run -- <agent>
          │  spawn + watch (WATCHED map, sched_process_fork follows the subtree)
          ▼
  ┌───────────────────────────── watched process tree ─────────────────────────┐
  │      exec                    file open                    connect           │
  └────────┬────────────────────────┬───────────────────────────┬──────────────┘
           ▼                         ▼                           ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  KERNEL (eBPF)                                                           │
  │   observe:  tp/execve          tp/openat          tp/connect  ──────┐    │
  │   enforce:  LSM bprm_check      LSM file_open      cgroup/connect4   │    │
  │             └─ -EPERM ─┘        └─ -EPERM ─┘       └─ deny ─┘        │    │
  │        ▲ compiled policy (basenames · dirs · CIDR LPM-trie)         │    │
  └────────┼────────────────────────────────────────────────────── ring│buf ─┘
           │ maps                                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  USERSPACE   policy.yaml ─▶ allow / warn / block                         │
  │              └─▶ live coloured TUI      └─▶ JSONL audit log              │
  └─────────────────────────────────────────────────────────────────────────┘
```

- **Observation** — tracepoints on `execve` / `openat` / `connect` stream a
  structured event per action into a ring buffer; userspace evaluates the policy,
  colours the feed, and writes the audit log.
- **Scoping** — `WATCHED` is seeded with the launched pid; a `sched_process_fork`
  hook adopts children in-kernel, so the whole subtree is followed race-free.
- **Enforcement** — separate programs deny inline: `cgroup/connect4·6` +
  `sendmsg4·6` return *deny* for blocked egress (TCP connect and UDP sendmsg, IPv4
  & IPv6); BPF-LSM `file_open` / `bprm_check_security` return `-EPERM` for blocked
  reads / execs. All gated on `WATCHED` + an `enforce` flag.

Full design, hook map, and the eBPF-verifier war stories are in
**[ARCHITECTURE.md](./ARCHITECTURE.md)**.

## Requirements

- Linux with BTF (`/sys/kernel/btf/vmlinux`) — kernel ≥ 5.8.
- cgroup v2 (for network blocking).
- BPF LSM (`CONFIG_BPF_LSM=y` + `lsm=...,bpf` on the cmdline) for file/exec blocking.
- Root (to load/attach eBPF).
- Built with Rust nightly + `bpf-linker` ([aya](https://aya-rs.dev)).

> The LSM file/exec matcher reads a few `dentry` fields at fixed offsets for the
> target kernel (aya-ebpf 0.1 ships neither `bpf_d_path` nor vmlinux structs).
> Regenerate them for another kernel with [`scripts/kernel-offsets.sh`](./scripts/kernel-offsets.sh).

## Roadmap

- [x] **M1 — Observe:** live tree of exec/open/connect, scoped to a subtree.
- [x] **M2 — Policy:** `policy.yaml` (glob + CIDR), allow/warn/block, JSONL audit.
- [x] **M3 — Block:** deny egress (cgroup — TCP + UDP, IPv4 + IPv6) + secret reads
  & blocked execs (LSM).
- [ ] **M4 — Ship:** demo GIF, devcontainer, packaging. _(IPv6/UDP egress ✓, presets ✓)_

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) for the dev
setup (nightly + `bpf-linker`, Linux/VM) and the checks CI runs. Please be kind;
we follow a [Code of Conduct](./CODE_OF_CONDUCT.md).

## Security

Wardyn runs as root and loads eBPF into the kernel. Found a vulnerability? Please
report it **privately** — see [SECURITY.md](./SECURITY.md), not the public issue
tracker. The threat model and known limitations are documented there too.

## License

Licensed under the **[GNU Affero General Public License v3.0 or later](./LICENSE)**
(AGPL-3.0-or-later), with per-file [SPDX](https://spdx.dev/) identifiers.

Copyright (C) 2026 Kadir Can Yildirim.

This is a strong copyleft licence: you may use, study, modify and redistribute
Wardyn, but any distributed derivative — **including one offered to others over a
network** — must be released under the AGPL and make its complete source
available. You must preserve the copyright and licence notices.

Unless you explicitly state otherwise, any contribution you intentionally submit
for inclusion in the work shall be licensed as above, without any additional
terms or conditions.
