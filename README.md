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

  wardyn: 4 policy violation(s) logged to wardyn-audit.jsonl
  wardyn: 3 denial(s) receipted to /tmp/wardyn-denials-40217.jsonl (WARDYN_DENIALS in the agent's env)
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
`block`, shown live (coloured) and written to a JSONL audit log. Under
`--enforce` the agent itself gets a machine-readable **denial receipt**
(`WARDYN_DENIALS`) — see [Telling the agent](#telling-the-agent).

**A denial is reported by the hook that made it.** The tracepoints observe a
*userspace path string*; the LSM and cgroup hooks act on the resolved object and
emit their own event naming the key they matched. So an open through a directory
fd, a symlinked path, or a `sendmsg()` destination — none of which the observed
string describes correctly — still shows up in the feed, the audit log and the
receipt. What the kernel could not tell you is counted too: ring-buffer drops and
watch-set saturation appear in the header and at exit, because a lost event for a
denied action is a missing audit record, not a cosmetic glitch.

**Surgically scoped & safe:** enforcement only ever touches the subtree you
launched, and only with `--enforce`. The rest of the system is never affected —
`wardyn --enforce run -- agent` can block the agent from `8.8.8.8` while every other
process on the host reaches it fine.

## Quickstart

Wardyn needs Linux with **BTF**, **cgroup v2**, and — for file/exec blocking —
**BPF LSM** enabled. On macOS/Windows, run it in a Linux VM.

**Prebuilt binary** (x86_64, statically linked — no toolchain, no glibc floor;
the eBPF object is compiled into it, so this one file is the whole tool):

```bash
# from https://github.com/kadircanyildirm-crypto/wardyn/releases
tar xzf wardyn-*-x86_64-unknown-linux-musl.tar.gz && cd wardyn-*/
sha256sum -c ../wardyn-*.tar.gz.sha256        # verify what you downloaded
./wardyn --dry-run --policy policy.yaml       # what will this policy do? (no root)
```

**Or build it** — and if you just want the toolchain without provisioning a VM,
the repo ships a [dev container](./.devcontainer/README.md) (it builds and
enforces egress; file/exec blocking needs a host booted with `lsm=...,bpf`):

```bash
# 1. one-time: enable BPF LSM (adds `lsm=...,bpf` to the kernel cmdline) + reboot
sudo ./scripts/enable-bpf-lsm.sh && sudo reboot

# 2. one-time: toolchain (rustup nightly + rust-src, bpf-linker)
./scripts/setup-vm.sh

# 3. build
cargo build --release      # userspace + eBPF, via aya-build

# 4. check what your policy will REALLY do — no root, no eBPF, no target
./target/release/wardyn --dry-run --policy policies/strict.yaml

# 5. observe (no blocking) — watch an agent's whole subtree
sudo ./target/release/wardyn run -- bash

# 6. enforce — actually block policy violations
sudo ./target/release/wardyn --enforce run -- bash scripts/demo.sh
```

Renders a live TUI when attached to a terminal; pipe it (or pass `--plain`) for a
plain table. `--policy <file>`, `--audit <file>` and `--denials <file>` override
the defaults. The watched agent is run as your non-root user by default (via
`$SUDO_UID`, so it can't disable its own warden); use `--as-user uid[:gid]` to
choose, or `--keep-root` to keep it as root.

In the TUI, `q` quits — **and stops the agent with it.** Wardyn's enforcement
lives in programs this process owns, so leaving the agent running after wardyn
exits would hand it the unsupervised shell the tool exists to prevent, silently,
at the moment you pressed a key. Under `--enforce`, `a` grants an approve-once
exception for the last denial (with a y/n confirm that names the true scope).
Wardyn exits with the agent's own exit status.

## Policy

[`policy.yaml`](./policy.yaml) — three rule lists; `default_action` is the
fallback. Actions: `allow | warn | block`. Matching order differs per axis, and
saying "first match wins" everywhere would be wrong:

| Axis | Order |
|---|---|
| `files` / `exec` | first match wins |
| `network` | **longest prefix wins** (the kernel uses an LPM trie) |
| `files` / `exec` under `--enforce` | **no order** — the kernel holds a *set* of block keys, so an earlier `allow` does not exempt what a later `block` covers |

`wardyn --dry-run` prints exactly which keys the kernel will hold, which rules are
flagged but never denied, which enforce more broadly than written, and which
`allow` rules the kernel's unordered set overrides. Unknown keys and unsupported
`version:` values are refused rather than ignored — a typo'd section used to
disable a whole rule class silently.

```yaml
default_action: allow

files:                                   # glob against the opened path (** spans dirs)
  - { match: "**/.env",      action: block }   # any file named .env
  - { match: "**/.ssh/**",   action: block }   # anything under a dir named .ssh, at any depth
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

## Telling the agent

A kernel denial reaches the agent as a bare `EPERM` — indistinguishable from an
ordinary permission error. Agents respond the way agents do: retry, reach for
`sudo`, or code around the failure. Half the loop was missing: you can see
everything the agent does, but the agent can't see you.

Under `--enforce`, wardyn spawns the target with `WARDYN_DENIALS=<path>` in its
environment: a per-run JSONL receipt whose first line explains the file (written
for an LLM to read) and every further line is one action the kernel actually
denied —

```json
{"wardyn":"denial-receipt","version":1,"note":"Wardyn is a kernel-level policy warden supervising this process tree. ... Do not retry or work around a denial — report the `rule` to the human operator ...","policy":"9 file rule(s), 8 network rule(s), 5 exec rule(s), default=allow","started":"2026-07-14T10:11:58.102Z","target":"claude refactor the auth module"}
{"ts":"2026-07-14T10:12:03.412Z","pid":40250,"comm":"node","event":"open","detail":"/home/me/project/.env","rule":"**/.env"}
{"ts":"2026-07-14T10:12:07.011Z","pid":40244,"comm":"curl","event":"connect","detail":"185.220.101.7:443","rule":"cidr:0.0.0.0/0"}
```

Tell your agent about it once, in its standing instructions (`CLAUDE.md`,
`AGENTS.md`, a system prompt):

> If a command fails with a permission or network error and the environment
> variable `WARDYN_DENIALS` is set, read that file. If a record matches the
> failure, a security policy denied the action: do **not** retry or work around
> it — report the `rule` to the user and continue with the rest of the task.

The receipt is advisory *output*, never input: the watched tree can read (or
even scribble on) it, but enforcement lives in kernel maps and root-owned policy
it cannot reach. Only real kernel denials are receipted — warns and
observe-only `block~` flags never appear. `--denials <path>` overrides the
default location (`/tmp/wardyn-denials-<pid>.jsonl`).

The loop closes from your side too: in the enforcing TUI, `a` offers to allow
the most recent denial. The confirm prompt states the **real blast radius** —
"ALL egress to 1.1.1.1", "ANY file named `.env`" — because the kernel matches
bare names and addresses, and wardyn won't pretend an exception is narrower
than it is. On `y` the kernel map and the feed's mirror update together, and an
`exception` record lands in the agent's receipt: *you may retry*. Deny →
report → approve → retry, without restarting the agent. Exceptions last for
the run only.

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
  Thread ids are evicted as their threads die, and a failed insert is counted —
  a full watch set would otherwise mean new children running unwatched.
- **Enforcement** — separate programs deny inline: `cgroup/connect4·6` +
  `sendmsg4·6` return *deny* for blocked egress (TCP connect and UDP sendmsg, IPv4
  & IPv6); BPF-LSM `file_open` / `bprm_check_security` return `-EPERM` for blocked
  reads / execs. All gated on `WATCHED` + an `enforce` flag.
- **Reporting** — each of those hooks emits its own event naming the key it
  matched, so the feed, the audit log and the receipt state what the kernel did
  rather than what userspace guessed from the observed path.

Full design, hook map, and the eBPF-verifier war stories are in
**[ARCHITECTURE.md](./ARCHITECTURE.md)**.

## Requirements

- Linux with BTF (`/sys/kernel/btf/vmlinux`) — kernel ≥ 5.8.
- cgroup v2 (for network blocking).
- BPF LSM (`CONFIG_BPF_LSM=y` + `lsm=...,bpf` on the cmdline) for file/exec blocking.
- Root (to load/attach eBPF).
- Built with Rust nightly + `bpf-linker` ([aya](https://aya-rs.dev)).
- Works from inside pid namespaces (containers, WSL2 distros): wardyn learns its
  kernel-view pid via an in-kernel handshake and says so when it differs.

> The LSM file/exec matcher reads a few `dentry` fields by offset. Wardyn now
> resolves those offsets **at runtime from the kernel's own BTF**
> (`/sys/kernel/btf/vmlinux`) and passes them to the eBPF program, so it adapts to
> the running kernel instead of being pinned to one layout; if BTF resolution
> fails it falls back to the built-in kernel-6.8 offsets and says so. (True
> CO-RE — compiler-emitted BTF relocations — is *not* available for the Rust BPF
> target; this is a `rustc`/LLVM limitation, not an aya one, so runtime resolution
> is the portable answer.) [`scripts/kernel-offsets.sh`](./scripts/kernel-offsets.sh)
> remains a manual cross-check.

## Roadmap

- [x] **M1 — Observe:** live tree of exec/open/connect, scoped to a subtree.
- [x] **M2 — Policy:** `policy.yaml` (glob + CIDR), allow/warn/block, JSONL audit.
- [x] **M3 — Block:** deny egress (cgroup — TCP + UDP, IPv4 + IPv6) + secret reads
  & blocked execs (LSM).
- [ ] **M4 — Ship:** demo GIF, devcontainer, packaging. _(IPv6/UDP egress ✓,
  presets ✓, `--dry-run` policy checker ✓, portable policy tests on Linux/macOS/
  Windows ✓, dev container ✓, static musl release builds ✓)_ Next: the demo GIF
  — the tapes are checked in ([`docs/RECORDING.md`](./docs/RECORDING.md)), the
  recording needs a BPF-LSM kernel so the `⛔BLOCK` rows are real.
- [ ] **M5 — Agent feedback:** the agent learns what was denied and why, instead
  of flailing at a bare `EPERM`. _(denial receipts ✓, approve-once exceptions
  from the TUI ✓, kernel-reported denials ✓)_ Next: persistent overrides kept
  outside the watched tree's reach.
- [ ] **M6 — Match on identity, not names:** full-path (`bpf_d_path`) and
  `(dev, ino)` keying, a read/write/create axis, and port/protocol in network
  rules. Until then a rename or a copy defeats a file rule — see
  [`SECURITY.md`](./SECURITY.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) for the dev
setup (nightly + `bpf-linker`, Linux/VM) and the checks CI runs. Please be kind;
we follow a [Code of Conduct](./CODE_OF_CONDUCT.md).

## Security

Wardyn runs as root and loads eBPF into the kernel. Found a vulnerability? Please
report it **privately** — see [SECURITY.md](./SECURITY.md), not the public issue
tracker. The threat model and known limitations are documented there too.

An independent, adversarially-verified audit of the whole codebase — every gap,
escape, and honesty caveat, ranked by severity — lives in
[`docs/AUDIT.md`](./docs/AUDIT.md); an honest comparison against sandboxes,
Landlock, and Tetragon/Tracee is in [`docs/COMPARISON.md`](./docs/COMPARISON.md).
Read both before relying on Wardyn as anything more than a defence-in-depth layer.

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
