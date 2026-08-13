# Wardyn dev container

Open the repo in VS Code (or `devcontainer up`) and you get the toolchain from
[`scripts/setup-vm.sh`](../scripts/setup-vm.sh) — Ubuntu 24.04, LLVM/clang, the
nightly pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) with `rust-src`,
`bpf-linker`, plus `just` and `shellcheck` so `just lint` runs as CI runs it.

```bash
just build      # userspace + the eBPF object
just lint       # everything CI checks
just test       # unit tests
just demo       # enforce the default policy on scripts/demo.sh
```

## What this container can actually enforce

A container shares the **host's kernel**. The image decides what you can *build*;
the host decides what you can *enforce*. `post-start.sh` prints the verdict on
every start — this table is what it is checking:

| Needs | Provided by | Available in a dev container? |
|---|---|---|
| build, unit tests, `--dry-run` | the image | ✅ always |
| loading eBPF at all | host BTF (`/sys/kernel/btf/vmlinux`) | ✅ on any modern distro kernel |
| **egress** blocking | host cgroup v2 | ✅ typically |
| **file/exec** blocking | host booted `lsm=...,bpf` | ⚠️ **usually not** |

BPF LSM is a kernel **command-line** setting. Nothing inside a container can turn
it on, and the VM kernels behind Docker Desktop on macOS/Windows do not ship with
it. Without it wardyn still runs — file and exec rows are observed and flagged,
just never denied — and `just e2e` skips its file assertions rather than failing.

For the full picture (and before claiming a kernel-side change works), use a real
Linux VM booted via [`scripts/enable-bpf-lsm.sh`](../scripts/enable-bpf-lsm.sh).
The [README GIF](../docs/RECORDING.md) has to be recorded there too, since its
whole point is showing real `⛔BLOCK` rows for `.env` reads.

## Privileges

`devcontainer.json` sets `privileged` and unconfines seccomp/AppArmor, because
Docker's default seccomp profile blocks `bpf(2)` outright. That gives the
container root-equivalent access to the host kernel. It is the same trust you
extend by running `sudo ./target/release/wardyn` — just don't point it at a
machine where that would not be fine.
