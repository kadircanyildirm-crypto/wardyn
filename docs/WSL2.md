# Running (and testing) Wardyn on WSL2

The README used to send Windows users to provision a Linux VM. They do not need
one. The WSL2 kernel already has everything Wardyn requires except one boot flag:

| Requirement | WSL2 status |
|---|---|
| BTF (`/sys/kernel/btf/vmlinux`) | ✅ shipped (`CONFIG_DEBUG_INFO_BTF=y`) |
| cgroup v2 | ✅ mounted at `/sys/fs/cgroup` |
| BPF LSM | ⚠️ compiled in (`CONFIG_BPF_LSM=y`) but **not active** — no `lsm=` on the boot cmdline |
| root | ✅ `wsl -u root` |

So egress enforcement works out of the box, and file/exec enforcement needs one
line of configuration and a restart. This is a real development environment, not
a degraded one: the full end-to-end suite — including every LSM assertion —
passes here.

## 1. Turn on the BPF LSM

An LSM that is compiled in is not necessarily *active*: the kernel only
initialises the ones named in the boot-time `lsm=` list. WSL2 lets you append to
the kernel command line from `%UserProfile%\.wslconfig`:

```ini
[wsl2]
kernelCommandLine = lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf
```

Take that list from your own kernel rather than copying it blindly — `lsm=`
*replaces* the built-in list, so anything you leave out is switched off:

```bash
# inside WSL
(zcat /proc/config.gz 2>/dev/null || cat /boot/config-"$(uname -r)") | grep '^CONFIG_LSM='
```

Append `,bpf` to that value. Then restart WSL from Windows:

```powershell
wsl --shutdown
```

> This stops **every** WSL distribution, including Docker Desktop's, so do it
> when nothing important is running there.

## 2. Mount securityfs

WSL does not mount `securityfs`, so `/sys/kernel/security/lsm` — the file every
tool (including Wardyn's own e2e suite) reads to decide whether the BPF LSM is
active — does not exist. Without it, an LSM-capable kernel looks LSM-less and the
file/exec tests **silently skip**.

```bash
sudo mount -t securityfs securityfs /sys/kernel/security
echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a /etc/fstab
```

Verify:

```bash
cat /sys/kernel/security/lsm
# capability,landlock,yama,safesetid,selinux,bpf,ima
#                                              ^^^
```

If `bpf` is missing, step 1 did not take effect — check `cat /proc/cmdline`.

## 3. Toolchain

```bash
./scripts/setup-vm.sh      # rustup + the pinned nightly + bpf-linker
```

`sudo` in WSL usually wants a password, which a non-interactive shell cannot
supply. `wsl -u root` avoids that entirely, and Wardyn needs root anyway.

## 4. Build and prove it works

```bash
cargo build --locked --release
just verify-programs                        # every eBPF program past the verifier
SUDO_UID=1000 SUDO_GID=1000 just e2e        # the real thing: does it actually block?
```

`SUDO_UID`/`SUDO_GID` are set by hand because running as root directly means
`sudo` never set them, and the privilege-drop assertion reads them. Use your own
uid (`id -u` as your normal user).

A green run ends with:

```
E2E PASSED — 24 passed, 0 skipped
```

`0 skipped` is the part that matters. A skip here means the BPF LSM is not
active and the file/exec assertions did not run — which looks like success and
is not.

## Build on ext4, not on `/mnt/c`

Cargo on a `/mnt/c` path goes through the 9p filesystem: roughly ten times
slower, with file-locking behaviour that confuses incremental builds. Keep the
worktree inside WSL (`~/wardyn`), or `rsync` into it before building.

## Known differences from a bare-metal host

- **pid namespace.** WSL2 runs the distro in its own pid namespace, so wardyn's
  `std::process::id()` is not the pid the kernel hooks see. Wardyn detects this
  and says so (`pid namespace detected (self 461, kernel view 22794)`); watching
  and enforcement are unaffected — it learns its init-namespace tgid through an
  in-kernel handshake.
- **Mount namespaces per command.** Each `wsl.exe … ` invocation can land in its
  own mount namespace, so a `mount` from one command may not be visible to the
  next. This is why step 2 writes to `/etc/fstab` instead of relying on a
  one-off mount.
- **No IPv6 route by default.** The v6 egress assertions still run — wardyn
  denies at `connect()`, before any packet — but a host with no v6 route simply
  never attempts them, and the e2e reports a skip rather than a pass.
