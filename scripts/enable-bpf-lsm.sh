#!/usr/bin/env bash
# Enable the BPF LSM so Leash can *block* file opens and exec (LSM file_open /
# bprm_check_security). Network blocking (cgroup/connect) does NOT need this.
#
# Ubuntu ships CONFIG_BPF_LSM=y but does not activate bpf in the LSM stack by
# default; it must be added to the kernel cmdline. Requires a reboot.
#
# NOTE: cloud images set GRUB_CMDLINE_LINUX_DEFAULT in
# /etc/default/grub.d/50-cloudimg-settings.cfg, which overrides /etc/default/grub.
# So we append via a 99- drop-in that is sourced *after* it.
#
#   sudo ./enable-bpf-lsm.sh   &&   sudo reboot
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }

CUR=$(cat /sys/kernel/security/lsm)
echo "Currently active LSMs: $CUR"
if grep -qw bpf <<<"$CUR"; then
  echo "bpf LSM already active — nothing to do."
  exit 0
fi
WANT="${CUR},bpf"
echo "Target: lsm=$WANT"

# Undo any earlier direct edit to /etc/default/grub (older versions of this script).
[[ -f /etc/default/grub.bak ]] && cp /etc/default/grub.bak /etc/default/grub

cat > /etc/default/grub.d/99-leash-lsm.cfg <<EOF
# Added by Leash: activate the BPF LSM (see scripts/enable-bpf-lsm.sh)
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT lsm=${WANT}"
EOF
echo "Wrote /etc/default/grub.d/99-leash-lsm.cfg"

update-grub
echo
echo "Done. Reboot, then verify:  cat /proc/cmdline   and   cat /sys/kernel/security/lsm"
