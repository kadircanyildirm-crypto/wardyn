#!/usr/bin/env bash
# Print the kernel struct field offsets that leash-ebpf hardcodes for the LSM
# file_open matcher (FILE_DENTRY_OFF etc.). aya-ebpf 0.1 ships opaque kernel
# structs and no bpf_d_path, so the matcher reads dentry fields at fixed offsets.
# Re-run on a new kernel; if these differ, update the *_OFF consts in
# leash-ebpf/src/main.rs. Needs `dwarves` (pahole) and kernel BTF.
set -euo pipefail
V=/sys/kernel/btf/vmlinux
echo "kernel: $(uname -r)"
echo "-- struct file --";   pahole -C file   "$V" | grep -E 'f_path'
echo "-- struct path --";   pahole -C path   "$V" | grep -E 'dentry'
echo "-- struct dentry --"; pahole -C dentry "$V" | grep -E 'd_name|d_parent'
echo "-- struct qstr --";   pahole -C qstr   "$V" | grep -E '\bname\b'
echo
echo "FILE_DENTRY_OFF  = offsetof(file,f_path) + offsetof(path,dentry)"
echo "DENTRY_NAME_OFF  = offsetof(dentry,d_name) + offsetof(qstr,name)"
echo "DENTRY_PARENT_OFF = offsetof(dentry,d_parent)"
