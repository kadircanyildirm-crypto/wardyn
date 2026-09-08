#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ask the kernel to enumerate BPF maps, and report whether it was allowed to.

Used by scenario 2 instead of `bpftool`, because `bpftool` is not installed
everywhere — and a test that passes because a binary is missing is worse than
no test. This issues `bpf(BPF_MAP_GET_NEXT_ID)` directly, so the only thing
that can stop it is the kernel.

The distinction that matters is EPERM (the caller has no CAP_BPF) versus
anything else (the syscall was permitted; ENOENT just means no maps exist at
this instant). Exit 1 = refused, exit 0 = the caller can reach BPF state.
"""
import ctypes
import ctypes.util
import errno
import sys

BPF_MAP_GET_NEXT_ID = 12
SYS_BPF = 321  # x86_64


class Attr(ctypes.Structure):
    _fields_ = [
        ("start_id", ctypes.c_uint32),
        ("next_id", ctypes.c_uint32),
        ("open_flags", ctypes.c_uint32),
    ]


def main() -> int:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    attr = Attr(0, 0, 0)
    ctypes.set_errno(0)
    rc = libc.syscall(SYS_BPF, BPF_MAP_GET_NEXT_ID, ctypes.byref(attr), ctypes.sizeof(attr))
    err = ctypes.get_errno()

    if rc >= 0:
        print(f"REACHED — first map id {attr.next_id}")
        return 0
    if err in (errno.EPERM, errno.EACCES):
        print("refused (EPERM: no CAP_BPF)")
        return 1
    # ENOENT means "allowed, but there are none" — the caller got in.
    print(f"REACHED — syscall permitted, returned {errno.errorcode.get(err, err)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
