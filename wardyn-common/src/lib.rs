// SPDX-License-Identifier: AGPL-3.0-or-later
//! Types shared between the eBPF programs (`wardyn-ebpf`) and userspace (`wardyn`).
//!
//! `#![no_std]` so it links into the eBPF object; it also compiles under std,
//! so userspace uses the exact same layout. Every type crossing the boundary is
//! `#[repr(C)]` and `Copy` (plain old data) — userspace reads the raw bytes out
//! of the ring buffer and reinterprets them as an [`Event`].
#![no_std]

/// Length of the `comm` (process name) field, matching the kernel's TASK_COMM_LEN.
pub const COMM_LEN: usize = 16;
/// Max bytes we copy for a path/filename in an event (truncated if longer).
pub const PATH_LEN: usize = 256;
/// Fixed key width for the file-enforcement basename / directory maps.
pub const NAME_LEN: usize = 40;

/// A NUL-padded file basename or directory name, used as an exact hash-map key
/// on both sides of the kernel boundary.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NameKey(pub [u8; NAME_LEN]);

/// What kind of syscall/LSM event this is.
pub mod kind {
    pub const EXEC: u32 = 0;
    pub const OPEN: u32 = 1;
    pub const CONNECT: u32 = 2;
    pub const FORK: u32 = 3;
}

/// The verdict the policy engine reached for this event.
pub mod action {
    pub const ALLOW: u32 = 0;
    pub const WARN: u32 = 1;
    pub const BLOCK: u32 = 2;
}

/// A single observed (and possibly enforced) action from the watched process
/// tree. One fixed-size record is pushed to the ring buffer per event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    /// One of [`kind`].
    pub kind: u32,
    /// One of [`action`] — the verdict applied (M1: always `ALLOW`, observe-only).
    pub action: u32,

    /// PID (tgid) of the process performing the action.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Real UID of the process.
    pub uid: u32,

    /// Process name (`comm`), NUL-padded.
    pub comm: [u8; COMM_LEN],

    /// For EXEC/OPEN: the executable / file path, NUL-padded, truncated to
    /// `PATH_LEN`. Unused for CONNECT.
    pub path: [u8; PATH_LEN],
    /// Number of valid bytes in `path`.
    pub path_len: u32,

    /// For CONNECT: destination IPv4 address, network byte order (family AF_INET).
    pub daddr: u32,
    /// For CONNECT: destination IPv6 address, network byte order (family AF_INET6).
    pub daddr6: [u8; 16],
    /// For CONNECT: destination port, host byte order.
    pub dport: u16,
    /// Address family for CONNECT: AF_INET (2) or AF_INET6 (10); 0 otherwise.
    pub family: u16,
}

impl Event {
    /// A zeroed event; fill in the fields the given `kind` needs.
    pub const fn zeroed() -> Self {
        Self {
            kind: 0,
            action: action::ALLOW,
            pid: 0,
            ppid: 0,
            uid: 0,
            comm: [0; COMM_LEN],
            path: [0; PATH_LEN],
            path_len: 0,
            daddr: 0,
            daddr6: [0; 16],
            dport: 0,
            family: 0,
        }
    }
}

/// A 16-byte IPv6 address (network byte order), used as the LPM-trie key for v6
/// network rules. Layout-compatible with the userspace mirror.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ip6Key(pub [u8; 16]);
