// SPDX-License-Identifier: AGPL-3.0-or-later
//! Landlock: the allowlist half of wardyn's filesystem story.
//!
//! Everything else here is a **blocklist** — the eBPF LSM matcher holds a set of
//! keys it denies, and anything a policy forgot to name stays reachable. That is
//! the right shape for "this machine, minus these secrets", and the wrong shape
//! for "only this project directory". Landlock is the other shape: a process
//! declares the hierarchies it may touch and loses everything else, enforced by
//! the kernel with no privilege required and no way to undo it.
//!
//! The two are complementary rather than competing, which is why wardyn gained
//! this instead of replacing anything: `allow_paths:` contains the agent,
//! `files:`/`exec:` deny specific objects inside what remains, and the eBPF side
//! keeps sole ownership of egress, which Landlock can only express by port.
//!
//! ## Where the work happens
//!
//! Building a ruleset means opening a file descriptor for every allowed
//! hierarchy, so it is done in the **parent, while still root** — the child has
//! already dropped privileges by the time it could try, and would fail to open
//! paths the operator legitimately granted. The child inherits the ruleset fd
//! across the fork and only calls `landlock_restrict_self`, which is one
//! syscall and safe in `pre_exec`.
//!
//! ## Handled versus allowed
//!
//! The distinction that decides whether any of this works. A ruleset declares
//! `handled_access_fs`: the rights it is *restricting at all*. A right left out
//! of that mask is **unrestricted everywhere** — not denied, ignored. Per-path
//! rules then grant subsets of the handled set.
//!
//! So wardyn handles every right the running kernel understands and grants what
//! the policy asked for. Handling only the rights that appear in `rights:` would
//! produce a ruleset that looks restrictive and silently permits everything
//! nobody happened to mention.
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};

use anyhow::{bail, Context as _, Result};

// ── the ABI ─────────────────────────────────────────────────────────────────

/// `struct landlock_ruleset_attr`, as of ABI 1.
///
/// Only the first field is passed. Later ABIs append `handled_access_net` (4)
/// and `scoped` (6), and the kernel validates `size` against the version it
/// knows — so passing the 8-byte ABI-1 shape is accepted by every kernel that
/// has Landlock at all, and asks for nothing this code does not implement.
/// ABI 4's shape. The kernel reads exactly `size` bytes and infers the version
/// from it, so an ABI-1 kernel is handed the first 8 and never sees the rest.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    /// ABI 4. Sent only when the kernel is new enough to read it.
    handled_access_net: u64,
}

/// `struct landlock_path_beneath_attr`. **Packed**: the kernel's definition is,
/// and a padded 16-byte version would be rejected for the wrong size.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
/// ABI 4.
const LANDLOCK_RULE_NET_PORT: u32 = 2;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

// Network access rights, ABI 4. Only TCP, and only by port — Landlock has no
// notion of an address here. That is why this sits *beside* the cgroup/connect
// hooks rather than replacing them: eBPF decides by address, port and protocol,
// and can say `warn`; Landlock says "never leave these ports" in a way no
// descendant can undo, even one that somehow got its privileges back.
const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;

/// Every network right this kernel's ABI understands, or 0 below ABI 4.
///
/// Both are handled together deliberately. Handling only `CONNECT` would leave
/// a contained agent free to `bind()` a listener on any port and invite the
/// other side to connect inwards — the same egress, with the arrow drawn the
/// other way.
fn handled_net_for_abi(abi: i32) -> u64 {
    if abi >= 4 {
        NET_BIND_TCP | NET_CONNECT_TCP
    } else {
        0
    }
}

// Filesystem access rights, by the ABI that introduced them. Grouped this way
// because the mask has to be trimmed to the running kernel: asking to handle a
// right it has never heard of fails the whole ruleset with EINVAL.
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
/// ABI 2.
const FS_REFER: u64 = 1 << 13;
/// ABI 3.
const FS_TRUNCATE: u64 = 1 << 14;
/// ABI 5.
const FS_IOCTL_DEV: u64 = 1 << 15;

/// Everything ABI 1 defines.
const ABI1: u64 = FS_EXECUTE
    | FS_WRITE_FILE
    | FS_READ_FILE
    | FS_READ_DIR
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_CHAR
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SOCK
    | FS_MAKE_FIFO
    | FS_MAKE_BLOCK
    | FS_MAKE_SYM;

/// Every right this kernel's ABI understands.
///
/// `REFER` is deliberately included from ABI 2 up. It governs linking and
/// renaming *across* hierarchies, and leaving it unhandled would mean a
/// contained agent could `rename()` a file out of the project and into a
/// directory the allowlist never mentioned — the containment would have a hole
/// shaped exactly like `mv`.
fn handled_for_abi(abi: i32) -> u64 {
    let mut m = ABI1;
    if abi >= 2 {
        m |= FS_REFER;
    }
    if abi >= 3 {
        m |= FS_TRUNCATE;
    }
    if abi >= 5 {
        m |= FS_IOCTL_DEV;
    }
    m
}

/// What a `rights:` entry grants, expanded to Landlock's bits.
///
/// `write` is broad on purpose: a policy that says an agent may write its
/// project directory means it may create, delete, rename and truncate files
/// there. Granting only `WRITE_FILE` would produce a directory the agent can
/// modify existing files in and not save a new one to, which is not what
/// anybody means and would read as wardyn being broken.
pub fn rights_mask(right: Right, abi: i32) -> u64 {
    match right {
        Right::Read => FS_READ_FILE | FS_READ_DIR,
        Right::Exec => FS_EXECUTE,
        Right::Write => {
            let mut m = FS_WRITE_FILE
                | FS_MAKE_REG
                | FS_MAKE_DIR
                | FS_MAKE_SYM
                | FS_MAKE_FIFO
                | FS_MAKE_SOCK
                | FS_REMOVE_FILE
                | FS_REMOVE_DIR;
            if abi >= 2 {
                m |= FS_REFER;
            }
            if abi >= 3 {
                m |= FS_TRUNCATE;
            }
            m
        }
    }
}

/// One right a policy can grant over a hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Right {
    Read,
    Write,
    Exec,
}

// ── syscalls ────────────────────────────────────────────────────────────────

/// `attr_size` is not `size_of::<RulesetAttr>()` and must not become it. The
/// kernel infers which version of the struct it was handed from the length, and
/// rejects a length it does not know — so a pre-ABI-4 kernel has to be told 8,
/// even though the type is 16 bytes wide here.
fn create_ruleset(attr: Option<(&RulesetAttr, usize)>, flags: u32) -> i64 {
    let (ptr, size) = match attr {
        Some((a, n)) => (a as *const RulesetAttr as *const libc::c_void, n),
        None => (std::ptr::null(), 0),
    };
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, ptr, size, flags) }
}

fn add_path_rule(ruleset: i32, attr: &PathBeneathAttr) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset,
            LANDLOCK_RULE_PATH_BENEATH,
            attr as *const PathBeneathAttr as *const libc::c_void,
            0u32,
        )
    }
}

fn add_net_rule(ruleset: i32, attr: &NetPortAttr) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset,
            LANDLOCK_RULE_NET_PORT,
            attr as *const NetPortAttr as *const libc::c_void,
            0u32,
        )
    }
}

/// How many bytes of [`RulesetAttr`] this kernel will accept.
fn attr_size_for_abi(abi: i32) -> usize {
    if abi >= 4 {
        size_of::<RulesetAttr>() // fs + net
    } else {
        size_of::<u64>() // fs alone, the ABI-1 shape
    }
}

/// Apply a ruleset to the calling thread and every descendant. Irreversible.
///
/// Called from `pre_exec`, so it must be async-signal-safe: it is one syscall
/// with no allocation, which is why the ruleset is built in the parent.
///
/// # Safety
/// `ruleset_fd` must be a valid Landlock ruleset descriptor.
/// `struct landlock_net_port_attr` — ABI 4. Not packed: both fields are `u64`,
/// so there is no padding to disagree about.
#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

pub unsafe fn restrict_self(ruleset_fd: i32) -> std::io::Result<()> {
    if libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The kernel's Landlock ABI version, or `None` when it has no Landlock at all
/// (or it is not in the active LSM list, which reports the same way).
pub fn abi_version() -> Option<i32> {
    let v = create_ruleset(None, LANDLOCK_CREATE_RULESET_VERSION);
    (v > 0).then_some(v as i32)
}

// ── building a ruleset ──────────────────────────────────────────────────────

/// One hierarchy the agent may reach, and what it may do there.
#[derive(Debug, Clone)]
pub struct Grant {
    pub path: std::path::PathBuf,
    pub rights: Vec<Right>,
}

/// A built ruleset, ready to hand to the child.
pub struct Ruleset {
    fd: OwnedFd,
    pub abi: i32,
    /// Grants whose path could not be opened. They restrict nothing, and an
    /// allowlist quietly missing an entry is how a contained agent fails to
    /// start with an error nobody can trace back to the policy.
    pub unresolved: Vec<(std::path::PathBuf, String)>,
    /// Whether TCP is actually confined by this ruleset. False when the policy
    /// asked for no ports, and false on a kernel below ABI 4 — the caller has
    /// to tell those apart before it prints anything.
    pub net_handled: bool,
    /// The ports the kernel accepted, for the startup line.
    pub net_ports: Vec<u16>,
}

impl Ruleset {
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Build a ruleset granting exactly `grants` and `ports`, handling every
    /// right the running kernel knows about.
    ///
    /// Must run while wardyn still has the privilege to open the granted paths
    /// — i.e. in the parent, before the child drops to the agent's uid.
    ///
    /// `ports` is TCP only and by number only; Landlock has no notion of an
    /// address. An empty list with a kernel that supports network rights means
    /// **no TCP at all**, which is a real thing to ask for and must not be
    /// confused with "not asked" — the caller passes `None` for that.
    pub fn build(grants: &[Grant], ports: Option<&[u16]>) -> Result<Ruleset> {
        let Some(abi) = abi_version() else {
            bail!(
                "this kernel has no Landlock (needs Linux 5.13+ with `landlock` in the active LSM \
                 list); `allow_paths:` cannot be enforced"
            );
        };
        // Handling a network right the kernel has never heard of fails the
        // whole ruleset, taking the filesystem containment with it — so the
        // mask is trimmed, and a policy that asked for ports on a kernel that
        // cannot enforce them is refused by the caller rather than silently
        // dropped here.
        let handled_net = if ports.is_some() {
            handled_net_for_abi(abi)
        } else {
            0
        };
        // Handling a dimension with no rules in it denies that dimension
        // ENTIRELY — Landlock is an allowlist, and an allowlist of nothing
        // permits nothing. A policy that asked only for `allow_ports:` would
        // otherwise get a ruleset that also forbids every file, and the agent
        // would fail to exec with a bare EACCES pointing at nothing.
        let attr = RulesetAttr {
            handled_access_fs: if grants.is_empty() {
                0
            } else {
                handled_for_abi(abi)
            },
            handled_access_net: handled_net,
        };
        let fd = create_ruleset(Some((&attr, attr_size_for_abi(abi))), 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("creating the Landlock ruleset");
        }
        // SAFETY: the syscall returned a valid, owned descriptor.
        let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd as i32) };

        let mut unresolved = Vec::new();
        for g in grants {
            let allowed = g
                .rights
                .iter()
                .fold(0u64, |acc, r| acc | rights_mask(*r, abi));
            // O_PATH: the descriptor names the object for the ruleset and is
            // never read through, so this works for directories the caller may
            // not open for reading, and does not keep a file busy.
            let c = match CString::new(g.path.as_os_str().as_encoded_bytes()) {
                Ok(c) => c,
                Err(_) => {
                    unresolved.push((g.path.clone(), "path contains a NUL byte".into()));
                    continue;
                }
            };
            let pfd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if pfd < 0 {
                unresolved.push((g.path.clone(), std::io::Error::last_os_error().to_string()));
                continue;
            }
            let rule = PathBeneathAttr {
                allowed_access: allowed,
                parent_fd: pfd,
            };
            let rc = add_path_rule(fd.as_raw_fd(), &rule);
            unsafe { libc::close(pfd) };
            if rc != 0 {
                unresolved.push((g.path.clone(), std::io::Error::last_os_error().to_string()));
            }
        }
        let mut net_ports = Vec::new();
        if handled_net != 0 {
            for &port in ports.unwrap_or(&[]) {
                let rule = NetPortAttr {
                    allowed_access: NET_BIND_TCP | NET_CONNECT_TCP,
                    port: u64::from(port),
                };
                if add_net_rule(fd.as_raw_fd(), &rule) != 0 {
                    unresolved.push((
                        std::path::PathBuf::from(format!("tcp/{port}")),
                        std::io::Error::last_os_error().to_string(),
                    ));
                } else {
                    net_ports.push(port);
                }
            }
        }

        Ok(Ruleset {
            fd,
            abi,
            unresolved,
            net_handled: handled_net != 0,
            net_ports,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `path_beneath` struct is packed in the kernel's headers, and the
    /// syscall validates its size. A padded 16-byte version is rejected — and
    /// the rejection would look like "this path could not be added", which
    /// reads as a filesystem problem rather than an ABI one.
    #[test]
    fn the_path_beneath_struct_is_packed() {
        assert_eq!(size_of::<PathBeneathAttr>(), 12);
        assert_eq!(size_of::<NetPortAttr>(), 16);
        // The type carries both fields now; what a pre-ABI-4 kernel is TOLD is
        // still 8, and that is the number the syscall validates.
        assert_eq!(size_of::<RulesetAttr>(), 16);
        assert_eq!(attr_size_for_abi(1), 8);
        assert_eq!(attr_size_for_abi(3), 8);
        assert_eq!(attr_size_for_abi(4), 16);
        assert_eq!(attr_size_for_abi(7), 16);
    }

    /// Network rights arrived in ABI 4. Asking an older kernel to handle them
    /// fails the whole ruleset — taking the filesystem containment down with
    /// it, which is the opposite of what the operator asked for.
    #[test]
    fn network_rights_are_only_handled_from_abi_4() {
        for abi in 1..=3 {
            assert_eq!(
                handled_net_for_abi(abi),
                0,
                "ABI {abi} has no network rights"
            );
        }
        for abi in 4..=7 {
            assert_eq!(
                handled_net_for_abi(abi),
                NET_BIND_TCP | NET_CONNECT_TCP,
                "ABI {abi} must handle both directions"
            );
        }
    }

    /// Bind is handled alongside connect on purpose: confining only outbound
    /// would leave the agent free to listen and be connected to instead.
    #[test]
    fn both_directions_are_handled_not_just_connect() {
        let m = handled_net_for_abi(4);
        assert_ne!(m & NET_CONNECT_TCP, 0);
        assert_ne!(
            m & NET_BIND_TCP,
            0,
            "a listener is egress with the arrow reversed"
        );
    }

    /// The handled mask must grow with the ABI and never include a bit the
    /// running kernel has not heard of, which fails the whole ruleset.
    #[test]
    fn the_handled_mask_tracks_the_abi() {
        assert_eq!(handled_for_abi(1), ABI1);
        assert_eq!(handled_for_abi(2), ABI1 | FS_REFER);
        assert_eq!(handled_for_abi(3), ABI1 | FS_REFER | FS_TRUNCATE);
        // 4 adds only network rights, which this code does not handle.
        assert_eq!(handled_for_abi(4), handled_for_abi(3));
        assert_eq!(
            handled_for_abi(5),
            ABI1 | FS_REFER | FS_TRUNCATE | FS_IOCTL_DEV
        );
        // A future ABI must not silently add bits this build cannot reason about.
        assert_eq!(handled_for_abi(99), handled_for_abi(5));
    }

    /// `write` has to cover creating and removing, or a granted project
    /// directory is one the agent cannot save a new file into.
    #[test]
    fn write_covers_creating_and_removing_not_just_writing() {
        let w = rights_mask(Right::Write, 3);
        for (bit, name) in [
            (FS_WRITE_FILE, "write_file"),
            (FS_MAKE_REG, "make_reg"),
            (FS_MAKE_DIR, "make_dir"),
            (FS_REMOVE_FILE, "remove_file"),
            (FS_REMOVE_DIR, "remove_dir"),
            (FS_TRUNCATE, "truncate"),
            (FS_REFER, "refer"),
        ] {
            assert!(w & bit != 0, "write does not grant {name}");
        }
        // And must not grant reading or executing, which are separate asks.
        assert_eq!(w & (FS_READ_FILE | FS_READ_DIR | FS_EXECUTE), 0);
    }

    /// Rights added by a later ABI must not appear on an older one, or the
    /// per-path grant asks for a bit outside the handled mask.
    #[test]
    fn write_does_not_grant_rights_the_abi_lacks() {
        let w1 = rights_mask(Right::Write, 1);
        assert_eq!(w1 & (FS_REFER | FS_TRUNCATE), 0);
        assert_eq!(rights_mask(Right::Write, 2) & FS_TRUNCATE, 0);
    }

    /// Every right a grant can ask for has to be inside what the ruleset
    /// handles, on every ABI. A grant outside the handled set is rejected by
    /// `landlock_add_rule`, and the failure would be reported per path.
    #[test]
    fn every_grantable_right_is_handled_on_every_abi() {
        for abi in 1..=7 {
            let handled = handled_for_abi(abi);
            for r in [Right::Read, Right::Write, Right::Exec] {
                let asked = rights_mask(r, abi);
                assert_eq!(
                    asked & !handled,
                    0,
                    "ABI {abi}: {r:?} asks for a right the ruleset does not handle"
                );
            }
        }
    }

    /// Landlock is an allowlist, so HANDLING a dimension with no rules in it
    /// forbids that dimension entirely. A policy asking only for `allow_ports:`
    /// must not end up with a ruleset that also denies every file — the first
    /// version of this did, and the agent failed to exec with a bare EACCES
    /// pointing at nothing.
    ///
    /// What this can assert from userspace is that the ruleset builds and takes
    /// the port. That it does *not* confine the filesystem is proved in the e2e
    /// suite, where a ports-only policy runs an agent that reads and writes.
    #[test]
    fn a_ports_only_ruleset_builds_and_takes_the_port() {
        let Some(abi) = abi_version() else {
            return; // no Landlock on this kernel; nothing to assert
        };
        let rs = Ruleset::build(&[], Some(&[443])).expect("ports-only ruleset");
        if abi >= 4 {
            assert!(rs.net_handled, "ABI {abi} must confine TCP");
            assert_eq!(rs.net_ports, vec![443]);
            assert!(rs.unresolved.is_empty(), "{:?}", rs.unresolved);
        } else {
            assert!(!rs.net_handled, "ABI {abi} cannot confine TCP");
        }
    }
}
