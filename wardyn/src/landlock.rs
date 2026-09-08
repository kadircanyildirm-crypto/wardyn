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
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr`. **Packed**: the kernel's definition is,
/// and a padded 16-byte version would be rejected for the wrong size.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

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

fn create_ruleset(attr: Option<&RulesetAttr>, flags: u32) -> i64 {
    let (ptr, size) = match attr {
        Some(a) => (
            a as *const RulesetAttr as *const libc::c_void,
            size_of::<RulesetAttr>(),
        ),
        None => (std::ptr::null(), 0),
    };
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, ptr, size, flags) }
}

fn add_rule(ruleset: i32, attr: &PathBeneathAttr) -> i64 {
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

/// Apply a ruleset to the calling thread and every descendant. Irreversible.
///
/// Called from `pre_exec`, so it must be async-signal-safe: it is one syscall
/// with no allocation, which is why the ruleset is built in the parent.
///
/// # Safety
/// `ruleset_fd` must be a valid Landlock ruleset descriptor.
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
}

impl Ruleset {
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Build a ruleset granting exactly `grants`, handling every right the
    /// running kernel knows about.
    ///
    /// Must run while wardyn still has the privilege to open the granted paths
    /// — i.e. in the parent, before the child drops to the agent's uid.
    pub fn build(grants: &[Grant]) -> Result<Ruleset> {
        let Some(abi) = abi_version() else {
            bail!(
                "this kernel has no Landlock (needs Linux 5.13+ with `landlock` in the active LSM \
                 list); `allow_paths:` cannot be enforced"
            );
        };
        let attr = RulesetAttr {
            handled_access_fs: handled_for_abi(abi),
        };
        let fd = create_ruleset(Some(&attr), 0);
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
            let rc = add_rule(fd.as_raw_fd(), &rule);
            unsafe { libc::close(pfd) };
            if rc != 0 {
                unresolved.push((g.path.clone(), std::io::Error::last_os_error().to_string()));
            }
        }
        Ok(Ruleset {
            fd,
            abi,
            unresolved,
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
        assert_eq!(size_of::<RulesetAttr>(), 8);
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
}
