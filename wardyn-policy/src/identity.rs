// SPDX-License-Identifier: AGPL-3.0-or-later
//! Resolving policy rules to filesystem **identity** — `(dev, ino)` — instead of
//! to a name (M6).
//!
//! A name rule (`**/.env`) describes a label. `mv .env x` detaches that label in
//! one syscall and the rule stops applying, which is why [`SECURITY.md`] has had
//! to call name matching "a guard against mistakes, not a defence against
//! deliberate exfiltration". An identity rule describes the object: renaming it
//! changes nothing, hard-linking it changes nothing, because the inode the hook
//! keys on never moved. Copying is not an escape either — `cp` must *read* the
//! source, and that read is precisely what is denied.
//!
//! What identity cannot do is name a file that does not exist yet, so this is
//! **additive**: the name maps stay, and every anchor here is an extra key the
//! kernel also denies on. A policy loses nothing by gaining anchors.
//!
//! ## The `dev` encoding, which is not the one you get from `stat`
//!
//! The kernel keys on `inode->i_sb->s_dev`, a 32-bit value packed as
//! `(major << 20) | minor`. `stat(2)` does **not** hand that back: it returns
//! `new_encode_dev()` of it, and glibc widens the result into a 64-bit `dev_t`
//! with major and minor split across four disjoint bit ranges. Feeding a raw
//! `st_dev` to the kernel map produces a key that matches nothing — silently,
//! which for a security tool is the worst possible failure. [`kernel_dev`] does
//! the conversion, and the tests below pin it in both directions.

use std::fmt;
use std::path::{Path, PathBuf};

use wardyn_common::InodeKey;

/// Convert a `stat(2)` `st_dev` (glibc's 64-bit `dev_t`) into the kernel's
/// internal `super_block->s_dev` encoding, which is what the eBPF hooks read.
///
/// glibc splits the device across four ranges (see `sys/sysmacros.h`); the
/// kernel packs it as `MKDEV(major, minor) = (major << 20) | minor`.
pub fn kernel_dev(st_dev: u64) -> u32 {
    let major =
        (((st_dev & 0x0000_0000_000f_ff00) >> 8) | ((st_dev & 0xffff_f000_0000_0000) >> 32)) as u32;
    let minor =
        ((st_dev & 0x0000_0000_0000_00ff) | ((st_dev & 0x0000_0fff_fff0_0000) >> 12)) as u32;
    mkdev(major, minor)
}

/// The kernel's `MKDEV`: minor is 20 bits, major occupies everything above.
pub fn mkdev(major: u32, minor: u32) -> u32 {
    (major << 20) | (minor & 0x000f_ffff)
}

/// The inverse of [`kernel_dev`] — glibc's `makedev`. Only used by tests and by
/// diagnostics that want to print a `major:minor` a human can compare against
/// `/proc/self/mountinfo`.
pub fn glibc_dev(major: u32, minor: u32) -> u64 {
    let (major, minor) = (major as u64, minor as u64);
    ((major & 0x0000_0fff) << 8)
        | ((major & 0xffff_f000) << 32)
        | (minor & 0x0000_00ff)
        | ((minor & 0xffff_ff00) << 12)
}

/// `(major, minor)` of a kernel-encoded `s_dev`, for display.
pub fn split_dev(dev: u32) -> (u32, u32) {
    (dev >> 20, dev & 0x000f_ffff)
}

/// Whether an anchor pins a single file or a whole directory subtree. The two
/// go into different kernel maps: a file inode is compared against the opened
/// object, a directory inode against every ancestor of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorKind {
    File,
    Dir,
}

/// A policy rule resolved to the object it actually names, at load time.
#[derive(Debug, Clone)]
pub struct Anchor {
    pub key: InodeKey,
    pub kind: AnchorKind,
    /// The path as it was when we resolved it. Display only — the whole point is
    /// that the object may not be reachable by this path any more.
    pub path: PathBuf,
    /// The policy rule this came from, for the feed, the audit log and the receipt.
    pub rule: String,
    /// Whether this anchor belongs to the `exec:` axis rather than `files:`.
    /// The same inode can legitimately appear on both (a binary that must not be
    /// run and must not be read), and they live in different kernel maps.
    pub exec: bool,
    /// Which access the rule denies; see [`crate::policy::Access`]. Carried here
    /// because it is stored beside the key in the kernel map.
    pub access_mask: u8,
}

impl Anchor {
    /// What denying this key really covers, phrased for an operator.
    pub fn blast_radius(&self) -> String {
        let (maj, min) = split_dev(self.key.dev);
        let what = match (self.exec, self.kind) {
            (true, _) => "executing the program",
            (false, AnchorKind::Dir) => "opening ANY file under the directory",
            (false, AnchorKind::File) => "opening the file",
        };
        format!(
            "{what} that is currently `{}` (dev {maj}:{min}, ino {}) — under ANY name it is later \
             given",
            self.path.display(),
            self.key.ino
        )
    }
}

impl fmt::Display for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (maj, min) = split_dev(self.key.dev);
        write!(f, "ino={} dev={maj}:{min}", self.key.ino)
    }
}

/// Why a rule produced no anchor. Reported rather than swallowed: a `path:` rule
/// that resolved to nothing enforces nothing, and the operator has to hear that
/// from startup instead of from an audit log after the fact.
#[derive(Debug, Clone)]
pub struct UnresolvedAnchor {
    pub rule: String,
    pub path: PathBuf,
    pub reason: String,
}

/// How a path in a policy is turned into an inode. Injectable for the same
/// reason [`crate::policy::Resolver`] is: the real one touches the filesystem,
/// which would make every policy test depend on the machine it runs on.
pub type Stat<'a> = &'a dyn Fn(&Path) -> Option<(u64, u64, bool)>;

/// `stat(2)`-backed implementation: returns `(st_dev, st_ino, is_dir)`.
///
/// Deliberately follows symlinks: a rule naming `~/.ssh` means the directory the
/// operator gets when they `cd` there, and pinning the symlink's own inode would
/// anchor the pointer instead of the target.
#[cfg(unix)]
pub fn system_stat(path: &Path) -> Option<(u64, u64, bool)> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(path).ok()?;
    Some((md.dev(), md.ino(), md.is_dir()))
}

#[cfg(not(unix))]
pub fn system_stat(_path: &Path) -> Option<(u64, u64, bool)> {
    // Wardyn only enforces on Linux; on other hosts `--dry-run` still parses a
    // policy, it just cannot resolve identity for it.
    None
}

/// A stat that never resolves — for tests and for explaining a policy without
/// touching the filesystem.
pub fn null_stat(_path: &Path) -> Option<(u64, u64, bool)> {
    None
}

/// Where a relative or `~`-prefixed policy path is anchored from.
///
/// Both matter and neither is guessable: `.env` in a rule means the one in the
/// project the agent was launched in, and `~/.ssh` means the *agent's* home, not
/// root's — wardyn runs under `sudo`, so `$HOME` at this point is usually wrong.
#[derive(Debug, Clone, Default)]
pub struct AnchorBase {
    /// Directory relative paths resolve against (the agent's working directory).
    pub cwd: Option<PathBuf>,
    /// Home directory `~` expands to (the identity the agent is dropped to).
    pub home: Option<PathBuf>,
}

impl AnchorBase {
    /// Expand `~` and make relative paths absolute. Returns `None` when the
    /// needed base is unknown, so the caller reports "could not resolve" rather
    /// than silently anchoring the wrong object.
    ///
    /// Joined as text with `/`, not through `Path::join`. These are paths the
    /// **Linux** kernel will key on; going through the host's path semantics
    /// would make `--dry-run` on a Windows laptop produce `\proj\.env` and
    /// disagree with the same policy checked on the machine that will run it.
    pub fn expand(&self, raw: &str) -> Option<PathBuf> {
        let joined = if raw == "~" || raw.starts_with("~/") {
            let home = posix(self.home.as_ref()?);
            let rest = raw.trim_start_matches('~').trim_start_matches('/');
            format!("{home}/{rest}")
        } else if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("{}/{raw}", posix(self.cwd.as_ref()?))
        };
        Some(PathBuf::from(normalize(&joined)))
    }
}

/// A path as the kernel spells it: `/`-separated, whatever the host uses.
fn posix(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Collapse `.`, `..` and repeated slashes lexically. Not a `realpath`:
/// symlinks are resolved by the `stat` that follows, and doing it lexically
/// keeps this portable and testable without a filesystem.
fn normalize(p: &str) -> String {
    let absolute = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    let body = out.join("/");
    if absolute {
        format!("/{body}")
    } else {
        body
    }
}

/// Resolve one policy path to an anchor.
pub fn resolve(rule: &str, raw: &str, base: &AnchorBase, stat: Stat<'_>) -> ResolveOutcome {
    let Some(path) = base.expand(raw) else {
        return ResolveOutcome::Unresolved(UnresolvedAnchor {
            rule: rule.to_string(),
            path: PathBuf::from(raw),
            reason: if raw.starts_with('~') {
                "no home directory known for the agent (pass --as-user, or write an absolute path)"
                    .into()
            } else {
                "relative path and no working directory known".into()
            },
        });
    };
    let Some((st_dev, ino, is_dir)) = stat(&path) else {
        return ResolveOutcome::Unresolved(UnresolvedAnchor {
            rule: rule.to_string(),
            path,
            reason: "does not exist (or is unreadable) at load time".into(),
        });
    };
    ResolveOutcome::Anchored(Anchor {
        key: InodeKey::new(kernel_dev(st_dev), ino),
        kind: if is_dir {
            AnchorKind::Dir
        } else {
            AnchorKind::File
        },
        path,
        rule: rule.to_string(),
        exec: false,
        access_mask: 0,
    })
}

#[derive(Debug, Clone)]
pub enum ResolveOutcome {
    Anchored(Anchor),
    Unresolved(UnresolvedAnchor),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoding round-trips for the ordinary devices a policy will hit.
    /// `(8, 1)` is the first SCSI disk partition, `(0, 42)` an anonymous
    /// (network/virtual) filesystem, and `(259, 3)` an NVMe namespace — the last
    /// one matters because its major does not fit the 12-bit legacy field, which
    /// is exactly where a hand-rolled conversion goes wrong.
    #[test]
    fn dev_encoding_round_trips() {
        for (major, minor) in [(8u32, 1u32), (0, 42), (259, 3), (253, 0), (0, 0)] {
            let st_dev = glibc_dev(major, minor);
            assert_eq!(
                kernel_dev(st_dev),
                mkdev(major, minor),
                "major={major} minor={minor}"
            );
            assert_eq!(split_dev(kernel_dev(st_dev)), (major, minor));
        }
    }

    /// A wide minor (>255) is split across two glibc ranges; the kernel keeps it
    /// contiguous in the low 20 bits.
    #[test]
    fn wide_minor_survives_the_split() {
        let st_dev = glibc_dev(259, 70000);
        assert_eq!(kernel_dev(st_dev), (259 << 20) | 70000);
    }

    /// The literal encoding, not just self-consistency with `glibc_dev`: an
    /// ext4 root on `/dev/sda1` stats as `st_dev == 0x801`, and the kernel holds
    /// `0x800001`. If this test and the kernel ever disagree, every identity key
    /// silently matches nothing.
    #[test]
    fn known_st_dev_maps_to_known_s_dev() {
        assert_eq!(kernel_dev(0x801), 0x0080_0001);
        assert_eq!(split_dev(0x0080_0001), (8, 1));
    }

    #[test]
    fn tilde_expands_to_the_agents_home_not_roots() {
        let base = AnchorBase {
            cwd: Some(PathBuf::from("/srv/project")),
            home: Some(PathBuf::from("/home/agent")),
        };
        assert_eq!(
            base.expand("~/.ssh"),
            Some(PathBuf::from("/home/agent/.ssh"))
        );
        assert_eq!(
            base.expand(".env"),
            Some(PathBuf::from("/srv/project/.env"))
        );
        assert_eq!(
            base.expand("/etc/shadow"),
            Some(PathBuf::from("/etc/shadow"))
        );
        assert_eq!(
            base.expand("./sub/../.env"),
            Some(PathBuf::from("/srv/project/.env"))
        );
    }

    #[test]
    fn a_tilde_rule_with_no_home_is_reported_not_guessed() {
        let base = AnchorBase {
            cwd: Some(PathBuf::from("/srv")),
            home: None,
        };
        match resolve("~/.ssh", "~/.ssh", &base, &null_stat) {
            ResolveOutcome::Unresolved(u) => assert!(u.reason.contains("home")),
            ResolveOutcome::Anchored(a) => panic!("guessed an anchor: {a:?}"),
        }
    }

    #[test]
    fn a_missing_file_is_unresolved_rather_than_anchored_to_nothing() {
        let base = AnchorBase {
            cwd: Some(PathBuf::from("/srv")),
            home: Some(PathBuf::from("/home/agent")),
        };
        match resolve("/etc/shadow", "/etc/shadow", &base, &null_stat) {
            ResolveOutcome::Unresolved(u) => assert!(u.reason.contains("does not exist")),
            ResolveOutcome::Anchored(a) => panic!("anchored a nonexistent path: {a:?}"),
        }
    }

    #[test]
    fn a_directory_anchors_as_a_dir_and_a_file_as_a_file() {
        let base = AnchorBase {
            cwd: Some(PathBuf::from("/srv")),
            home: Some(PathBuf::from("/home/agent")),
        };
        let fake =
            |p: &Path| -> Option<(u64, u64, bool)> { Some((0x801, 4242, p.ends_with(".ssh"))) };
        let ResolveOutcome::Anchored(dir) = resolve("~/.ssh", "~/.ssh", &base, &fake) else {
            panic!("expected an anchor");
        };
        assert_eq!(dir.kind, AnchorKind::Dir);
        assert_eq!(dir.key, InodeKey::new(0x0080_0001, 4242));

        let ResolveOutcome::Anchored(file) = resolve(".env", ".env", &base, &fake) else {
            panic!("expected an anchor");
        };
        assert_eq!(file.kind, AnchorKind::File);
    }

    /// The blast radius must say "under any name", because that is the whole
    /// claim an inode rule makes and the operator is approving exactly it.
    #[test]
    fn blast_radius_states_that_renaming_does_not_help() {
        let a = Anchor {
            key: InodeKey::new(0x0080_0001, 99),
            kind: AnchorKind::File,
            path: PathBuf::from("/home/agent/.env"),
            rule: "path:.env".into(),
            exec: false,
            access_mask: 0,
        };
        let text = a.blast_radius();
        assert!(text.contains("ANY name"), "{text}");
        assert!(text.contains("8:1"), "{text}");
        assert!(text.contains("99"), "{text}");
    }
}
