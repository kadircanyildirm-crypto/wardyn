// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where stored approvals live, and who is allowed to have written them.
//!
//! [`wardyn_policy::overrides`] decides what an approval *means*: which policy
//! it belongs to, when it lapses. This module answers the question that crate
//! deliberately cannot, because it needs the OS: is this file one wardyn should
//! believe?
//!
//! The answer matters more than it looks. An approval says "stop denying this
//! key" — so anything that can write this file can switch off any part of the
//! policy, permanently, from outside the run. The watched agent is exactly the
//! process that would benefit, and it starts with a writable working directory
//! and a known uid. So:
//!
//! * The default path is **not** in the working directory, and `--overrides`
//!   pointing back into one is the operator's business, not the default.
//! * The file must be owned by root and writable by nobody else. A file that
//!   fails that is not read, and the run says why — a silently-ignored
//!   approvals file and an honoured one look identical from the feed.
//! * Every open is `O_NOFOLLOW`, and the checks run on the opened descriptor
//!   rather than on the path, so a symlink swapped in between the check and the
//!   read changes nothing.
//! * Writes land on a temporary file in the same directory and are renamed
//!   over, so an interrupted save leaves the previous approvals intact rather
//!   than a half-written file that parses to "nothing is approved".
//!
//! Not yet called: the run still starts from an empty [`Exceptions`] set. The
//! remaining wiring is `RunCtx` carrying the loaded store, and the TUI
//! separating `a` (this run) from `A` (stored). It is compiled and type-checked
//! from here in the meantime, because this file cannot be built on the machine
//! it was written on — `aya` is Linux-only — and unreferenced code would not be
//! compiled at all.
#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use wardyn_policy::overrides::OverrideStore;

/// Root-owned, outside every project tree, and conventional for state a program
/// keeps across runs. Deliberately not `$XDG_STATE_HOME`: under `sudo` that
/// resolves to whichever home the environment happens to carry, which is the
/// invoking user's often enough to be a trap.
pub const DEFAULT_PATH: &str = "/var/lib/wardyn/overrides.yaml";

pub fn default_path() -> PathBuf {
    PathBuf::from(DEFAULT_PATH)
}

/// Seconds since the epoch, for stamping and expiring approvals.
///
/// The policy crate takes `now` as an argument precisely so this call lives
/// here and expiry stays testable there.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Read the approvals file, or an empty store if it does not exist yet.
///
/// Returns an error — never an empty store — when the file exists but cannot be
/// trusted. Treating an untrustworthy approvals file as "no approvals" would be
/// the safe-looking choice and the wrong one: it hides the fact that something
/// on this machine is writing where only root should.
pub fn load(path: &Path) -> Result<OverrideStore> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(OverrideStore::default()),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => bail!(
            "{} is a symlink; refusing to read approvals through one",
            path.display()
        ),
        Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
    };

    // On the descriptor, not the path: whatever the name points at now, this is
    // the object being read.
    let meta = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    ensure_trustworthy(&meta, path, "approvals file")?;

    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .with_context(|| format!("reading {}", path.display()))?;
    OverrideStore::parse(&buf).with_context(|| format!("parsing {}", path.display()))
}

/// Write the store, replacing whatever was there, atomically.
pub fn save(path: &Path, store: &OverrideStore) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    if !dir.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        // 0700 from the start rather than umask-dependent, since what lands
        // here decides what the kernel stops denying.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing {}", dir.display()))?;
    }
    let dir_meta = std::fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    ensure_trustworthy(&dir_meta, dir, "approvals directory")?;

    // Same directory, so the rename is atomic; pid-suffixed so two wardyns
    // saving at once do not collide on the temporary.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let yaml = store.to_yaml()?;
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true) // O_CREAT|O_EXCL
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(yaml.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        // The next run's enforcement depends on this file; a save reported as
        // done while still in the page cache is a promise this cannot keep.
        f.sync_all()
            .with_context(|| format!("flushing {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!("replacing {}", path.display())
    })?;
    Ok(())
}

/// Root-owned and writable by root alone.
///
/// Group- and world-writable are both fatal: "the agent's group can edit it" is
/// the same capability as "the agent can edit it", one `usermod` apart.
fn ensure_trustworthy(meta: &std::fs::Metadata, path: &Path, what: &str) -> Result<()> {
    if meta.uid() != 0 {
        bail!(
            "{what} {} is owned by uid {}, not root — anything that can write it can switch off \
             any rule in the policy, so wardyn will not read it. Fix with: \
             sudo chown root:root {}",
            path.display(),
            meta.uid(),
            path.display()
        );
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        bail!(
            "{what} {} is mode {:04o} — group- or world-writable, so a user on this machine could \
             grant themselves any exception. Fix with: sudo chmod go-w {}",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}
