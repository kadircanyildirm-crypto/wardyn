// SPDX-License-Identifier: AGPL-3.0-or-later
//! JSONL audit log (M2). One JSON object per line for each policy violation
//! (warn/block), flushed immediately so the file is tail-able live.
//!
//! Write failures are counted rather than discarded: a full disk or a read-only
//! mount silently turning the security record into a partial one is worse than
//! a noisy run, so the count is reported at exit.
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::path::Path;

use anyhow::{bail, Context as _, Result};

use wardyn_policy::policy::Action;

/// The version of the record shape in the audit log and the `--format json`
/// stream. Bumped only for a change a consumer could not absorb: adding a field
/// is not one, removing or repurposing one is.
///
/// It rides on **every record**, not on a header. An audit log is appended to
/// across runs and read with `grep`, `tail -f` and `jq -c`, so a consumer
/// routinely holds one line with no idea what came before it. A header would be
/// correct exactly once per file and useless to everyone downstream of a pipe.
/// Eight bytes a line is the price of every line being self-describing.
pub const SCHEMA_VERSION: u32 = 1;

/// One event, in the shape both the audit log and the JSON stream emit.
///
/// Built in one place so the two cannot drift: an operator who correlates a
/// shipped stream against the on-disk log has to find the same record twice,
/// and that only holds if there is one definition of what a record is.
#[allow(clippy::too_many_arguments)]
pub fn event_json(
    ts: &str,
    pid: u32,
    comm: &str,
    event: &str,
    detail: &str,
    action: Action,
    rule: &str,
    enforced: bool,
    kernel_reported: bool,
    matched_key: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "ts": ts,
        "pid": pid,
        "comm": comm,
        "event": event,
        "action": action.as_str(),
        "enforced": enforced,
        "source": if kernel_reported { "kernel" } else { "observed" },
        "detail": detail,
        "rule": rule,
        // The kernel key the decision was made on (`name=.aws/credentials`,
        // `ip=1.1.1.1:25`), when there was one. This is the unit an exception
        // operates at and the right thing to aggregate by: `rule` is the policy
        // text, which several rules can share, while this is what actually
        // fired. Null for a warn, which denies nothing and so matches no key.
        "matched_key": matched_key,
    })
}

pub struct Audit {
    writer: BufWriter<File>,
    path: String,
    count: u64,
    write_failures: u64,
}

impl Audit {
    /// Open (or create) the audit log, refusing anything that would make it
    /// something other than a record only wardyn writes.
    ///
    /// The default path is *relative*, so it usually lands in the directory
    /// wardyn was launched in — which for the documented `cd project && sudo
    /// wardyn run -- agent` is a directory the **watched agent can write**.
    /// That makes every check below load-bearing rather than ceremonial:
    ///
    /// * **`O_NOFOLLOW`.** Without it, an agent that drops a symlink named
    ///   `wardyn-audit.jsonl` before wardyn starts gets root to append attacker-
    ///   influenced JSON to whatever it points at. That was live, and is what
    ///   this function was rewritten for.
    /// * **Regular file, owned by us, not writable by anyone else.** A
    ///   pre-existing file failing any of those was put there by someone other
    ///   than wardyn, and a security record a second party can rewrite is not
    ///   one. Refused, matching what `overrides_file` already does.
    /// * **Mode 0600 on creation.** The log names every path the agent touched,
    ///   which is exactly the map of a project an attacker would want.
    ///
    /// Append, never truncate: the record must survive across runs. Use
    /// `--audit /dev/null`, or a fresh path, if a clean log is wanted.
    pub fn create(path: &Path) -> Result<Audit> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| {
                format!(
                    "opening audit log {} (if it exists as a symlink, wardyn refuses to follow \
                     it — the security record must not be redirected by whoever it is recording)",
                    path.display()
                )
            })?;

        // Checked on the DESCRIPTOR, not the path: anything checked by name can
        // be swapped between the check and the open.
        let meta = file
            .metadata()
            .with_context(|| format!("stat audit log {}", path.display()))?;
        if !meta.is_file() {
            bail!(
                "audit log {} is not a regular file — refusing to write the security record to it",
                path.display()
            );
        }
        let us = unsafe { libc::geteuid() };
        if meta.uid() != us {
            bail!(
                "audit log {} is owned by uid {} and wardyn runs as {us} — it was created by \
                 someone else, and a record a second party can rewrite is not a record. Point \
                 --audit somewhere only root can write",
                path.display(),
                meta.uid()
            );
        }
        if meta.mode() & 0o022 != 0 {
            bail!(
                "audit log {} is writable by group or others (mode {:o}) — anyone on this machine \
                 could edit the security record. Point --audit somewhere only root can write",
                path.display(),
                meta.mode() & 0o777
            );
        }

        // Where the bytes ACTUALLY go, read back from the descriptor while we
        // still hold it.
        let real = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.display().to_string());

        Ok(Audit {
            writer: BufWriter::new(file),
            // Read back from the descriptor rather than from the string we
            // were handed: `O_NOFOLLOW` refuses a symlinked log file but not a
            // symlinked directory above it, so the requested path and the real
            // one can differ — and a security record that reports the wrong
            // location is the failure this file exists to avoid. Falls back to
            // the requested path when procfs is unavailable, which is the only
            // thing left to say at that point.
            path: real,
            count: 0,
            write_failures: 0,
        })
    }

    /// Whether the log's *directory* is writable by `uid` — the identity the
    /// watched agent will run as.
    ///
    /// The open descriptor is safe from this: appends follow the inode, so a
    /// rename cannot redirect what is already being written. What it cannot
    /// survive is someone moving the finished log aside and leaving a file of
    /// their own in its place, which anyone reading it afterwards would have no
    /// way to notice. A warning rather than a refusal, because the default path
    /// is a project directory and refusing there would break the documented way
    /// to run the tool.
    pub fn directory_is_writable_by(path: &Path, uid: u32) -> bool {
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
        let dir = dir.unwrap_or(Path::new("."));
        let Ok(meta) = std::fs::metadata(dir) else {
            return false;
        };
        let mode = meta.mode();
        if mode & 0o002 != 0 {
            return true; // world-writable
        }
        if meta.uid() == uid {
            return mode & 0o200 != 0;
        }
        if meta.gid() == uid {
            return mode & 0o020 != 0;
        }
        false
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Records that could not be written. Non-zero means this run's security
    /// record is incomplete, which the operator has to be told.
    pub fn write_failures(&self) -> u64 {
        self.write_failures
    }

    /// Append one record. Call only for warn/block events.
    ///
    /// `enforced` is whether the kernel denied the action (vs merely flagged
    /// it), and `kernel_reported` distinguishes a denial the kernel itself
    /// reported from one userspace predicted from the observed path — the two
    /// differ for relative paths, dirfd-relative opens and symlinks, and an
    /// audit that cannot tell them apart cannot be relied on afterwards.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        pid: u32,
        comm: &str,
        event: &str,
        detail: &str,
        action: Action,
        rule: &str,
        enforced: bool,
        kernel_reported: bool,
        matched_key: Option<&str>,
    ) {
        let line = event_json(
            &now(),
            pid,
            comm,
            event,
            detail,
            action,
            rule,
            enforced,
            kernel_reported,
            matched_key,
        );
        if self.write_line(&line) {
            self.count += 1;
        }
    }

    /// Record an operator-granted exception (from the TUI). Part of the
    /// security record — an override matters at least as much as a violation —
    /// but not counted as one.
    pub fn record_exception(&mut self, key: &str, now_allowed: &str) {
        self.write_line(&serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "ts": now(),
            "event": "exception",
            "key": key,
            "now_allowed": now_allowed,
        }));
    }

    /// Returns whether the record reached the file.
    fn write_line(&mut self, value: &serde_json::Value) -> bool {
        let ok = writeln!(self.writer, "{value}").is_ok() && self.writer.flush().is_ok();
        if !ok {
            self.write_failures += 1;
        }
        ok
    }
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_carry_the_verdict_and_its_provenance() {
        let path = std::env::temp_dir().join(format!("wardyn-audit-{}.jsonl", std::process::id()));
        std::fs::remove_file(&path).ok();
        {
            let mut a = Audit::create(&path).unwrap();
            a.record(
                42,
                "cat",
                "open",
                "/home/u/.env",
                Action::Block,
                "**/.env",
                true,
                true,
                Some("name=.env"),
            );
            a.record(
                42,
                "cat",
                "open",
                "/home/u/.npmrc",
                Action::Warn,
                "**/.npmrc",
                false,
                false,
                None,
            );
            a.record_exception("name=.env", "opening ANY file named `.env`");
            assert_eq!(a.count(), 2, "exceptions are not violations");
            assert_eq!(a.write_failures(), 0);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("valid JSON"))
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["source"], "kernel");
        assert_eq!(lines[0]["enforced"], true);
        assert_eq!(lines[1]["source"], "observed");
        assert_eq!(lines[2]["event"], "exception");
        // The key the kernel decided on, not the policy text — a warn denies
        // nothing and so has none.
        assert_eq!(lines[0]["matched_key"], "name=.env");
        assert_eq!(lines[1]["matched_key"], serde_json::Value::Null);
        // Every line carries its own version, including the exception: a
        // consumer that greps one line out of the middle of the file still
        // knows the shape it is holding.
        for l in &lines {
            assert_eq!(l["schema_version"], SCHEMA_VERSION);
        }
        std::fs::remove_file(&path).ok();
    }

    /// The stream and the log must emit the same record for the same event, or
    /// an operator correlating one against the other is comparing two things
    /// that only look alike.
    #[test]
    fn the_stream_and_the_log_share_one_record_shape() {
        let path =
            std::env::temp_dir().join(format!("wardyn-audit-eq-{}.jsonl", std::process::id()));
        std::fs::remove_file(&path).ok();
        let ts = now();
        let direct = event_json(
            &ts,
            7,
            "cat",
            "open",
            "/x/.env",
            Action::Block,
            "**/.env",
            true,
            true,
            Some("name=.env"),
        );
        {
            let mut a = Audit::create(&path).unwrap();
            // Same inputs through the writer, with its own timestamp.
            a.record(
                7,
                "cat",
                "open",
                "/x/.env",
                Action::Block,
                "**/.env",
                true,
                true,
                Some("name=.env"),
            );
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let mut logged: serde_json::Value =
            serde_json::from_str(text.lines().next().unwrap()).expect("valid JSON");
        // The timestamps differ by microseconds; everything else must not.
        logged["ts"] = serde_json::Value::String(ts);
        assert_eq!(logged, direct);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn appending_preserves_a_previous_runs_record() {
        let path =
            std::env::temp_dir().join(format!("wardyn-audit-append-{}.jsonl", std::process::id()));
        std::fs::remove_file(&path).ok();
        for _ in 0..2 {
            let mut a = Audit::create(&path).unwrap();
            a.record(1, "x", "open", "/x", Action::Warn, "**", false, false, None);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2, "a new run must not truncate");
        std::fs::remove_file(&path).ok();
    }

    /// The hole this file was rewritten for. An agent that plants a symlink
    /// named `wardyn-audit.jsonl` before wardyn starts got **root** to append
    /// attacker-influenced JSON wherever it pointed. It worked: the exploit
    /// added lines to a file the agent could not otherwise write.
    ///
    /// The default `--audit` path is relative, so it lands in the directory the
    /// agent works in — which is what made this reachable rather than
    /// theoretical.
    #[test]
    fn a_symlinked_audit_path_is_refused_rather_than_followed() {
        let dir = std::env::temp_dir().join(format!("wardyn-sym-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.txt");
        let link = dir.join("audit.jsonl");
        std::fs::write(&victim, "ORIGINAL\n").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        assert!(
            Audit::create(&link).is_err(),
            "wardyn followed a symlink for its own security record"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "ORIGINAL\n",
            "the symlink target was written to"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A record anyone else on the machine can edit is not a record. Matches
    /// what `overrides_file` already refused, which is where the standard for
    /// this came from.
    #[test]
    fn a_world_writable_audit_log_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = std::env::temp_dir().join(format!("wardyn-perm-{}.jsonl", std::process::id()));
        std::fs::remove_file(&path).ok();
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let err = Audit::create(&path).err().expect("must refuse");
        assert!(
            format!("{err:#}").contains("writable by group or others"),
            "{err:#}"
        );
        std::fs::remove_file(&path).ok();
    }

    /// The log names every path the agent touched — the map of a project an
    /// attacker would want. It is created private, like the receipt.
    #[test]
    fn a_new_audit_log_is_created_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = std::env::temp_dir().join(format!("wardyn-mode-{}.jsonl", std::process::id()));
        std::fs::remove_file(&path).ok();
        {
            let _a = Audit::create(&path).unwrap();
        }
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit log created as {mode:o}");
        std::fs::remove_file(&path).ok();
    }

    /// The warning that tells an operator their record can be swapped after the
    /// run. `/tmp` is world-writable, so it stands in for the project directory
    /// the default path lands in.
    #[test]
    fn a_world_writable_directory_is_reported() {
        let in_tmp = std::env::temp_dir().join("x.jsonl");
        assert!(Audit::directory_is_writable_by(&in_tmp, 12345));
        // Nobody but root writes /, so an audit log there is not swappable.
        assert!(!Audit::directory_is_writable_by(
            Path::new("/x.jsonl"),
            12345
        ));
    }

    #[test]
    fn control_bytes_in_a_path_stay_escaped_in_the_json() {
        let path =
            std::env::temp_dir().join(format!("wardyn-audit-esc-{}.jsonl", std::process::id()));
        std::fs::remove_file(&path).ok();
        {
            let mut a = Audit::create(&path).unwrap();
            a.record(
                1,
                "x",
                "open",
                "/tmp/\x1b[2K\nfake",
                Action::Warn,
                "**",
                false,
                false,
                None,
            );
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "one record is one line");
        assert!(!text.contains('\x1b'));
        std::fs::remove_file(&path).ok();
    }

    /// The log reports where the bytes went, not where they were asked to go.
    /// A symlinked parent redirects a root-owned write that `O_NOFOLLOW` does
    /// not cover, and a security record naming the wrong file is worse than one
    /// naming an inconvenient file.
    #[test]
    fn the_reported_path_is_where_the_bytes_actually_went() {
        let dir = std::env::temp_dir().join(format!("wardyn-realpath-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("logs")).unwrap();

        let asked = dir.join("logs").join("audit.jsonl");
        let a = Audit::create(&asked).unwrap();
        assert_eq!(
            a.path(),
            dir.join("real").join("audit.jsonl").display().to_string(),
            "reported {} for a log that landed elsewhere",
            a.path()
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
