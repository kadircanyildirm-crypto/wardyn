// SPDX-License-Identifier: AGPL-3.0-or-later
//! JSONL audit log (M2). One JSON object per line for each policy violation
//! (warn/block), flushed immediately so the file is tail-able live.
//!
//! Write failures are counted rather than discarded: a full disk or a read-only
//! mount silently turning the security record into a partial one is worse than
//! a noisy run, so the count is reported at exit.
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context as _, Result};

use wardyn_policy::policy::Action;

pub struct Audit {
    writer: BufWriter<File>,
    path: String,
    count: u64,
    write_failures: u64,
}

impl Audit {
    pub fn create(path: &Path) -> Result<Audit> {
        // Append, never truncate: the audit log is a security record and must
        // survive across runs (JSONL, so appending is well-formed). Use
        // `--audit /dev/null` or a fresh path if a clean log is wanted.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening audit log {}", path.display()))?;
        Ok(Audit {
            writer: BufWriter::new(file),
            path: path.display().to_string(),
            count: 0,
            write_failures: 0,
        })
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
    ) {
        let line = serde_json::json!({
            "ts": now(),
            "pid": pid,
            "comm": comm,
            "event": event,
            "action": action.as_str(),
            "enforced": enforced,
            "source": if kernel_reported { "kernel" } else { "observed" },
            "detail": detail,
            "rule": rule,
        });
        if self.write_line(&line) {
            self.count += 1;
        }
    }

    /// Record an operator-granted exception (from the TUI). Part of the
    /// security record — an override matters at least as much as a violation —
    /// but not counted as one.
    pub fn record_exception(&mut self, key: &str, now_allowed: &str) {
        self.write_line(&serde_json::json!({
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

fn now() -> String {
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
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn appending_preserves_a_previous_runs_record() {
        let path =
            std::env::temp_dir().join(format!("wardyn-audit-append-{}.jsonl", std::process::id()));
        std::fs::remove_file(&path).ok();
        for _ in 0..2 {
            let mut a = Audit::create(&path).unwrap();
            a.record(1, "x", "open", "/x", Action::Warn, "**", false, false);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2, "a new run must not truncate");
        std::fs::remove_file(&path).ok();
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
            );
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "one record is one line");
        assert!(!text.contains('\x1b'));
        std::fs::remove_file(&path).ok();
    }
}
