// SPDX-License-Identifier: AGPL-3.0-or-later
//! Denial receipt (M5): a per-run JSONL file written for the *watched agent*,
//! not the human. A kernel denial reaches the agent as a bare `EPERM` (or a
//! refused connect) — indistinguishable from an ordinary permission error, so
//! agents retry, reach for `sudo`, or code around the block. The receipt closes
//! the loop: the child is spawned with `WARDYN_DENIALS=<path>` in its
//! environment and can read back what was denied and by which rule, then
//! surface that to its operator instead of flailing.
//!
//! Line 1 is a self-describing JSON header; every further line is one event the
//! kernel actually denied. Advisory only: the watched tree can read (or even
//! scribble on) it, but enforcement lives in kernel maps it cannot reach — the
//! receipt just talks.
//!
//! Creation is deliberately careful. The default path lives in a world-writable
//! directory, is predictable (`wardyn-denials-<pid>.jsonl`), and is opened by
//! **root**: a plain `File::create` there follows a symlink an unprivileged
//! local user planted first, which turns a helpful diagnostic into an arbitrary
//! root-owned file overwrite. So: `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, then
//! `fchown` to the identity the agent will run as — the only user that needs it.
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::Path;

use anyhow::{Context as _, Result};

/// What the header tells an agent that reads the receipt. Written for an LLM:
/// imperative, self-contained, and honest about the two ways `rule` can look.
const NOTE: &str = "Wardyn is a kernel-level policy warden supervising this process tree. \
    Each line after this header is one action it DENIED in-kernel (EPERM on file \
    open or exec, refused outbound connect/send). If an operation just failed \
    with a permission or network error, match it against these records. Do not \
    retry or work around a denial — report the `rule` to the human operator, who \
    can adjust policy.yaml and re-run. `rule` is the policy pattern that fired; \
    `kernel:<key>` means the kernel reported denying on that key directly, which \
    can be broader than the written glob. A line with event=\"exception\" means \
    the operator granted an exception: the scope in `now_allowed` is permitted \
    for the rest of this run, and you MAY retry the operation it covers. Records \
    may lag the syscall by a few milliseconds.";

pub struct Receipt {
    writer: BufWriter<File>,
    path: String,
    count: u64,
}

impl Receipt {
    /// Create the per-run receipt and write the header line. Truncates, unlike
    /// the append-only audit log: the receipt describes THIS run, and an agent
    /// must not read a previous run's denials as current.
    ///
    /// `owner` is the `(uid, gid)` the watched agent will run as; the file is
    /// chowned to it so that exactly the intended reader — and no one else on
    /// the machine — can read it.
    pub fn create(
        path: &Path,
        target: &str,
        policy_summary: &str,
        owner: Option<(u32, u32)>,
    ) -> Result<Receipt> {
        let file = create_exclusive(path)
            .with_context(|| format!("creating denial receipt {}", path.display()))?;
        if let Some((uid, gid)) = owner {
            // Best-effort: if we cannot hand it over, the agent simply won't be
            // able to read it — never a reason to widen the mode instead.
            let rc = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
            if rc != 0 {
                eprintln!(
                    "wardyn: warning: could not give the denial receipt to uid={uid} \
                     ({}) — the agent will not be able to read it",
                    std::io::Error::last_os_error()
                );
            }
        }
        let mut receipt = Receipt {
            writer: BufWriter::new(file),
            path: path.display().to_string(),
            count: 0,
        };
        receipt.write_line(&serde_json::json!({
            "wardyn": "denial-receipt",
            "version": 1,
            "started": now(),
            "target": target,
            "policy": policy_summary,
            "note": NOTE,
        }))?;
        Ok(receipt)
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Denials written so far (the header doesn't count).
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Append one denied event. Call only for events the kernel actually denied
    /// (`Desc::denied`) — never for warns or unenforced `block~` flags, or the
    /// receipt would claim denials that didn't happen.
    pub fn record(
        &mut self,
        pid: u32,
        comm: &str,
        event: &str,
        detail: &str,
        rule: &str,
    ) -> Result<()> {
        self.write_line(&serde_json::json!({
            "ts": now(),
            "pid": pid,
            "comm": comm,
            "event": event,
            "detail": detail,
            "rule": rule,
        }))?;
        self.count += 1;
        Ok(())
    }

    /// Tell the agent the operator granted an exception: the denied operation
    /// may now be retried. Not counted — `count()` stays denials-only.
    pub fn record_exception(&mut self, key: &str, now_allowed: &str) -> Result<()> {
        self.write_line(&serde_json::json!({
            "ts": now(),
            "event": "exception",
            "key": key,
            "now_allowed": now_allowed,
            "note": "You may retry the operation this covers.",
        }))
    }

    /// One JSON object per line, flushed immediately: the agent reads this the
    /// moment its syscall fails, not at exit.
    fn write_line(&mut self, value: &serde_json::Value) -> Result<()> {
        writeln!(self.writer, "{value}").context("writing denial receipt")?;
        self.writer.flush().context("flushing denial receipt")
    }
}

/// Create `path` fresh, refusing to follow a symlink or reuse an existing file.
///
/// A stale receipt from a previous run is removed first — but through the same
/// `O_EXCL` gate, so the worst an attacker who wins the race can do is make
/// creation fail loudly, never redirect a root-owned write.
fn create_exclusive(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    match opts.open(path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(path)?;
            opts.open(path)
        }
        Err(e) => Err(e),
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn temp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("wardyn-receipt-{tag}-{}.jsonl", std::process::id()))
    }

    #[test]
    fn header_then_one_record_per_denial() {
        let path = temp("basic");
        std::fs::remove_file(&path).ok();
        {
            let mut r = Receipt::create(&path, "bash demo.sh", "9 file rule(s)", None).unwrap();
            r.record(42, "cat", "open", "/home/u/.env", "**/.env")
                .unwrap();
            assert_eq!(r.count(), 1);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("every line is valid JSON"))
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["wardyn"], "denial-receipt");
        assert_eq!(lines[0]["target"], "bash demo.sh");
        assert!(lines[0]["note"].as_str().unwrap().contains("policy.yaml"));
        assert_eq!(lines[1]["event"], "open");
        assert_eq!(lines[1]["detail"], "/home/u/.env");
        assert_eq!(lines[1]["rule"], "**/.env");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn exception_records_tell_the_agent_to_retry() {
        let path = temp("exc");
        std::fs::remove_file(&path).ok();
        {
            let mut r = Receipt::create(&path, "t", "p", None).unwrap();
            r.record(1, "curl", "connect", "1.1.1.1:443", "cidr:0.0.0.0/0")
                .unwrap();
            r.record_exception("ip=1.1.1.1", "ALL egress to 1.1.1.1 (any port/protocol)")
                .unwrap();
            assert_eq!(r.count(), 1, "exceptions are not counted as denials");
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(last["event"], "exception");
        assert_eq!(last["key"], "ip=1.1.1.1");
        assert!(last["note"].as_str().unwrap().contains("retry"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn create_truncates_stale_receipts() {
        let path = temp("trunc");
        std::fs::remove_file(&path).ok();
        {
            let mut r = Receipt::create(&path, "run1", "p", None).unwrap();
            r.record(1, "a", "open", "/x", "**").unwrap();
        }
        {
            Receipt::create(&path, "run2", "p", None).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.lines().count(),
            1,
            "a stale run's denials must not survive into the new receipt"
        );
        assert!(text.contains("run2"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_receipt_is_private_and_never_follows_a_symlink() {
        let path = temp("perm");
        std::fs::remove_file(&path).ok();
        Receipt::create(&path, "t", "p", None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "world-readable receipts leak the agent's activity"
        );
        std::fs::remove_file(&path).ok();

        // A symlink planted at the target path must not be written through.
        let victim = temp("victim");
        std::fs::write(&victim, "important\n").unwrap();
        std::fs::remove_file(&path).ok();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        let created = Receipt::create(&path, "t", "p", None);
        assert!(
            created.is_err() || std::fs::read_to_string(&victim).unwrap() == "important\n",
            "the victim file was overwritten through a symlink"
        );
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&victim).ok();
    }
}
