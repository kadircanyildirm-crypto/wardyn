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
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context as _, Result};

/// What the header tells an agent that reads the receipt. Written for an LLM:
/// imperative, self-contained, and honest about the two ways `rule` can look
/// and the one denial kind that can't be receipted.
const NOTE: &str = "Wardyn is a kernel-level policy warden supervising this process tree. \
    Each line after this header is one action it DENIED in-kernel (EPERM on file \
    open or exec, refused outbound connect/send). If an operation just failed \
    with a permission or network error, match it against these records. Do not \
    retry or work around a denial — report the `rule` to the human operator, who \
    can adjust policy.yaml and re-run. `rule` is the policy pattern that fired; \
    `kernel:<key>` means the kernel's coarser basename/dir matcher denied beyond \
    the written glob. Records may lag the syscall by a few milliseconds; UDP sent \
    via sendmsg() can be denied without a record.";

pub struct Receipt {
    writer: BufWriter<File>,
    path: String,
    count: u64,
}

impl Receipt {
    /// Create the per-run receipt and write the header line. Truncates, unlike
    /// the append-only audit log: the receipt describes THIS run, and an agent
    /// must not read a previous run's denials as current.
    pub fn create(path: &Path, target: &str, policy_summary: &str) -> Result<Receipt> {
        let file = File::create(path)
            .with_context(|| format!("creating denial receipt {}", path.display()))?;
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

    /// One JSON object per line, flushed immediately: the agent reads this the
    /// moment its syscall fails, not at exit.
    fn write_line(&mut self, value: &serde_json::Value) -> Result<()> {
        writeln!(self.writer, "{value}").context("writing denial receipt")?;
        self.writer.flush().context("flushing denial receipt")
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_then_one_record_per_denial() {
        let path =
            std::env::temp_dir().join(format!("wardyn-receipt-test-{}.jsonl", std::process::id()));
        {
            let mut r = Receipt::create(&path, "bash demo.sh", "9 file rule(s)").unwrap();
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
    fn create_truncates_stale_receipts() {
        let path =
            std::env::temp_dir().join(format!("wardyn-receipt-trunc-{}.jsonl", std::process::id()));
        {
            let mut r = Receipt::create(&path, "run1", "p").unwrap();
            r.record(1, "a", "open", "/x", "**").unwrap();
        }
        {
            Receipt::create(&path, "run2", "p").unwrap();
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
}
