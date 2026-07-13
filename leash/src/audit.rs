//! JSONL audit log (M2). One JSON object per line for each policy violation
//! (warn/block), flushed immediately so the file is tail-able live.
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context as _, Result};

use crate::policy::Action;

pub struct Audit {
    writer: BufWriter<File>,
    path: String,
    count: u64,
}

impl Audit {
    pub fn create(path: &Path) -> Result<Audit> {
        let file =
            File::create(path).with_context(|| format!("creating audit log {}", path.display()))?;
        Ok(Audit {
            writer: BufWriter::new(file),
            path: path.display().to_string(),
            count: 0,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Append one record. Call only for warn/block events.
    pub fn record(
        &mut self,
        pid: u32,
        comm: &str,
        event: &str,
        detail: &str,
        action: Action,
        rule: &str,
    ) -> Result<()> {
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let line = serde_json::json!({
            "ts": ts,
            "pid": pid,
            "comm": comm,
            "event": event,
            "action": action.as_str(),
            "detail": detail,
            "rule": rule,
        });
        writeln!(self.writer, "{line}").context("writing audit record")?;
        self.writer.flush().context("flushing audit log")?;
        self.count += 1;
        Ok(())
    }
}
