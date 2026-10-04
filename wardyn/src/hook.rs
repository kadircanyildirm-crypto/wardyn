// SPDX-License-Identifier: AGPL-3.0-or-later
//! `wardyn hook` — put a denial in front of the model, not in a file it has to
//! remember to read.
//!
//! The receipt ([`crate::receipt`]) already carries what the kernel refused and
//! which rule refused it, and the agent is handed its path in `WARDYN_DENIALS`.
//! That closes the loop only for an agent written to look there. A coding agent
//! driven by a language model is not: it sees a tool call fail with `EPERM`,
//! which reads exactly like an ordinary permission problem, and does the
//! reasonable-looking thing — retries, rewrites the path, reaches for `sudo`.
//!
//! Claude Code runs a command of the operator's choosing after each tool call
//! and splices what it prints into the model's context. This subcommand is that
//! command. It needs no root, loads no eBPF and reads no policy: it tails the
//! receipt the supervising wardyn is already writing and reports what is new.
//!
//! Three properties it has to have, because it sits in the agent's inner loop:
//!
//! - **It never breaks the agent.** Every failure path — no receipt, truncated
//!   JSON, unreadable cursor — prints nothing and exits 0. A monitoring aid that
//!   can stop the thing it monitors is worse than no monitoring aid.
//! - **It never repeats itself.** A byte offset is kept beside the receipt, so a
//!   denial is reported to the model once. Re-reporting the same five denials
//!   after every tool call would train the model to ignore the channel.
//! - **It says the operation cannot succeed.** This is the whole point. The
//!   model's default reading of `EPERM` is "try differently"; the text below
//!   exists to replace that with "this is policy, report it".
//!
//! Advisory, like the receipt itself. The agent can read the receipt, scribble
//! on it, or delete the cursor — enforcement lives in kernel maps it cannot
//! reach. This only talks.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Claude Code documents a 10,000-character ceiling on injected context. Stay
/// under it with room to spare rather than discovering the truncation point in
/// production, and say so when the list is cut.
const MAX_CONTEXT: usize = 8_000;

/// How many denials to name individually before summarising the rest. A model
/// that is shown forty identical `.env` refusals learns nothing it did not learn
/// from the first three.
const MAX_LISTED: usize = 12;

/// One denial, as the receipt recorded it.
struct Denial {
    event: String,
    detail: String,
    rule: String,
}

/// Read the hook payload on stdin, report anything new in the receipt, exit 0.
///
/// The return value is the process exit code and is always 0; it is returned
/// rather than hard-coded at the call site so the signature matches the other
/// modes.
pub fn run() -> i32 {
    // Claude Code writes the hook payload to stdin and the hook is expected to
    // consume it. The only field used is the event name, echoed back so the
    // same binary serves PostToolUse and PostToolUseFailure without the
    // operator configuring two different commands.
    let mut raw = String::new();
    let _ = std::io::stdin().read_to_string(&mut raw);
    let event_name = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v["hook_event_name"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "PostToolUse".to_string());

    // No receipt in the environment means this agent is not running under
    // wardyn --enforce. That is an ordinary state, not an error: the hook can
    // be left configured in settings.json permanently and costs one exec.
    let Some(receipt) = std::env::var_os("WARDYN_DENIALS").map(PathBuf::from) else {
        return 0;
    };

    let (denials, exceptions, next_offset) = match collect(&receipt) {
        Some(v) => v,
        None => return 0,
    };
    if denials.is_empty() && exceptions.is_empty() {
        // Still advance the cursor: `collect` may have skipped the header line.
        save_cursor(&receipt, next_offset);
        return 0;
    }

    let context = render(&denials, &exceptions);
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "additionalContext": context,
        },
    });
    println!("{out}");

    // Only after the report is on stdout. If printing failed, the denials are
    // still unread and the next tool call should see them again.
    save_cursor(&receipt, next_offset);
    0
}

/// Parse everything added to the receipt since the last call.
///
/// Returns `None` when there is nothing to say and nothing to record — an
/// unreadable receipt, or no new bytes.
fn collect(receipt: &Path) -> Option<(Vec<Denial>, Vec<String>, u64)> {
    let text = std::fs::read_to_string(receipt).ok()?;
    let len = text.len() as u64;
    let mut from = load_cursor(receipt);
    // The receipt is recreated per run at a pid-derived path, so a stale cursor
    // from a previous, longer run would silently skip this run's first denials.
    // A shorter file than the cursor is proof of that, and the only cheap one.
    if from > len {
        from = 0;
    }
    if from == len {
        return None;
    }

    let mut denials = Vec::new();
    let mut exceptions = Vec::new();
    for line in text[from as usize..].lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            // A partially flushed final line: leave the cursor before it so the
            // next call sees it whole.
            break;
        };
        if v.get("wardyn").is_some() {
            continue; // the header
        }
        match v["event"].as_str() {
            Some("exception") => {
                if let Some(k) = v["key"].as_str() {
                    exceptions.push(k.to_string());
                }
            }
            Some(event) => denials.push(Denial {
                event: event.to_string(),
                detail: v["detail"].as_str().unwrap_or("?").to_string(),
                rule: v["rule"].as_str().unwrap_or("?").to_string(),
            }),
            None => {}
        }
    }
    Some((denials, exceptions, len))
}

/// The message the model reads.
///
/// Written for a reader whose next instinct is to retry. It names the
/// operations, names the rule behind each, and then spends its remaining words
/// on the one thing the model cannot infer from `EPERM`: that no amount of
/// rephrasing will make the call succeed.
fn render(denials: &[Denial], exceptions: &[String]) -> String {
    let mut s = String::new();

    if !denials.is_empty() {
        let n = denials.len();
        s.push_str(&format!(
            "wardyn denied {n} operation{} during that tool call.\n\n",
            if n == 1 { "" } else { "s" }
        ));
        // Group identical refusals. An agent that has not understood a denial
        // retries it, so the common shape of this list is the same line fifty
        // times — and `(x50)` is both shorter and more informative than fifty
        // rows, because it tells the model it has already been here.
        let mut groups: Vec<(&Denial, usize)> = Vec::new();
        for d in denials {
            match groups
                .iter_mut()
                .find(|(g, _)| g.event == d.event && g.detail == d.detail && g.rule == d.rule)
            {
                Some((_, count)) => *count += 1,
                None => groups.push((d, 1)),
            }
        }
        for (d, count) in groups.iter().take(MAX_LISTED) {
            let times = if *count > 1 {
                format!("   (x{count})")
            } else {
                String::new()
            };
            s.push_str(&format!(
                "  {:<8} {}{}\n           rule: {}\n",
                d.event, d.detail, times, d.rule
            ));
        }
        if groups.len() > MAX_LISTED {
            s.push_str(&format!(
                "  ... and {} more distinct\n",
                groups.len() - MAX_LISTED
            ));
        }
        s.push_str(
            "\nThese were refused by the Linux kernel, inside the syscall, under a policy \
             this session is running beneath. They are not missing files, not a file-mode \
             problem, and not something a different path or sudo will get around — the \
             same call will fail the same way.\n\n\
             If the task genuinely needs one of these, stop and tell the operator which \
             rule is in the way and what you needed it for. Do not try to work around it, \
             and do not silently drop the part of the task that depended on it.\n",
        );
    }

    if !exceptions.is_empty() {
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str("The operator has granted an exception; these may now be retried:\n");
        for k in exceptions {
            s.push_str(&format!("  {k}\n"));
        }
    }

    if s.len() > MAX_CONTEXT {
        // Cut on a character boundary, not a byte one: paths are arbitrary
        // bytes rendered lossily and can be multi-byte here.
        let mut cut = MAX_CONTEXT;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n... report truncated.\n");
    }
    s
}

/// Where the byte offset lives: beside the receipt, same ownership, same
/// lifetime. It holds no secret — the receipt it indexes is the sensitive
/// part — so a plain file written as the agent is the right weight. A tampered
/// cursor can only make this report a denial twice or not at all.
fn cursor_path(receipt: &Path) -> PathBuf {
    let mut p = receipt.as_os_str().to_owned();
    p.push(".hook-cursor");
    PathBuf::from(p)
}

fn load_cursor(receipt: &Path) -> u64 {
    std::fs::read_to_string(cursor_path(receipt))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_cursor(receipt: &Path, offset: u64) {
    let _ = std::fs::write(cursor_path(receipt), offset.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Removes the receipt and its cursor when the test ends, pass or panic.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(cursor_path(&self.0));
        }
    }

    /// No `tempfile` dependency on purpose: this crate has none, and a security
    /// tool should not gain one for a test helper. Named per test so the suite
    /// can run in parallel within a single pid.
    fn receipt_with(name: &str, lines: &[&str]) -> (Scratch, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("wardyn-hook-{}-{}.jsonl", name, std::process::id()));
        let _ = std::fs::remove_file(cursor_path(&path));
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        (Scratch(path.clone()), path)
    }

    const HEADER: &str = r#"{"wardyn":"denial-receipt","version":1}"#;
    const OPEN: &str = r#"{"ts":"t","pid":1,"comm":"cat","event":"open","detail":"/home/u/.env","rule":"**/.env"}"#;
    const CONNECT: &str = r#"{"ts":"t","pid":1,"comm":"curl","event":"connect","detail":"1.1.1.1:443","rule":"cidr:0.0.0.0/0"}"#;

    #[test]
    fn header_is_not_a_denial() {
        let (_d, p) = receipt_with("header", &[HEADER]);
        let (denials, exceptions, _) = collect(&p).unwrap();
        assert!(denials.is_empty());
        assert!(exceptions.is_empty());
    }

    #[test]
    fn reports_each_denial_once() {
        let (_d, p) = receipt_with("once", &[HEADER, OPEN]);
        let (first, _, off) = collect(&p).unwrap();
        assert_eq!(first.len(), 1);
        save_cursor(&p, off);
        // nothing new: the second call has nothing to say
        assert!(collect(&p).is_none());
    }

    #[test]
    fn a_later_denial_is_picked_up_from_the_cursor() {
        let (_d, p) = receipt_with("later", &[HEADER, OPEN]);
        let (_, _, off) = collect(&p).unwrap();
        save_cursor(&p, off);
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push_str(CONNECT);
        text.push('\n');
        std::fs::write(&p, text).unwrap();

        let (second, _, _) = collect(&p).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].detail, "1.1.1.1:443");
    }

    #[test]
    fn a_shorter_receipt_resets_the_cursor() {
        // A new run writes a fresh, shorter receipt at the same path. Trusting
        // the old offset would skip this run's opening denials entirely.
        let (_d, p) = receipt_with("shorter", &[HEADER, OPEN, CONNECT]);
        let (_, _, off) = collect(&p).unwrap();
        save_cursor(&p, off);
        std::fs::write(&p, format!("{HEADER}\n{OPEN}\n")).unwrap();
        let (again, _, _) = collect(&p).unwrap();
        assert_eq!(again.len(), 1);
    }

    #[test]
    fn a_half_written_line_waits_for_the_rest() {
        let (_d, p) = receipt_with("torn", &[HEADER, OPEN]);
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push_str(r#"{"ts":"t","event":"open","det"#); // flushed mid-line
        std::fs::write(&p, text).unwrap();
        let (denials, _, _) = collect(&p).unwrap();
        assert_eq!(
            denials.len(),
            1,
            "the torn line is not reported as a denial"
        );
    }

    #[test]
    fn exceptions_are_reported_as_retryable() {
        let line = r#"{"ts":"t","event":"exception","key":"name=.env","now_allowed":"read"}"#;
        let (_d, p) = receipt_with("exception", &[HEADER, line]);
        let (denials, exceptions, _) = collect(&p).unwrap();
        assert!(denials.is_empty());
        assert_eq!(exceptions, ["name=.env"]);
        assert!(render(&denials, &exceptions).contains("may now be retried"));
    }

    #[test]
    fn the_text_tells_the_model_not_to_retry() {
        let (_d, p) = receipt_with("text", &[HEADER, OPEN, CONNECT]);
        let (denials, exceptions, _) = collect(&p).unwrap();
        let out = render(&denials, &exceptions);
        assert!(out.contains("wardyn denied 2 operations"));
        assert!(out.contains("/home/u/.env"));
        assert!(out.contains("**/.env"));
        assert!(out.contains("1.1.1.1:443"));
        assert!(out.contains("fail the same way"));
        assert!(out.contains("tell the operator"));
    }

    #[test]
    fn a_flood_is_summarised_and_stays_under_the_ceiling() {
        let mut lines = vec![HEADER.to_string()];
        for i in 0..500 {
            lines.push(format!(
                r#"{{"ts":"t","pid":1,"comm":"cat","event":"open","detail":"/home/u/secret-{i}","rule":"**/secret-*"}}"#
            ));
        }
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let (_d, p) = receipt_with("flood", &refs);
        let (denials, exceptions, _) = collect(&p).unwrap();
        let out = render(&denials, &exceptions);
        assert!(out.contains("wardyn denied 500 operations"));
        assert!(out.contains("and 488 more distinct"));
        assert!(out.len() <= MAX_CONTEXT + 32, "len was {}", out.len());
    }

    #[test]
    fn a_repeated_denial_is_grouped_with_a_count() {
        // The retry loop this feature exists to break produces exactly this.
        let (_d, p) = receipt_with("grouped", &[HEADER, OPEN, OPEN, OPEN]);
        let (denials, exceptions, _) = collect(&p).unwrap();
        let out = render(&denials, &exceptions);
        assert!(out.contains("denied 3 operations"), "{out}");
        assert!(out.contains("(x3)"), "{out}");
        assert_eq!(
            out.matches("rule: **/.env").count(),
            1,
            "listed once, not thrice"
        );
    }

    #[test]
    fn singular_reads_naturally() {
        let (_d, p) = receipt_with("singular", &[HEADER, OPEN]);
        let (denials, exceptions, _) = collect(&p).unwrap();
        assert!(render(&denials, &exceptions).contains("denied 1 operation during"));
    }
}
