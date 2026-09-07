// SPDX-License-Identifier: AGPL-3.0-or-later
//! Command-line parsing.
//!
//! Split out of `main.rs` and made a pure function over an argument iterator so
//! it can be tested: two argument-handling bugs shipped while this logic was
//! structurally untestable (options after the mode keyword were dropped, and an
//! option would happily swallow the *next flag* as its value).
//!
//! Arguments are [`OsString`] end to end. `std::env::args()` panics on a
//! non-UTF-8 argument, which would abort wardyn before it started merely
//! because the agent's command line mentioned a file with odd bytes in its name.
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use anyhow::{bail, Result};

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    All,
    Run(Vec<OsString>),
}

impl Mode {
    /// Human label for the header/receipt. Lossy on purpose: this is display
    /// text, never something we exec.
    pub fn label(&self) -> String {
        match self {
            Mode::All => "system-wide".to_string(),
            Mode::Run(argv) => argv
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" "),
        }
    }
}

#[derive(Debug)]
pub struct Opts {
    pub plain: bool,
    pub enforce: bool,
    /// Load and check the policy, print every honesty warning, and exit without
    /// touching the kernel. Needs neither root nor eBPF, so a policy can be
    /// validated in CI or on a laptop.
    pub dry_run: bool,
    pub policy_path: Option<PathBuf>,
    pub audit_path: PathBuf,
    pub denials_path: Option<PathBuf>,
    /// Where approvals that outlive the run are stored. `None` means the
    /// built-in system path; approvals are never kept in the working directory,
    /// because the agent can write there and would be granting its own.
    pub overrides_path: Option<PathBuf>,
    /// How long a newly stored approval lasts, in days. `0` disables storing
    /// them for this run: the TUI's persist key becomes a no-op and says so.
    pub override_ttl_days: u32,
    pub keep_root: bool,
    pub as_user: Option<String>,
    pub mode: Mode,
}

/// What the command line asked for. `--help` / `--version` are values rather
/// than a `process::exit` inside the parser, so tests can observe them.
#[derive(Debug)]
pub enum ParseOutcome {
    Run(Box<Opts>),
    Help,
    Version,
}

pub const USAGE: &str = "wardyn — a kernel-level warden for AI coding agents\n\n\
     USAGE:\n  \
     wardyn [OPTIONS] run -- <cmd> [args...]   watch that command's subtree\n  \
     wardyn [OPTIONS] [--all]                  watch system-wide\n\n\
     OPTIONS:\n  \
     --enforce         deny blocked file reads / execs / egress (default: observe)\n  \
     --dry-run         load and check the policy, print its gaps, and exit (no root, no eBPF)\n  \
     --plain           force the plain line printer (no TUI)\n  \
     --policy <path>   policy file (default: ./policy.yaml, else embedded)\n  \
     --audit <path>    JSONL audit log (default: ./wardyn-audit.jsonl)\n  \
     --denials <path>  agent-readable denial receipt, exported as WARDYN_DENIALS (--enforce only)\n  \
     --overrides <path>  stored approvals (default: /var/lib/wardyn/overrides.yaml)\n  \
     --override-ttl <days>  how long a stored approval lasts (default: 30, 0 disables storing)\n  \
     --as-user <spec>  run the agent as uid[:gid] instead of root (default: $SUDO_UID)\n  \
     --keep-root       do NOT drop the agent's privileges (unsafe under --enforce)\n  \
     -h, --help        print this help\n  \
     -V, --version     print version";

/// Parse the process's own arguments (skipping argv[0]).
pub fn parse_args() -> Result<ParseOutcome> {
    parse_from(std::env::args_os().skip(1))
}

pub fn parse_from(args: impl IntoIterator<Item = OsString>) -> Result<ParseOutcome> {
    let mut it = args.into_iter().peekable();
    let mut plain = false;
    let mut enforce = false;
    let mut dry_run = false;
    let mut policy_path = None;
    let mut audit_path = PathBuf::from("wardyn-audit.jsonl");
    let mut denials_path = None;
    let mut overrides_path = None;
    let mut override_ttl_days = crate::overrides::DEFAULT_TTL_DAYS;
    let mut keep_root = false;
    let mut as_user = None;

    // An option's value must not itself look like an option: `wardyn --audit
    // --enforce run -- x` silently consumed `--enforce` as the audit path and
    // then ran in observe mode, claiming to enforce.
    fn value(it: &mut impl Iterator<Item = OsString>, flag: &str, what: &str) -> Result<OsString> {
        match it.next() {
            Some(v) if !is_flag(&v) => Ok(v),
            Some(v) => bail!(
                "{flag} needs {what}, but the next argument is `{}` — did you forget the value?",
                v.to_string_lossy()
            ),
            None => bail!("{flag} needs {what}"),
        }
    }

    while let Some(a) = it.peek() {
        match a.to_str() {
            Some("--help") | Some("-h") => return Ok(ParseOutcome::Help),
            Some("--version") | Some("-V") => return Ok(ParseOutcome::Version),
            Some("--plain") => {
                plain = true;
                it.next();
            }
            Some("--enforce") => {
                enforce = true;
                it.next();
            }
            Some("--dry-run") => {
                dry_run = true;
                it.next();
            }
            Some("--policy") => {
                it.next();
                policy_path = Some(PathBuf::from(value(&mut it, "--policy", "a path")?));
            }
            Some("--audit") => {
                it.next();
                audit_path = PathBuf::from(value(&mut it, "--audit", "a path")?);
            }
            Some("--denials") => {
                it.next();
                denials_path = Some(PathBuf::from(value(&mut it, "--denials", "a path")?));
            }
            Some("--keep-root") => {
                keep_root = true;
                it.next();
            }
            Some("--overrides") => {
                it.next();
                overrides_path = Some(PathBuf::from(value(&mut it, "--overrides", "a path")?));
            }
            Some("--override-ttl") => {
                it.next();
                let raw = value(&mut it, "--override-ttl", "a number of days")?;
                let s = raw.to_string_lossy();
                override_ttl_days = s.parse::<u32>().map_err(|_| {
                    anyhow::anyhow!("--override-ttl needs a whole number of days, got `{s}`")
                })?;
                // An approval that never expires is the thing this feature is
                // built to avoid, so there is no "forever" value: 0 means "do
                // not store approvals at all", which is the honest opposite.
                anyhow::ensure!(
                    override_ttl_days <= 3650,
                    "--override-ttl of {override_ttl_days} days is longer than this tool should \
                     vouch for; use a shorter window and re-approve"
                );
            }
            Some("--as-user") => {
                it.next();
                as_user = Some(
                    value(&mut it, "--as-user", "a uid[:gid]")?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            _ => break,
        }
    }

    let next = it.next();
    let mode = match next.as_deref().and_then(OsStr::to_str) {
        None if next.is_none() => Mode::All,
        Some("--all") | Some("watch") => {
            // Options are only recognised BEFORE the mode; a flag here (e.g.
            // `wardyn --all --enforce`) would otherwise be silently dropped and
            // the user would get observe-only despite asking to enforce.
            if let Some(extra) = it.next() {
                bail!(
                    "unexpected argument `{}` after `--all` — put options such as --enforce \
                     BEFORE the mode: wardyn --enforce run -- <cmd>",
                    extra.to_string_lossy()
                );
            }
            Mode::All
        }
        Some("run") => {
            let mut rest: Vec<OsString> = it.collect();
            if rest.first().is_some_and(|s| s == "--") {
                rest.remove(0);
            }
            if rest.is_empty() {
                bail!("usage: wardyn run -- <command> [args...]");
            }
            Mode::Run(rest)
        }
        _ => {
            let shown = next.unwrap_or_default();
            bail!(
                "unknown argument `{}`; usage: wardyn [OPTIONS] [run -- <cmd> | --all] \
                 (see --help)",
                shown.to_string_lossy()
            )
        }
    };

    Ok(ParseOutcome::Run(Box::new(Opts {
        plain,
        enforce,
        dry_run,
        policy_path,
        audit_path,
        denials_path,
        overrides_path,
        override_ttl_days,
        keep_root,
        as_user,
        mode,
    })))
}

fn is_flag(v: &OsStr) -> bool {
    v.to_str().is_some_and(|s| s.starts_with('-') && s != "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Opts> {
        match parse_from(args.iter().map(OsString::from))? {
            ParseOutcome::Run(o) => Ok(*o),
            other => anyhow::bail!("expected Run, got {other:?}"),
        }
    }

    fn run_argv(o: &Opts) -> Vec<String> {
        match &o.mode {
            Mode::Run(v) => v.iter().map(|s| s.to_string_lossy().into_owned()).collect(),
            Mode::All => panic!("expected run mode"),
        }
    }

    #[test]
    fn bare_invocation_watches_everything() {
        assert_eq!(parse(&[]).unwrap().mode, Mode::All);
        assert_eq!(parse(&["--all"]).unwrap().mode, Mode::All);
    }

    #[test]
    fn run_takes_the_rest_of_the_line_with_or_without_the_separator() {
        assert_eq!(
            run_argv(&parse(&["run", "--", "bash", "-c", "x"]).unwrap()),
            ["bash", "-c", "x"]
        );
        assert_eq!(run_argv(&parse(&["run", "bash"]).unwrap()), ["bash"]);
        // Flags AFTER the command belong to the command, not to wardyn.
        assert_eq!(
            run_argv(&parse(&["run", "--", "claude", "--enforce"]).unwrap()),
            ["claude", "--enforce"]
        );
        assert!(
            !parse(&["run", "--", "claude", "--enforce"])
                .unwrap()
                .enforce
        );
    }

    #[test]
    fn options_are_collected_before_the_mode() {
        let o = parse(&[
            "--enforce",
            "--plain",
            "--policy",
            "p.yaml",
            "--audit",
            "a.jsonl",
            "--denials",
            "d.jsonl",
            "--as-user",
            "1000:1000",
            "run",
            "--",
            "bash",
        ])
        .unwrap();
        assert!(o.enforce && o.plain);
        assert_eq!(o.policy_path.unwrap().to_str().unwrap(), "p.yaml");
        assert_eq!(o.audit_path.to_str().unwrap(), "a.jsonl");
        assert_eq!(o.denials_path.unwrap().to_str().unwrap(), "d.jsonl");
        assert_eq!(o.as_user.unwrap(), "1000:1000");
    }

    #[test]
    fn an_option_never_swallows_the_next_flag_as_its_value() {
        // Shipped bug: this ran in OBSERVE mode with the audit log named
        // "--enforce", while the operator believed enforcement was on.
        let err = parse(&["--audit", "--enforce", "run", "--", "x"]).unwrap_err();
        assert!(
            format!("{err:#}").contains("--audit needs a path"),
            "{err:#}"
        );
        assert!(parse(&["--policy"]).is_err());
        assert!(parse(&["--as-user", "--plain"]).is_err());
        assert!(parse(&["--overrides"]).is_err());
        assert!(parse(&["--override-ttl", "--enforce"]).is_err());
    }

    #[test]
    fn override_ttl_takes_days_and_refuses_nonsense() {
        assert_eq!(
            parse(&["--override-ttl", "7", "run", "--", "x"])
                .unwrap()
                .override_ttl_days,
            7
        );
        // 0 is meaningful: store nothing this run.
        assert_eq!(
            parse(&["--override-ttl", "0", "run", "--", "x"])
                .unwrap()
                .override_ttl_days,
            0
        );
        assert!(parse(&["--override-ttl", "week"]).is_err());
        assert!(parse(&["--override-ttl", "-3"]).is_err());
        // There is deliberately no "forever": an approval nobody revisits is
        // exactly the hole this feature exists to keep from opening.
        assert!(parse(&["--override-ttl", "99999"]).is_err());
    }

    #[test]
    fn overrides_default_to_the_system_path_not_the_working_directory() {
        let o = parse(&["run", "--", "x"]).unwrap();
        assert!(
            o.overrides_path.is_none(),
            "None means the built-in system path; anything derived from the cwd would let the \
             agent grant its own approvals"
        );
        assert_eq!(o.override_ttl_days, crate::overrides::DEFAULT_TTL_DAYS);
    }

    #[test]
    fn a_bare_dash_is_a_value_not_a_flag() {
        // A bare `-` is a legitimate value (stdin convention), not a flag.
        assert_eq!(
            parse(&["--audit", "-", "run", "bash"])
                .unwrap()
                .audit_path
                .to_str()
                .unwrap(),
            "-"
        );
    }

    #[test]
    fn options_after_the_mode_are_a_hard_error() {
        assert!(parse(&["--all", "--enforce"]).is_err());
        assert!(parse(&["watch", "--plain"]).is_err());
    }

    #[test]
    fn run_needs_a_command() {
        assert!(parse(&["run"]).is_err());
        assert!(parse(&["run", "--"]).is_err());
    }

    #[test]
    fn unknown_arguments_are_refused() {
        assert!(parse(&["--nope"]).is_err());
        assert!(parse(&["frobnicate"]).is_err());
    }

    #[test]
    fn help_and_version_are_values_not_exits() {
        assert!(matches!(
            parse_from(["--help".into()]).unwrap(),
            ParseOutcome::Help
        ));
        assert!(matches!(
            parse_from(["-V".into()]).unwrap(),
            ParseOutcome::Version
        ));
        // ...and they win wherever they appear among the options.
        assert!(matches!(
            parse_from(["--enforce".into(), "--help".into()]).unwrap(),
            ParseOutcome::Help
        ));
    }

    #[test]
    fn dry_run_is_parsed() {
        let o = parse(&["--dry-run", "--policy", "p.yaml"]).unwrap();
        assert!(o.dry_run);
    }

    #[test]
    fn non_utf8_arguments_do_not_abort_the_parser() {
        // `std::env::args()` panics here; `args_os` does not. Build a
        // non-UTF-8 OsString the way each platform allows.
        #[cfg(unix)]
        let odd = {
            use std::os::unix::ffi::OsStringExt as _;
            OsString::from_vec(vec![b'/', b't', b'm', b'p', b'/', 0xff, 0xfe])
        };
        #[cfg(windows)]
        let odd = {
            use std::os::windows::ffi::OsStringExt as _;
            OsString::from_wide(&[0x002f, 0xD800, 0x0074]) // lone surrogate
        };
        let out = parse_from(["run".into(), "--".into(), "cat".into(), odd.clone()]).unwrap();
        match out {
            ParseOutcome::Run(o) => match o.mode {
                Mode::Run(argv) => assert_eq!(argv[1], odd, "the exact bytes reach exec()"),
                Mode::All => panic!("expected run mode"),
            },
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn the_mode_label_is_the_command_line() {
        let o = parse(&["run", "--", "claude", "refactor auth"]).unwrap();
        assert_eq!(o.mode.label(), "claude refactor auth");
        assert_eq!(Mode::All.label(), "system-wide");
    }
}
