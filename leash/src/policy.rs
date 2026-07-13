//! Policy engine (M2).
//!
//! Loads `policy.yaml`, compiles it into ordered matchers, and evaluates each
//! observed event to an [`Action`] (`allow | warn | block`). First matching rule
//! wins; if nothing matches, `default_action` applies.
//!
//! This is the single source of truth for policy in warn-mode. Kernel-side
//! *enforcement* (M3) will reuse these same rules to deny inline via cgroup/LSM
//! hooks; keeping evaluation here (and unit-tested) pins the semantics first.
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::Path;

use anyhow::{Context as _, Result};
use globset::{Glob, GlobMatcher};
use ipnet::Ipv4Net;
use leash_common::NAME_LEN;
use serde::Deserialize;

/// The three policy verdicts. Wire values match `leash_common::action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Warn,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Warn => "warn",
            Action::Block => "block",
        }
    }

    /// Wire value shared with the eBPF side (`leash_common::action`).
    pub fn code(self) -> u32 {
        match self {
            Action::Allow => 0,
            Action::Warn => 1,
            Action::Block => 2,
        }
    }
}

/// A policy decision plus the rule that produced it (for audit / display).
pub struct Verdict {
    pub action: Action,
    pub rule: String,
}

// ── raw YAML shape ──────────────────────────────────────────────────────────

fn default_action() -> Action {
    Action::Allow
}

#[derive(Deserialize)]
struct RawPolicy {
    #[serde(default = "default_action")]
    default_action: Action,
    #[serde(default)]
    files: Vec<PathRuleRaw>,
    #[serde(default)]
    network: Vec<NetRuleRaw>,
    #[serde(default)]
    exec: Vec<PathRuleRaw>,
    // `version` (and any other keys) are ignored.
}

#[derive(Deserialize)]
struct PathRuleRaw {
    #[serde(rename = "match")]
    pattern: String,
    action: Action,
}

#[derive(Deserialize)]
struct NetRuleRaw {
    cidr: Option<String>,
    domain: Option<String>,
    action: Action,
}

// ── compiled policy ─────────────────────────────────────────────────────────

struct PathRule {
    pattern: String,
    matcher: GlobMatcher,
    action: Action,
}

enum NetMatch {
    Cidr(Ipv4Net),
    Ip(Ipv4Addr),
}

struct NetRule {
    label: String,
    which: NetMatch,
    action: Action,
}

impl NetRule {
    fn matches(&self, ip: Ipv4Addr) -> bool {
        match &self.which {
            NetMatch::Cidr(net) => net.contains(&ip),
            NetMatch::Ip(a) => *a == ip,
        }
    }
}

pub struct Policy {
    default_action: Action,
    files: Vec<PathRule>,
    exec: Vec<PathRule>,
    network: Vec<NetRule>,
}

/// The default policy, embedded so `leash` runs out of the box with no file.
const DEFAULT_POLICY: &str = include_str!("../../policy.yaml");

impl Policy {
    /// Load from an explicit path, else `./policy.yaml`, else the embedded default.
    pub fn load(path: Option<&Path>) -> Result<Policy> {
        if let Some(p) = path {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading policy {}", p.display()))?;
            return Policy::from_yaml_str(&text)
                .with_context(|| format!("parsing {}", p.display()));
        }
        if let Ok(text) = std::fs::read_to_string("policy.yaml") {
            return Policy::from_yaml_str(&text).context("parsing ./policy.yaml");
        }
        Policy::from_yaml_str(DEFAULT_POLICY).context("parsing embedded default policy")
    }

    pub fn from_yaml_str(text: &str) -> Result<Policy> {
        let raw: RawPolicy = serde_yaml::from_str(text).context("invalid policy YAML")?;

        let compile_paths = |rules: Vec<PathRuleRaw>| -> Result<Vec<PathRule>> {
            rules
                .into_iter()
                .map(|r| {
                    let matcher = Glob::new(&r.pattern)
                        .with_context(|| format!("bad glob `{}`", r.pattern))?
                        .compile_matcher();
                    Ok(PathRule {
                        pattern: r.pattern,
                        matcher,
                        action: r.action,
                    })
                })
                .collect()
        };

        let files = compile_paths(raw.files)?;
        let exec = compile_paths(raw.exec)?;

        // Network: cidr rules compile directly; domain rules resolve (best effort)
        // at load time, expanding to one Ip rule per resolved address, preserving
        // order.
        let mut network = Vec::new();
        for r in raw.network {
            match (&r.cidr, &r.domain) {
                (Some(cidr), _) => {
                    let net: Ipv4Net =
                        cidr.parse().with_context(|| format!("bad cidr `{cidr}`"))?;
                    network.push(NetRule {
                        label: format!("cidr:{cidr}"),
                        which: NetMatch::Cidr(net),
                        action: r.action,
                    });
                }
                (None, Some(domain)) => {
                    let ips = resolve_domain(domain);
                    if ips.is_empty() {
                        log::warn!("policy: could not resolve domain `{domain}` (rule ignored)");
                    }
                    for ip in ips {
                        network.push(NetRule {
                            label: format!("domain:{domain}"),
                            which: NetMatch::Ip(ip),
                            action: r.action,
                        });
                    }
                }
                (None, None) => {
                    anyhow::bail!("network rule needs `cidr` or `domain`");
                }
            }
        }

        Ok(Policy {
            default_action: raw.default_action,
            files,
            exec,
            network,
        })
    }

    pub fn summary(&self) -> String {
        format!(
            "{} file rule(s), {} network rule(s), {} exec rule(s), default={}",
            self.files.len(),
            self.network.len(),
            self.exec.len(),
            self.default_action.as_str()
        )
    }

    pub fn default_action_code(&self) -> u32 {
        self.default_action.code()
    }

    /// Network rules as `(prefix_len, ipv4-in-network-byte-order-as-u32, action
    /// code)` for the kernel LPM trie. Reversed so earlier policy rules win on
    /// identical keys (LPM `insert` overwrites on collision).
    pub fn net_entries(&self) -> Vec<(u32, u32, u32)> {
        self.network
            .iter()
            .rev()
            .map(|r| {
                let (plen, data) = match &r.which {
                    NetMatch::Cidr(net) => (
                        net.prefix_len() as u32,
                        u32::from_le_bytes(net.network().octets()),
                    ),
                    NetMatch::Ip(a) => (32u32, u32::from_le_bytes(a.octets())),
                };
                (plen, data, r.action.code())
            })
            .collect()
    }

    /// Block rules compiled for kernel-side file enforcement: exact basenames
    /// (e.g. `.env`, `shadow`) and exact parent-directory names (e.g. `.ssh`).
    /// Patterns that can't reduce to a literal segment stay observe/warn only.
    pub fn file_enforcement(&self) -> (Vec<[u8; NAME_LEN]>, Vec<[u8; NAME_LEN]>) {
        let mut names = Vec::new();
        let mut dirs = Vec::new();
        for r in &self.files {
            if r.action != Action::Block {
                continue;
            }
            if let Some(stripped) = r.pattern.strip_suffix("/**") {
                if let Some(k) = last_segment(stripped).and_then(name_key) {
                    dirs.push(k);
                }
            } else if let Some(k) = last_segment(&r.pattern).and_then(name_key) {
                names.push(k);
            }
        }
        (names, dirs)
    }

    /// Exec block rules compiled to exact basenames for the LSM bprm_check matcher.
    pub fn exec_enforcement(&self) -> Vec<[u8; NAME_LEN]> {
        self.exec
            .iter()
            .filter(|r| r.action == Action::Block)
            .filter_map(|r| last_segment(&r.pattern).and_then(name_key))
            .collect()
    }

    pub fn eval_file(&self, path: &str) -> Verdict {
        eval_path(&self.files, path, self.default_action)
    }

    pub fn eval_exec(&self, path: &str) -> Verdict {
        eval_path(&self.exec, path, self.default_action)
    }

    pub fn eval_connect(&self, ip: Ipv4Addr) -> Verdict {
        for r in &self.network {
            if r.matches(ip) {
                return Verdict {
                    action: r.action,
                    rule: r.label.clone(),
                };
            }
        }
        Verdict {
            action: self.default_action,
            rule: "default".to_string(),
        }
    }
}

fn eval_path(rules: &[PathRule], path: &str, default: Action) -> Verdict {
    for r in rules {
        if r.matcher.is_match(path) {
            return Verdict {
                action: r.action,
                rule: r.pattern.clone(),
            };
        }
    }
    Verdict {
        action: default,
        rule: "default".to_string(),
    }
}

/// Last non-empty `/`-separated segment of a glob pattern.
fn last_segment(p: &str) -> Option<&str> {
    p.rsplit('/').find(|s| !s.is_empty())
}

/// A literal path segment -> NUL-padded fixed key, or `None` if it contains glob
/// metacharacters (those can't be enforced as an exact name).
fn name_key(seg: &str) -> Option<[u8; NAME_LEN]> {
    if seg == "**" || seg.chars().any(|c| matches!(c, '*' | '?' | '[' | ']')) {
        return None;
    }
    let bytes = seg.as_bytes();
    if bytes.is_empty() || bytes.len() >= NAME_LEN {
        return None;
    }
    let mut k = [0u8; NAME_LEN];
    k[..bytes.len()].copy_from_slice(bytes);
    Some(k)
}

/// Best-effort A-record lookup; returns the IPv4 addresses for `domain`.
fn resolve_domain(domain: &str) -> Vec<Ipv4Addr> {
    match (domain, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs
            .filter_map(|sa| match sa.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = r#"
version: 1
default_action: allow
files:
  - { match: "**/.env", action: block }
  - { match: "**/.env.*", action: block }
  - { match: "**/.ssh/**", action: block }
  - { match: "/etc/shadow", action: block }
  - { match: "**/.npmrc", action: warn }
  - { match: "**", action: allow }
network:
  - { cidr: "127.0.0.0/8", action: allow }
  - { cidr: "192.168.0.0/16", action: allow }
  - { cidr: "0.0.0.0/0", action: block }
exec:
  - { match: "**/nc", action: block }
  - { match: "**/curl", action: warn }
  - { match: "**", action: allow }
"#;

    fn policy() -> Policy {
        Policy::from_yaml_str(P).expect("policy parses")
    }

    #[test]
    fn file_rules_first_match_wins() {
        let p = policy();
        assert_eq!(p.eval_file("/home/u/.env").action, Action::Block);
        assert_eq!(p.eval_file("/home/u/proj/.env").action, Action::Block);
        assert_eq!(p.eval_file("/home/u/.env.local").action, Action::Block);
        assert_eq!(p.eval_file("/home/u/.ssh/id_ed25519").action, Action::Block);
        assert_eq!(p.eval_file("/etc/shadow").action, Action::Block);
        assert_eq!(p.eval_file("/home/u/.npmrc").action, Action::Warn);
        assert_eq!(p.eval_file("/home/u/src/main.rs").action, Action::Allow);
    }

    #[test]
    fn exec_rules() {
        let p = policy();
        assert_eq!(p.eval_exec("/usr/bin/nc").action, Action::Block);
        assert_eq!(p.eval_exec("/usr/bin/curl").action, Action::Warn);
        assert_eq!(p.eval_exec("/usr/bin/ls").action, Action::Allow);
    }

    #[test]
    fn network_cidr_matching() {
        let p = policy();
        assert_eq!(
            p.eval_connect("127.0.0.1".parse().unwrap()).action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect("192.168.1.5".parse().unwrap()).action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap()).action,
            Action::Block
        );
        assert_eq!(
            p.eval_connect("8.8.8.8".parse().unwrap()).action,
            Action::Block
        );
    }

    #[test]
    fn verdict_carries_rule() {
        let p = policy();
        assert_eq!(p.eval_file("/x/.env").rule, "**/.env");
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap()).rule,
            "cidr:0.0.0.0/0"
        );
        assert_eq!(p.eval_file("/x/main.rs").rule, "**");
    }

    #[test]
    fn file_enforcement_compiles_block_rules() {
        let p = policy();
        let (names, dirs) = p.file_enforcement();
        let key = |s: &str| {
            let mut k = [0u8; NAME_LEN];
            k[..s.len()].copy_from_slice(s.as_bytes());
            k
        };
        assert!(names.contains(&key(".env"))); // **/.env
        assert!(names.contains(&key("shadow"))); // /etc/shadow
        assert!(dirs.contains(&key(".ssh"))); // **/.ssh/**
        assert!(!names.contains(&key(".env.*"))); // glob segment -> not enforced

        let execs = p.exec_enforcement();
        assert!(execs.contains(&key("nc"))); // **/nc block
        assert!(!execs.contains(&key("curl"))); // curl is warn, not block
    }

    #[test]
    fn empty_policy_uses_default() {
        let p = Policy::from_yaml_str("default_action: warn").unwrap();
        assert_eq!(p.eval_file("/anything").action, Action::Warn);
        assert_eq!(
            p.eval_connect("8.8.8.8".parse().unwrap()).action,
            Action::Warn
        );
    }
}
