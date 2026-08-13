// SPDX-License-Identifier: AGPL-3.0-or-later
//! Policy engine (M2).
//!
//! Loads `policy.yaml`, compiles it into ordered matchers, and evaluates each
//! observed event to an [`Action`] (`allow | warn | block`).
//!
//! **Matching order is not uniform, and pretending otherwise would misdescribe
//! what the kernel does:**
//! - *files / exec* — first matching rule wins, then `default_action`.
//! - *network* — longest-prefix-match (the kernel decides egress with an LPM
//!   trie; CIDRs covering one address are always nested, so "most specific
//!   wins" is the only semantics that can agree with it), then `default_action`.
//! - *under `--enforce`*, the kernel's file/exec matcher is an unordered set of
//!   block keys: an `allow` rule listed before a `block` rule does **not** save
//!   a path the block rule's key covers. [`Policy::shadowed_by_kernel`] finds
//!   those rules so startup can say so out loud.
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;

use anyhow::{Context as _, Result};
use globset::{Glob, GlobMatcher};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use wardyn_common::NAME_LEN;

/// The policy schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// The three policy verdicts. Wire values match `wardyn_common::action`.
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

    /// Wire value shared with the eBPF side (`wardyn_common::action`).
    pub fn code(self) -> u32 {
        match self {
            Action::Allow => 0,
            Action::Warn => 1,
            Action::Block => 2,
        }
    }
}

/// A policy decision plus the rule that produced it (for audit / display).
#[derive(Debug, Clone)]
pub struct Verdict {
    pub action: Action,
    pub rule: String,
    /// For a `block`: will the kernel actually deny it under `--enforce`? File/
    /// exec globs that don't reduce to a basename/dir are observe-only (the feed
    /// flags them, but they are NOT enforced). Network blocks are always true.
    pub enforceable: bool,
}

/// The exact key the kernel's coarse matcher denies on — and therefore the
/// exact unit an approve-once exception operates at. An exception can't be
/// narrower than what the kernel matches, so this type is also the honest
/// vocabulary for telling the operator what they are about to allow.
/// `kind`/`value` rather than serde's default shape, because this type is
/// written into an overrides file a human is expected to audit and edit.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DenialKey {
    /// LSM `file_open`: basename match (BLOCK_NAMES), e.g. `.env`.
    FileName(String),
    /// LSM `file_open`: ancestor-directory match (BLOCK_DIRS), e.g. `.ssh`.
    FileDir(String),
    /// LSM `bprm_check`: exec basename match (BLOCK_EXEC), e.g. `nc`.
    Exec(String),
    /// cgroup connect/sendmsg: destination address (NET_RULES LPM trie).
    Net4(Ipv4Addr),
    Net6(Ipv6Addr),
}

impl DenialKey {
    /// What granting this key REALLY allows, phrased for the confirm prompt.
    /// The kernel matches by bare name / address, so the honest scope is
    /// always broader than the single event the operator is looking at.
    pub fn blast_radius(&self) -> String {
        match self {
            DenialKey::FileName(n) => format!("opening ANY file named `{n}` (any directory)"),
            DenialKey::FileDir(d) => {
                format!("opening ANY file anywhere under a directory named `{d}`")
            }
            DenialKey::Exec(n) => format!("executing ANY program named `{n}` (any path)"),
            DenialKey::Net4(ip) => format!("ALL egress to {ip} (any port/protocol)"),
            DenialKey::Net6(ip) => format!("ALL egress to [{ip}] (any port/protocol)"),
        }
    }
}

impl fmt::Display for DenialKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenialKey::FileName(n) => write!(f, "name={n}"),
            DenialKey::FileDir(d) => write!(f, "dir={d}"),
            DenialKey::Exec(n) => write!(f, "exec={n}"),
            DenialKey::Net4(ip) => write!(f, "ip={ip}"),
            DenialKey::Net6(ip) => write!(f, "ip=[{ip}]"),
        }
    }
}

/// Approve-once exceptions granted from the TUI — the userspace overlay that
/// keeps the feed honest about keys the kernel no longer denies. The kernel
/// maps are updated separately; `contains` must be consulted wherever the
/// kernel matcher is mirrored, or the feed would keep claiming denials.
#[derive(Default)]
pub struct Exceptions(HashSet<DenialKey>);

impl Exceptions {
    /// Returns false if the key was already granted.
    pub fn grant(&mut self, key: DenialKey) -> bool {
        self.0.insert(key)
    }

    pub fn contains(&self, key: &DenialKey) -> bool {
        self.0.contains(key)
    }
}

// ── raw YAML shape ──────────────────────────────────────────────────────────

fn default_action() -> Action {
    Action::Allow
}

/// `deny_unknown_fields` throughout: a typo'd key (`file:` for `files:`,
/// `match_:` for `match`) used to be silently ignored, which disabled an entire
/// rule class while the policy looked fine. A policy that does not mean what it
/// says is worse than one that refuses to load.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default = "default_action")]
    default_action: Action,
    #[serde(default)]
    files: Vec<PathRuleRaw>,
    #[serde(default)]
    network: Vec<NetRuleRaw>,
    #[serde(default)]
    exec: Vec<PathRuleRaw>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathRuleRaw {
    #[serde(rename = "match")]
    pattern: String,
    action: Action,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// `action == block` AND the pattern reduces to a kernel-enforceable key.
    enforceable: bool,
}

enum NetMatch {
    V4Cidr(Ipv4Net),
    V4Ip(Ipv4Addr),
    V6Cidr(Ipv6Net),
    V6Ip(Ipv6Addr),
}

struct NetRule {
    label: String,
    which: NetMatch,
    action: Action,
}

impl NetRule {
    /// If this rule matches `ip`, the prefix length it matched at (a /32 host or
    /// `V4Ip` is 32) — used to pick the most-specific rule, mirroring the
    /// kernel's longest-prefix-match trie. `None` if it doesn't match.
    fn v4_prefix(&self, ip: Ipv4Addr) -> Option<u8> {
        match &self.which {
            NetMatch::V4Cidr(net) if net.contains(&ip) => Some(net.prefix_len()),
            NetMatch::V4Ip(a) if *a == ip => Some(32),
            _ => None,
        }
    }
    fn v6_prefix(&self, ip: Ipv6Addr) -> Option<u8> {
        match &self.which {
            NetMatch::V6Cidr(net) if net.contains(&ip) => Some(net.prefix_len()),
            NetMatch::V6Ip(a) if *a == ip => Some(128),
            _ => None,
        }
    }
}

pub struct Policy {
    default_action: Action,
    files: Vec<PathRule>,
    exec: Vec<PathRule>,
    network: Vec<NetRule>,
    /// Mirror of the kernel's `BLOCK_NAMES` / `BLOCK_DIRS` / `BLOCK_EXEC` maps.
    /// The LSM hook can only see dentry names, so these are what it *actually*
    /// matches on — kept here so userspace can reproduce the kernel's verdict
    /// instead of guessing from the glob.
    kern_names: BTreeSet<String>,
    kern_dirs: BTreeSet<String>,
    kern_execs: BTreeSet<String>,
    /// `domain:` rules that resolved to nothing at load time — they enforce
    /// nothing at all, so startup says so instead of leaving a silent hole.
    unresolved_domains: Vec<String>,
    /// Identifies this exact policy source, so a stored approval granted under
    /// it stops applying the moment the rules change. Computed here because
    /// this is the only place the source text exists.
    fingerprint: String,
}

/// The default policy, embedded so `wardyn` runs out of the box with no file.
const DEFAULT_POLICY: &str = include_str!("../../policy.yaml");

/// How a `domain:` rule is turned into addresses. Injectable because the real
/// one performs live DNS: baking it into the parser made every policy test
/// network-dependent, and made the documented `domain:` form untestable.
pub type Resolver<'a> = &'a dyn Fn(&str) -> Vec<IpAddr>;

/// Best-effort A/AAAA lookup through the system resolver.
pub fn system_resolver(domain: &str) -> Vec<IpAddr> {
    match (domain, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// A resolver that never resolves anything — for tests and for `--dry-run`
/// style parsing where touching the network would be wrong.
pub fn null_resolver(_domain: &str) -> Vec<IpAddr> {
    Vec::new()
}

impl Policy {
    /// Identifies this policy's source. A stored approval records it and
    /// applies to no other, so editing the rules retires the approvals granted
    /// against the version that no longer exists.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

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

    /// Parse with the system DNS resolver (what the binary uses).
    pub fn from_yaml_str(text: &str) -> Result<Policy> {
        Policy::from_yaml_str_with(text, &system_resolver)
    }

    pub fn from_yaml_str_with(text: &str, resolve: Resolver<'_>) -> Result<Policy> {
        let raw: RawPolicy = serde_yaml::from_str(text).context("invalid policy YAML")?;
        if let Some(v) = raw.version {
            if v != SCHEMA_VERSION {
                anyhow::bail!(
                    "policy `version: {v}` is not supported by this build (expected \
                     {SCHEMA_VERSION}) — upgrade wardyn or drop the version key"
                );
            }
        }

        // `dir_capable` files support the `**/dir/**` parent-directory form; exec
        // rules are basename-only.
        let compile_paths = |rules: Vec<PathRuleRaw>, dir_capable: bool| -> Result<Vec<PathRule>> {
            rules
                .into_iter()
                .map(|r| {
                    let matcher = Glob::new(&r.pattern)
                        .with_context(|| format!("bad glob `{}`", r.pattern))?
                        .compile_matcher();
                    let enforceable = r.action == Action::Block
                        && if dir_capable {
                            file_key(&r.pattern).is_some()
                        } else {
                            last_segment(&r.pattern).and_then(name_key).is_some()
                        };
                    Ok(PathRule {
                        pattern: r.pattern,
                        matcher,
                        action: r.action,
                        enforceable,
                    })
                })
                .collect()
        };

        let files = compile_paths(raw.files, true)?;
        let exec = compile_paths(raw.exec, false)?;

        // Network: cidr rules compile directly; domain rules resolve (best effort)
        // at load time, expanding to one Ip rule per resolved address, preserving
        // order.
        let mut network = Vec::new();
        let mut unresolved_domains = Vec::new();
        for r in raw.network {
            match (&r.cidr, &r.domain) {
                (Some(cidr), Some(domain)) => {
                    anyhow::bail!(
                        "network rule has both `cidr: {cidr}` and `domain: {domain}` — pick one"
                    );
                }
                (Some(cidr), None) => {
                    let net: IpNet = cidr.parse().with_context(|| format!("bad cidr `{cidr}`"))?;
                    let which = match net {
                        IpNet::V4(n) => NetMatch::V4Cidr(n),
                        IpNet::V6(n) => NetMatch::V6Cidr(n),
                    };
                    network.push(NetRule {
                        label: format!("cidr:{cidr}"),
                        which,
                        action: r.action,
                    });
                }
                (None, Some(domain)) => {
                    let ips = resolve(domain);
                    if ips.is_empty() {
                        unresolved_domains.push(domain.clone());
                    }
                    for ip in ips {
                        let which = match ip {
                            IpAddr::V4(v4) => NetMatch::V4Ip(v4),
                            IpAddr::V6(v6) => NetMatch::V6Ip(v6),
                        };
                        network.push(NetRule {
                            label: format!("domain:{domain}"),
                            which,
                            action: r.action,
                        });
                    }
                }
                (None, None) => {
                    anyhow::bail!("network rule needs `cidr` or `domain`");
                }
            }
        }

        // Compile the kernel-side matcher once, from the same rules, so the
        // feed and the LSM hook can never drift apart.
        let mut kern_names = BTreeSet::new();
        let mut kern_dirs = BTreeSet::new();
        for r in &files {
            if r.action != Action::Block {
                continue;
            }
            if let Some((is_dir, seg)) = file_seg(&r.pattern) {
                if is_dir {
                    kern_dirs.insert(seg.to_string());
                } else {
                    kern_names.insert(seg.to_string());
                }
            }
        }
        let kern_execs = exec
            .iter()
            .filter(|r| r.action == Action::Block)
            .filter_map(|r| last_segment(&r.pattern).filter(|s| name_key(s).is_some()))
            .map(str::to_string)
            .collect();

        Ok(Policy {
            fingerprint: crate::overrides::fingerprint(text),
            default_action: raw.default_action,
            files,
            exec,
            network,
            kern_names,
            kern_dirs,
            kern_execs,
            unresolved_domains,
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

    /// Network rules as `(prefix_len, ipv4 address as it is laid out in memory,
    /// action code)` for the kernel LPM trie, which compares the key bytes from
    /// the most significant end. `from_ne_bytes` keeps the octets in network
    /// order *in memory* on either endianness — `from_le_bytes` happened to do
    /// that only on a little-endian host. Reversed so earlier policy rules win
    /// on identical keys (LPM `insert` overwrites on collision).
    pub fn net_entries(&self) -> Vec<(u32, u32, u32)> {
        self.network
            .iter()
            .rev()
            .filter_map(|r| {
                let (plen, data) = match &r.which {
                    NetMatch::V4Cidr(net) => (
                        net.prefix_len() as u32,
                        u32::from_ne_bytes(net.network().octets()),
                    ),
                    NetMatch::V4Ip(a) => (32u32, u32::from_ne_bytes(a.octets())),
                    _ => return None,
                };
                Some((plen, data, r.action.code()))
            })
            .collect()
    }

    /// IPv6 network rules as `(prefix_len, address bytes (network order), action
    /// code)` for the v6 LPM trie.
    pub fn net_entries6(&self) -> Vec<(u32, [u8; 16], u32)> {
        self.network
            .iter()
            .rev()
            .filter_map(|r| {
                let (plen, data) = match &r.which {
                    NetMatch::V6Cidr(net) => (net.prefix_len() as u32, net.network().octets()),
                    NetMatch::V6Ip(a) => (128u32, a.octets()),
                    _ => return None,
                };
                Some((plen, data, r.action.code()))
            })
            .collect()
    }

    /// Block rules compiled for kernel-side file enforcement: exact basenames
    /// (e.g. `.env`, `shadow`) and exact directory names (e.g. `.ssh`), the
    /// latter matched against every ancestor of the opened file.
    /// Patterns that can't reduce to a literal segment stay observe/warn only.
    pub fn file_enforcement(&self) -> (Vec<[u8; NAME_LEN]>, Vec<[u8; NAME_LEN]>) {
        let keys = |set: &BTreeSet<String>| -> Vec<[u8; NAME_LEN]> {
            set.iter().filter_map(|s| name_key(s)).collect()
        };
        (keys(&self.kern_names), keys(&self.kern_dirs))
    }

    /// The key the LSM `file_open` hook would deny `path` on, if any — the
    /// userspace mirror of the kernel's matcher.
    ///
    /// The hook sees dentry names, not the glob the rule was written as, so it
    /// is coarser: `/etc/shadow` compiles to the bare name `shadow` and
    /// therefore denies `/srv/app/shadow` too. Directory keys are matched
    /// against **every** ancestor (the hook walks `d_parent` up to
    /// [`MAX_DIR_WALK`] levels), so `**/.ssh/**` covers deep paths as its glob
    /// always claimed. Consult this (not just the glob) before reporting a
    /// verdict, otherwise the feed says `ok` for an open the kernel actually
    /// turned into `-EPERM`.
    pub fn kernel_file_denial(&self, path: &str) -> Option<DenialKey> {
        let mut segs = path.rsplit('/').filter(|s| !s.is_empty());
        let name = segs.next()?;
        if self.kern_names.contains(name) {
            return Some(DenialKey::FileName(name.to_string()));
        }
        // Ancestors, nearest first, bounded exactly like the kernel walk.
        for dir in segs.take(MAX_DIR_WALK) {
            if self.kern_dirs.contains(dir) {
                return Some(DenialKey::FileDir(dir.to_string()));
            }
        }
        None
    }

    /// Same, for the LSM `bprm_check_security` hook (exec basenames).
    pub fn kernel_exec_denial(&self, path: &str) -> Option<DenialKey> {
        let name = last_segment(path)?;
        if self.kern_execs.contains(name) {
            return Some(DenialKey::Exec(name.to_string()));
        }
        None
    }

    /// `block` rules whose kernel key is BROADER than the glob that produced it,
    /// as `(pattern, what the kernel will really deny)`. Only `**/name` and
    /// `**/dir/**` survive the reduction intact; anything more specific
    /// (`/etc/shadow`, `**/.aws/credentials`) loses its directory context and
    /// over-blocks. Startup prints these so the over-reach is never a surprise.
    pub fn overbroad_block_keys(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for r in &self.files {
            if r.action != Action::Block {
                continue;
            }
            if let Some((is_dir, seg)) = file_seg(&r.pattern) {
                let (exact, reach) = if is_dir {
                    (
                        format!("**/{seg}/**"),
                        format!("any file anywhere under a dir named `{seg}`"),
                    )
                } else {
                    (format!("**/{seg}"), format!("any file named `{seg}`"))
                };
                if r.pattern != exact {
                    out.push((r.pattern.clone(), reach));
                }
            }
        }
        for r in &self.exec {
            if r.action != Action::Block {
                continue;
            }
            if let Some(seg) = last_segment(&r.pattern) {
                if name_key(seg).is_some() && r.pattern != format!("**/{seg}") {
                    out.push((r.pattern.clone(), format!("any program named `{seg}`")));
                }
            }
        }
        out
    }

    /// Rules the kernel's unordered block-key set overrides under `--enforce`.
    ///
    /// Userspace evaluates file/exec rules first-match-wins, but the LSM hook
    /// holds only a *set* of block keys with no notion of order: an `allow`
    /// listed before a `block` does not protect anything the block rule's key
    /// covers. Each entry is `(allow-rule pattern, the key that beats it)`.
    pub fn shadowed_by_kernel(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut check = |rules: &[PathRule], names: &BTreeSet<String>, dirs: &BTreeSet<String>| {
            for (i, r) in rules.iter().enumerate() {
                if r.action == Action::Block {
                    continue;
                }
                // Does a *later* block rule's key cover paths this rule matches?
                let later_blocks = rules[i + 1..].iter().any(|b| b.action == Action::Block);
                if !later_blocks {
                    continue;
                }
                if let Some(seg) = last_segment(&r.pattern) {
                    if names.contains(seg) {
                        out.push((r.pattern.clone(), format!("name={seg}")));
                        continue;
                    }
                }
                // Any literal segment of this pattern that is a blocked dir name
                // makes the whole subtree denied, wherever it appears.
                if let Some(seg) = r
                    .pattern
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .find(|s| dirs.contains(*s))
                {
                    out.push((r.pattern.clone(), format!("dir={seg}")));
                }
            }
        };
        check(&self.files, &self.kern_names, &self.kern_dirs);
        check(&self.exec, &self.kern_execs, &BTreeSet::new());
        out
    }

    /// Egress coverage gaps between the IPv4 and IPv6 rule sets, as human warnings.
    /// The kernel decides v6 (and v4-mapped `::ffff:` — see the connect6 hook) with
    /// the v6 trie, falling back to `default_action` on a miss; so a v4 `0.0.0.0/0`
    /// deny-all with no `::/0` counterpart and a non-`block` default leaves every
    /// IPv6 destination allowed while the operator believes "deny all other egress"
    /// is in force. Surfaced at startup so the hole is never silent.
    pub fn net_coverage_gaps(&self) -> Vec<String> {
        let has_block_all = |v6: bool| {
            self.network.iter().any(|r| {
                r.action == Action::Block
                    && match &r.which {
                        NetMatch::V4Cidr(n) => !v6 && n.prefix_len() == 0,
                        NetMatch::V6Cidr(n) => v6 && n.prefix_len() == 0,
                        _ => false,
                    }
            })
        };
        let mut out = Vec::new();
        if has_block_all(false) && !has_block_all(true) && self.default_action != Action::Block {
            out.push(
                "policy denies all IPv4 egress (0.0.0.0/0 block) but has no IPv6 catch-all and \
                 default_action is not `block` — IPv6 and IPv4-mapped destinations are NOT denied. \
                 Add `- { cidr: \"::/0\", action: block }` (plus any v6 allow rules) to close it."
                    .to_string(),
            );
        }
        out
    }

    /// Everything else about this policy that does not mean what it looks like.
    /// Returned as ready-to-print sentences; startup prints them under
    /// `--enforce` so no gap is discovered later from an audit log.
    pub fn semantic_warnings(&self) -> Vec<String> {
        let mut out = self.net_coverage_gaps();

        // `default_action: block` is a real kernel default-deny for network (the
        // LPM miss path consults it) but NOT for files or exec: the LSM hooks
        // only deny on an explicit block key, so "deny everything by default"
        // silently means "deny all egress, allow every file and exec".
        if self.default_action == Action::Block {
            out.push(
                "default_action: block is a real deny-all for NETWORK only. The file and exec LSM \
                 hooks deny on explicit block keys, so unmatched file opens and execs are still \
                 ALLOWED in the kernel — list what must be blocked explicitly."
                    .to_string(),
            );
        }

        for pat in &self.unresolved_domains {
            out.push(format!(
                "network rule `domain: {pat}` resolved to no addresses — it enforces NOTHING. \
                 Domain rules are resolved once, at load: prefer an explicit `cidr:`."
            ));
        }
        if !self.unresolved_domains.is_empty() || self.has_domain_rules() {
            out.push(
                "`domain:` rules freeze the addresses DNS returned at startup: a CDN that answers \
                 with a different address later is not covered by an allow, and not caught by a \
                 block. Use `cidr:` where the answer can move."
                    .to_string(),
            );
        }
        out
    }

    fn has_domain_rules(&self) -> bool {
        self.network.iter().any(|r| r.label.starts_with("domain:"))
    }

    /// A full, plain-language account of what this policy will actually do in
    /// the kernel — printed by `--dry-run`, which validates a policy without
    /// root or eBPF. Written because every gap below used to be discoverable
    /// only by reading an audit log after the fact.
    pub fn explain(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "policy: {}", self.summary());

        let _ = writeln!(s, "\nkernel-enforced under --enforce:");
        for n in &self.kern_names {
            let _ = writeln!(
                s,
                "  file  name={n:<24} denies opening ANY file named `{n}`"
            );
        }
        for d in &self.kern_dirs {
            let _ = writeln!(
                s,
                "  file  dir={d:<25} denies ANY file under a directory named `{d}` (any depth)"
            );
        }
        for e in &self.kern_execs {
            let _ = writeln!(
                s,
                "  exec  name={e:<24} denies executing ANY program named `{e}`"
            );
        }
        let blocked_nets: Vec<&str> = self
            .network
            .iter()
            .filter(|r| r.action == Action::Block)
            .map(|r| r.label.as_str())
            .collect();
        if blocked_nets.is_empty() {
            let _ = writeln!(s, "  net   (no block rules — no egress is denied)");
        } else {
            let _ = writeln!(s, "  net   blocked: {}", blocked_nets.join(", "));
        }
        if self.kern_names.is_empty() && self.kern_dirs.is_empty() && self.kern_execs.is_empty() {
            let _ = writeln!(
                s,
                "  file/exec: NOTHING is kernel-enforced (no block rule reduces to a name or dir)"
            );
        }

        // A name-form rule (`**/.aws`) denies opening the entry itself; it does
        // not cover the files inside a directory of that name — very easy to
        // write believing the opposite, so state it per rule rather than guess.
        let name_only: Vec<&String> = self
            .kern_names
            .iter()
            .filter(|n| !self.kern_dirs.contains(*n))
            .collect();
        if !name_only.is_empty() {
            let _ = writeln!(
                s,
                "\nnote: these deny the entry itself, NOT files inside a directory of that name.\n\
                 If any is a directory, add `- {{ match: \"**/<name>/**\", action: block }}` too:"
            );
            for n in name_only {
                let _ = writeln!(s, "  {n}");
            }
        }

        let observe_only = self.observe_only_blocks();
        if !observe_only.is_empty() {
            let _ = writeln!(
                s,
                "\nflagged but NEVER denied (no kernel key — glob segment, or name too long):"
            );
            for p in observe_only {
                let _ = writeln!(s, "  {p}");
            }
        }
        let overbroad = self.overbroad_block_keys();
        if !overbroad.is_empty() {
            let _ = writeln!(s, "\nenforced MORE broadly than written:");
            for (pat, reach) in overbroad {
                let _ = writeln!(s, "  {pat}  ->  {reach}");
            }
        }
        let shadowed = self.shadowed_by_kernel();
        if !shadowed.is_empty() {
            let _ = writeln!(
                s,
                "\noverridden by the kernel's unordered block-key set (the allow does NOT win):"
            );
            for (pat, key) in shadowed {
                let _ = writeln!(s, "  {pat}  <-  {key}");
            }
        }
        let warnings = self.semantic_warnings();
        if !warnings.is_empty() {
            let _ = writeln!(s, "\nwarnings:");
            for w in warnings {
                let _ = writeln!(s, "  - {w}");
            }
        }
        s
    }

    /// Patterns of `block` file/exec rules that CANNOT be kernel-enforced (glob
    /// segments, or a name at/over the [`NAME_LEN`] key width). The feed flags
    /// these distinctly and startup warns about them.
    pub fn observe_only_blocks(&self) -> Vec<String> {
        self.files
            .iter()
            .chain(&self.exec)
            .filter(|r| r.action == Action::Block && !r.enforceable)
            .map(|r| r.pattern.clone())
            .collect()
    }

    /// Exec block rules compiled to exact basenames for the LSM bprm_check matcher.
    pub fn exec_enforcement(&self) -> Vec<[u8; NAME_LEN]> {
        self.kern_execs.iter().filter_map(|s| name_key(s)).collect()
    }

    pub fn eval_file(&self, path: &str) -> Verdict {
        eval_path(&self.files, path, self.default_action)
    }

    pub fn eval_exec(&self, path: &str) -> Verdict {
        eval_path(&self.exec, path, self.default_action)
    }

    pub fn eval_connect(&self, ip: Ipv4Addr) -> Verdict {
        self.net_verdict(
            self.network
                .iter()
                .filter_map(|r| Some((r, r.v4_prefix(ip)?))),
        )
    }

    pub fn eval_connect6(&self, ip: Ipv6Addr) -> Verdict {
        self.net_verdict(
            self.network
                .iter()
                .filter_map(|r| Some((r, r.v6_prefix(ip)?))),
        )
    }

    /// Pick the verdict for a connect from the matching `(rule, prefix_len)`
    /// pairs, MOST-SPECIFIC first (longest prefix wins), ties broken by policy
    /// order. This is longest-prefix-match, not first-match — the kernel decides
    /// egress with an LPM trie, and CIDRs matching one IP are always nested, so
    /// this is the semantics the kernel actually enforces. Evaluating it any
    /// other way would make the feed disagree with the block that really fired.
    fn net_verdict<'a>(&self, matches: impl Iterator<Item = (&'a NetRule, u8)>) -> Verdict {
        let mut best: Option<(&NetRule, u8)> = None;
        for (r, plen) in matches {
            // Strictly-greater keeps the earliest rule on a prefix-length tie,
            // matching the kernel trie (net_entries inserts earliest rule last).
            if best.is_none_or(|(_, bp)| plen > bp) {
                best = Some((r, plen));
            }
        }
        match best {
            Some((r, _)) => Verdict {
                action: r.action,
                rule: r.label.clone(),
                enforceable: true,
            },
            None => Verdict {
                action: self.default_action,
                rule: "default".to_string(),
                enforceable: true,
            },
        }
    }
}

/// How many ancestor directories the LSM hook walks when matching `BLOCK_DIRS`.
/// The kernel program must stay a bounded loop for the verifier; userspace
/// mirrors the same bound so the feed cannot claim a denial from a deeper
/// ancestor than the hook actually inspects.
pub const MAX_DIR_WALK: usize = 16;

fn eval_path(rules: &[PathRule], path: &str, default: Action) -> Verdict {
    for r in rules {
        if r.matcher.is_match(path) {
            return Verdict {
                action: r.action,
                rule: r.pattern.clone(),
                enforceable: r.enforceable,
            };
        }
    }
    // A default block on files/exec is NOT kernel-enforced (LSM has no default-deny).
    Verdict {
        action: default,
        rule: "default".to_string(),
        enforceable: false,
    }
}

/// Last non-empty `/`-separated segment of a glob pattern.
fn last_segment(p: &str) -> Option<&str> {
    p.rsplit('/').find(|s| !s.is_empty())
}

/// The literal segment the kernel would key a file glob on, if it reduces to
/// one: `**/dir/**` → `(true, "dir")`; `**/name` or `/abs/name` →
/// `(false, "name")`. Glob-y segments return `None` (observe-only).
fn file_seg(pattern: &str) -> Option<(bool, &str)> {
    match pattern.strip_suffix("/**") {
        Some(stripped) => last_segment(stripped).map(|s| (true, s)),
        None => last_segment(pattern).map(|s| (false, s)),
    }
    .filter(|(_, s)| name_key(s).is_some())
}

/// As [`file_seg`], but as the NUL-padded fixed-width kernel map key.
fn file_key(pattern: &str) -> Option<(bool, [u8; NAME_LEN])> {
    file_seg(pattern).and_then(|(is_dir, s)| name_key(s).map(|k| (is_dir, k)))
}

/// A literal path segment -> NUL-padded fixed key, or `None` if it contains glob
/// metacharacters (those can't be enforced as an exact name) or does not fit the
/// fixed key width. Also used by the exception path in main.rs to address the
/// kernel block maps.
pub fn name_key(seg: &str) -> Option<[u8; NAME_LEN]> {
    if seg == "**" || seg.chars().any(|c| matches!(c, '*' | '?' | '[' | ']')) {
        return None;
    }
    let bytes = seg.as_bytes();
    // `>= NAME_LEN` and not `>`: the kernel reads the dentry name with
    // `bpf_probe_read_kernel_str`, which needs room for the trailing NUL. A name
    // that exactly fills the buffer could never be matched, so refusing it here
    // routes the rule through `observe_only_blocks` and it is reported instead
    // of quietly enforcing nothing.
    if bytes.is_empty() || bytes.len() >= NAME_LEN {
        return None;
    }
    let mut k = [0u8; NAME_LEN];
    k[..bytes.len()].copy_from_slice(bytes);
    Some(k)
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
  - { cidr: "::1/128", action: allow }
  - { cidr: "2001:db8::/32", action: block }
  - { cidr: "0.0.0.0/0", action: block }
exec:
  - { match: "**/nc", action: block }
  - { match: "**/curl", action: warn }
  - { match: "**", action: allow }
"#;

    fn parse(text: &str) -> Result<Policy> {
        Policy::from_yaml_str_with(text, &null_resolver)
    }

    fn policy() -> Policy {
        parse(P).expect("policy parses")
    }

    fn key(s: &str) -> [u8; NAME_LEN] {
        let mut k = [0u8; NAME_LEN];
        k[..s.len()].copy_from_slice(s.as_bytes());
        k
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
    fn network_v6_matching() {
        let p = policy();
        assert_eq!(
            p.eval_connect6("::1".parse().unwrap()).action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect6("2001:db8::5".parse().unwrap()).action,
            Action::Block
        );
        // unmatched v6 -> default (allow in P); the v4 0.0.0.0/0 rule does not apply
        assert_eq!(
            p.eval_connect6("2606:4700::1".parse().unwrap()).action,
            Action::Allow
        );
    }

    #[test]
    fn the_fingerprint_tracks_the_rules_a_policy_was_approved_against() {
        let a = "files:\n  - match: \"**/.env\"\n    action: block\n";
        let b = "files:\n  - match: \"**/.env\"\n    action: warn\n";
        let pa = Policy::from_yaml_str_with(a, &null_resolver).unwrap();
        let pb = Policy::from_yaml_str_with(b, &null_resolver).unwrap();
        let pa2 = Policy::from_yaml_str_with(a, &null_resolver).unwrap();
        assert_eq!(pa.fingerprint(), pa2.fingerprint(), "same source, same id");
        assert_ne!(
            pa.fingerprint(),
            pb.fingerprint(),
            "block -> warn must retire approvals granted under the block"
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
        assert!(names.contains(&key(".env"))); // **/.env
        assert!(names.contains(&key("shadow"))); // /etc/shadow
        assert!(dirs.contains(&key(".ssh"))); // **/.ssh/**
        assert!(!names.contains(&key(".env.*"))); // glob segment -> not enforced

        let execs = p.exec_enforcement();
        assert!(execs.contains(&key("nc"))); // **/nc block
        assert!(!execs.contains(&key("curl"))); // curl is warn, not block
    }

    #[test]
    fn enforceable_flag_and_observe_only() {
        let p = policy();
        assert!(p.eval_file("/x/.env").enforceable); // reduces to name .env
        assert!(p.eval_file("/x/.ssh/id").enforceable); // dir .ssh
                                                        // **/.env.* has a glob segment: block requested but NOT kernel-enforceable
        let v = p.eval_file("/x/.env.local");
        assert_eq!(v.action, Action::Block);
        assert!(!v.enforceable);
        // network blocks are always enforceable
        assert!(p.eval_connect("1.1.1.1".parse().unwrap()).enforceable);

        let oo = p.observe_only_blocks();
        assert!(oo.contains(&"**/.env.*".to_string()));
        assert!(!oo.contains(&"**/.env".to_string()));
    }

    #[test]
    fn empty_policy_uses_default() {
        let p = parse("default_action: warn").unwrap();
        assert_eq!(p.eval_file("/anything").action, Action::Warn);
        assert_eq!(
            p.eval_connect("8.8.8.8".parse().unwrap()).action,
            Action::Warn
        );
    }

    #[test]
    fn kernel_file_denial_mirrors_the_coarse_lsm_matcher() {
        let p = policy();
        // `/etc/shadow` reduced to bare name `shadow`: the kernel denies it
        // ANYWHERE, even where the glob-based eval says allow.
        assert_eq!(p.eval_file("/home/u/shadow").action, Action::Allow);
        assert_eq!(
            p.kernel_file_denial("/home/u/shadow"),
            Some(DenialKey::FileName("shadow".into()))
        );
        // A file directly in `.ssh` IS denied by the kernel.
        assert_eq!(
            p.kernel_file_denial("/home/u/.ssh/id_ed25519"),
            Some(DenialKey::FileDir(".ssh".into()))
        );
        // `.env.*` is a glob segment: never a kernel key, so never denied here.
        assert_eq!(p.kernel_file_denial("/home/u/.env.local"), None);
        assert_eq!(p.kernel_file_denial("/home/u/src/main.rs"), None);
    }

    #[test]
    fn dir_rules_cover_the_whole_subtree_not_just_direct_children() {
        let p = policy();
        // `**/.ssh/**` matches deep paths as a glob...
        assert_eq!(
            p.eval_file("/home/u/.ssh/sub/deep/id").action,
            Action::Block
        );
        // ...and the kernel now agrees, because the hook walks every ancestor.
        assert_eq!(
            p.kernel_file_denial("/home/u/.ssh/sub/deep/id"),
            Some(DenialKey::FileDir(".ssh".into()))
        );
    }

    #[test]
    fn ancestor_walk_is_bounded_exactly_like_the_kernel_loop() {
        let p = parse(r#"files: [{ match: "**/secret/**", action: block }]"#).unwrap();
        // `secret` sits MAX_DIR_WALK levels above the file: still caught.
        let just_inside = format!("/secret{}/f", "/d".repeat(MAX_DIR_WALK - 1));
        assert_eq!(
            p.kernel_file_denial(&just_inside),
            Some(DenialKey::FileDir("secret".into()))
        );
        // One level deeper than the kernel walks: not claimed, because the hook
        // would not have seen it either.
        let too_deep = format!("/secret{}/f", "/d".repeat(MAX_DIR_WALK));
        assert_eq!(p.kernel_file_denial(&too_deep), None);
    }

    #[test]
    fn denial_key_display_and_blast_radius_are_honest() {
        let k = DenialKey::FileName(".env".into());
        assert_eq!(k.to_string(), "name=.env");
        assert!(k.blast_radius().contains("ANY file named `.env`"));
        let d = DenialKey::FileDir(".ssh".into());
        assert_eq!(d.to_string(), "dir=.ssh");
        assert!(d.blast_radius().contains("directory named `.ssh`"));
        let n = DenialKey::Net4("1.1.1.1".parse().unwrap());
        assert_eq!(n.to_string(), "ip=1.1.1.1");
        assert!(n.blast_radius().contains("ALL egress to 1.1.1.1"));
    }

    #[test]
    fn exceptions_grant_once() {
        let mut exc = Exceptions::default();
        let key = DenialKey::Exec("nc".into());
        assert!(!exc.contains(&key));
        assert!(exc.grant(key.clone()));
        assert!(exc.contains(&key));
        assert!(!exc.grant(key), "second grant reports already-granted");
    }

    #[test]
    fn network_uses_longest_prefix_not_first_match() {
        // A broad block listed BEFORE a specific allow: first-match would block
        // 1.1.1.1, but the kernel LPM trie (and now userspace) let the /32 win.
        let p = parse(
            r#"
default_action: allow
network:
  - { cidr: "0.0.0.0/0", action: block }
  - { cidr: "1.1.1.1/32", action: allow }
"#,
        )
        .unwrap();
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap()).action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap()).rule,
            "cidr:1.1.1.1/32"
        );
        assert_eq!(
            p.eval_connect("8.8.8.8".parse().unwrap()).action,
            Action::Block
        );
    }

    #[test]
    fn kernel_exec_denial_matches_basename() {
        let p = policy();
        assert_eq!(
            p.kernel_exec_denial("/usr/bin/nc"),
            Some(DenialKey::Exec("nc".into()))
        );
        assert_eq!(
            p.kernel_exec_denial("/opt/tools/nc"),
            Some(DenialKey::Exec("nc".into()))
        );
        assert_eq!(p.kernel_exec_denial("/usr/bin/curl"), None); // curl is warn
    }

    #[test]
    fn overbroad_block_keys_flags_only_the_over_reaching_rules() {
        let p = policy();
        let flagged: Vec<String> = p
            .overbroad_block_keys()
            .into_iter()
            .map(|(pat, _)| pat)
            .collect();
        // `/etc/shadow` enforces as bare `shadow` -> over-broad.
        assert!(flagged.contains(&"/etc/shadow".to_string()));
        // `**/.env` and `**/.ssh/**` are already the exact canonical form.
        assert!(!flagged.contains(&"**/.env".to_string()));
        assert!(!flagged.contains(&"**/.ssh/**".to_string()));
        // `**/nc` exec rule is canonical too.
        assert!(!flagged.contains(&"**/nc".to_string()));
    }

    // ── schema validation ───────────────────────────────────────────────────

    #[test]
    fn unknown_keys_are_rejected_instead_of_silently_disabling_a_rule_class() {
        // `file:` instead of `files:` used to parse fine and enforce nothing.
        let err = parse("file:\n  - { match: \"**/.env\", action: block }\n")
            .err()
            .expect("an unknown top-level key is refused");
        assert!(format!("{err:#}").contains("file"), "{err:#}");
        // Same for a mistyped rule key.
        assert!(parse(r#"files: [{ pattern: "**/.env", action: block }]"#).is_err());
        // ...and for a stray top-level key.
        assert!(parse("defualt_action: block").is_err());
    }

    #[test]
    fn unsupported_schema_version_is_refused() {
        assert!(parse("version: 2\ndefault_action: allow").is_err());
        assert!(parse("version: 1\ndefault_action: allow").is_ok());
        assert!(parse("default_action: allow").is_ok(), "version optional");
    }

    #[test]
    fn a_network_rule_needs_exactly_one_of_cidr_or_domain() {
        assert!(parse(r#"network: [{ action: block }]"#).is_err());
        assert!(
            parse(r#"network: [{ cidr: "0.0.0.0/0", domain: "x.test", action: block }]"#).is_err()
        );
    }

    #[test]
    fn domain_rules_resolve_through_the_injected_resolver() {
        let stub = |d: &str| -> Vec<IpAddr> {
            if d == "example.test" {
                vec!["203.0.113.7".parse().unwrap()]
            } else {
                vec![]
            }
        };
        let p = Policy::from_yaml_str_with(
            r#"
default_action: block
network:
  - { domain: "example.test", action: allow }
  - { domain: "nowhere.test", action: allow }
"#,
            &stub,
        )
        .unwrap();
        assert_eq!(
            p.eval_connect("203.0.113.7".parse().unwrap()).action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect("203.0.113.8".parse().unwrap()).action,
            Action::Block
        );
        assert!(p
            .semantic_warnings()
            .iter()
            .any(|w| w.contains("nowhere.test")));
    }

    // ── honesty warnings ────────────────────────────────────────────────────

    #[test]
    fn default_block_warns_that_files_and_exec_are_not_deny_all() {
        let p = parse("default_action: block").unwrap();
        assert!(p
            .semantic_warnings()
            .iter()
            .any(|w| w.contains("NETWORK only")));
    }

    #[test]
    fn explain_calls_out_a_name_rule_that_is_really_a_directory() {
        let p = parse(r#"files: [{ match: "**/.aws", action: block }]"#).unwrap();
        let text = p.explain();
        assert!(
            text.contains("NOT files inside a directory"),
            "a bare `**/.aws` block protects the entry, not its contents:\n{text}"
        );
        // Adding the dir form silences it.
        let p = parse(
            r#"files:
  - { match: "**/.aws", action: block }
  - { match: "**/.aws/**", action: block }"#,
        )
        .unwrap();
        assert!(!p.explain().contains("NOT files inside a directory"));
    }

    #[test]
    fn explain_names_every_key_the_kernel_will_deny_on() {
        let text = policy().explain();
        for expected in [
            "name=.env",
            "name=shadow",
            "dir=.ssh",
            "exec  name=nc",
            "cidr:0.0.0.0/0",
            // the observe-only block must be shown as never denied
            "**/.env.*",
        ] {
            assert!(text.contains(expected), "missing `{expected}` in:\n{text}");
        }
    }

    #[test]
    fn explain_says_so_when_nothing_is_enforced() {
        let p = parse("default_action: allow").unwrap();
        assert!(p.explain().contains("NOTHING is kernel-enforced"));
    }

    #[test]
    fn allow_rules_the_kernel_block_set_overrides_are_reported() {
        // Userspace says "this one .env is fine"; the kernel's key set has no
        // order and denies every `.env`. Say so instead of letting the operator
        // believe the exception took.
        let p = parse(
            r#"
files:
  - { match: "**/fixtures/.env", action: allow }
  - { match: "**/.env", action: block }
"#,
        )
        .unwrap();
        let shadowed = p.shadowed_by_kernel();
        assert_eq!(shadowed.len(), 1);
        assert_eq!(shadowed[0].0, "**/fixtures/.env");
        assert_eq!(shadowed[0].1, "name=.env");

        // A dir key shadows any allow rule whose path passes through it.
        let p = parse(
            r#"
files:
  - { match: "**/.ssh/known_hosts", action: allow }
  - { match: "**/.ssh/**", action: block }
"#,
        )
        .unwrap();
        assert_eq!(p.shadowed_by_kernel()[0].1, "dir=.ssh");

        // The ordinary catch-all `**` allow is not flagged.
        assert!(policy()
            .shadowed_by_kernel()
            .iter()
            .all(|(pat, _)| pat != "**"));
    }

    #[test]
    fn oversized_names_are_reported_rather_than_silently_unenforced() {
        let long = "a".repeat(NAME_LEN);
        let p = parse(&format!(
            r#"files: [{{ match: "**/{long}", action: block }}]"#
        ))
        .unwrap();
        assert!(p.observe_only_blocks().len() == 1);
        assert_eq!(p.kernel_file_denial(&format!("/x/{long}")), None);
    }

    // ── the policies actually shipped ───────────────────────────────────────

    const SHIPPED: [(&str, &str); 3] = [
        ("policy.yaml", include_str!("../../policy.yaml")),
        (
            "policies/strict.yaml",
            include_str!("../../policies/strict.yaml"),
        ),
        (
            "policies/permissive.yaml",
            include_str!("../../policies/permissive.yaml"),
        ),
    ];

    #[test]
    fn every_shipped_policy_parses() {
        for (name, text) in SHIPPED {
            Policy::from_yaml_str_with(text, &null_resolver)
                .unwrap_or_else(|e| panic!("{name} does not parse: {e:#}"));
        }
    }

    #[test]
    fn blocking_presets_really_protect_the_secrets_they_advertise() {
        // permissive.yaml is warn-only by design, so it is not in this set.
        for (name, text) in SHIPPED
            .iter()
            .filter(|(n, _)| *n != "policies/permissive.yaml")
        {
            let p = Policy::from_yaml_str_with(text, &null_resolver).unwrap();
            for secret in [
                "/home/u/.env",
                "/home/u/.ssh/id_ed25519",
                "/home/u/.ssh/nested/deeper/key",
            ] {
                assert_eq!(
                    p.eval_file(secret).action,
                    Action::Block,
                    "{name} does not block {secret}"
                );
                assert!(
                    p.kernel_file_denial(secret).is_some(),
                    "{name} blocks {secret} only in userspace — the kernel would allow it"
                );
            }
        }
    }

    #[test]
    fn shipped_policies_do_not_break_git_or_ordinary_source_files() {
        // A regression guard for the strict.yaml bug where `**/.kube/config`
        // reduced to the bare name `config` and denied `.git/config`.
        for (name, text) in SHIPPED {
            let p = Policy::from_yaml_str_with(text, &null_resolver).unwrap();
            for ordinary in [
                "/home/u/proj/.git/config",
                "/home/u/proj/src/main.rs",
                "/home/u/proj/Cargo.toml",
            ] {
                assert_eq!(
                    p.kernel_file_denial(ordinary),
                    None,
                    "{name} would make the kernel deny {ordinary}"
                );
            }
        }
    }

    #[test]
    fn a_deny_all_egress_preset_covers_ipv6_too() {
        for (name, text) in SHIPPED {
            let p = Policy::from_yaml_str_with(text, &null_resolver).unwrap();
            assert!(
                p.net_coverage_gaps().is_empty(),
                "{name} leaves an IPv6 egress gap: {:?}",
                p.net_coverage_gaps()
            );
        }
    }
}
