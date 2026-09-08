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
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;

use anyhow::{Context as _, Result};
use globset::{Glob, GlobMatcher};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use wardyn_common::{
    fmode, proto as ipproto, InodeKey, PortKey4, PortKey6, ProtoKey4, ProtoKey6, ProtoPortKey4,
    ProtoPortKey6, NAME_LEN, PORT_BITS, PROTO_BITS,
};

use crate::identity::{self, Anchor, AnchorBase, AnchorKind, ResolveOutcome, UnresolvedAnchor};

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

/// One right an `allow_paths:` entry grants over a hierarchy.
///
/// Three, not Landlock's sixteen. The kernel's bits distinguish making a FIFO
/// from making a socket, which no policy author has an opinion about; what they
/// have an opinion about is whether the agent may read a directory, change it,
/// or run things from it. The expansion is in `wardyn::landlock`, and `write`
/// deliberately covers creating, removing and renaming — a project directory an
/// agent cannot save a new file into is not one it can work in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Right {
    Read,
    Write,
    Exec,
}

impl Right {
    pub fn as_str(self) -> &'static str {
        match self {
            Right::Read => "read",
            Right::Write => "write",
            Right::Exec => "exec",
        }
    }
}

/// One hierarchy the agent may reach, and what it may do there.
#[derive(Debug, Clone)]
pub struct AllowPath {
    /// As written, for reporting.
    pub raw: String,
    /// Resolved against the agent's home and working directory. `None` when the
    /// base was unknown — reported, never guessed.
    pub path: Option<std::path::PathBuf>,
    pub rights: Vec<Right>,
}

/// Which operation a file rule applies to.
///
/// Two axes, and the split is not cosmetic — they are enforced at different
/// kernel hooks and mean different things:
///
/// - **opens** (`any`, `read`, `write`). `block` used to mean "this file cannot
///   be opened at all", which also forbids *writing* it — so a policy could not
///   say "the agent may create a `.env`, it just may not read one", and a rule
///   meant to protect a secret also broke the tools that write it. The kernel
///   has always known the difference (`f_mode` carries `FMODE_READ`/`FMODE_WRITE`
///   at `file_open`); the policy simply had no way to ask.
/// - **lifecycle** (`create`, `delete`). An `rm` is not an open: `file_open`
///   never fires for `unlink(2)`, so a rule guarding a secret's *contents* said
///   nothing whatsoever about destroying it. `rm -rf` was never a read.
///
/// [`Access::All`] is the union, and it exists because "protect this thing"
/// should be one line rather than three.
///
/// `any` deliberately does **not** cover the lifecycle axis. It is the default,
/// so widening it would mean every `block` rule in every policy already written
/// silently starts refusing `rm` — a behaviour change nobody asked for, on the
/// rules people are least likely to re-read. Lifecycle coverage is opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// Every open, whatever it asked for. The default, and exactly the
    /// behaviour of a rule written before either axis existed.
    #[default]
    Any,
    Read,
    Write,
    /// A new name for this object may not be created.
    Create,
    /// This object may not be removed, renamed away, or replaced.
    Delete,
    /// Every open *and* both lifecycle operations.
    All,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Any => "any",
            Access::Read => "read",
            Access::Write => "write",
            Access::Create => "create",
            Access::Delete => "delete",
            Access::All => "all",
        }
    }

    /// The mask stored beside a block key in the kernel maps; see
    /// [`wardyn_common::fmode`].
    pub fn mask(self) -> u8 {
        match self {
            Access::Any => fmode::MASK_ANY,
            Access::Read => fmode::READ as u8,
            Access::Write => fmode::WRITE as u8,
            Access::Create => fmode::CREATE,
            Access::Delete => fmode::DELETE,
            Access::All => fmode::OPEN_ANY | fmode::CREATE | fmode::DELETE,
        }
    }

    /// Does an open requesting `requested` (raw `f_mode` bits) match this rule?
    pub fn matches(self, requested: u32) -> bool {
        fmode::matches(self.mask(), requested)
    }

    /// Does this rule cover the lifecycle operation `op` ([`fmode::CREATE`] or
    /// [`fmode::DELETE`])?
    pub fn covers(self, op: u8) -> bool {
        fmode::covers(self.mask(), op)
    }

    /// Whether this rule says anything at all about creating or removing.
    /// Drives `CFG_LIFECYCLE_ON`, so a policy that never mentions the axis keeps
    /// the five lifecycle hooks switched off entirely.
    pub fn is_lifecycle(self) -> bool {
        self.mask() & fmode::LIFECYCLE_BITS != 0
    }
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

/// The transport a network rule can name.
///
/// Two values, not 256: these are the protocols an egress policy can say
/// anything useful about, and a rule able to name any IP protocol number would
/// mostly be able to name ones no socket the hooks see ever carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// The IP protocol number the kernel key is built from.
    pub fn number(self) -> u8 {
        match self {
            Proto::Tcp => ipproto::TCP,
            Proto::Udp => ipproto::UDP,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    /// The rule vocabulary for a protocol number seen on the wire, or `None` for
    /// anything a rule cannot name.
    pub fn from_number(n: u8) -> Option<Proto> {
        match n {
            ipproto::TCP => Some(Proto::Tcp),
            ipproto::UDP => Some(Proto::Udp),
            _ => None,
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

/// Which lifecycle hook refused, for a [`DenialKey::Lifecycle`].
///
/// The kernel matches a removal and a creation against the *same* four maps as
/// an open; only the bit of the stored mask differs. So the operation has to
/// ride alongside the key rather than inside it — an exception lifts one bit,
/// and dropping the key outright would also unblock reading the file, which is
/// not what the operator approved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOp {
    Create,
    Delete,
}

impl LifecycleOp {
    /// The [`fmode`] bit this operation consults.
    pub fn bit(self) -> u8 {
        match self {
            LifecycleOp::Create => fmode::CREATE,
            LifecycleOp::Delete => fmode::DELETE,
        }
    }

    /// The verb, for the feed and the confirm prompt.
    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleOp::Create => "create",
            LifecycleOp::Delete => "delete",
        }
    }
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
    /// LSM `file_open`: the object's `(parent, name)` matched `BLOCK_PAIRS` —
    /// `credentials` directly under `.aws`, not every `credentials`.
    FilePair {
        parent: String,
        name: String,
    },
    /// LSM `file_open`: an ancestor and *its* parent matched `BLOCK_DIR_PAIRS`
    /// — `gcloud` under `.config`, not every `gcloud`.
    DirPair {
        parent: String,
        name: String,
    },
    /// LSM `bprm_check`: exec basename match (BLOCK_EXEC), e.g. `nc`.
    Exec(String),
    /// cgroup connect/sendmsg: destination address (NET_RULES LPM trie).
    Net4(Ipv4Addr),
    Net6(Ipv6Addr),
    /// The same hooks, but the decision came from the **port** trie
    /// (`NET_PORT_RULES`). A separate key because an exception has to be written
    /// into the trie that denied — an allow in the address trie would be
    /// overruled by the port rule on the very next connect, and the operator
    /// would watch their approval do nothing.
    Net4Port {
        ip: Ipv4Addr,
        port: u16,
    },
    Net6Port {
        ip: Ipv6Addr,
        port: u16,
    },
    /// LSM `file_open`: the opened object's own `(dev, ino)` matched
    /// `BLOCK_INODES` — the rule found the file regardless of its current name.
    FileInode {
        dev: u32,
        ino: u64,
    },
    /// LSM `file_open`: an ancestor directory's `(dev, ino)` matched
    /// `BLOCK_DIR_INODES`.
    DirInode {
        dev: u32,
        ino: u64,
    },
    /// LSM `bprm_check`: the executable's `(dev, ino)` matched.
    ExecInode {
        dev: u32,
        ino: u64,
    },
    /// The same cgroup hooks, but the decision came from one of the two
    /// **protocol** tries.
    ///
    /// `key` is the address-or-port key inside that trie, and `proto` says which
    /// trie holds it. Wrapping rather than adding four flat variants keeps the
    /// overrides file readable, and keeps the invariant that matters: an
    /// exception is written into the trie that denied, or the rule that is still
    /// there overrules it on the very next connect.
    NetProto {
        proto: Proto,
        key: Box<DenialKey>,
    },
    /// One of the lifecycle hooks (`inode_unlink`, `inode_rmdir`,
    /// `inode_create`, `inode_mkdir`, `inode_rename`) refused.
    ///
    /// `key` is the ordinary file key the kernel matched — the lifecycle hooks
    /// share `BLOCK_NAMES` / `BLOCK_DIRS` / `BLOCK_INODES` / `BLOCK_DIR_INODES`
    /// with `file_open` — and `op` says which bit of its mask fired. Both halves
    /// are needed: an exception must clear that one bit and leave the rest of
    /// the rule standing, or approving a single `rm` would quietly also grant
    /// every read of the file.
    Lifecycle {
        op: LifecycleOp,
        key: Box<DenialKey>,
    },
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
            DenialKey::FilePair { parent, name } => format!(
                "opening ANY file named `{name}` directly inside a directory named `{parent}`"
            ),
            DenialKey::DirPair { parent, name } => format!(
                "opening ANY file anywhere under a directory named `{name}` that sits inside one \
                 named `{parent}`"
            ),
            DenialKey::Exec(n) => format!("executing ANY program named `{n}` (any path)"),
            DenialKey::Net4(ip) => format!("ALL egress to {ip} (any port/protocol)"),
            DenialKey::Net6(ip) => format!("ALL egress to [{ip}] (any port/protocol)"),
            // Narrower than the address form, and saying so matters: this is a
            // smaller thing to approve, and an operator who has been told "ALL
            // egress to this host" for a single-port denial will approve less
            // than they safely could — or trust the prompt less next time.
            DenialKey::Net4Port { ip, port } => format!("egress to {ip} on port {port} only"),
            DenialKey::Net6Port { ip, port } => format!("egress to [{ip}] on port {port} only"),
            // An identity key is the one exception to "the honest scope is
            // always broader": it names exactly one object. Saying so is the
            // point — approving it is a far smaller decision than approving a
            // name, and an operator should be able to see that.
            DenialKey::FileInode { dev, ino } => {
                format!(
                    "opening ONE file — {} — under any name",
                    dev_ino(*dev, *ino)
                )
            }
            DenialKey::DirInode { dev, ino } => format!(
                "opening ANY file under ONE directory — {} — under any name",
                dev_ino(*dev, *ino)
            ),
            DenialKey::ExecInode { dev, ino } => format!(
                "executing ONE program — {} — under any name",
                dev_ino(*dev, *ino)
            ),
            // Narrower than the key it wraps, and the prompt should say so:
            // granting this lifts one operation, not the whole rule. The file
            // stays as unreadable as the policy made it.
            DenialKey::Lifecycle { op, key } => {
                format!("{}-ing, and only that, for: {}", op.as_str(), key.scope())
            }
            // Narrower than the key it wraps, in the same way and for the same
            // reason as a port key: this grants one transport, not the host.
            DenialKey::NetProto { proto, key } => {
                format!(
                    "{} only — {}",
                    proto.as_str().to_uppercase(),
                    key.blast_radius()
                )
            }
        }
    }

    /// The object a key covers, without the leading verb — so
    /// [`Self::blast_radius`] can put a different verb in front of it.
    fn scope(&self) -> String {
        match self {
            DenialKey::FileName(n) => format!("ANY file named `{n}` (any directory)"),
            DenialKey::FileDir(d) => format!("ANY file anywhere under a directory named `{d}`"),
            DenialKey::FilePair { parent, name } => {
                format!("ANY file named `{name}` directly inside a directory named `{parent}`")
            }
            DenialKey::DirPair { parent, name } => format!(
                "ANY file anywhere under a directory named `{name}` that sits inside one named \
                 `{parent}`"
            ),
            DenialKey::FileInode { dev, ino } => {
                format!("ONE file — {} — under any name", dev_ino(*dev, *ino))
            }
            DenialKey::DirInode { dev, ino } => format!(
                "ANY file under ONE directory — {} — under any name",
                dev_ino(*dev, *ino)
            ),
            // The lifecycle hooks only ever match the four file keys above, so
            // the rest cannot appear here; fall back to the full sentence rather
            // than inventing a phrasing for a case that never occurs.
            other => other.blast_radius(),
        }
    }

    /// The kernel-map identity this key addresses, if it is an identity key.
    pub fn inode(&self) -> Option<InodeKey> {
        match self {
            DenialKey::FileInode { dev, ino }
            | DenialKey::DirInode { dev, ino }
            | DenialKey::ExecInode { dev, ino } => Some(InodeKey::new(*dev, *ino)),
            DenialKey::Lifecycle { key, .. } | DenialKey::NetProto { key, .. } => key.inode(),
            _ => None,
        }
    }
}

/// A kernel name key with the access mask stored beside it — the exact shape of
/// one `BLOCK_NAMES` / `BLOCK_DIRS` / `BLOCK_EXEC` entry.
pub type NameEntry = ([u8; NAME_LEN], u8);

/// `(parent key, name key, access mask)` — one `BLOCK_PAIRS` / `BLOCK_DIR_PAIRS`
/// entry.
pub type PairEntry = ([u8; NAME_LEN], [u8; NAME_LEN], u8);

/// The identity keys a policy compiles to, split by the kernel map each set
/// goes into. Each entry is `(key, access mask)`.
#[derive(Default, Debug)]
pub struct InodeKeys {
    pub files: Vec<(InodeKey, u8)>,
    pub dirs: Vec<(InodeKey, u8)>,
    pub execs: Vec<(InodeKey, u8)>,
}

impl InodeKeys {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.is_empty() && self.execs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.files.len() + self.dirs.len() + self.execs.len()
    }
}

/// What a stored mask denies, as a verb phrase for a sentence.
///
/// The two axes are listed separately and joined rather than collapsed into one
/// word, because a mask can carry both and "access to" would hide the single
/// thing an operator most needs to check: whether a rule that says `block`
/// actually stops an `rm`.
pub fn mask_verbs(mask: u8) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let rw = mask & (fmode::READ as u8 | fmode::WRITE as u8);
    if mask == fmode::MASK_ANY || mask & fmode::OPEN_ANY != 0 {
        parts.push("opening");
    } else if rw == fmode::READ as u8 {
        parts.push("READS of");
    } else if rw == fmode::WRITE as u8 {
        parts.push("WRITES to");
    } else if rw != 0 {
        parts.push("reads or writes of");
    }
    if fmode::covers(mask, fmode::CREATE) {
        parts.push("CREATING");
    }
    if fmode::covers(mask, fmode::DELETE) {
        parts.push("DELETING");
    }
    // A mask with no bit at all is never compiled, but one that denies nothing
    // must not read as if it denied everything.
    if parts.is_empty() {
        return "nothing about".to_string();
    }
    parts.join(" / ")
}

/// Name → fixed-width kernel key, carrying the access mask.
fn keyed(map: &BTreeMap<String, u8>) -> Vec<NameEntry> {
    map.iter()
        .filter_map(|(s, &mask)| name_key(s).map(|k| (k, mask)))
        .collect()
}

/// `(parent, name)` → the two fixed-width keys, carrying the access mask.
fn keyed_pairs(map: &BTreeMap<(String, String), u8>) -> Vec<PairEntry> {
    map.iter()
        .filter_map(|((p, n), &mask)| Some((name_key(p)?, name_key(n)?, mask)))
        .collect()
}

/// `dev 8:1 ino 4242`, the form `stat` and `/proc/self/mountinfo` also speak.
fn dev_ino(dev: u32, ino: u64) -> String {
    let (maj, min) = crate::identity::split_dev(dev);
    format!("dev {maj}:{min} ino {ino}")
}

impl fmt::Display for DenialKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenialKey::FileName(n) => write!(f, "name={n}"),
            DenialKey::FileDir(d) => write!(f, "dir={d}"),
            DenialKey::FilePair { parent, name } => write!(f, "name={parent}/{name}"),
            DenialKey::DirPair { parent, name } => write!(f, "dir={parent}/{name}"),
            DenialKey::Exec(n) => write!(f, "exec={n}"),
            DenialKey::Net4(ip) => write!(f, "ip={ip}"),
            DenialKey::Net6(ip) => write!(f, "ip=[{ip}]"),
            DenialKey::Net4Port { ip, port } => write!(f, "ip={ip}:{port}"),
            DenialKey::Net6Port { ip, port } => write!(f, "ip=[{ip}]:{port}"),
            DenialKey::FileInode { dev, ino } => write!(f, "ino={}", dev_ino(*dev, *ino)),
            DenialKey::DirInode { dev, ino } => write!(f, "dir-ino={}", dev_ino(*dev, *ino)),
            DenialKey::ExecInode { dev, ino } => write!(f, "exec-ino={}", dev_ino(*dev, *ino)),
            DenialKey::Lifecycle { op, key } => write!(f, "{}:{key}", op.as_str()),
            DenialKey::NetProto { proto, key } => write!(f, "{}/{key}", proto.as_str()),
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
    /// Landlock hierarchies. Present means the agent is *contained*: it reaches
    /// these and nothing else. Absent means no containment at all — this is an
    /// allowlist, and an empty allowlist would deny everything including the
    /// agent's own loader, so "not mentioned" cannot mean "allow nothing".
    #[serde(default)]
    allow_paths: Vec<AllowPathRaw>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowPathRaw {
    path: String,
    /// Named `rights:` rather than `access:` on purpose. `access:` already means
    /// something else one section up — which operation a *block* rule covers —
    /// and reusing it would suggest the two axes are the same.
    rights: Vec<Right>,
}

/// A file or exec rule. Exactly one of `match:` (a glob over names) and `path:`
/// (a concrete object, pinned by identity) — they are different questions, and a
/// rule that tried to be both would have to lie about one of them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathRuleRaw {
    #[serde(rename = "match")]
    pattern: Option<String>,
    path: Option<String>,
    action: Action,
    #[serde(default)]
    access: Access,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetRuleRaw {
    cidr: Option<String>,
    domain: Option<String>,
    /// Destination port. A rule that names one is treated as more specific than
    /// any rule that does not, whatever their address prefixes — see
    /// [`Policy::eval_connect`].
    port: Option<u16>,
    /// Transport. Same idea one dimension further: a rule naming a protocol is
    /// more specific than one that does not, and the two combine — `proto` +
    /// `port` is the most specific rule there is.
    proto: Option<Proto>,
    action: Action,
}

// ── compiled policy ─────────────────────────────────────────────────────────

/// How a compiled rule decides whether it covers a path.
enum Matcher {
    /// A `match:` glob, over the path as the syscall reported it.
    Glob(GlobMatcher),
    /// A `path:` rule, resolved to a concrete location. Compared exactly rather
    /// than compiled to a glob, so a literal `[` or `*` in a filename means
    /// itself.
    ///
    /// This is only the *userspace prediction*: the observed path can be
    /// relative, or reach the object through a symlink, and then it will not
    /// compare equal even though the kernel denies the open. The kernel's own
    /// `DENY_FILE` event remains the authority — which is exactly why identity
    /// rules are enforced by inode and not by this comparison.
    Path {
        exact: std::path::PathBuf,
        subtree: bool,
    },
}

impl Matcher {
    fn is_match(&self, path: &str) -> bool {
        match self {
            Matcher::Glob(g) => g.is_match(path),
            Matcher::Path { exact, subtree } => {
                let p = Path::new(path);
                p == exact || (*subtree && p.starts_with(exact))
            }
        }
    }
}

struct PathRule {
    pattern: String,
    matcher: Matcher,
    action: Action,
    access: Access,
    /// `action == block` AND the rule reduces to a kernel-enforceable key —
    /// a basename/directory name, or a resolved `(dev, ino)`.
    enforceable: bool,
}

impl PathRule {
    /// Whether this came from `match:`. The name-key analyses (over-broad keys,
    /// kernel shadowing) only apply to globs — a `path:` rule has no basename
    /// semantics to over-reach with.
    fn is_glob(&self) -> bool {
        matches!(self.matcher, Matcher::Glob(_))
    }
}

#[derive(Clone)]
enum NetMatch {
    V4Cidr(Ipv4Net),
    V4Ip(Ipv4Addr),
    V6Cidr(Ipv6Net),
    V6Ip(Ipv6Addr),
}

#[derive(Clone)]
struct NetRule {
    label: String,
    which: NetMatch,
    /// `Some(p)` puts this rule in a port trie, which the kernel consults
    /// before the address-only ones.
    port: Option<u16>,
    /// `Some(p)` puts this rule in a protocol trie. With `port`, that is four
    /// tries in all, consulted most-specific first.
    proto: Option<Proto>,
    action: Action,
    /// Where this rule sat in the policy file.
    ///
    /// Precedence within a tier is longest-prefix first, ties to the earliest
    /// rule — and "earliest" used to mean "earlier in `self.network`". Domain
    /// rules now live in a separate collection because their addresses move, so
    /// position has to travel with the rule instead of being implied by which
    /// vector it is in. Two rules that resolve to the same `/32` still resolve
    /// their tie exactly as they did.
    order: usize,
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
    /// Does this rule's port constraint (if any) admit `dport`?
    fn port_matches(&self, dport: u16) -> bool {
        self.port.is_none_or(|p| p == dport)
    }

    /// Which of the four tiers this rule lives in: `(names a proto, names a
    /// port)`. The tuple is the trie, and the order tiers are consulted in.
    fn tier(&self) -> (bool, bool) {
        (self.proto.is_some(), self.port.is_some())
    }
}

/// One `domain:` rule as written, kept as a *spec* rather than as the addresses
/// it happened to resolve to at load.
#[derive(Clone, Debug)]
struct DomainSpec {
    domain: String,
    port: Option<u16>,
    proto: Option<Proto>,
    action: Action,
    label: String,
    order: usize,
}

/// One address a `domain:` rule currently covers, as the caller needs it to
/// address a kernel trie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainAddr {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub proto: Option<Proto>,
    pub action: Action,
    /// The name it came from, for the feed row.
    pub domain: String,
}

/// What changed when the domain rules were re-resolved.
///
/// Empty in all three fields means the answer did not move, which is the common
/// case and the one the caller should do nothing about.
#[derive(Default, Debug)]
pub struct DomainRefresh {
    pub added: Vec<DomainAddr>,
    pub removed: Vec<DomainAddr>,
    /// Names that resolved to nothing this time. Reported rather than swallowed:
    /// a rule that stops resolving stops enforcing, and the operator has to hear
    /// that from the feed instead of finding it in an audit log afterwards.
    pub failed: Vec<String>,
}

impl DomainRefresh {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.failed.is_empty()
    }
}

/// The `domain:` rules and the addresses they currently point at.
///
/// Separate from `Policy::network`, and behind a lock, because a name is not an
/// address: CDN-fronted hosts rotate within minutes, so a rule frozen at load
/// stops meaning what it says inside one agent session. An allowlisted domain
/// starts hitting the deny-all catch-all — which users experience as wardyn
/// being flaky, and flakiness is how a security tool gets switched off.
#[derive(Default)]
struct DomainSet {
    specs: Vec<DomainSpec>,
    /// Rules expanded from `specs` at the last resolution. Read on every
    /// connect the mirror evaluates, written by the refresh timer, so a
    /// read-biased lock is the right shape.
    live: std::sync::RwLock<Vec<NetRule>>,
}

impl DomainSet {
    fn snapshot(&self) -> Vec<NetRule> {
        self.live.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// Expand every spec through `resolve`, replacing what is live.
    ///
    /// Replaces rather than accumulates. Keeping every address a name has ever
    /// had would make an `allow` steadily more permissive than the operator
    /// wrote — the policy would drift open on its own, which is not a direction
    /// a security tool may drift in without being told to.
    fn refresh(&self, resolve: Resolver<'_>) -> DomainRefresh {
        let mut next = Vec::new();
        let mut failed = Vec::new();
        for spec in &self.specs {
            let ips = resolve(&spec.domain);
            if ips.is_empty() {
                failed.push(spec.domain.clone());
                continue;
            }
            for ip in ips {
                next.push(NetRule {
                    label: spec.label.clone(),
                    which: match ip {
                        IpAddr::V4(v4) => NetMatch::V4Ip(v4),
                        IpAddr::V6(v6) => NetMatch::V6Ip(v6),
                    },
                    port: spec.port,
                    proto: spec.proto,
                    action: spec.action,
                    order: spec.order,
                });
            }
        }

        let before = self.snapshot();
        let key = |r: &NetRule| (addr_of(r), r.port, r.proto, r.action);
        let had: Vec<_> = before.iter().map(key).collect();
        let has: Vec<_> = next.iter().map(key).collect();

        let mut out = DomainRefresh {
            failed,
            ..Default::default()
        };
        for (r, k) in next.iter().zip(&has) {
            if !had.contains(k) {
                out.added.push(as_domain_addr(r));
            }
        }
        for (r, k) in before.iter().zip(&had) {
            if !has.contains(k) {
                out.removed.push(as_domain_addr(r));
            }
        }
        if let Ok(mut g) = self.live.write() {
            *g = next;
        }
        out
    }
}

/// The single address a domain-derived rule names. Domain rules are always host
/// rules, so this is never a prefix.
fn addr_of(r: &NetRule) -> Option<IpAddr> {
    match &r.which {
        NetMatch::V4Ip(a) => Some(IpAddr::V4(*a)),
        NetMatch::V6Ip(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

fn as_domain_addr(r: &NetRule) -> DomainAddr {
    DomainAddr {
        ip: addr_of(r).expect("domain rules are host rules"),
        port: r.port,
        proto: r.proto,
        action: r.action,
        domain: r.label.clone(),
    }
}

pub struct Policy {
    default_action: Action,
    files: Vec<PathRule>,
    exec: Vec<PathRule>,
    network: Vec<NetRule>,
    /// Mirror of the kernel's `BLOCK_NAMES` / `BLOCK_DIRS` / `BLOCK_EXEC` maps:
    /// name → the access mask stored with it. The LSM hook can only see dentry
    /// names, so these are what it *actually* matches on — kept here so
    /// userspace can reproduce the kernel's verdict instead of guessing from the
    /// glob.
    kern_names: BTreeMap<String, u8>,
    kern_dirs: BTreeMap<String, u8>,
    /// Mirror of `BLOCK_PAIRS` / `BLOCK_DIR_PAIRS`: rules whose glob kept a
    /// literal parent segment, keyed `(parent, name)`. Consulted before the
    /// single-name maps, on both sides of the boundary.
    kern_pairs: BTreeMap<(String, String), u8>,
    kern_dir_pairs: BTreeMap<(String, String), u8>,
    kern_execs: BTreeMap<String, u8>,
    /// Mirror of `BLOCK_INODES` / `BLOCK_DIR_INODES` / `BLOCK_EXEC_INODES`:
    /// every `path:` rule that resolved to a real object.
    anchors: Vec<Anchor>,
    /// `path:` rules that resolved to nothing. They enforce nothing, and a
    /// policy whose identity rules quietly evaporated is worse than one that
    /// never had them — startup and `--dry-run` name every one.
    unresolved_anchors: Vec<UnresolvedAnchor>,
    /// `domain:` rules that resolved to nothing at load time — they enforce
    /// nothing at all, so startup says so instead of leaving a silent hole.
    unresolved_domains: Vec<String>,
    /// The `domain:` rules, and the addresses they point at right now.
    domains: DomainSet,
    /// Landlock hierarchies, resolved. Empty means no containment was asked for.
    allow_paths: Vec<AllowPath>,
    /// Which of the three sources this came from. Set by `Loader::load`;
    /// `from_str` leaves it `Embedded`, since there is no file behind it.
    source: PolicySource,
    /// The text this was compiled from, kept so a stored approval can be
    /// fingerprinted against the policy it was granted under. An approval is
    /// only meaningful for the rules it was an exception TO; carrying it into a
    /// policy that has since changed would silently widen the new one.
    source_text: String,
    /// Identifies this exact policy source, so a stored approval granted under
    /// it stops applying the moment the rules change. Computed here because
    /// this is the only place the source text exists.
    fingerprint: String,
}

/// What [`Policy::containment_denies`] is passed for an **exec**, which carries
/// no `f_mode`. Distinct from any real `FMODE_*` combination so the check can
/// tell "this needs the exec right" from "this is a read".
pub const EXEC_ONLY: u32 = 1 << 30;

/// Where a loaded policy came from.
///
/// Reported at startup, because "policy loaded: 11 file rules" looks identical
/// whether those rules are the operator's or the embedded default that happened
/// to apply when `./policy.yaml` was not where they thought. Three sources fall
/// back to each other silently, and running from a different directory used to
/// change the policy with nothing said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// `--policy <path>`.
    Explicit(std::path::PathBuf),
    /// `./policy.yaml`, found by falling back.
    WorkingDirectory(std::path::PathBuf),
    /// The policy compiled into the binary — nothing on disk applied.
    Embedded,
}

impl PolicySource {
    /// The file this came from, if any. `None` for the embedded default, which
    /// is the one source nothing can tamper with.
    pub fn path(&self) -> Option<&Path> {
        match self {
            PolicySource::Explicit(p) | PolicySource::WorkingDirectory(p) => Some(p),
            PolicySource::Embedded => None,
        }
    }
}

impl fmt::Display for PolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicySource::Explicit(p) => write!(f, "{}", p.display()),
            PolicySource::WorkingDirectory(p) => {
                write!(f, "./{} (found by falling back)", p.display())
            }
            PolicySource::Embedded => write!(f, "the built-in default (no policy file was read)"),
        }
    }
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
        Loader::new().load(path)
    }

    /// Parse with the system DNS resolver (what the binary uses).
    pub fn from_yaml_str(text: &str) -> Result<Policy> {
        Loader::new().from_str(text)
    }

    /// Parse with a custom DNS resolver and no identity resolution — the shape
    /// most tests want.
    pub fn from_yaml_str_with(text: &str, resolve: Resolver<'_>) -> Result<Policy> {
        Loader::offline().resolver(resolve).from_str(text)
    }

    fn compile(
        text: &str,
        resolve: Resolver<'_>,
        stat: identity::Stat<'_>,
        base: &AnchorBase,
    ) -> Result<Policy> {
        let raw: RawPolicy = serde_yaml::from_str(text).context("invalid policy YAML")?;
        if let Some(v) = raw.version {
            if v != SCHEMA_VERSION {
                anyhow::bail!(
                    "policy `version: {v}` is not supported by this build (expected \
                     {SCHEMA_VERSION}) — upgrade wardyn or drop the version key"
                );
            }
        }

        let mut anchors = Vec::new();
        let mut unresolved_anchors = Vec::new();
        let files = compile_rules(
            raw.files,
            true,
            false,
            base,
            stat,
            &mut anchors,
            &mut unresolved_anchors,
        )
        .context("in `files:`")?;
        let exec = compile_rules(
            raw.exec,
            false,
            true,
            base,
            stat,
            &mut anchors,
            &mut unresolved_anchors,
        )
        .context("in `exec:`")?;

        // Network: cidr rules compile directly; domain rules resolve (best effort)
        // at load time, expanding to one Ip rule per resolved address, preserving
        // order.
        let mut network = Vec::new();
        let mut unresolved_domains = Vec::new();
        let mut domain_specs: Vec<DomainSpec> = Vec::new();
        // Every rule's position in the file, static or domain-derived, so a
        // precedence tie resolves the same way after the two are split apart.
        for (order, r) in raw.network.into_iter().enumerate() {
            let suffix = match (r.proto, r.port) {
                (Some(t), Some(p)) => format!(" {} port {p}", t.as_str()),
                (Some(t), None) => format!(" {}", t.as_str()),
                (None, Some(p)) => format!(" port {p}"),
                (None, None) => String::new(),
            };
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
                        label: format!("cidr:{cidr}{suffix}"),
                        which,
                        port: r.port,
                        proto: r.proto,
                        action: r.action,
                        order,
                    });
                }
                // Kept as a spec, not as the addresses it happens to resolve
                // to right now — those are re-resolved for the life of the run.
                (None, Some(domain)) => {
                    if resolve(domain).is_empty() {
                        unresolved_domains.push(domain.clone());
                    }
                    domain_specs.push(DomainSpec {
                        domain: domain.clone(),
                        port: r.port,
                        proto: r.proto,
                        action: r.action,
                        label: format!("domain:{domain}{suffix}"),
                        order,
                    });
                }
                // `port:` on its own means "this port, anywhere" — the most
                // useful port rule there is ("never SMTP"). It covers BOTH
                // families: a v4-only reading would leave the same port open
                // over IPv6, which is the exact shape of the hole the `::/0`
                // rule had to be added for.
                (None, None) => {
                    if r.port.is_none() && r.proto.is_none() {
                        anyhow::bail!("network rule needs `cidr`, `domain`, `port`, or `proto`");
                    }
                    let label = match (r.proto, r.port) {
                        (Some(t), Some(p)) => format!("{}:{p}", t.as_str()),
                        (Some(t), None) => format!("proto:{}", t.as_str()),
                        (None, Some(p)) => format!("port:{p}"),
                        (None, None) => unreachable!("guarded above"),
                    };
                    for which in [
                        NetMatch::V4Cidr("0.0.0.0/0".parse().expect("valid")),
                        NetMatch::V6Cidr("::/0".parse().expect("valid")),
                    ] {
                        network.push(NetRule {
                            label: label.clone(),
                            which,
                            port: r.port,
                            proto: r.proto,
                            action: r.action,
                            order,
                        });
                    }
                }
            }
        }

        // Compile the kernel-side matcher once, from the same rules, so the
        // feed and the LSM hook can never drift apart. Only `match:` rules
        // contribute names; a `path:` rule deliberately does not, because it
        // means "this object", and turning it into a basename would silently
        // widen it back into the thing it exists to replace.
        let mut kern_names = BTreeMap::new();
        let mut kern_dirs = BTreeMap::new();
        let mut kern_pairs = BTreeMap::new();
        let mut kern_dir_pairs = BTreeMap::new();
        for r in &files {
            if r.action != Action::Block || !matches!(r.matcher, Matcher::Glob(_)) {
                continue;
            }
            let Some(seg) = file_seg(&r.pattern) else {
                continue;
            };
            let mask = r.access.mask();
            match (seg.parent, seg.is_dir) {
                (Some(p), true) => merge_mask(
                    &mut kern_dir_pairs,
                    (p.to_string(), seg.name.to_string()),
                    mask,
                ),
                (Some(p), false) => {
                    merge_mask(&mut kern_pairs, (p.to_string(), seg.name.to_string()), mask)
                }
                (None, true) => merge_mask(&mut kern_dirs, seg.name.to_string(), mask),
                (None, false) => merge_mask(&mut kern_names, seg.name.to_string(), mask),
            }
        }
        let mut kern_execs = BTreeMap::new();
        for r in &exec {
            if r.action != Action::Block || !matches!(r.matcher, Matcher::Glob(_)) {
                continue;
            }
            if let Some(seg) = last_segment(&r.pattern).filter(|s| name_key(s).is_some()) {
                merge_mask(&mut kern_execs, seg.to_string(), r.access.mask());
            }
        }

        // Resolved the same way `path:` rules are, so `~` means the agent's home
        // in both and a relative path means the directory wardyn was launched
        // in. An entry that cannot be resolved is kept with `path: None` rather
        // than dropped: a containment allowlist missing an entry is how an agent
        // fails to start with an error nobody traces back to the policy.
        let allow_paths: Vec<AllowPath> = raw
            .allow_paths
            .into_iter()
            .map(|a| AllowPath {
                path: base.expand(&a.path),
                raw: a.path,
                rights: a.rights,
            })
            .collect();

        // The first resolution happens here, through the same path every later
        // one takes — so the load-time set and a refreshed set can never be
        // built differently.
        let domains = DomainSet {
            specs: domain_specs,
            ..Default::default()
        };
        domains.refresh(resolve);

        Ok(Policy {
            fingerprint: crate::overrides::fingerprint(text),
            default_action: raw.default_action,
            files,
            exec,
            network,
            kern_names,
            kern_dirs,
            kern_pairs,
            kern_dir_pairs,
            kern_execs,
            anchors,
            unresolved_anchors,
            unresolved_domains,
            domains,
            allow_paths,
            source: PolicySource::Embedded,
            source_text: text.to_string(),
        })
    }

    /// Every network rule — the static ones and whatever the `domain:` rules
    /// resolve to right now — in policy order.
    ///
    /// Cloned rather than borrowed: the domain half lives behind a lock that a
    /// refresh may take at any moment, and holding a read guard across the
    /// callers (which populate kernel maps and format explanations) would let a
    /// slow one block the resolver. These callers run at load and on refresh,
    /// never per event.
    fn all_net_rules(&self) -> Vec<NetRule> {
        let mut all = self.network.clone();
        all.extend(self.domains.snapshot());
        all.sort_by_key(|r| r.order);
        all
    }

    /// Re-resolve every `domain:` rule and report what moved.
    ///
    /// The caller applies the difference to the kernel tries; the userspace
    /// mirror picks it up on its own, because both read the same live set. An
    /// empty result means the answer did not move, which is the common case.
    pub fn refresh_domains(&self, resolve: Resolver<'_>) -> DomainRefresh {
        self.domains.refresh(resolve)
    }

    /// Where this policy came from.
    pub fn source(&self) -> &PolicySource {
        &self.source
    }

    /// The text this policy was compiled from — the input a stored approval is
    /// fingerprinted against.
    pub fn source_text(&self) -> &str {
        &self.source_text
    }

    /// The Landlock hierarchies this policy grants. Empty means the policy asked
    /// for no containment, and wardyn must not invent one — an empty allowlist
    /// denies everything, including the agent's own loader.
    pub fn allow_paths(&self) -> &[AllowPath] {
        &self.allow_paths
    }

    /// Would Landlock refuse this open/exec, given the containment boundary?
    ///
    /// Returns the reason, or `None` when the boundary permits it — or when
    /// there is no boundary, or when the observed path is not something this can
    /// judge.
    ///
    /// ## Why this is a prediction, and a weaker one than the rest
    ///
    /// Every other mirror in here can be corrected: the eBPF hooks report their
    /// own denials, so a wrong guess is overwritten by the kernel's own event.
    /// Landlock reports nothing to wardyn — it is a different LSM, and its
    /// refusal is invisible to our hooks. Without this the feed showed `ok` for
    /// an open the agent had just been refused, which is the exact failure the
    /// whole mirror exists to prevent.
    ///
    /// So it predicts, and it is conservative about it: a **relative** path is
    /// not judged at all, because resolving it here would mean guessing the
    /// agent's working directory, and a symlink is judged on the name the
    /// syscall passed rather than the object Landlock resolved. Both can be
    /// wrong in the permissive direction, never the alarming one — this reports
    /// a denial only when the observed path is plainly outside every granted
    /// hierarchy.
    pub fn containment_denies(&self, path: &str, requested: u32) -> Option<String> {
        if self.allow_paths.is_empty() || !path.starts_with('/') {
            return None;
        }
        let p = Path::new(path);
        let mut best: Option<&AllowPath> = None;
        for a in &self.allow_paths {
            let Some(root) = a.path.as_ref() else {
                continue;
            };
            if p.starts_with(root) {
                // The most specific hierarchy wins, matching Landlock: a nested
                // grant overrides the one it sits inside.
                let deeper = best
                    .and_then(|b| b.path.as_ref())
                    .is_none_or(|b| root.components().count() > b.components().count());
                if deeper {
                    best = Some(a);
                }
            }
        }
        let Some(a) = best else {
            return Some("not listed".to_string());
        };
        // Inside a hierarchy, but perhaps without the right this asked for.
        // `requested` is the access the open wanted; an exec passes `EXEC_ONLY`.
        let need_write = requested & fmode::WRITE != 0;
        let need_read = requested & fmode::READ != 0;
        let need_exec = requested == EXEC_ONLY;
        let has = |r: Right| a.rights.contains(&r);
        if need_exec && !has(Right::Exec) {
            return Some(format!("{} has no exec", a.raw));
        }
        if need_write && !has(Right::Write) {
            return Some(format!("{} has no write", a.raw));
        }
        if need_read && !need_exec && !has(Right::Read) {
            return Some(format!("{} has no read", a.raw));
        }
        None
    }

    /// Whether this policy has anything to re-resolve at all. A policy with no
    /// `domain:` rules should not pay for a timer.
    pub fn has_domain_specs(&self) -> bool {
        !self.domains.specs.is_empty()
    }

    pub fn summary(&self) -> String {
        format!(
            "{} file rule(s), {} network rule(s), {} exec rule(s), default={}",
            self.files.len(),
            self.all_net_rules().len(),
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
        self.all_net_rules()
            .iter()
            .rev()
            // A rule that names a port or a protocol lives in one of the three
            // more specific tries; leaving it here as well would make
            // `{ cidr: "0.0.0.0/0", port: 25, action: block }` read as a
            // deny-all for every port, and `{ proto: udp, action: block }` as a
            // deny-all for every transport.
            .filter(|r| r.tier() == (false, false))
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

    /// Port-qualified IPv4 rules for `NET_PORT_RULES`, as
    /// `(prefix_len, key, action)`.
    ///
    /// The prefix covers the whole 16-bit port plus however much of the address
    /// the rule constrained, so two rules for different ports can never match
    /// each other and, within one port, the more specific address still wins.
    pub fn port_entries(&self) -> Vec<(u32, PortKey4, u32)> {
        self.all_net_rules()
            .iter()
            .rev()
            .filter_map(|r| {
                let port = r.port.filter(|_| r.proto.is_none())?;
                let (addr_bits, octets) = match &r.which {
                    NetMatch::V4Cidr(net) => (net.prefix_len() as u32, net.network().octets()),
                    NetMatch::V4Ip(a) => (32u32, a.octets()),
                    _ => return None,
                };
                Some((
                    PORT_BITS + addr_bits,
                    PortKey4::new(port, octets),
                    r.action.code(),
                ))
            })
            .collect()
    }

    /// Same, for IPv6.
    pub fn port_entries6(&self) -> Vec<(u32, PortKey6, u32)> {
        self.all_net_rules()
            .iter()
            .rev()
            .filter_map(|r| {
                let port = r.port.filter(|_| r.proto.is_none())?;
                let (addr_bits, octets) = match &r.which {
                    NetMatch::V6Cidr(net) => (net.prefix_len() as u32, net.network().octets()),
                    NetMatch::V6Ip(a) => (128u32, a.octets()),
                    _ => return None,
                };
                Some((
                    PORT_BITS + addr_bits,
                    PortKey6::new(port, octets),
                    r.action.code(),
                ))
            })
            .collect()
    }

    /// Whether any rule names a port — i.e. whether the kernel needs to consult
    /// the port tries at all.
    pub fn has_port_rules(&self) -> bool {
        self.all_net_rules()
            .iter()
            .any(|r| r.tier() == (false, true))
    }

    /// Whether any rule names a protocol, for the same reason.
    pub fn has_proto_rules(&self) -> bool {
        self.all_net_rules().iter().any(|r| r.proto.is_some())
    }

    /// Rules naming a protocol AND a port, for `NET_PROTO_PORT_RULES`.
    ///
    /// The prefix covers the protocol and port bits in full and only the address
    /// is prefixed — a rule reaches this trie by naming both, so neither leading
    /// field is ever a don't-care, and the address keeps exactly the meaning it
    /// has in the tries with no protocol at all.
    pub fn proto_port_entries(&self) -> Vec<(u32, ProtoPortKey4, u32)> {
        self.all_net_rules()
            .iter()
            .rev()
            .filter_map(|r| {
                let (proto, port) = (r.proto?, r.port?);
                let (addr_bits, octets) = match &r.which {
                    NetMatch::V4Cidr(net) => (net.prefix_len() as u32, net.network().octets()),
                    NetMatch::V4Ip(a) => (32u32, a.octets()),
                    _ => return None,
                };
                Some((
                    PROTO_BITS + PORT_BITS + addr_bits,
                    ProtoPortKey4::new(proto.number(), port, octets),
                    r.action.code(),
                ))
            })
            .collect()
    }

    /// Same, for IPv6.
    pub fn proto_port_entries6(&self) -> Vec<(u32, ProtoPortKey6, u32)> {
        self.all_net_rules()
            .iter()
            .rev()
            .filter_map(|r| {
                let (proto, port) = (r.proto?, r.port?);
                let (addr_bits, octets) = match &r.which {
                    NetMatch::V6Cidr(net) => (net.prefix_len() as u32, net.network().octets()),
                    NetMatch::V6Ip(a) => (128u32, a.octets()),
                    _ => return None,
                };
                Some((
                    PROTO_BITS + PORT_BITS + addr_bits,
                    ProtoPortKey6::new(proto.number(), port, octets),
                    r.action.code(),
                ))
            })
            .collect()
    }

    /// Rules naming a protocol but no port, for `NET_PROTO_RULES`.
    pub fn proto_entries(&self) -> Vec<(u32, ProtoKey4, u32)> {
        self.all_net_rules()
            .iter()
            .rev()
            .filter(|r| r.port.is_none())
            .filter_map(|r| {
                let proto = r.proto?;
                let (addr_bits, octets) = match &r.which {
                    NetMatch::V4Cidr(net) => (net.prefix_len() as u32, net.network().octets()),
                    NetMatch::V4Ip(a) => (32u32, a.octets()),
                    _ => return None,
                };
                Some((
                    PROTO_BITS + addr_bits,
                    ProtoKey4::new(proto.number(), octets),
                    r.action.code(),
                ))
            })
            .collect()
    }

    /// Same, for IPv6.
    pub fn proto_entries6(&self) -> Vec<(u32, ProtoKey6, u32)> {
        self.all_net_rules()
            .iter()
            .rev()
            .filter(|r| r.port.is_none())
            .filter_map(|r| {
                let proto = r.proto?;
                let (addr_bits, octets) = match &r.which {
                    NetMatch::V6Cidr(net) => (net.prefix_len() as u32, net.network().octets()),
                    NetMatch::V6Ip(a) => (128u32, a.octets()),
                    _ => return None,
                };
                Some((
                    PROTO_BITS + addr_bits,
                    ProtoKey6::new(proto.number(), octets),
                    r.action.code(),
                ))
            })
            .collect()
    }

    /// IPv6 network rules as `(prefix_len, address bytes (network order), action
    /// code)` for the v6 LPM trie.
    pub fn net_entries6(&self) -> Vec<(u32, [u8; 16], u32)> {
        self.all_net_rules()
            .iter()
            .rev()
            .filter(|r| r.port.is_none())
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
    pub fn file_enforcement(&self) -> (Vec<NameEntry>, Vec<NameEntry>) {
        (keyed(&self.kern_names), keyed(&self.kern_dirs))
    }

    /// The two-component keys, `(files, directories)`, each entry as
    /// `(parent key, name key, access mask)` — the exact shape of one
    /// `BLOCK_PAIRS` / `BLOCK_DIR_PAIRS` entry.
    pub fn pair_enforcement(&self) -> (Vec<PairEntry>, Vec<PairEntry>) {
        (
            keyed_pairs(&self.kern_pairs),
            keyed_pairs(&self.kern_dir_pairs),
        )
    }

    /// Whether any rule compiled to a two-component key. Drives `CFG_PAIRS_ON`,
    /// so a policy with none pays no extra lookup per ancestor level.
    pub fn has_pair_rules(&self) -> bool {
        !self.kern_pairs.is_empty() || !self.kern_dir_pairs.is_empty()
    }

    /// Identity keys for `BLOCK_INODES` / `BLOCK_DIR_INODES` / `BLOCK_EXEC_INODES`,
    /// each with the access mask stored beside it.
    pub fn inode_enforcement(&self) -> InodeKeys {
        let mut out = InodeKeys::default();
        for a in &self.anchors {
            let entry = (a.key, a.access_mask);
            match (a.exec, a.kind) {
                (true, _) => out.execs.push(entry),
                (false, AnchorKind::Dir) => out.dirs.push(entry),
                (false, AnchorKind::File) => out.files.push(entry),
            }
        }
        out
    }

    /// Every resolved identity anchor, for `--dry-run` and startup reporting.
    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    /// Does any block rule name a `create`/`delete` access?
    ///
    /// Drives `CFG_LIFECYCLE_ON`. False leaves the five lifecycle hooks inert,
    /// which is both a hot-path saving and the compatibility guarantee: a policy
    /// that never mentions the axis cannot begin refusing an `rm` because of it.
    pub fn has_lifecycle_rules(&self) -> bool {
        self.files
            .iter()
            .any(|r| r.action == Action::Block && r.access.is_lifecycle())
    }

    /// Does any block rule narrow itself to reads or writes?
    ///
    /// Narrowing needs the kernel to read `file->f_mode`, which needs an offset
    /// resolved from BTF. When that is unavailable the rule still fires — it
    /// just covers every open, i.e. it is broader than written. Over-blocking is
    /// the safe direction, but it is not what the policy says, so startup has to
    /// be able to say so.
    pub fn uses_access_narrowing(&self) -> bool {
        self.files
            .iter()
            .any(|r| r.action == Action::Block && r.access != Access::Any)
    }

    /// `path:` block rules that resolved to nothing — they enforce nothing.
    pub fn unresolved_anchors(&self) -> &[UnresolvedAnchor] {
        &self.unresolved_anchors
    }

    /// The anchor a kernel identity denial refers to, so a `DENY_FILE` carrying
    /// only `(dev, ino)` can be rendered as the path the operator wrote in the
    /// policy — which is the whole story: *this* is the file you named, whatever
    /// it is called now.
    pub fn anchor_for(&self, key: &InodeKey) -> Option<&Anchor> {
        self.anchors.iter().find(|a| a.key == *key)
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
    ///
    /// `requested` is the access the open asked for ([`fmode`] bits, derived
    /// from the syscall's flags). A key whose rule only covers reads must not
    /// predict a denial for a write-only open — the kernel would not have made
    /// one, and a claimed denial that never happened is the failure mode this
    /// whole mirror exists to avoid.
    ///
    /// Identity keys are deliberately absent here: this mirror only has the
    /// path string, and the point of an identity rule is that the path string
    /// is not what decides. Those denials arrive as kernel `DENY_FILE` events.
    pub fn kernel_file_denial(&self, path: &str, requested: u32) -> Option<DenialKey> {
        let hit = |m: &BTreeMap<String, u8>, k: &str| -> bool {
            m.get(k)
                .is_some_and(|&mask| fmode::matches(mask, requested))
        };
        let hit_pair = |m: &BTreeMap<(String, String), u8>, p: &str, n: &str| -> bool {
            m.get(&(p.to_string(), n.to_string()))
                .is_some_and(|&mask| fmode::matches(mask, requested))
        };
        // Nearest first: `segs[0]` is the file, `segs[1]` its parent, and so
        // on — the same order the kernel's `d_parent` walk produces.
        let segs: Vec<&str> = path.rsplit('/').filter(|s| !s.is_empty()).collect();
        let name = *segs.first()?;
        // The pair before the bare name, exactly as the hook does it.
        if let Some(parent) = segs.get(1) {
            if hit_pair(&self.kern_pairs, parent, name) {
                return Some(DenialKey::FilePair {
                    parent: parent.to_string(),
                    name: name.to_string(),
                });
            }
        }
        if hit(&self.kern_names, name) {
            return Some(DenialKey::FileName(name.to_string()));
        }
        // Ancestors, bounded exactly like the kernel walk. At `level`, `dir` is
        // `segs[level + 1]` and the name below it is `segs[level]`; the pair
        // check starts at level 1 because at level 0 that lower name is the
        // file, and `(parent, file)` was consulted above in the file map.
        for level in 0..MAX_DIR_WALK {
            let Some(&dir) = segs.get(level + 1) else {
                break;
            };
            if level > 0 && hit_pair(&self.kern_dir_pairs, dir, segs[level]) {
                return Some(DenialKey::DirPair {
                    parent: dir.to_string(),
                    name: segs[level].to_string(),
                });
            }
            if hit(&self.kern_dirs, dir) {
                return Some(DenialKey::FileDir(dir.to_string()));
            }
        }
        None
    }

    /// Same, for the LSM `bprm_check_security` hook (exec basenames).
    pub fn kernel_exec_denial(&self, path: &str) -> Option<DenialKey> {
        let name = last_segment(path)?;
        if self.kern_execs.contains_key(name) {
            return Some(DenialKey::Exec(name.to_string()));
        }
        None
    }

    /// `block` rules whose kernel key is BROADER than the glob that produced it,
    /// as `(pattern, what the kernel will really deny)`. Only `**/name` and
    /// `**/dir/**` survive the reduction intact; anything more specific
    /// (`/etc/shadow`, `**/.aws/credentials`) loses its directory context and
    /// over-blocks. Startup prints these so the over-reach is never a surprise.
    /// A `path:` rule is never over-broad — it names exactly one object — so
    /// only glob rules are considered here and in [`Self::shadowed_by_kernel`].
    pub fn overbroad_block_keys(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for r in &self.files {
            if r.action != Action::Block || !r.is_glob() {
                continue;
            }
            if let Some(seg) = file_seg(&r.pattern) {
                // Exactly what the kernel key covers, phrased so the gap between
                // it and the glob is what the reader sees. A pair is still a
                // suffix match — `/etc/shadow` compiles to `etc/shadow` at ANY
                // depth — and saying "under a dir named `etc`" is what keeps
                // that honest without pretending the old `shadow` reach.
                let reach = match (seg.parent, seg.is_dir) {
                    (Some(p), true) => format!(
                        "any file anywhere under a dir named `{}` that sits in a dir named `{p}`",
                        seg.name
                    ),
                    (Some(p), false) => {
                        format!(
                            "any file named `{}` directly under a dir named `{p}`",
                            seg.name
                        )
                    }
                    (None, true) => format!("any file anywhere under a dir named `{}`", seg.name),
                    (None, false) => format!("any file named `{}`", seg.name),
                };
                if r.pattern != seg.exact_glob() {
                    out.push((r.pattern.clone(), reach));
                }
            }
        }
        for r in &self.exec {
            if r.action != Action::Block || !r.is_glob() {
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
        let empty = BTreeMap::new();
        let no_pairs = BTreeMap::new();
        let mut check = |rules: &[PathRule],
                         names: &BTreeMap<String, u8>,
                         dirs: &BTreeMap<String, u8>,
                         pairs: &BTreeMap<(String, String), u8>,
                         dir_pairs: &BTreeMap<(String, String), u8>| {
            for (i, r) in rules.iter().enumerate() {
                if r.action == Action::Block || !r.is_glob() {
                    continue;
                }
                // Does a *later* block rule's key cover paths this rule matches?
                let later_blocks = rules[i + 1..].iter().any(|b| b.action == Action::Block);
                if !later_blocks {
                    continue;
                }
                // The most specific key first, so the report names the one the
                // kernel would actually fire.
                if let Some(seg) = file_seg(&r.pattern) {
                    if let Some(p) = seg.parent {
                        if pairs.contains_key(&(p.to_string(), seg.name.to_string())) {
                            out.push((r.pattern.clone(), format!("name={}", seg.label())));
                            continue;
                        }
                    }
                }
                if let Some(seg) = last_segment(&r.pattern) {
                    if names.contains_key(seg) {
                        out.push((r.pattern.clone(), format!("name={seg}")));
                        continue;
                    }
                }
                // Any adjacent pair of literal segments that is a blocked dir
                // pair, or any single literal segment that is a blocked dir
                // name, makes the whole subtree denied wherever it appears.
                let literal: Vec<&str> = r.pattern.split('/').filter(|s| !s.is_empty()).collect();
                if let Some(w) = literal
                    .windows(2)
                    .find(|w| dir_pairs.contains_key(&(w[0].to_string(), w[1].to_string())))
                {
                    out.push((r.pattern.clone(), format!("dir={}/{}", w[0], w[1])));
                    continue;
                }
                if let Some(seg) = literal.iter().find(|s| dirs.contains_key(**s)) {
                    out.push((r.pattern.clone(), format!("dir={seg}")));
                }
            }
        };
        check(
            &self.files,
            &self.kern_names,
            &self.kern_dirs,
            &self.kern_pairs,
            &self.kern_dir_pairs,
        );
        check(&self.exec, &self.kern_execs, &empty, &no_pairs, &no_pairs);
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
            self.all_net_rules().iter().any(|r| {
                // A port-qualified `0.0.0.0/0` denies one port, not all egress.
                r.action == Action::Block
                    && r.port.is_none()
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
                 It is re-resolved every minute and will start enforcing if the name comes \
                 back — but prefer an explicit `cidr:` for anything security-critical."
            ));
        }
        if !self.unresolved_domains.is_empty() || self.has_domain_rules() {
            out.push(
                "`domain:` rules are re-resolved every 60s, so a CDN that moves is followed \
                 within a minute — but only between refreshes, and only for names the system \
                 resolver answers the same way the agent's does. A `block` by name is still \
                 defeated by anyone who controls the name. Use `cidr:` where it has to be sound."
                    .to_string(),
            );
        }
        out
    }

    fn has_domain_rules(&self) -> bool {
        self.has_domain_specs()
    }

    /// A full, plain-language account of what this policy will actually do in
    /// the kernel — printed by `--dry-run`, which validates a policy without
    /// root or eBPF. Written because every gap below used to be discoverable
    /// only by reading an audit log after the fact.
    pub fn explain(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "policy: {}", self.summary());
        // Stored approvals are keyed by this. An operator editing the overrides
        // file by hand has no other way to learn it, and an approval filed under
        // the wrong fingerprint is simply ignored — silently, since being
        // ignored is the safe direction and there is nothing to warn about.
        let _ = writeln!(
            s,
            "fingerprint: {} (stored approvals are keyed by this; it changes with the policy text)",
            crate::overrides::fingerprint(&self.source_text)
        );

        // Containment first: it is the outer boundary, and every block key below
        // only narrows what is left inside it. Reading them the other way round
        // suggests the block rules are the whole story.
        if !self.allow_paths.is_empty() {
            let _ = writeln!(
                s,
                "\ncontained by Landlock — the agent reaches ONLY these, whatever the rules below \
                 say:"
            );
            for a in &self.allow_paths {
                let rights = a
                    .rights
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join("+");
                match &a.path {
                    Some(p) => {
                        let shown = p.display().to_string();
                        let _ = writeln!(s, "  path  {shown:<29} {rights}");
                    }
                    None => {
                        let _ = writeln!(
                            s,
                            "  path  {:<29} UNRESOLVED — wardyn will refuse to start",
                            a.raw
                        );
                    }
                }
            }
            let _ = writeln!(
                s,
                "\nnote: this is an ALLOWLIST — anything not listed is denied, including paths the\
                 \n      agent needs but nobody thought of (its loader, /dev/null, its own \
                 script).\n      A missing entry looks like a broken agent, not like a policy \
                 gap. Landlock\n      is applied to the child before exec and cannot be undone."
            );
        }

        let _ = writeln!(s, "\nkernel-enforced under --enforce:");
        for (n, &mask) in &self.kern_names {
            let _ = writeln!(
                s,
                "  file  name={n:<24} denies {} ANY file named `{n}`",
                mask_verbs(mask)
            );
        }
        for (d, &mask) in &self.kern_dirs {
            let _ = writeln!(
                s,
                "  file  dir={d:<25} denies {} ANY file under a directory named `{d}` (any depth)",
                mask_verbs(mask)
            );
        }
        // Two-component keys, where the operator can see that `/etc/shadow`
        // no longer means every `shadow` — and exactly what it does mean.
        for ((p, n), &mask) in &self.kern_pairs {
            let key = format!("name={p}/{n}");
            let _ = writeln!(
                s,
                "  file  {key:<29} denies {} ANY file named `{n}` directly under a dir named `{p}`",
                mask_verbs(mask)
            );
        }
        for ((p, n), &mask) in &self.kern_dir_pairs {
            let key = format!("dir={p}/{n}");
            let _ = writeln!(
                s,
                "  file  {key:<29} denies {} ANY file under a dir named `{n}` that sits in `{p}` (any depth)",
                mask_verbs(mask)
            );
        }
        for e in self.kern_execs.keys() {
            let _ = writeln!(
                s,
                "  exec  name={e:<24} denies executing ANY program named `{e}`"
            );
        }
        // Identity keys, which is where the operator can see that a rule follows
        // the object rather than the label — and see the exact object it landed
        // on, so a mis-resolved `~` or a wrong working directory is visible here
        // rather than after an incident.
        for a in &self.anchors {
            let axis = if a.exec { "exec" } else { "file" };
            let _ = writeln!(s, "  {axis}  {:<29} {}", a.to_string(), a.blast_radius());
        }
        // Deduplicated: a bare `port:`/`proto:` rule is compiled into one entry
        // per address family, and a rule listed twice reads as two rules.
        let all = self.all_net_rules();
        let blocked = |tier: (bool, bool)| -> Vec<&str> {
            let mut out: Vec<&str> = Vec::new();
            for r in &all {
                if r.action == Action::Block && r.tier() == tier && !out.contains(&r.label.as_str())
                {
                    out.push(&r.label);
                }
            }
            out
        };
        // Listed in the order the kernel consults them, because that order IS
        // the semantics: reading them in policy order would suggest a
        // first-match rule that does not exist.
        let tiers = [
            ((true, true), "blocked by protocol+port"),
            ((false, true), "blocked by port"),
            ((true, false), "blocked by protocol"),
            ((false, false), "blocked"),
        ];
        let mut any = false;
        for (tier, label) in tiers {
            let rules = blocked(tier);
            if !rules.is_empty() {
                any = true;
                let _ = writeln!(s, "  net   {label}: {}", rules.join(", "));
            }
        }
        if !any {
            let _ = writeln!(s, "  net   (no block rules — no egress is denied)");
        }
        // The one thing about these rules that cannot be inferred from the list.
        if self.has_port_rules() || self.has_proto_rules() {
            let _ = writeln!(
                s,
                "\nnote: rules are consulted MOST SPECIFIC FIRST — protocol+port, then port, then\
                 \n      protocol, then address — whatever their address prefixes. \
                 `{{ port: 25,\n      action: block }}` denies SMTP even to a network another rule \
                 allows in full, and\n      `{{ proto: udp, action: block }}` denies UDP there too."
            );
        }
        // A protocol rule enforces nothing on a connect whose protocol the feed
        // could not read, and the feed reads none of them — so the row an
        // operator sees may say `ok` for a connection the kernel then refuses.
        // The kernel's own DENY_NET event still reports it; saying so here is
        // what keeps that from looking like a contradiction.
        if self.has_proto_rules() {
            let _ = writeln!(
                s,
                "      A `proto:` rule is enforced by the kernel but NOT predicted in the feed: \
                 the\n      connect tracepoint sees a sockaddr, not a socket, so it has no \
                 protocol to\n      match on. Such a denial arrives as a kernel-reported row \
                 instead."
            );
        }
        if self.kern_names.is_empty()
            && self.kern_dirs.is_empty()
            && self.kern_pairs.is_empty()
            && self.kern_dir_pairs.is_empty()
            && self.kern_execs.is_empty()
            && self.anchors.is_empty()
        {
            let _ = writeln!(
                s,
                "  file/exec: NOTHING is kernel-enforced (no block rule reduces to a name, a dir, \
                 or a resolved object)"
            );
        }

        if !self.unresolved_anchors.is_empty() {
            let _ = writeln!(
                s,
                "\n`path:` rules that resolved to NOTHING (they enforce nothing):"
            );
            for u in &self.unresolved_anchors {
                let _ = writeln!(s, "  {}  ->  {} — {}", u.rule, u.path.display(), u.reason);
            }
        }

        // A name-form rule (`**/.aws`) denies opening the entry itself; it does
        // not cover the files inside a directory of that name — very easy to
        // write believing the opposite, so state it per rule rather than guess.
        let name_only: Vec<&String> = self
            .kern_names
            .keys()
            .filter(|n| !self.kern_dirs.contains_key(*n))
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
    /// Glob rules only: an unenforceable `path:` rule has a different cause (it
    /// resolved to nothing) and its own report, and listing it here as well —
    /// under a heading that explains it as a glob problem — would be two wrong
    /// answers where one right one exists.
    pub fn observe_only_blocks(&self) -> Vec<String> {
        self.files
            .iter()
            .chain(&self.exec)
            .filter(|r| r.action == Action::Block && !r.enforceable && r.is_glob())
            .map(|r| r.pattern.clone())
            .collect()
    }

    /// Exec block rules compiled to exact basenames for the LSM bprm_check matcher.
    pub fn exec_enforcement(&self) -> Vec<NameEntry> {
        keyed(&self.kern_execs)
    }

    pub fn eval_file(&self, path: &str) -> Verdict {
        eval_path(&self.files, path, self.default_action)
    }

    pub fn eval_exec(&self, path: &str) -> Verdict {
        eval_path(&self.exec, path, self.default_action)
    }

    /// The verdict for a connect whose transport is not known.
    ///
    /// That is every *observed* connect: the `sys_enter` tracepoint sees a
    /// `sockaddr`, not a socket, so it cannot report the protocol and does not
    /// guess one. See [`Self::eval_connect_proto`] for what the mirror does with
    /// that.
    pub fn eval_connect(&self, ip: Ipv4Addr, dport: u16) -> Verdict {
        self.eval_connect_proto(ip, dport, None)
    }

    pub fn eval_connect6(&self, ip: Ipv6Addr, dport: u16) -> Verdict {
        self.eval_connect6_proto(ip, dport, None)
    }

    /// The verdict for a connect on a known transport.
    ///
    /// `None` means "not known", and the mirror then evaluates **both**
    /// transports. Where they agree, the answer is certain and nothing about the
    /// prediction changes. Where they disagree, the policy has made the outcome
    /// depend on something the feed cannot see, and the verdict comes back as
    /// the least severe of the two with `enforceable: false`.
    ///
    /// Neither half of that is arbitrary. Simply skipping the protocol tiers
    /// looks safe and is not: a proto-qualified *allow* outranks a lower-tier
    /// block, so ignoring it makes the mirror claim a denial the kernel never
    /// made — which is the failure this mirror exists to prevent, and which the
    /// e2e suite caught doing exactly that. Leaning to the permissive side
    /// instead costs nothing, because a denial the mirror misses still reaches
    /// the feed: the cgroup hook reports its own decision, exactly as it does
    /// for an identity match no path string could have predicted.
    pub fn eval_connect_proto(&self, ip: Ipv4Addr, dport: u16, proto: Option<Proto>) -> Verdict {
        self.net_verdict(|r| r.v4_prefix(ip), dport, proto)
    }

    pub fn eval_connect6_proto(&self, ip: Ipv6Addr, dport: u16, proto: Option<Proto>) -> Verdict {
        self.net_verdict(|r| r.v6_prefix(ip), dport, proto)
    }

    /// Pick the verdict for a connect, mirroring what the kernel will do.
    ///
    /// Four passes, and the order between them is the one thing about these
    /// rules that has to be stated rather than guessed:
    ///
    /// 1. **Rules naming this protocol AND this port**, most-specific address first.
    /// 2. **Rules naming this port** (any protocol), most-specific address first.
    /// 3. **Rules naming this protocol** (any port), most-specific address first.
    /// 4. **Rules naming neither**, most-specific address first.
    /// 5. `default_action`.
    ///
    /// So a rule that names a dimension beats one that does not, whatever their
    /// address prefixes — `{ port: 25, action: block }` denies SMTP even to a
    /// `/8` the policy otherwise allows, and `{ proto: udp, action: block }`
    /// denies UDP there too. That is what the kernel does, because each tier is
    /// its own LPM trie and the hook consults them in this order; it is also
    /// what people mean when they write "never SMTP" or "no UDP at all".
    ///
    /// Letting prefix length decide *across* dimensions instead would make
    /// `{ proto: udp, action: block }` a `/0` rule that any `/8` allow outranks,
    /// so the most useful protocol rule there is would quietly not mean what it
    /// says. Within each pass it is longest-prefix-match, not first-match,
    /// because the kernel decides with an LPM trie; ties keep the earliest rule.
    fn net_verdict(
        &self,
        prefix_of: impl Fn(&NetRule) -> Option<u8>,
        dport: u16,
        proto: Option<Proto>,
    ) -> Verdict {
        // A known transport, or a policy with nothing protocol-dependent in it:
        // one pass, and the answer is exact.
        if proto.is_some() || !self.has_proto_rules() {
            return self.net_verdict_for(&prefix_of, dport, proto);
        }
        // Otherwise ask both transports. Agreement means the protocol never
        // mattered here, so the prediction is as good as it ever was.
        let tcp = self.net_verdict_for(&prefix_of, dport, Some(Proto::Tcp));
        let udp = self.net_verdict_for(&prefix_of, dport, Some(Proto::Udp));
        if tcp.action == udp.action {
            return tcp;
        }
        // Disagreement means the feed genuinely cannot say. Report the least
        // severe of the two and mark it unenforceable, so the row never asserts
        // a denial the kernel may not make; if the kernel does deny, its own
        // `DENY_NET` event says so, and that row is the authority.
        let (lenient, other) = if tcp.action.code() <= udp.action.code() {
            (tcp, udp)
        } else {
            (udp, tcp)
        };
        Verdict {
            action: lenient.action,
            rule: format!(
                "{} (transport-dependent: `{}` if the other protocol)",
                lenient.rule, other.rule
            ),
            enforceable: false,
        }
    }

    /// One pass of the four-tier match, for a single (possibly unknown) transport.
    fn net_verdict_for(
        &self,
        prefix_of: &impl Fn(&NetRule) -> Option<u8>,
        dport: u16,
        proto: Option<Proto>,
    ) -> Verdict {
        // One read guard for the whole match rather than a merged copy per
        // connect: this runs on every connect the mirror evaluates, and
        // cloning the rule set here would put an allocation on that path. The
        // guard is held only for this verdict; the refresh timer's write is a
        // once-a-minute event that waits behind it.
        let guard = self.domains.live.read().ok();
        let live: &[NetRule] = guard.as_ref().map(|g| g.as_slice()).unwrap_or(&[]);

        for tier in [(true, true), (false, true), (true, false), (false, false)] {
            // An unknown protocol matches no protocol rule.
            if tier.0 && proto.is_none() {
                continue;
            }
            let mut best: Option<(&NetRule, u8)> = None;
            // Static rules and the live domain rules are two collections, so
            // the chain is not in policy order — the tie-break reads `order`
            // instead of relying on iteration position, which is why the field
            // exists.
            for r in self.network.iter().chain(live.iter()) {
                if r.tier() != tier || !r.port_matches(dport) {
                    continue;
                }
                if r.proto.is_some() && r.proto != proto {
                    continue;
                }
                let Some(plen) = prefix_of(r) else {
                    continue;
                };
                // Longest prefix wins; a tie keeps the earliest rule, matching
                // the kernel trie (the entry lists insert the earliest rule
                // last, and LPM `insert` overwrites on collision).
                let better = match best {
                    None => true,
                    Some((b, bp)) => plen > bp || (plen == bp && r.order < b.order),
                };
                if better {
                    best = Some((r, plen));
                }
            }
            if let Some((r, _)) = best {
                return Verdict {
                    action: r.action,
                    rule: r.label.clone(),
                    enforceable: true,
                };
            }
        }
        Verdict {
            action: self.default_action,
            rule: "default".to_string(),
            enforceable: true,
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

/// Assemble a policy: where DNS comes from, where `stat` comes from, and what a
/// relative or `~` path is relative to.
///
/// A struct rather than more `from_yaml_str_*` overloads because identity
/// resolution needs three injectables, and every one of them touches the outside
/// world — a test that could not replace them would depend on the machine it
/// runs on.
pub struct Loader<'a> {
    resolve: Resolver<'a>,
    stat: identity::Stat<'a>,
    base: AnchorBase,
}

impl Default for Loader<'_> {
    fn default() -> Self {
        Loader::new()
    }
}

impl<'a> Loader<'a> {
    /// The real thing: system DNS, real `stat`, relative paths anchored at the
    /// current working directory.
    pub fn new() -> Self {
        Loader {
            resolve: &system_resolver,
            stat: &identity::system_stat,
            base: AnchorBase {
                cwd: std::env::current_dir().ok(),
                home: None,
            },
        }
    }

    /// Touches nothing outside the process: no DNS, no filesystem. What
    /// `--dry-run` and the tests want.
    pub fn offline() -> Self {
        Loader {
            resolve: &null_resolver,
            stat: &identity::null_stat,
            base: AnchorBase::default(),
        }
    }

    pub fn resolver(mut self, r: Resolver<'a>) -> Self {
        self.resolve = r;
        self
    }

    pub fn stat(mut self, s: identity::Stat<'a>) -> Self {
        self.stat = s;
        self
    }

    pub fn base(mut self, b: AnchorBase) -> Self {
        self.base = b;
        self
    }

    pub fn from_str(&self, text: &str) -> Result<Policy> {
        Policy::compile(text, self.resolve, self.stat, &self.base)
    }

    /// From an explicit path, else `./policy.yaml`, else the embedded default.
    pub fn load(&self, path: Option<&Path>) -> Result<Policy> {
        if let Some(p) = path {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading policy {}", p.display()))?;
            let mut policy = self
                .from_str(&text)
                .with_context(|| format!("parsing {}", p.display()))?;
            policy.source = PolicySource::Explicit(p.to_path_buf());
            return Ok(policy);
        }
        if let Ok(text) = std::fs::read_to_string("policy.yaml") {
            let mut policy = self.from_str(&text).context("parsing ./policy.yaml")?;
            policy.source = PolicySource::WorkingDirectory("policy.yaml".into());
            return Ok(policy);
        }
        self.from_str(DEFAULT_POLICY)
            .context("parsing embedded default policy")
    }
}

/// Compile one axis' rules. `dir_capable` files support the `**/dir/**`
/// parent-directory form; exec rules are basename-only.
#[allow(clippy::too_many_arguments)]
fn compile_rules(
    rules: Vec<PathRuleRaw>,
    dir_capable: bool,
    is_exec: bool,
    base: &AnchorBase,
    stat: identity::Stat<'_>,
    anchors: &mut Vec<Anchor>,
    unresolved: &mut Vec<UnresolvedAnchor>,
) -> Result<Vec<PathRule>> {
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        // An `exec:` rule compiles into `BLOCK_EXEC` / `BLOCK_EXEC_INODES`, and
        // the lifecycle hooks do not consult either — they match the *file*
        // maps. A `delete` here would therefore enforce nothing at all while
        // reading exactly like a rule that does, which is the failure this
        // codebase refuses to ship. Say so at load, and point at the axis that
        // works: a program is a file, so `files:` can protect it from `rm`.
        if is_exec && r.access.is_lifecycle() {
            let named = r.pattern.as_deref().or(r.path.as_deref()).unwrap_or("?");
            anyhow::bail!(
                "`exec:` rule `{named}` has `access: {}` — exec rules are matched when a program \
                 is RUN, and nothing about creating or deleting it. Move it to `files:`, where \
                 that axis is enforced",
                r.access.as_str()
            );
        }
        let compiled = match (r.pattern, r.path) {
            (Some(p), Some(q)) => anyhow::bail!(
                "rule has both `match: {p}` and `path: {q}` — a glob describes names, a path \
                 describes one object; pick one"
            ),
            (None, None) => {
                anyhow::bail!("rule needs `match:` (a glob) or `path:` (one concrete object)")
            }
            (Some(pattern), None) => {
                let glob = Glob::new(&pattern)
                    .with_context(|| format!("bad glob `{pattern}`"))?
                    .compile_matcher();
                let enforceable = r.action == Action::Block
                    && if dir_capable {
                        file_key(&pattern).is_some()
                    } else {
                        last_segment(&pattern).and_then(name_key).is_some()
                    };
                PathRule {
                    pattern,
                    matcher: Matcher::Glob(glob),
                    action: r.action,
                    access: r.access,
                    enforceable,
                }
            }
            (None, Some(raw)) => {
                let label = format!("path:{raw}");
                let outcome = identity::resolve(&label, &raw, base, stat);
                match outcome {
                    // An exec rule names a program. Anchoring it to a directory
                    // would put the inode in a map the bprm hook never consults,
                    // which reads as "enforced" and is not.
                    ResolveOutcome::Anchored(a) if is_exec && a.kind == AnchorKind::Dir => {
                        if r.action == Action::Block {
                            unresolved.push(UnresolvedAnchor {
                                rule: label.clone(),
                                path: a.path.clone(),
                                reason: "is a directory; an `exec:` rule must name a program"
                                    .into(),
                            });
                        }
                        PathRule {
                            pattern: label,
                            matcher: Matcher::Path {
                                exact: a.path,
                                subtree: false,
                            },
                            action: r.action,
                            access: r.access,
                            enforceable: false,
                        }
                    }
                    ResolveOutcome::Anchored(mut a) => {
                        a.exec = is_exec;
                        a.access_mask = r.access.mask();
                        let subtree = a.kind == AnchorKind::Dir;
                        let exact = a.path.clone();
                        if r.action == Action::Block {
                            anchors.push(a);
                        }
                        PathRule {
                            pattern: label,
                            matcher: Matcher::Path { exact, subtree },
                            action: r.action,
                            access: r.access,
                            enforceable: r.action == Action::Block,
                        }
                    }
                    ResolveOutcome::Unresolved(u) => {
                        let exact = base
                            .expand(&raw)
                            .unwrap_or_else(|| std::path::PathBuf::from(&raw));
                        if r.action == Action::Block {
                            unresolved.push(u);
                        }
                        PathRule {
                            pattern: label,
                            matcher: Matcher::Path {
                                exact,
                                subtree: false,
                            },
                            action: r.action,
                            access: r.access,
                            enforceable: false,
                        }
                    }
                }
            }
        };
        out.push(compiled);
    }
    Ok(out)
}

/// Fold a rule's access mask into a kernel key set.
///
/// One key, one value: if two rules name the same basename with different
/// access, the kernel map can only hold one mask, so the merge has to widen
/// rather than narrow — the alternative is a rule that silently stops applying
/// because an unrelated rule was added next to it. [`fmode::widen`] owns that
/// algebra, because the kernel side needs the same answer.
fn merge_mask<K: Ord>(map: &mut BTreeMap<K, u8>, key: K, mask: u8) {
    match map.get_mut(&key) {
        Some(existing) => *existing = fmode::widen(*existing, mask),
        None => {
            map.insert(key, mask);
        }
    }
}

/// Last non-empty `/`-separated segment of a glob pattern.
fn last_segment(p: &str) -> Option<&str> {
    p.rsplit('/').find(|s| !s.is_empty())
}

/// What a file glob reduces to in the kernel: its last literal segment, and —
/// when the segment before it is literal too — that one as a parent.
///
/// `**/.aws/credentials` → `{ parent: Some(".aws"), name: "credentials" }`;
/// `/etc/shadow` → `{ parent: Some("etc"), name: "shadow" }`;
/// `**/.env` → `{ parent: None, name: ".env" }` (the segment before it is `**`,
/// which names nothing); `**/.config/gcloud/**` → `{ is_dir: true, parent:
/// Some(".config"), name: "gcloud" }`.
///
/// Two components is the ceiling. `/etc/ssl/private/key.pem` keeps `private/
/// key.pem` and drops the rest — still far narrower than `key.pem` alone, and
/// [`Policy::overbroad_block_keys`] says exactly what was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seg<'a> {
    is_dir: bool,
    parent: Option<&'a str>,
    name: &'a str,
}

impl Seg<'_> {
    /// The glob this key is exactly equivalent to. Anything the rule said
    /// beyond this is what the kernel does NOT see.
    fn exact_glob(&self) -> String {
        let tail = if self.is_dir { "/**" } else { "" };
        match self.parent {
            Some(p) => format!("**/{p}/{}{tail}", self.name),
            None => format!("**/{}{tail}", self.name),
        }
    }

    /// `parent/name` or `name`, for display.
    fn label(&self) -> String {
        match self.parent {
            Some(p) => format!("{p}/{}", self.name),
            None => self.name.to_string(),
        }
    }
}

fn file_seg(pattern: &str) -> Option<Seg<'_>> {
    let (is_dir, body) = match pattern.strip_suffix("/**") {
        Some(stripped) => (true, stripped),
        None => (false, pattern),
    };
    let mut segs = body.rsplit('/').filter(|s| !s.is_empty());
    let name = segs.next().filter(|s| name_key(s).is_some())?;
    // `name_key` already refuses `**` and anything with glob metacharacters,
    // so a `**/name` pattern yields no parent and lands in the single-name map
    // exactly as it always did.
    let parent = segs.next().filter(|s| name_key(s).is_some());
    Some(Seg {
        is_dir,
        parent,
        name,
    })
}

/// Whether a file glob reduces to *some* kernel key at all.
fn file_key(pattern: &str) -> Option<(bool, [u8; NAME_LEN])> {
    file_seg(pattern).and_then(|seg| name_key(seg.name).map(|k| (seg.is_dir, k)))
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
    use std::path::PathBuf;

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

    /// A destination port no test policy names, so an assertion about address
    /// matching stays an assertion about address matching.
    const ANY_PORT: u16 = 4242;

    fn key(s: &str) -> [u8; NAME_LEN] {
        let mut k = [0u8; NAME_LEN];
        k[..s.len()].copy_from_slice(s.as_bytes());
        k
    }

    /// "Would the kernel deny *reading* this?" — the question every one of these
    /// assertions is really asking, now that a rule can name an access.
    fn denies_read(p: &Policy, path: &str) -> Option<DenialKey> {
        p.kernel_file_denial(path, fmode::READ)
    }

    /// A filesystem for identity tests: `/proj/.env` and `/proj/nc` are files,
    /// `/home/a/.ssh` is a directory, and nothing else exists.
    fn fake_fs(p: &Path) -> Option<(u64, u64, bool)> {
        match p.to_str()? {
            "/proj/.env" => Some((0x801, 100, false)),
            "/proj/nc" => Some((0x801, 101, false)),
            "/home/a/.ssh" => Some((0x801, 200, true)),
            _ => None,
        }
    }

    fn identity_loader<'a>() -> Loader<'a> {
        Loader::offline().stat(&fake_fs).base(AnchorBase {
            cwd: Some(PathBuf::from("/proj")),
            home: Some(PathBuf::from("/home/a")),
        })
    }

    #[test]
    fn path_rules_resolve_to_identity_keys() {
        let p = identity_loader()
            .from_str(
                r#"
files:
  - { path: ".env",  action: block }
  - { path: "~/.ssh", action: block }
exec:
  - { path: "nc", action: block }
"#,
            )
            .expect("parses");

        let keys = p.inode_enforcement();
        assert_eq!(keys.files, vec![(InodeKey::new(0x0080_0001, 100), 0)]);
        assert_eq!(keys.dirs, vec![(InodeKey::new(0x0080_0001, 200), 0)]);
        assert_eq!(keys.execs, vec![(InodeKey::new(0x0080_0001, 101), 0)]);

        // The whole claim: the rule is about the object, so it does NOT put a
        // basename in the name maps where a rename could shake it off.
        let (names, dirs) = p.file_enforcement();
        assert!(names.is_empty(), "{names:?}");
        assert!(dirs.is_empty(), "{dirs:?}");
        assert!(p.exec_enforcement().is_empty());
    }

    /// A `path:` rule that resolves to nothing enforces nothing, and must say so
    /// rather than look like coverage.
    #[test]
    fn unresolved_path_rules_are_reported_not_silently_dropped() {
        let p = identity_loader()
            .from_str("files:\n  - { path: \"nope.txt\", action: block }\n")
            .expect("parses");
        assert!(p.inode_enforcement().is_empty());
        let u = p.unresolved_anchors();
        assert_eq!(u.len(), 1);
        assert!(u[0].reason.contains("does not exist"), "{:?}", u[0]);
        assert!(
            p.explain().contains("resolved to NOTHING"),
            "{}",
            p.explain()
        );
    }

    #[test]
    fn a_rule_must_be_either_a_glob_or_a_path_never_both_and_never_neither() {
        let err = |yaml: &str| -> String {
            match identity_loader().from_str(yaml) {
                Ok(_) => panic!("expected a parse error for: {yaml}"),
                Err(e) => format!("{e:?}"),
            }
        };
        assert!(
            err("files:\n  - { match: \"**/.env\", path: \".env\", action: block }\n")
                .contains("pick one")
        );
        assert!(err("files:\n  - { action: block }\n").contains("needs `match:`"));
    }

    /// The access axis: a read-only rule must not claim a denial for an open
    /// that only asked to write, because the kernel would not have made one.
    #[test]
    fn access_narrows_which_opens_a_key_denies() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/secret", action: block, access: read }
  - { match: "**/logfile", action: block, access: write }
"#,
            )
            .expect("parses");

        assert!(p.kernel_file_denial("/x/secret", fmode::READ).is_some());
        assert!(p.kernel_file_denial("/x/secret", fmode::WRITE).is_none());
        assert!(p.kernel_file_denial("/x/logfile", fmode::WRITE).is_some());
        assert!(p.kernel_file_denial("/x/logfile", fmode::READ).is_none());
        // O_RDWR asks for both, so either rule fires.
        let rw = fmode::READ | fmode::WRITE;
        assert!(p.kernel_file_denial("/x/secret", rw).is_some());
        assert!(p.kernel_file_denial("/x/logfile", rw).is_some());
    }

    /// A rule with no `access:` must behave exactly as it did before the axis
    /// existed — including for an open that requests neither read nor write
    /// (`O_PATH`), which a naive `READ|WRITE` mask would have stopped covering.
    #[test]
    fn omitting_access_still_means_every_open() {
        let p = Loader::offline()
            .from_str("files:\n  - { match: \"**/secret\", action: block }\n")
            .expect("parses");
        for requested in [fmode::READ, fmode::WRITE, fmode::READ | fmode::WRITE, 0] {
            assert!(
                p.kernel_file_denial("/x/secret", requested).is_some(),
                "an unqualified block must cover fmode {requested}"
            );
        }
    }

    /// Two rules naming the same basename with different access collapse into
    /// one kernel key, and the merge must widen — never silently drop one.
    #[test]
    fn masks_for_the_same_key_merge_by_widening() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/secret", action: block, access: read }
  - { match: "**/secret", action: block, access: write }
"#,
            )
            .expect("parses");
        let (names, _) = p.file_enforcement();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].1, (fmode::READ | fmode::WRITE) as u8);
    }

    /// This used to be the merge test's fixture — `**/secret` and
    /// `/etc/secret` — and both landed on the bare key `secret`. They no
    /// longer share a key at all: the second keeps its parent, so the two
    /// rules mean two different things and the kernel holds two entries.
    #[test]
    fn a_rule_with_a_literal_parent_does_not_collapse_onto_the_bare_name() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/secret", action: block, access: read }
  - { match: "/etc/secret", action: block, access: write }
"#,
            )
            .expect("parses");
        let (names, _) = p.file_enforcement();
        let (pairs, _) = p.pair_enforcement();
        assert_eq!(names.len(), 1, "only `**/secret` is a bare name");
        assert_eq!(names[0].1, fmode::READ as u8, "and it kept its own mask");
        assert_eq!(pairs.len(), 1, "`/etc/secret` is a pair");
        assert_eq!(pairs[0].0, key("etc"));
        assert_eq!(pairs[0].1, key("secret"));
        assert_eq!(pairs[0].2, fmode::WRITE as u8);
    }

    /// An `exec:` rule pointing at a directory can never be enforced — the
    /// bprm hook never consults the directory map — so it must be reported
    /// rather than counted as coverage.
    #[test]
    fn an_exec_path_rule_naming_a_directory_is_refused() {
        let p = identity_loader()
            .from_str("exec:\n  - { path: \"~/.ssh\", action: block }\n")
            .expect("parses");
        assert!(p.inode_enforcement().is_empty());
        assert!(
            p.unresolved_anchors()[0].reason.contains("directory"),
            "{:?}",
            p.unresolved_anchors()
        );
    }

    const PORTED: &str = r#"
default_action: allow
network:
  - { cidr: "10.0.0.0/8", action: allow }        # the whole private LAN
  - { port: 25, action: block }                  # ...but never SMTP, anywhere
  - { cidr: "10.0.0.5/32", port: 25, action: allow }  # except this one relay
  - { cidr: "0.0.0.0/0", action: block }
"#;

    /// The ordering decision, stated as behaviour: a rule that names a port is
    /// consulted before one that does not, whatever their address prefixes.
    #[test]
    fn a_port_rule_beats_an_address_rule_with_a_longer_prefix() {
        let p = parse(PORTED).expect("parses");
        // 10.0.0.0/8 allows the LAN...
        assert_eq!(
            p.eval_connect("10.1.2.3".parse().unwrap(), 443).action,
            Action::Allow
        );
        // ...but the /0 port rule still denies SMTP inside it, despite a
        // 0-bit address prefix losing to /8 on address specificity alone.
        assert_eq!(
            p.eval_connect("10.1.2.3".parse().unwrap(), 25).action,
            Action::Block
        );
        // Within the port pass, the more specific address wins as usual.
        assert_eq!(
            p.eval_connect("10.0.0.5".parse().unwrap(), 25).action,
            Action::Allow
        );
        // And an address with no port rule falls through to the address pass.
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap(), 443).action,
            Action::Block
        );
    }

    /// `port:` with no address covers BOTH families. A v4-only reading would
    /// leave the same port open over IPv6 — the exact shape of the hole the
    /// `::/0` rule had to be added for.
    #[test]
    fn a_bare_port_rule_covers_ipv6_too() {
        let p = parse("default_action: allow\nnetwork:\n  - { port: 25, action: block }\n")
            .expect("parses");
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap(), 25).action,
            Action::Block
        );
        assert_eq!(
            p.eval_connect6("2606:4700::1111".parse().unwrap(), 25)
                .action,
            Action::Block
        );
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap(), 26).action,
            Action::Allow
        );
    }

    /// Port rules must not leak into the address-only trie: a port-qualified
    /// `0.0.0.0/0 block` there would read as a deny-all for every port.
    #[test]
    fn port_rules_are_kept_out_of_the_address_trie() {
        let p = parse("default_action: allow\nnetwork:\n  - { port: 25, action: block }\n")
            .expect("parses");
        assert!(p.net_entries().is_empty(), "{:?}", p.net_entries());
        assert!(p.net_entries6().is_empty());
        assert_eq!(p.port_entries().len(), 1);
        assert_eq!(p.port_entries6().len(), 1);
        // Prefix covers the whole port and no address bits.
        assert_eq!(p.port_entries()[0].0, PORT_BITS);
    }

    /// The key's bit layout IS the semantics — port first, so a prefix can pin a
    /// port without pinning an address. If these ever swap, "port 25 anywhere"
    /// silently becomes inexpressible.
    #[test]
    fn the_port_key_puts_the_port_before_the_address() {
        let p = parse(
            "default_action: allow\nnetwork:\n  - { cidr: \"10.0.0.0/8\", port: 5432, action: allow }\n",
        )
        .expect("parses");
        let (plen, key, _) = p.port_entries()[0];
        assert_eq!(plen, PORT_BITS + 8);
        assert_eq!(key.port, 5432u16.to_be_bytes());
        assert_eq!(key.addr, [10, 0, 0, 0]);
        assert_eq!(key._pad, [0, 0]);
    }

    /// A rule with no address and no port is still an error — `port:` widened
    /// what a rule may be, it did not make every field optional.
    #[test]
    fn a_network_rule_still_needs_something_to_match_on() {
        let Err(e) = parse("network:\n  - { action: block }\n") else {
            panic!("a rule with nothing to match on must be refused");
        };
        assert!(
            format!("{e:?}").contains("`cidr`, `domain`, `port`, or `proto`"),
            "{e:?}"
        );
    }

    /// A port-qualified deny-all is not a deny-all, and the IPv6 coverage
    /// warning must not be silenced by one.
    #[test]
    fn a_port_qualified_catch_all_does_not_count_as_deny_all() {
        let p = parse(
            "default_action: allow\nnetwork:\n  - { cidr: \"0.0.0.0/0\", port: 25, action: block }\n",
        )
        .expect("parses");
        assert!(
            p.net_coverage_gaps().is_empty(),
            "a port rule is not a v4 deny-all"
        );

        let q =
            parse("default_action: allow\nnetwork:\n  - { cidr: \"0.0.0.0/0\", action: block }\n")
                .expect("parses");
        assert_eq!(
            q.net_coverage_gaps().len(),
            1,
            "a real v4 deny-all still warns"
        );
    }

    /// An exception for a port-trie denial names the port, because it has to be
    /// written into the trie that denied — and it is a smaller thing to approve.
    #[test]
    fn a_port_denial_key_is_narrower_than_an_address_one() {
        let ported = DenialKey::Net4Port {
            ip: "1.1.1.1".parse().unwrap(),
            port: 25,
        };
        assert_eq!(ported.to_string(), "ip=1.1.1.1:25");
        let text = ported.blast_radius();
        assert!(text.contains("port 25 only"), "{text}");
        assert!(!text.contains("ALL egress"), "{text}");
        // The address form is the broad one, and still says so.
        let broad = DenialKey::Net4("1.1.1.1".parse().unwrap());
        assert!(broad.blast_radius().contains("ALL egress"));
    }

    /// An unresolved `path:` rule has its own report, with its own reason. It
    /// must not ALSO appear under "no kernel key — glob segment, or name too
    /// long", which is a different problem and a wrong explanation.
    #[test]
    fn an_unresolved_path_rule_is_reported_once_and_for_the_right_reason() {
        let p = identity_loader()
            .from_str(
                "files:\n  - { path: \"nope.txt\", action: block }\n  \
                 - { match: \"**/*.pem\", action: block }\n",
            )
            .expect("parses");
        // The glob still belongs there — it genuinely reduces to no kernel key.
        assert_eq!(p.observe_only_blocks(), vec!["**/*.pem".to_string()]);
        let text = p.explain();
        // Counted by LINE: the one legitimate report names both the rule and the
        // path it expanded to, so the substring appears twice on it.
        let lines = text.lines().filter(|l| l.contains("nope.txt")).count();
        assert_eq!(
            lines, 1,
            "the unresolved path rule is reported twice:\n{text}"
        );
    }

    /// `--dry-run` must show the object an identity rule landed on: a wrong
    /// working directory or an unexpanded `~` is otherwise invisible until an
    /// incident.
    #[test]
    fn explain_names_the_object_each_identity_rule_resolved_to() {
        let p = identity_loader()
            .from_str("files:\n  - { path: \".env\", action: block }\n")
            .expect("parses");
        let text = p.explain();
        assert!(text.contains("/proj/.env"), "{text}");
        assert!(text.contains("ino 100"), "{text}");
        assert!(text.contains("ANY name"), "{text}");
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
            p.eval_connect("127.0.0.1".parse().unwrap(), ANY_PORT)
                .action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect("192.168.1.5".parse().unwrap(), ANY_PORT)
                .action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap(), ANY_PORT).action,
            Action::Block
        );
        assert_eq!(
            p.eval_connect("8.8.8.8".parse().unwrap(), ANY_PORT).action,
            Action::Block
        );
    }

    #[test]
    fn network_v6_matching() {
        let p = policy();
        assert_eq!(
            p.eval_connect6("::1".parse().unwrap(), ANY_PORT).action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect6("2001:db8::5".parse().unwrap(), ANY_PORT)
                .action,
            Action::Block
        );
        // unmatched v6 -> default (allow in P); the v4 0.0.0.0/0 rule does not apply
        assert_eq!(
            p.eval_connect6("2606:4700::1".parse().unwrap(), ANY_PORT)
                .action,
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
            p.eval_connect("1.1.1.1".parse().unwrap(), ANY_PORT).rule,
            "cidr:0.0.0.0/0"
        );
        assert_eq!(p.eval_file("/x/main.rs").rule, "**");
    }

    #[test]
    fn file_enforcement_compiles_block_rules() {
        let p = policy();
        let (names, dirs) = p.file_enforcement();
        let (pairs, _) = p.pair_enforcement();
        let has = |v: &[([u8; NAME_LEN], u8)], s: &str| v.iter().any(|(k, _)| *k == key(s));
        assert!(has(&names, ".env")); // **/.env
        assert!(!has(&names, "shadow")); // /etc/shadow is NOT a bare name any more...
        assert!(pairs
            .iter()
            .any(|(p, n, _)| *p == key("etc") && *n == key("shadow"))); // ...it is this
        assert!(has(&dirs, ".ssh")); // **/.ssh/**
        assert!(!has(&names, ".env.*")); // glob segment -> not enforced

        let execs = p.exec_enforcement();
        assert!(has(&execs, "nc")); // **/nc block
        assert!(!has(&execs, "curl")); // curl is warn, not block

        // Every key here is stored with MASK_ANY: none of these rules named an
        // access, so they must behave exactly as they did before the axis existed.
        for (_, mask) in names.iter().chain(&dirs).chain(&execs) {
            assert_eq!(*mask, fmode::MASK_ANY);
        }
        for (_, _, mask) in &pairs {
            assert_eq!(*mask, fmode::MASK_ANY);
        }
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
        assert!(
            p.eval_connect("1.1.1.1".parse().unwrap(), ANY_PORT)
                .enforceable
        );

        let oo = p.observe_only_blocks();
        assert!(oo.contains(&"**/.env.*".to_string()));
        assert!(!oo.contains(&"**/.env".to_string()));
    }

    #[test]
    fn empty_policy_uses_default() {
        let p = parse("default_action: warn").unwrap();
        assert_eq!(p.eval_file("/anything").action, Action::Warn);
        assert_eq!(
            p.eval_connect("8.8.8.8".parse().unwrap(), ANY_PORT).action,
            Action::Warn
        );
    }

    #[test]
    fn kernel_file_denial_mirrors_the_coarse_lsm_matcher() {
        let p = policy();
        // `/etc/shadow` compiles to the pair `(etc, shadow)`. It used to
        // reduce to the bare name `shadow` and deny it ANYWHERE; now a `shadow`
        // that is not directly under an `etc` is left alone...
        assert_eq!(p.eval_file("/home/u/shadow").action, Action::Allow);
        assert_eq!(denies_read(&p, "/home/u/shadow"), None);
        // ...while the one the rule actually named is denied, by the pair.
        assert_eq!(
            denies_read(&p, "/etc/shadow"),
            Some(DenialKey::FilePair {
                parent: "etc".into(),
                name: "shadow".into()
            })
        );
        // Still a suffix match, not an anchored path: this is the honest
        // remaining over-reach, and `overbroad_block_keys` reports it.
        assert_eq!(
            denies_read(&p, "/srv/jail/etc/shadow"),
            Some(DenialKey::FilePair {
                parent: "etc".into(),
                name: "shadow".into()
            })
        );
        // A file directly in `.ssh` IS denied by the kernel.
        assert_eq!(
            denies_read(&p, "/home/u/.ssh/id_ed25519"),
            Some(DenialKey::FileDir(".ssh".into()))
        );
        // `.env.*` is a glob segment: never a kernel key, so never denied here.
        assert_eq!(denies_read(&p, "/home/u/.env.local"), None);
        assert_eq!(denies_read(&p, "/home/u/src/main.rs"), None);
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
            denies_read(&p, "/home/u/.ssh/sub/deep/id"),
            Some(DenialKey::FileDir(".ssh".into()))
        );
    }

    #[test]
    fn ancestor_walk_is_bounded_exactly_like_the_kernel_loop() {
        let p = parse(r#"files: [{ match: "**/secret/**", action: block }]"#).unwrap();
        // `secret` sits MAX_DIR_WALK levels above the file: still caught.
        let just_inside = format!("/secret{}/f", "/d".repeat(MAX_DIR_WALK - 1));
        assert_eq!(
            denies_read(&p, &just_inside),
            Some(DenialKey::FileDir("secret".into()))
        );
        // One level deeper than the kernel walks: not claimed, because the hook
        // would not have seen it either.
        let too_deep = format!("/secret{}/f", "/d".repeat(MAX_DIR_WALK));
        assert_eq!(denies_read(&p, &too_deep), None);
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
            p.eval_connect("1.1.1.1".parse().unwrap(), ANY_PORT).action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect("1.1.1.1".parse().unwrap(), ANY_PORT).rule,
            "cidr:1.1.1.1/32"
        );
        assert_eq!(
            p.eval_connect("8.8.8.8".parse().unwrap(), ANY_PORT).action,
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
            p.eval_connect("203.0.113.7".parse().unwrap(), ANY_PORT)
                .action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect("203.0.113.8".parse().unwrap(), ANY_PORT)
                .action,
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
            "name=etc/shadow",
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
        assert_eq!(denies_read(&p, &format!("/x/{long}")), None);
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
                    denies_read(&p, secret).is_some(),
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
                    denies_read(&p, ordinary),
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

    // ── the create/delete axis (M6) ─────────────────────────────────────────

    /// The compatibility guarantee, stated as a test because it is the one
    /// thing a new axis can silently break: a rule written before this axis
    /// existed must not begin refusing an `rm` because wardyn was updated.
    #[test]
    fn a_plain_block_rule_says_nothing_about_deleting() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/.env", action: block }
  - { match: "**/logfile", action: block, access: any }
"#,
            )
            .expect("parses");

        // Still blocks opens, exactly as before.
        assert!(p.kernel_file_denial("/x/.env", fmode::READ).is_some());
        // And still stores the canonical MASK_ANY, so the map bytes are
        // identical to a build that predates the axis.
        let (names, _) = p.file_enforcement();
        for (_, mask) in &names {
            assert_eq!(*mask, fmode::MASK_ANY);
            assert!(!fmode::covers(*mask, fmode::DELETE));
            assert!(!fmode::covers(*mask, fmode::CREATE));
        }
        // And the five lifecycle hooks stay switched off entirely.
        assert!(!p.has_lifecycle_rules());
    }

    #[test]
    fn a_delete_rule_blocks_removal_without_blocking_reads() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/keep.txt", action: block, access: delete }
"#,
            )
            .expect("parses");

        assert!(p.has_lifecycle_rules());
        let (names, _) = p.file_enforcement();
        let (_, mask) = names
            .iter()
            .find(|(k, _)| *k == key("keep.txt"))
            .expect("key");
        assert!(fmode::covers(*mask, fmode::DELETE));
        assert!(!fmode::covers(*mask, fmode::CREATE));

        // The whole point: the agent may still read and write the file.
        assert!(p.kernel_file_denial("/x/keep.txt", fmode::READ).is_none());
        assert!(p.kernel_file_denial("/x/keep.txt", fmode::WRITE).is_none());
        // Including an `O_PATH` open, which asks for neither bit — the case a
        // `READ | WRITE` mask would have got wrong.
        assert!(p.kernel_file_denial("/x/keep.txt", 0).is_none());
    }

    #[test]
    fn access_all_covers_every_open_and_both_lifecycle_operations() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/.env", action: block, access: all }
"#,
            )
            .expect("parses");

        let (names, _) = p.file_enforcement();
        let (_, mask) = names.iter().find(|(k, _)| *k == key(".env")).expect("key");
        assert!(fmode::covers(*mask, fmode::DELETE));
        assert!(fmode::covers(*mask, fmode::CREATE));
        // `all` must keep covering an `O_PATH` open, which sets neither
        // FMODE_READ nor FMODE_WRITE — the reason it is not spelled READ|WRITE.
        assert!(p.kernel_file_denial("/x/.env", 0).is_some());
        assert!(p.kernel_file_denial("/x/.env", fmode::READ).is_some());
    }

    /// Two rules, one kernel key, one stored value. Neither rule may be lost.
    #[test]
    fn an_open_rule_and_a_delete_rule_on_one_key_keep_both_axes() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/.env", action: block, access: read }
  - { match: "**/.env", action: block, access: delete }
"#,
            )
            .expect("parses");

        let (names, _) = p.file_enforcement();
        let (_, mask) = names.iter().find(|(k, _)| *k == key(".env")).expect("key");
        assert!(fmode::covers(*mask, fmode::DELETE), "delete rule was lost");
        assert!(p.kernel_file_denial("/x/.env", fmode::READ).is_some());
        // The read rule is still a READ rule: widening must not turn it into
        // "every open" just because a delete rule sat next to it.
        assert!(p.kernel_file_denial("/x/.env", fmode::WRITE).is_none());
    }

    /// `any` and `delete` together mean "every open, and no removal" — the
    /// case that forced `OPEN_ANY` to exist, because MASK_ANY is zero and zero
    /// cannot carry a second bit.
    #[test]
    fn merging_any_with_delete_keeps_every_open_covered() {
        let merged = fmode::widen(fmode::MASK_ANY, fmode::DELETE);
        assert!(fmode::matches(merged, 0), "O_PATH open stopped matching");
        assert!(fmode::matches(merged, fmode::READ));
        assert!(fmode::matches(merged, fmode::WRITE));
        assert!(fmode::covers(merged, fmode::DELETE));
        assert!(!fmode::covers(merged, fmode::CREATE));
    }

    /// An approve-once exception lifts one operation, not the whole rule.
    #[test]
    fn lifting_a_lifecycle_bit_leaves_the_rest_of_the_rule_standing() {
        let both = Access::All.mask();
        let after = fmode::without(both, fmode::DELETE).expect("something is left");
        assert!(!fmode::covers(after, fmode::DELETE));
        assert!(fmode::covers(after, fmode::CREATE));
        assert!(fmode::matches(after, fmode::READ), "reads were unblocked");

        // A delete-only key has nothing left, and must be REMOVED rather than
        // written back as zero — zero is MASK_ANY, i.e. "block every open",
        // which would be the opposite of the exception that was granted.
        assert_eq!(fmode::without(Access::Delete.mask(), fmode::DELETE), None);
    }

    /// The kernel matches a removal against the same key as an open, so an
    /// exception has to name the operation alongside it.
    #[test]
    fn a_lifecycle_exception_is_narrower_than_the_key_it_wraps() {
        let inner = DenialKey::FileName(".env".into());
        let wrapped = DenialKey::Lifecycle {
            op: LifecycleOp::Delete,
            key: Box::new(inner.clone()),
        };
        assert_eq!(wrapped.inode(), None);
        let radius = wrapped.blast_radius();
        assert!(radius.contains("delete"), "{radius}");
        assert!(radius.contains(".env"), "{radius}");
        // Distinct keys: granting the removal must not also grant the open.
        assert_ne!(wrapped, inner);
    }

    /// `exec:` rules compile into maps the lifecycle hooks never read, so a
    /// `delete` there would enforce nothing while reading as if it did.
    #[test]
    fn an_exec_rule_cannot_carry_a_lifecycle_access() {
        let err = Loader::offline()
            .from_str(
                r#"
exec:
  - { match: "**/nc", action: block, access: delete }
"#,
            )
            .err()
            .expect("must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("files:"), "{msg}");
    }

    /// A `path:` rule carries the axis into the identity maps, and `--dry-run`
    /// has to say which operations it really covers — a rule that pins the
    /// right object and the wrong axis looks identical otherwise.
    #[test]
    fn a_path_rule_reports_the_lifecycle_axis_it_enforces() {
        let p = identity_loader()
            .from_str(
                r#"
files:
  - { path: "/home/a/.ssh", action: block, access: delete }
"#,
            )
            .expect("parses");

        let keys = p.inode_enforcement();
        assert_eq!(keys.dirs.len(), 1);
        assert!(fmode::covers(keys.dirs[0].1, fmode::DELETE));

        let text = p.explain();
        assert!(text.contains("DELETING"), "{text}");
    }

    // ── the protocol axis (M6) ──────────────────────────────────────────────

    /// The claim the whole tiering exists to make: a rule that names a protocol
    /// beats one that does not, whatever their address prefixes. Prefix-length
    /// ordering alone would make this a `/0` losing to a `/8`.
    #[test]
    fn a_proto_rule_beats_an_address_rule_with_a_longer_prefix() {
        let p = parse(
            r#"
network:
  - { cidr: "10.0.0.0/8", action: allow }
  - { proto: udp,         action: block }
"#,
        )
        .expect("parses");

        let host: Ipv4Addr = "10.1.2.3".parse().unwrap();
        assert_eq!(
            p.eval_connect_proto(host, 443, Some(Proto::Udp)).action,
            Action::Block,
            "a /8 allow outranked `no UDP at all`"
        );
        // ...and says nothing about the other transport.
        assert_eq!(
            p.eval_connect_proto(host, 443, Some(Proto::Tcp)).action,
            Action::Allow
        );
    }

    /// Naming both dimensions is more specific than naming either, and the two
    /// combine in the order the kernel consults its tries.
    #[test]
    fn protocol_and_port_together_are_the_most_specific_tier() {
        let p = parse(
            r#"
network:
  - { port: 53, proto: udp, action: allow }
  - { port: 53,             action: block }
  - { cidr: "0.0.0.0/0",    action: allow }
"#,
        )
        .expect("parses");

        let dns: Ipv4Addr = "1.1.1.1".parse().unwrap();
        // The proto+port rule is consulted first, so DNS over UDP is allowed...
        assert_eq!(
            p.eval_connect_proto(dns, 53, Some(Proto::Udp)).action,
            Action::Allow
        );
        // ...while the bare port rule still denies the same port over TCP.
        assert_eq!(
            p.eval_connect_proto(dns, 53, Some(Proto::Tcp)).action,
            Action::Block
        );
        // And a port nobody mentioned falls through to the address tier.
        assert_eq!(
            p.eval_connect_proto(dns, 443, Some(Proto::Tcp)).action,
            Action::Allow
        );
    }

    /// The feed cannot read a socket's protocol, so where the policy makes the
    /// outcome depend on one it must not pretend to know.
    ///
    /// This is the regression the e2e suite caught: skipping the protocol tiers
    /// looks like the safe direction and is not. A proto-qualified *allow*
    /// outranks a lower-tier block, so ignoring it made the mirror record
    /// `block, enforced: true` for a connection the kernel had just permitted —
    /// the exact claim this mirror exists to never make.
    #[test]
    fn a_transport_dependent_outcome_is_reported_as_unknown_not_as_a_denial() {
        let p = parse(
            r#"
network:
  - { port: 11, proto: udp, action: allow }
  - { port: 11,             action: block }
  - { cidr: "0.0.0.0/0",    action: allow }
"#,
        )
        .expect("parses");

        let host: Ipv4Addr = "127.0.0.1".parse().unwrap();
        // Known transports: exact, and they disagree.
        assert_eq!(
            p.eval_connect_proto(host, 11, Some(Proto::Udp)).action,
            Action::Allow
        );
        assert_eq!(
            p.eval_connect_proto(host, 11, Some(Proto::Tcp)).action,
            Action::Block
        );
        // Unknown: the lenient side, and explicitly not enforceable, so the row
        // never asserts a denial. The kernel reports its own if it makes one.
        let v = p.eval_connect(host, 11);
        assert_eq!(
            v.action,
            Action::Allow,
            "the feed claimed a denial it cannot know about"
        );
        assert!(
            !v.enforceable,
            "an uncertain verdict was recorded as enforced"
        );
        assert!(v.rule.contains("transport-dependent"), "{}", v.rule);
    }

    /// Where both transports agree, nothing about the prediction changes — a
    /// policy whose protocol rules do not reach this connection keeps the exact
    /// verdict it had before the axis existed.
    #[test]
    fn agreement_between_transports_keeps_the_verdict_certain() {
        let p = parse(
            r#"
network:
  - { cidr: "10.0.0.0/8", proto: udp, action: block }
  - { cidr: "0.0.0.0/0",  action: block }
"#,
        )
        .expect("parses");

        // 1.1.1.1 is outside the /8, so both transports land on the deny-all.
        let v = p.eval_connect("1.1.1.1".parse().unwrap(), 443);
        assert_eq!(v.action, Action::Block);
        assert!(
            v.enforceable,
            "a verdict both transports agree on must stay enforceable"
        );
    }

    /// Each tier owns its own trie, and a rule must appear in exactly one —
    /// leaving a `proto:` rule in the address trie as well would turn
    /// `{ proto: udp, action: block }` into a deny-all for every transport.
    #[test]
    fn proto_rules_are_kept_out_of_the_less_specific_tries() {
        let p = parse(
            r#"
network:
  - { cidr: "0.0.0.0/0", proto: udp, action: block }
  - { cidr: "1.1.1.1/32", port: 53, proto: udp, action: block }
"#,
        )
        .expect("parses");

        assert!(p.has_proto_rules());
        assert!(!p.has_port_rules(), "a proto+port rule is not a port rule");
        assert!(
            p.net_entries().is_empty(),
            "a protocol rule leaked into the address trie"
        );
        assert!(
            p.port_entries().is_empty(),
            "a protocol+port rule leaked into the port trie"
        );
        assert_eq!(p.proto_entries().len(), 1);
        assert_eq!(p.proto_port_entries().len(), 1);
    }

    /// The prefix has to cover the protocol and port bits in full: a rule
    /// reaches these tries by naming them, so neither is ever a don't-care.
    #[test]
    fn the_protocol_key_puts_the_protocol_before_everything_else() {
        let p = parse(
            r#"
network:
  - { cidr: "10.0.0.0/8", port: 25, proto: tcp, action: block }
"#,
        )
        .expect("parses");

        let (plen, key, _) = p.proto_port_entries()[0];
        assert_eq!(
            plen,
            PROTO_BITS + PORT_BITS + 8,
            "prefix must cover proto+port in full"
        );
        assert_eq!(key.proto, 6, "IPPROTO_TCP");
        assert_eq!(key.port, 25u16.to_be_bytes(), "port in network order");
        assert_eq!(key.addr, [10, 0, 0, 0]);

        let (plen, key, _) = parse("network:\n  - { proto: udp, action: block }\n")
            .expect("parses")
            .proto_entries()[0];
        assert_eq!(plen, PROTO_BITS, "a bare proto rule pins the protocol only");
        assert_eq!(key.proto, 17, "IPPROTO_UDP");
    }

    /// A bare `proto:` with no address covers BOTH families — a v4-only reading
    /// would leave the same transport open over IPv6, which is the exact shape
    /// of the hole the `::/0` rule had to be added for.
    #[test]
    fn a_bare_protocol_rule_covers_both_address_families() {
        let p = parse("network:\n  - { proto: udp, action: block }\n").expect("parses");
        assert_eq!(p.proto_entries().len(), 1);
        assert_eq!(p.proto_entries6().len(), 1);
        assert_eq!(
            p.eval_connect6_proto("2606:4700::1".parse().unwrap(), 443, Some(Proto::Udp))
                .action,
            Action::Block
        );
    }

    /// An exception must name the trie that denied, or the rule still sitting in
    /// it overrules the approval on the very next connect.
    #[test]
    fn a_protocol_exception_is_narrower_than_the_address_it_wraps() {
        let inner = DenialKey::Net4("1.1.1.1".parse().unwrap());
        let wrapped = DenialKey::NetProto {
            proto: Proto::Udp,
            key: Box::new(inner.clone()),
        };
        assert_ne!(wrapped, inner);
        let radius = wrapped.blast_radius();
        assert!(radius.contains("UDP"), "{radius}");
        assert!(radius.contains("1.1.1.1"), "{radius}");
    }

    /// `--dry-run` has to state the order, because it is the one thing about
    /// these rules that cannot be read off the list.
    #[test]
    fn dry_run_lists_the_protocol_tiers_and_names_the_prediction_gap() {
        let p = parse(
            r#"
network:
  - { port: 53, proto: udp, action: block }
  - { proto: udp,           action: block }
"#,
        )
        .expect("parses");
        let text = p.explain();
        assert!(text.contains("blocked by protocol+port"), "{text}");
        assert!(text.contains("blocked by protocol"), "{text}");
        assert!(text.contains("MOST SPECIFIC FIRST"), "{text}");
        assert!(text.contains("NOT predicted in the feed"), "{text}");
    }

    // ── two-component keys ─────────────────────────────────────────────────

    /// The wart this exists to fix: `**/.aws/credentials` used to deny every
    /// file called `credentials`. Now it denies the one under `.aws`.
    #[test]
    fn a_literal_parent_narrows_the_kernel_key_to_the_pair() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/.aws/credentials", action: block }
"#,
            )
            .expect("parses");

        assert!(p.has_pair_rules());
        let (names, _) = p.file_enforcement();
        assert!(names.is_empty(), "nothing landed in the bare-name map");

        assert_eq!(
            denies_read(&p, "/home/u/.aws/credentials"),
            Some(DenialKey::FilePair {
                parent: ".aws".into(),
                name: "credentials".into()
            })
        );
        // The over-reach that used to happen, and no longer does.
        assert_eq!(denies_read(&p, "/home/u/project/credentials"), None);
        assert_eq!(denies_read(&p, "/home/u/.aws/other"), None);
        // A pair is a FILE key: a directory called `credentials` under `.aws`
        // does not put its contents under the rule.
        assert_eq!(denies_read(&p, "/home/u/.aws/credentials/inner"), None);
    }

    /// The directory form: `**/.config/gcloud/**` denies what is under a
    /// `gcloud` that sits in a `.config` — at any depth below it — and leaves
    /// a `gcloud` anywhere else alone.
    #[test]
    fn a_directory_pair_covers_the_subtree_and_only_that_subtree() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/.config/gcloud/**", action: block }
"#,
            )
            .expect("parses");

        let (_, dirs) = p.file_enforcement();
        assert!(dirs.is_empty(), "nothing landed in the bare-dir map");
        let hit = Some(DenialKey::DirPair {
            parent: ".config".into(),
            name: "gcloud".into(),
        });
        assert_eq!(denies_read(&p, "/home/u/.config/gcloud/creds.json"), hit);
        assert_eq!(denies_read(&p, "/home/u/.config/gcloud/a/b/c/deep"), hit);
        // Not under `.config`: not covered.
        assert_eq!(denies_read(&p, "/home/u/gcloud/creds.json"), None);
        assert_eq!(denies_read(&p, "/opt/gcloud/bin/gcloud"), None);
    }

    /// `strict.yaml` had to make `**/.git/config` a `warn` because it and
    /// `**/.kube/config` both reduced to `config` and would have blocked each
    /// other's files. They are now two keys.
    #[test]
    fn two_rules_that_used_to_collide_on_a_basename_are_now_distinct() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/.kube/config", action: block }
  - { match: "**/.git/config",  action: block, access: delete }
"#,
            )
            .expect("parses");

        let (pairs, _) = p.pair_enforcement();
        assert_eq!(pairs.len(), 2, "two keys, not one merged `config`");

        // The kube one blocks reads; the git one does not.
        assert!(denies_read(&p, "/proj/.kube/config").is_some());
        assert!(denies_read(&p, "/proj/.git/config").is_none());
        // And neither touches an unrelated `config`.
        assert!(denies_read(&p, "/proj/nginx/config").is_none());
        // The git one carries its own axis, on its own key.
        let git = pairs
            .iter()
            .find(|(par, _, _)| *par == key(".git"))
            .expect("git pair");
        assert!(fmode::covers(git.2, fmode::DELETE));
    }

    /// Order matters for which key the feed names: a pair is more specific than
    /// a bare name and must be reported first, because the exception it offers
    /// is the smaller one.
    #[test]
    fn a_pair_is_reported_before_a_bare_name_that_also_matches() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/config",       action: block }
  - { match: "**/.kube/config", action: block }
"#,
            )
            .expect("parses");
        assert_eq!(
            denies_read(&p, "/x/.kube/config"),
            Some(DenialKey::FilePair {
                parent: ".kube".into(),
                name: "config".into()
            })
        );
        // Where only the bare name applies, that is what is reported.
        assert_eq!(
            denies_read(&p, "/x/nginx/config"),
            Some(DenialKey::FileName("config".into()))
        );
    }

    /// What is still over-broad, said precisely: two components is a suffix
    /// match, so `/etc/shadow` is `etc/shadow` at any depth, and a three-segment
    /// rule loses its first one. What is no longer over-broad must not be
    /// reported as if it were.
    #[test]
    fn overbroad_reports_only_what_the_pair_still_drops() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "**/.aws/credentials",       action: block }
  - { match: "**/.config/gcloud/**",      action: block }
  - { match: "/etc/shadow",               action: block }
  - { match: "/etc/ssl/private/key.pem",  action: block }
  - { match: "**/.env",                   action: block }
"#,
            )
            .expect("parses");
        let over: Vec<String> = p
            .overbroad_block_keys()
            .into_iter()
            .map(|(r, _)| r)
            .collect();
        assert!(
            !over.contains(&"**/.aws/credentials".to_string()),
            "{over:?}"
        );
        assert!(
            !over.contains(&"**/.config/gcloud/**".to_string()),
            "{over:?}"
        );
        assert!(!over.contains(&"**/.env".to_string()), "{over:?}");
        assert!(over.contains(&"/etc/shadow".to_string()), "{over:?}");
        assert!(
            over.contains(&"/etc/ssl/private/key.pem".to_string()),
            "{over:?}"
        );

        let reach = p
            .overbroad_block_keys()
            .into_iter()
            .find(|(r, _)| r == "/etc/ssl/private/key.pem")
            .map(|(_, reach)| reach)
            .unwrap();
        assert!(
            reach.contains("`key.pem` directly under a dir named `private`"),
            "{reach}"
        );
    }

    /// An `allow` written before a `block` that the kernel's pair key covers is
    /// shadowed — and the report names the pair, not the bare name.
    #[test]
    fn shadowing_is_detected_through_a_pair_key() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "/home/me/.aws/credentials", action: allow }
  - { match: "**/.aws/credentials",       action: block }
  - { match: "/tmp/.config/gcloud/x",     action: allow }
  - { match: "**/.config/gcloud/**",      action: block }
"#,
            )
            .expect("parses");
        let shadowed = p.shadowed_by_kernel();
        let keys: Vec<&str> = shadowed.iter().map(|(_, k)| k.as_str()).collect();
        assert!(keys.contains(&"name=.aws/credentials"), "{keys:?}");
        assert!(keys.contains(&"dir=.config/gcloud"), "{keys:?}");
    }

    /// `--dry-run` has to show the pair, or the operator cannot tell the
    /// narrowed key from the old broad one.
    #[test]
    fn dry_run_lists_pairs_as_pairs() {
        let p = Loader::offline()
            .from_str(
                r#"
files:
  - { match: "/etc/shadow",          action: block }
  - { match: "**/.config/gcloud/**", action: block, access: all }
"#,
            )
            .expect("parses");
        let text = p.explain();
        assert!(text.contains("name=etc/shadow"), "{text}");
        assert!(text.contains("dir=.config/gcloud"), "{text}");
        assert!(text.contains("DELETING"), "{text}");
        assert!(
            !text.contains("name=shadow "),
            "the bare key must be gone: {text}"
        );
    }

    // ── domain rules are re-resolved, not frozen ────────────────────────────

    /// A resolver whose answer can be changed between calls, the way a CDN's
    /// answer changes between minutes.
    fn moving_resolver<'a>(
        answers: &'a std::cell::RefCell<Vec<&'static str>>,
    ) -> impl Fn(&str) -> Vec<IpAddr> + 'a {
        move |_domain: &str| {
            answers
                .borrow()
                .iter()
                .map(|a| a.parse().expect("test address"))
                .collect()
        }
    }

    /// The bug this exists to fix: a `domain:` allow was frozen at load, so when
    /// the name started answering with a different address the agent's
    /// legitimate traffic hit the deny-all catch-all instead.
    #[test]
    fn a_domain_allow_follows_the_name_when_its_address_moves() {
        let answers = std::cell::RefCell::new(vec!["93.184.216.34"]);
        let p = Loader::offline()
            .resolver(&moving_resolver(&answers))
            .from_str(
                r#"
network:
  - { domain: "cdn.example", action: allow }
  - { cidr: "0.0.0.0/0",     action: block }
"#,
            )
            .expect("parses");

        let old: Ipv4Addr = "93.184.216.34".parse().unwrap();
        let new: Ipv4Addr = "93.184.216.99".parse().unwrap();
        assert_eq!(p.eval_connect(old, 443).action, Action::Allow);
        assert_eq!(p.eval_connect(new, 443).action, Action::Block);

        // The name starts answering with a different address.
        *answers.borrow_mut() = vec!["93.184.216.99"];
        let refresh = p.refresh_domains(&moving_resolver(&answers));

        assert_eq!(refresh.added.len(), 1, "{refresh:?}");
        assert_eq!(refresh.added[0].ip, IpAddr::V4(new));
        assert_eq!(refresh.removed.len(), 1, "{refresh:?}");
        assert_eq!(refresh.removed[0].ip, IpAddr::V4(old));

        // The mirror follows immediately — it and the kernel read one set.
        assert_eq!(p.eval_connect(new, 443).action, Action::Allow);
        assert_eq!(
            p.eval_connect(old, 443).action,
            Action::Block,
            "an address the name no longer answers with must stop being allowed"
        );
    }

    /// Replacing rather than accumulating is the whole reason the old address
    /// stops being allowed above. Stated as its own test because the opposite
    /// choice is tempting — it would never break a working agent — and it would
    /// let an `allow` drift steadily more permissive than what was written.
    #[test]
    fn a_refresh_replaces_the_address_set_rather_than_growing_it() {
        let answers = std::cell::RefCell::new(vec!["10.0.0.1", "10.0.0.2"]);
        let p = Loader::offline()
            .resolver(&moving_resolver(&answers))
            .from_str("network:\n  - { domain: \"x.example\", action: allow }\n")
            .expect("parses");
        assert_eq!(p.net_entries().len(), 2);

        *answers.borrow_mut() = vec!["10.0.0.3"];
        p.refresh_domains(&moving_resolver(&answers));
        let entries = p.net_entries();
        assert_eq!(entries.len(), 1, "the set was grown, not replaced");
        assert_eq!(entries[0].1, u32::from_ne_bytes([10, 0, 0, 3]));
    }

    /// A name that stops resolving stops enforcing, and that has to reach the
    /// operator. Reported as a failure rather than silently leaving the last
    /// good answer in place — which would be a rule claiming coverage it no
    /// longer has.
    #[test]
    fn a_name_that_stops_resolving_is_reported_and_stops_covering() {
        let answers = std::cell::RefCell::new(vec!["10.0.0.1"]);
        let p = Loader::offline()
            .resolver(&moving_resolver(&answers))
            .from_str(
                r#"
network:
  - { domain: "gone.example", action: block }
  - { cidr: "0.0.0.0/0",      action: allow }
"#,
            )
            .expect("parses");
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        assert_eq!(p.eval_connect(ip, 443).action, Action::Block);

        answers.borrow_mut().clear();
        let refresh = p.refresh_domains(&moving_resolver(&answers));
        assert_eq!(refresh.failed, vec!["gone.example".to_string()]);
        assert_eq!(refresh.removed.len(), 1);
        assert_eq!(p.eval_connect(ip, 443).action, Action::Allow);
    }

    /// An unchanged answer must produce no rows, or a policy with a stable
    /// domain would print a notice every minute for the life of the run.
    #[test]
    fn a_refresh_that_changes_nothing_reports_nothing() {
        let answers = std::cell::RefCell::new(vec!["10.0.0.1"]);
        let p = Loader::offline()
            .resolver(&moving_resolver(&answers))
            .from_str("network:\n  - { domain: \"stable.example\", action: allow }\n")
            .expect("parses");
        let refresh = p.refresh_domains(&moving_resolver(&answers));
        assert!(refresh.is_empty(), "{refresh:?}");
    }

    /// Precedence has to survive the split: domain rules live in their own
    /// collection now, so a tie with a `cidr:` rule on the same prefix can no
    /// longer be decided by position in one vector.
    #[test]
    fn a_domain_rule_keeps_its_policy_position_against_a_tying_cidr() {
        let answers = std::cell::RefCell::new(vec!["10.0.0.7"]);
        // The domain rule is written FIRST, so on a /32 tie it wins.
        let first = Loader::offline()
            .resolver(&moving_resolver(&answers))
            .from_str(
                r#"
network:
  - { domain: "x.example",   action: allow }
  - { cidr: "10.0.0.7/32",   action: block }
"#,
            )
            .expect("parses");
        let ip: Ipv4Addr = "10.0.0.7".parse().unwrap();
        assert_eq!(first.eval_connect(ip, 443).action, Action::Allow);

        // Reversed, the cidr rule is first and wins the same tie.
        let second = Loader::offline()
            .resolver(&moving_resolver(&answers))
            .from_str(
                r#"
network:
  - { cidr: "10.0.0.7/32",   action: block }
  - { domain: "x.example",   action: allow }
"#,
            )
            .expect("parses");
        assert_eq!(second.eval_connect(ip, 443).action, Action::Block);
    }

    /// A `domain:` rule that also names a port or protocol keeps them across a
    /// refresh — those decide which of the four kernel tries the address lands
    /// in, and losing them would file it in the wrong one.
    #[test]
    fn a_refreshed_domain_rule_keeps_its_port_and_protocol() {
        let answers = std::cell::RefCell::new(vec!["10.0.0.1"]);
        let p = Loader::offline()
            .resolver(&moving_resolver(&answers))
            .from_str(
                "network:\n  - { domain: \"d.example\", port: 443, proto: tcp, action: allow }\n",
            )
            .expect("parses");
        assert!(p.net_entries().is_empty(), "not an address-tier rule");
        assert_eq!(p.proto_port_entries().len(), 1);

        *answers.borrow_mut() = vec!["10.0.0.2"];
        let refresh = p.refresh_domains(&moving_resolver(&answers));
        assert_eq!(refresh.added[0].port, Some(443));
        assert_eq!(refresh.added[0].proto, Some(Proto::Tcp));
        assert_eq!(
            p.proto_port_entries().len(),
            1,
            "still in the proto+port trie"
        );
    }

    // ── allow_paths: (Landlock containment) ─────────────────────────────────

    #[test]
    fn allow_paths_resolve_like_path_rules_do() {
        let p = identity_loader()
            .from_str(
                r#"
allow_paths:
  - { path: "/usr",     rights: [read, exec] }
  - { path: "~/work",   rights: [read, write] }
  - { path: "sub",      rights: [read] }
"#,
            )
            .expect("parses");
        let got: Vec<String> = p
            .allow_paths()
            .iter()
            .map(|a| a.path.as_ref().unwrap().display().to_string())
            .collect();
        // `~` is the agent's home and a bare name is relative to the launch
        // directory — the same two bases `path:` rules use, so an operator does
        // not have to hold two rules in their head.
        assert_eq!(got, vec!["/usr", "/home/a/work", "/proj/sub"]);
        assert_eq!(p.allow_paths()[0].rights, vec![Right::Read, Right::Exec]);
    }

    /// An entry that cannot be resolved is kept, not dropped. Dropping it would
    /// confine the agent out of a hierarchy the policy grants, and the failure
    /// would surface as the agent crashing rather than as a policy problem.
    #[test]
    fn an_unresolvable_allow_path_is_kept_and_marked() {
        let p = Loader::offline()
            .base(AnchorBase {
                cwd: None,
                home: None,
            })
            .from_str("allow_paths:\n  - { path: \"~/work\", rights: [read] }\n")
            .expect("parses");
        assert_eq!(p.allow_paths().len(), 1);
        assert!(p.allow_paths()[0].path.is_none());
        assert_eq!(p.allow_paths()[0].raw, "~/work");
    }

    /// No `allow_paths:` must mean no containment — never an empty allowlist,
    /// which denies everything including the agent's own loader.
    #[test]
    fn a_policy_without_allow_paths_asks_for_no_containment() {
        let p = policy();
        assert!(p.allow_paths().is_empty());
        assert!(!p.explain().contains("contained by Landlock"));
    }

    /// `--dry-run` has to show the boundary before the rules inside it, and say
    /// out loud that an unlisted path is denied — the one thing about an
    /// allowlist that bites people who have only written blocklists.
    #[test]
    fn dry_run_shows_containment_and_warns_that_it_is_an_allowlist() {
        let p = identity_loader()
            .from_str(
                r#"
allow_paths:
  - { path: "/usr", rights: [read, exec] }
files:
  - { match: "**/.env", action: block }
"#,
            )
            .expect("parses");
        let text = p.explain();
        assert!(text.contains("contained by Landlock"), "{text}");
        assert!(text.contains("/usr"), "{text}");
        assert!(text.contains("read+exec"), "{text}");
        assert!(text.contains("ALLOWLIST"), "{text}");
        // The boundary is listed before the keys it contains.
        let boundary = text.find("contained by Landlock").unwrap();
        let keys = text.find("kernel-enforced under --enforce").unwrap();
        assert!(boundary < keys, "containment must be listed first");
    }

    /// An unknown right is a typo, and a typo in an allowlist silently narrows
    /// or widens what the agent can reach. `deny_unknown_fields` covers the key;
    /// the enum covers the value.
    #[test]
    fn an_unknown_right_is_refused_rather_than_ignored() {
        assert!(Loader::offline()
            .from_str("allow_paths:\n  - { path: \"/usr\", rights: [execute] }\n")
            .is_err());
        assert!(Loader::offline()
            .from_str("allow_paths:\n  - { path: \"/usr\", right: [read] }\n")
            .is_err());
    }

    // ── the feed has to know about the containment boundary ─────────────────

    fn contained() -> Policy {
        Loader::offline()
            .base(AnchorBase {
                cwd: Some(PathBuf::from("/proj")),
                home: Some(PathBuf::from("/home/a")),
            })
            .from_str(
                r#"
allow_paths:
  - { path: "/usr",        rights: [read, exec] }
  - { path: "/etc",        rights: [read] }
  - { path: "/proj",       rights: [read, write] }
  - { path: "/proj/bin",   rights: [read, write, exec] }
files:
  - { match: "**", action: allow }
"#,
            )
            .expect("parses")
    }

    /// The bug this exists to fix: Landlock reports nothing to wardyn, so
    /// without an explicit check the feed printed `ok` for an open the agent had
    /// just been refused — the exact feed/reality disagreement the mirror is for.
    #[test]
    fn a_path_outside_every_hierarchy_is_reported_as_denied() {
        let p = contained();
        assert_eq!(
            p.containment_denies("/home/a/.ssh/id_ed25519", fmode::READ)
                .as_deref(),
            Some("not listed")
        );
        assert!(p
            .containment_denies("/proj/src/main.rs", fmode::READ)
            .is_none());
    }

    /// Inside a hierarchy but without the right it asked for. The message names
    /// the grant, because "denied" without saying which line to edit sends the
    /// operator hunting.
    #[test]
    fn a_missing_right_inside_a_hierarchy_names_the_grant() {
        let p = contained();
        let why = p
            .containment_denies("/etc/wardyn-probe", fmode::WRITE)
            .unwrap();
        assert!(why.contains("/etc"), "{why}");
        assert!(why.contains("write"), "{why}");
        // Reading it is granted, so nothing is reported.
        assert!(p.containment_denies("/etc/hostname", fmode::READ).is_none());
    }

    /// The most specific hierarchy decides, matching Landlock: a nested grant
    /// overrides the one it sits inside, in both directions.
    #[test]
    fn the_deepest_matching_hierarchy_decides() {
        let p = contained();
        // /proj has no `exec`, /proj/bin does.
        assert!(p.containment_denies("/proj/bin/tool", EXEC_ONLY).is_none());
        let why = p.containment_denies("/proj/tool", EXEC_ONLY).unwrap();
        assert!(why.contains("exec"), "{why}");
    }

    /// Conservative where it cannot know. A relative path would have to be
    /// resolved against the agent's working directory, which this does not have
    /// — guessing would mean reporting denials that never happened.
    #[test]
    fn a_relative_path_is_not_judged() {
        let p = contained();
        assert!(p
            .containment_denies("../../etc/shadow", fmode::READ)
            .is_none());
        assert!(p.containment_denies("secret.txt", fmode::READ).is_none());
    }

    /// A policy with no `allow_paths:` has no boundary, and must not invent one.
    #[test]
    fn no_containment_means_nothing_is_reported() {
        let p = policy();
        assert!(p
            .containment_denies("/anything/at/all", fmode::READ)
            .is_none());
    }

    /// Three sources fall back to each other, and "11 file rules" reads the same
    /// whichever won. An operator who ran from the wrong directory got the
    /// embedded default with nothing said — which is the policy they did not
    /// write, silently enforcing rules they did not choose.
    #[test]
    fn a_loaded_policy_says_which_of_the_three_sources_it_came_from() {
        let dir = std::env::temp_dir().join(format!("wardyn-src-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let explicit = dir.join("mine.yaml");
        std::fs::write(&explicit, "files:\n  - { match: \"**\", action: allow }\n").unwrap();

        let p = Loader::offline().load(Some(&explicit)).expect("loads");
        assert_eq!(p.source(), &PolicySource::Explicit(explicit.clone()));
        assert_eq!(p.source().path(), Some(explicit.as_path()));
        assert!(p.source().to_string().contains("mine.yaml"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The embedded default is the one source nothing on disk can tamper with,
    /// so it reports no path — the writability check has nothing to warn about.
    #[test]
    fn the_embedded_default_reports_no_file() {
        let p = Loader::offline().from_str("files: []\n").expect("parses");
        assert_eq!(p.source(), &PolicySource::Embedded);
        assert_eq!(p.source().path(), None);
        assert!(p.source().to_string().contains("built-in"));
    }
}
