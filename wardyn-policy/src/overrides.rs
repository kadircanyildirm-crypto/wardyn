// SPDX-License-Identifier: AGPL-3.0-or-later
//! Persistent overrides — approvals that outlive the run that granted them.
//!
//! An approve-once exception ([`Exceptions`]) dies with the process. That is
//! safe and, for anything an agent does more than once, unusable: the operator
//! re-approves the same `.env` on every run until they stop reading the prompt,
//! which is the failure mode the confirm text exists to prevent.
//!
//! A stored approval is a different object, so it carries different guarantees:
//!
//! * **Bound to a policy.** Each entry records the fingerprint of the policy it
//!   was granted under and applies to no other. Edit the policy and the grants
//!   made against the old one stop applying — the operator is asked again,
//!   against the rules that are actually in force now.
//! * **It expires.** Entries carry an absolute deadline (default
//!   [`DEFAULT_TTL_DAYS`]). A forgotten approval is a permanent hole in a tool
//!   whose whole claim is that the kernel says no, so the default is that
//!   approvals decay rather than accumulate.
//! * **No clock in here.** Every function takes `now_unix` from the caller.
//!   Expiry is the part most worth testing and a hidden `SystemTime::now()`
//!   makes it the part that cannot be.
//!
//! What this module deliberately does *not* do is decide where the file lives
//! or who may write it. Storing it outside the watched tree, root-owned and
//! `O_NOFOLLOW`, is the wardyn crate's job — it needs `libc`, and this crate
//! stays portable so the semantics above can be tested on any host.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::policy::{DenialKey, Exceptions};

/// How long a stored approval lasts when the caller does not say otherwise.
pub const DEFAULT_TTL_DAYS: u32 = 30;

/// The `version:` this module writes and is willing to read.
const STORE_VERSION: u32 = 1;

/// Identifies the policy an approval was granted against.
///
/// FNV-1a over the policy source, rendered as `fnv1a64:<hex>`. This detects a
/// policy that *changed*; it is explicitly not a defence against a policy that
/// was *forged*, and nothing here should be read as one. An attacker who can
/// rewrite the policy file already decides what is enforced — a stored approval
/// for one extra key adds nothing to what they can do. (That the policy is
/// loaded from the agent's own working directory by default is a known,
/// documented weakness; see SECURITY.md. If it moves out of the agent's reach,
/// this fingerprint becomes load-bearing and should become a real digest.)
pub fn fingerprint(policy_source: &str) -> String {
    // FNV-1a, 64-bit. Stable across runs, versions and machines, which
    // `DefaultHasher` is explicitly not — it is seeded per process, so an
    // approval stored by one run would never match the next.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in policy_source.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64:{hash:016x}")
}

/// One stored approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// Exactly what the kernel would have denied — and therefore exactly what
    /// this permits. See [`DenialKey::blast_radius`].
    pub key: DenialKey,
    /// Fingerprint of the policy this was granted under.
    pub policy: String,
    /// Where that policy lived, for the operator reading this file later. Not
    /// used for matching — the fingerprint is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<String>,
    /// Unix seconds.
    pub granted: i64,
    /// Unix seconds. Past this, the entry is inert and gets pruned.
    pub expires: i64,
}

impl Override {
    pub fn is_active_at(&self, now_unix: i64) -> bool {
        now_unix < self.expires
    }
}

/// The parsed contents of an overrides file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideStore {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub overrides: Vec<Override>,
}

impl OverrideStore {
    /// Parse an overrides file. An empty (or whitespace-only) input is an empty
    /// store, so a first run against a file that does not exist yet and a run
    /// against one that was truncated behave the same.
    pub fn parse(source: &str) -> anyhow::Result<Self> {
        if source.trim().is_empty() {
            return Ok(Self::default());
        }
        let store: Self = serde_yaml::from_str(source)?;
        if let Some(v) = store.version {
            anyhow::ensure!(
                v == STORE_VERSION,
                "overrides file is version {v}, this wardyn understands {STORE_VERSION}"
            );
        }
        Ok(store)
    }

    pub fn to_yaml(&self) -> anyhow::Result<String> {
        let stamped = Self {
            version: Some(STORE_VERSION),
            overrides: self.overrides.clone(),
        };
        Ok(serde_yaml::to_string(&stamped)?)
    }

    /// The approvals that apply to `policy_fingerprint` right now, as the
    /// overlay the feed and the kernel-mirror consult.
    ///
    /// Entries for another policy, or past their deadline, are simply absent —
    /// there is no "expired but still counted" state to get wrong downstream.
    pub fn exceptions_for(&self, policy_fingerprint: &str, now_unix: i64) -> Exceptions {
        let mut exc = Exceptions::default();
        for o in &self.overrides {
            if o.policy == policy_fingerprint && o.is_active_at(now_unix) {
                exc.grant(o.key.clone());
            }
        }
        exc
    }

    /// Record an approval, replacing any existing one for the same key under the
    /// same policy — re-approving extends the deadline instead of stacking a
    /// second entry that the operator would have to revoke twice.
    pub fn grant(
        &mut self,
        key: DenialKey,
        policy_fingerprint: &str,
        policy_path: Option<String>,
        now_unix: i64,
        ttl_secs: i64,
    ) {
        self.overrides
            .retain(|o| !(o.policy == policy_fingerprint && o.key == key));
        self.overrides.push(Override {
            key,
            policy: policy_fingerprint.to_string(),
            policy_path,
            granted: now_unix,
            expires: now_unix.saturating_add(ttl_secs),
        });
    }

    /// Drop everything past its deadline. Returns how many went.
    ///
    /// Called before writing, so the file shrinks on its own instead of growing
    /// a tail of dead approvals that make it unreadable at review time.
    pub fn prune_expired(&mut self, now_unix: i64) -> usize {
        let before = self.overrides.len();
        self.overrides.retain(|o| o.is_active_at(now_unix));
        before - self.overrides.len()
    }

    /// How many active approvals each policy fingerprint holds — for the
    /// startup line that tells the operator what is already permitted before
    /// they read a single feed row.
    pub fn active_summary(&self, now_unix: i64) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for o in self.overrides.iter().filter(|o| o.is_active_at(now_unix)) {
            *out.entry(o.policy.clone()).or_insert(0) += 1;
        }
        out
    }
}

/// `days` as seconds, for callers turning a CLI value into a deadline.
pub fn ttl_secs(days: u32) -> i64 {
    i64::from(days) * 24 * 60 * 60
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn store_with_one(expires_in: i64, policy: &str) -> OverrideStore {
        let mut s = OverrideStore::default();
        s.grant(
            DenialKey::FileName(".env".into()),
            policy,
            Some("/p/policy.yaml".into()),
            NOW,
            expires_in,
        );
        s
    }

    #[test]
    fn fingerprint_is_stable_and_content_sensitive() {
        assert_eq!(fingerprint("files: []"), fingerprint("files: []"));
        assert_ne!(fingerprint("files: []"), fingerprint("files: [] "));
        assert!(fingerprint("x").starts_with("fnv1a64:"));
    }

    #[test]
    fn an_approval_applies_only_to_the_policy_it_was_granted_under() {
        let s = store_with_one(30 * DAY, "fnv1a64:aaaa");
        let key = DenialKey::FileName(".env".into());
        assert!(s.exceptions_for("fnv1a64:aaaa", NOW).contains(&key));
        // Same key, different policy: the operator never approved this one.
        assert!(!s.exceptions_for("fnv1a64:bbbb", NOW).contains(&key));
    }

    #[test]
    fn an_approval_stops_applying_once_it_expires() {
        let s = store_with_one(30 * DAY, "p");
        let key = DenialKey::FileName(".env".into());
        assert!(s.exceptions_for("p", NOW + 29 * DAY).contains(&key));
        assert!(!s.exceptions_for("p", NOW + 30 * DAY).contains(&key));
        assert!(!s.exceptions_for("p", NOW + 365 * DAY).contains(&key));
    }

    #[test]
    fn re_approving_extends_rather_than_duplicates() {
        let mut s = store_with_one(10 * DAY, "p");
        s.grant(
            DenialKey::FileName(".env".into()),
            "p",
            None,
            NOW + DAY,
            30 * DAY,
        );
        assert_eq!(s.overrides.len(), 1, "one key under one policy, one entry");
        assert_eq!(s.overrides[0].expires, NOW + DAY + 30 * DAY);
    }

    #[test]
    fn the_same_key_under_two_policies_is_two_approvals() {
        let mut s = store_with_one(30 * DAY, "p1");
        s.grant(
            DenialKey::FileName(".env".into()),
            "p2",
            None,
            NOW,
            30 * DAY,
        );
        assert_eq!(s.overrides.len(), 2);
    }

    #[test]
    fn pruning_removes_exactly_the_dead_ones() {
        let mut s = OverrideStore::default();
        s.grant(DenialKey::FileName("a".into()), "p", None, NOW, DAY);
        s.grant(DenialKey::FileName("b".into()), "p", None, NOW, 90 * DAY);
        assert_eq!(s.prune_expired(NOW + 2 * DAY), 1);
        assert_eq!(s.overrides.len(), 1);
        assert_eq!(s.overrides[0].key, DenialKey::FileName("b".into()));
    }

    #[test]
    fn survives_a_round_trip_through_yaml() {
        let mut s = OverrideStore::default();
        s.grant(DenialKey::FileDir(".ssh".into()), "p", None, NOW, DAY);
        s.grant(
            DenialKey::Net4(Ipv4Addr::new(1, 1, 1, 1)),
            "p",
            Some("/p.yaml".into()),
            NOW,
            DAY,
        );
        s.grant(DenialKey::Exec("nc".into()), "p", None, NOW, DAY);
        let yaml = s.to_yaml().unwrap();
        let back = OverrideStore::parse(&yaml).unwrap();
        assert_eq!(back.overrides, s.overrides);
        assert_eq!(back.version, Some(STORE_VERSION));
    }

    #[test]
    fn an_absent_or_empty_file_is_an_empty_store() {
        assert!(OverrideStore::parse("").unwrap().overrides.is_empty());
        assert!(OverrideStore::parse("   \n").unwrap().overrides.is_empty());
    }

    #[test]
    fn a_future_version_is_refused_rather_than_half_read() {
        let err = OverrideStore::parse("version: 99\noverrides: []\n").unwrap_err();
        assert!(err.to_string().contains("version 99"), "{err}");
    }

    #[test]
    fn a_typo_is_refused_rather_than_silently_dropping_an_approval() {
        // Same reasoning as the policy parser's deny_unknown_fields: a mistyped
        // key that parses to "no approvals" is worse than one that refuses.
        let yaml = "version: 1\noverride:\n  - key: {kind: exec, value: nc}\n";
        assert!(OverrideStore::parse(yaml).is_err());
    }

    #[test]
    fn expired_entries_are_not_counted_as_active() {
        let mut s = OverrideStore::default();
        s.grant(DenialKey::FileName("a".into()), "p", None, NOW, DAY);
        s.grant(DenialKey::FileName("b".into()), "p", None, NOW, 90 * DAY);
        let summary = s.active_summary(NOW + 2 * DAY);
        assert_eq!(summary.get("p"), Some(&1));
    }

    #[test]
    fn ttl_days_convert_to_seconds() {
        assert_eq!(ttl_secs(1), DAY);
        assert_eq!(ttl_secs(DEFAULT_TTL_DAYS), 30 * DAY);
    }
}
