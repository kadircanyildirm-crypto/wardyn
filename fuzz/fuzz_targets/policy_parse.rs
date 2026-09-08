// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fuzz the policy parser.
//!
//! This is the one input in wardyn that an attacker may actually control. The
//! default policy path is `./policy.yaml`, which lands in the directory the
//! watched agent works in — wardyn warns about that at startup, but "the agent
//! could rewrite it" means the parser reads attacker-chosen bytes on the *next*
//! run, as root.
//!
//! The bar is: parsing must never panic and never hang. A malformed policy is
//! expected and is an error; a malformed policy that aborts wardyn before it
//! attaches anything is a denial of the tool itself.
//!
//! The resolver is stubbed so no fuzz input can reach DNS.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wardyn_policy::policy::Policy;

fn no_dns(_: &str) -> Vec<std::net::IpAddr> {
    Vec::new()
}

fuzz_target!(|data: &[u8]| {
    // Non-UTF-8 is rejected before the parser sees it, by the same
    // `read_to_string` the real loader uses.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Policy::from_yaml_str_with(text, &no_dns);
    }
});
