// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compile the `wardyn-ebpf` crate for the BPF target (via aya-build, using the
//! toolchain `rust-toolchain.toml` pins) and place the object in OUT_DIR, where
//! src/main.rs picks it up with include_bytes_aligned!.
//!
//! `WARDYN_SKIP_EBPF_BUILD=1` writes an empty placeholder instead. That exists so
//! the userspace crate can be **type-checked** (`cargo check --target
//! x86_64-unknown-linux-gnu`, clippy, rust-analyzer) on a machine without
//! `bpf-linker` — a macOS or Windows laptop, or a CI lane that only lints. A
//! binary built that way cannot load anything and says so at startup; never ship
//! one.
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use aya_build::{Package, Toolchain};

const SKIP_VAR: &str = "WARDYN_SKIP_EBPF_BUILD";

fn main() -> Result<()> {
    println!("cargo:rerun-if-env-changed={SKIP_VAR}");
    if std::env::var(SKIP_VAR).as_deref() == Ok("1") {
        let out = PathBuf::from(std::env::var("OUT_DIR")?).join("wardyn");
        std::fs::write(&out, [])?;
        println!(
            "cargo:warning={SKIP_VAR}=1 — the eBPF object was NOT built. This binary can only be \
             type-checked, not run: it has no programs to load."
        );
        return Ok(());
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let channel = pinned_channel(&manifest_dir)?;
    aya_build::build_ebpf(
        [Package {
            name: "wardyn-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../wardyn-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Custom(&channel),
    )?;
    Ok(())
}

/// The toolchain channel pinned in `rust-toolchain.toml`.
///
/// `Toolchain::default()` is aya-build's *floating* `nightly`, and passing it
/// here quietly undid the pin for the one artifact the pin exists to protect:
/// `rust-toolchain.toml` governs which compiler builds **userspace**, while the
/// eBPF object — the bytecode that actually goes into the kernel and gets
/// verified — was built by whatever `rustup`'s `nightly` happened to be that
/// day. Two builds of the same commit could ship different kernel programs, and
/// a verifier rejection that only reproduces on one machine is the kind of bug
/// that costs a week. Reading the channel here keeps one source of truth.
fn pinned_channel(manifest_dir: &Path) -> Result<String> {
    let path = manifest_dir.join("..").join("rust-toolchain.toml");
    println!("cargo:rerun-if-changed={}", path.display());
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    parse_channel(&text).with_context(|| format!("no `channel = \"...\"` in {}", path.display()))
}

/// Pull `channel = "nightly-YYYY-MM-DD"` out of a `rust-toolchain.toml`.
///
/// Hand-rolled rather than pulling in a TOML parser as a build dependency: this
/// file has exactly one key we care about, and a build-script dependency is a
/// dependency every consumer of the crate compiles.
fn parse_channel(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("channel") else {
            continue;
        };
        let rest = rest.trim_start().strip_prefix('=')?.trim();
        let value = rest.strip_prefix('"')?;
        let end = value.find('"')?;
        return Some(value[..end].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_channel;

    #[test]
    fn reads_the_pinned_channel_past_comments_and_whitespace() {
        let text = r#"
# channel = "nightly-1999-01-01"   <- a comment, not the pin
[toolchain]
channel = "nightly-2026-07-13"
components = ["rust-src"]
"#;
        assert_eq!(parse_channel(text).as_deref(), Some("nightly-2026-07-13"));
    }

    #[test]
    fn a_file_without_a_channel_is_an_error_not_a_silent_floating_nightly() {
        assert_eq!(parse_channel("[toolchain]\ncomponents = []\n"), None);
    }
}
