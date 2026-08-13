// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compile the `wardyn-ebpf` crate for the BPF target (via aya-build, using the
//! nightly toolchain) and place the object in OUT_DIR, where src/main.rs picks it
//! up with include_bytes_aligned!.
//!
//! `WARDYN_SKIP_EBPF_BUILD=1` writes an empty placeholder instead. That exists so
//! the userspace crate can be **type-checked** (`cargo check --target
//! x86_64-unknown-linux-gnu`, clippy, rust-analyzer) on a machine without
//! `bpf-linker` — a macOS or Windows laptop, or a CI lane that only lints. A
//! binary built that way cannot load anything and says so at startup; never ship
//! one.
use std::path::PathBuf;

use aya_build::{Package, Toolchain};

const SKIP_VAR: &str = "WARDYN_SKIP_EBPF_BUILD";

fn main() -> anyhow::Result<()> {
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
    aya_build::build_ebpf(
        [Package {
            name: "wardyn-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../wardyn-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(), // nightly
    )?;
    Ok(())
}
