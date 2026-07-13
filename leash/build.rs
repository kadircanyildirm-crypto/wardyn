// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compile the `leash-ebpf` crate for the BPF target (via aya-build, using the
//! nightly toolchain) and place the object in OUT_DIR, where src/main.rs picks it
//! up with include_bytes_aligned!.
use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf(
        [Package {
            name: "leash-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../leash-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(), // nightly
    )?;
    Ok(())
}
