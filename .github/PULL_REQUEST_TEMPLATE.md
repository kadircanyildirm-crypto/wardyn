<!-- Thanks for contributing to Leash! -->

## What & why

<!-- What does this change and why? Link any issue: "Fixes #123". -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Docs / presets
- [ ] Refactor / chore

## How was it tested?

<!-- Runtime enforcement can't be tested in CI — say what you ran. -->

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo build` (warning-free, incl. the eBPF crate)
- [ ] `cargo test`
- [ ] Manually exercised on a kernel: <!-- e.g. 6.8, BPF LSM on, --enforce -->

## Checklist

- [ ] Policy semantics changes have matching unit tests in `policy.rs`.
- [ ] Kernel-offset changes update `OFFSETS_KERNEL` and were regenerated with `scripts/kernel-offsets.sh`.
- [ ] `CHANGELOG.md` updated under **Unreleased** if user-facing.
