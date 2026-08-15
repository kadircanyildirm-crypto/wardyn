// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wardyn's portable core: the policy engine and the command-line parser.
//!
//! Everything here is pure logic — no eBPF, no `libc`, no Linux-only syscalls —
//! so it compiles and is tested on every host, not just the Linux machines that
//! can actually load the kernel programs. The semantics that decide what an
//! agent may read, run and reach are the part that most needs tests, and
//! trapping them inside a Linux-only binary crate meant `cargo test` could not
//! run on a contributor's macOS or Windows laptop at all.
pub mod cli;
pub mod identity;
pub mod overrides;
pub mod policy;

pub use cli::{Mode, Opts, ParseOutcome};
pub use identity::{Anchor, AnchorBase, AnchorKind};
pub use overrides::{OverrideStore, DEFAULT_TTL_DAYS};
pub use policy::{Access, Action, DenialKey, Exceptions, Policy, Verdict};
