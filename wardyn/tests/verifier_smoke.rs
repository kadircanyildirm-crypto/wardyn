// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Hand every eBPF program in the object to the kernel verifier.
//!
//! Loading and attaching are separate steps, and they need different things:
//! loading needs `CAP_BPF` and nothing else, while attaching needs cgroup v2 for
//! the network hooks and an active BPF LSM for the file/exec ones. That gap is
//! what this test lives in — it can put all fourteen programs through the
//! verifier on a stock CI runner, on a kernel that could never attach some of
//! them.
//!
//! It exists because the alternative already failed. Every `cgroup_sock_addr`
//! program was rejected at load with
//!
//! ```text
//! At program exit the register R0 has smin=0 smax=4294967295
//! should have been in [0, 1]
//! ```
//!
//! and nothing caught it: the code compiled, clippy was clean, and the unit
//! tests never load the object. Wardyn fails open, so the result was a security
//! tool with no network enforcement whatsoever, discovered only when the
//! end-to-end workflow ran for the first time. A rejected program is not a
//! runtime edge case — it is the whole feature, absent.

use aya::programs::{CgroupSockAddr, Lsm, TracePoint};
use aya::Btf;

/// Tracepoints carry no verifier-visible return contract, but they are the bulk
/// of the observation path and a bad memory read fails here too.
const TRACEPOINTS: &[&str] = &[
    "wardyn_execve",
    "wardyn_openat",
    "wardyn_connect",
    "wardyn_fork",
    "wardyn_exit",
    "wardyn_openat2",
    "wardyn_execveat",
    "wardyn_sendto",
];

/// Must exit with `R0` in `[0, 1]`; this is the set that was rejected.
const CGROUP_PROGS: &[&str] = &["connect4", "connect6", "sendmsg4", "sendmsg6"];

/// `(program name, LSM hook)`. Must exit with `R0` in `[-4095, 0]`.
const LSM_PROGS: &[(&str, &str)] = &[
    ("file_open", "file_open"),
    ("bprm_check", "bprm_check_security"),
];

/// aya's own wording when `BPF_PROG_LOAD` comes back with a verifier log. It is
/// the discriminator between "this kernel cannot host the program" (missing BPF
/// LSM, no BTF for the hook — an environment fact) and "the kernel read the
/// program and refused it" (our bug). Only the second one may fail this test,
/// or it would go red on every runner that simply has no BPF LSM.
const VERIFIER_MARKER: &str = "Verifier output";

fn skip(reason: &str) {
    eprintln!("verifier smoke: SKIP — {reason}");
}

/// Fail on a verifier rejection; report anything else as an environment skip.
fn judge<E: std::fmt::Debug + std::fmt::Display>(what: &str, err: E, skipped: &mut Vec<String>) {
    let msg = format!("{err:?}");
    assert!(
        !msg.contains(VERIFIER_MARKER),
        "{what}: the verifier REJECTED this program — it would silently not be \
         enforced at runtime, because wardyn fails open.\n\n{msg}"
    );
    skipped.push(format!("{what}: {err}"));
}

#[test]
fn every_program_passes_the_verifier() {
    // The same object main.rs embeds, loaded the same way — built by build.rs
    // into OUT_DIR, which cargo also sets when compiling this package's tests.
    let object = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/wardyn"));
    if object.is_empty() {
        skip("built with WARDYN_SKIP_EBPF_BUILD=1 — no programs to verify");
        return;
    }
    // Loading BPF needs CAP_BPF (or root). Skipping rather than failing keeps
    // `cargo test` usable for a contributor who is not running it under sudo;
    // CI runs this test as root, where the skip cannot silently apply.
    if unsafe { libc::geteuid() } != 0 {
        skip("not root — loading eBPF needs CAP_BPF (run this test under sudo)");
        return;
    }

    let mut ebpf = aya::Ebpf::load(object).expect("loading the eBPF object (maps + relocations)");
    let mut skipped: Vec<String> = Vec::new();
    let mut verified = 0usize;

    for name in TRACEPOINTS {
        let prog: &mut TracePoint = ebpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("program `{name}` missing from the object"))
            .try_into()
            .expect("program is a tracepoint");
        match prog.load() {
            Ok(()) => verified += 1,
            Err(e) => judge(&format!("tracepoint/{name}"), &e, &mut skipped),
        }
    }

    for name in CGROUP_PROGS {
        let prog: &mut CgroupSockAddr = ebpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("program `{name}` missing from the object"))
            .try_into()
            .expect("program is a cgroup_sock_addr");
        match prog.load() {
            Ok(()) => verified += 1,
            Err(e) => judge(&format!("cgroup/{name}"), &e, &mut skipped),
        }
    }

    // The LSM programs need kernel BTF to resolve the hook's attach id. No BTF
    // means no wardyn at all, so a missing one is worth reporting loudly even
    // though it is not this test's subject.
    match Btf::from_sys_fs() {
        Ok(btf) => {
            for (name, hook) in LSM_PROGS {
                let prog: &mut Lsm = ebpf
                    .program_mut(name)
                    .unwrap_or_else(|| panic!("program `{name}` missing from the object"))
                    .try_into()
                    .expect("program is an LSM hook");
                match prog.load(hook, &btf) {
                    Ok(()) => verified += 1,
                    Err(e) => judge(&format!("lsm/{hook}"), &e, &mut skipped),
                }
            }
        }
        Err(e) => skipped.push(format!("lsm/*: kernel BTF unavailable ({e})")),
    }

    for s in &skipped {
        eprintln!("verifier smoke: skipped {s}");
    }
    eprintln!("verifier smoke: {verified} program(s) accepted by the verifier");

    // The network hooks are loadable on any kernel wardyn can run on at all, so
    // "everything was skipped" means the test proved nothing and should say so
    // rather than pass quietly.
    assert!(
        verified > 0,
        "no program was verified — the test proved nothing"
    );
}
