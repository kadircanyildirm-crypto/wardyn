// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runtime resolution of the kernel struct offsets the LSM file/exec matcher
//! needs (`file->f_path.dentry`, `dentry->d_name.name`, `dentry->d_parent`,
//! `linux_binprm->file`).
//!
//! The eBPF hooks read these `dentry` fields by byte offset. Those offsets are
//! kernel-version specific (`struct file`/`struct dentry` have been repacked
//! several times), and true CO-RE — compiler-emitted BTF relocations — is not
//! available for the Rust BPF target (a `rustc`/LLVM limitation, not an aya one).
//! So we do the portable thing: parse the running kernel's own BTF blob
//! (`/sys/kernel/btf/vmlinux`) in userspace and publish the resolved offsets to
//! the eBPF program via `CONFIG`. If anything here fails, the caller falls back
//! to the built-in kernel-6.8 constants, so this is strictly a portability win
//! with no regression risk.
//!
//! This is a deliberately tiny, dependency-free BTF reader: it walks the type
//! section far enough to find named STRUCT/UNION types and their member bit
//! offsets, and nothing more.

/// The four LSM struct offsets the name matcher needs, in bytes.
#[derive(Debug, Clone, Copy)]
pub struct LsmOffsets {
    /// `offsetof(file, f_path) + offsetof(path, dentry)`.
    pub file_dentry: u32,
    /// `offsetof(dentry, d_name) + offsetof(qstr, name)`.
    pub dentry_name: u32,
    /// `offsetof(dentry, d_parent)`.
    pub dentry_parent: u32,
    /// `offsetof(linux_binprm, file)`.
    pub bprm_file: u32,
}

/// The extra offsets identity matching needs (M6): enough to read an object's
/// `(dev, ino)` and the access an open asked for.
#[derive(Debug, Clone, Copy)]
pub struct IdentityOffsets {
    /// `offsetof(file, f_inode)`.
    pub file_inode: u32,
    /// `offsetof(file, f_mode)`.
    pub file_mode: u32,
    /// `offsetof(inode, i_ino)`.
    pub inode_ino: u32,
    /// `offsetof(inode, i_sb)`.
    pub inode_sb: u32,
    /// `offsetof(super_block, s_dev)`.
    pub sb_dev: u32,
    /// `offsetof(dentry, d_inode)` — for the ancestor walk.
    pub dentry_inode: u32,
}

/// Everything resolved from the running kernel's BTF in one pass.
#[derive(Debug, Clone, Copy)]
pub struct KernelOffsets {
    pub lsm: LsmOffsets,
    /// `None` when the kernel's BTF did not yield the inode fields. Name
    /// matching still works; identity rules are reported as unavailable rather
    /// than quietly enforcing nothing.
    pub identity: Option<IdentityOffsets>,
}

/// Resolve the kernel struct offsets from `/sys/kernel/btf/vmlinux`.
///
/// Returns a *reason* on failure rather than a bare `None`. The reason is not
/// decoration: when this fails, file and exec enforcement silently falls back to
/// offsets baked in for one kernel, and "could not resolve" with nothing after
/// it leaves an operator no way to tell a missing BTF blob from a struct that
/// was renamed three releases ago.
pub fn resolve_offsets() -> Result<KernelOffsets, String> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("reading /sys/kernel/btf/vmlinux: {e}"))?;
    let btf = Btf::parse(&data).ok_or("/sys/kernel/btf/vmlinux is not parseable BTF")?;

    let need = |s: &str, m: &str| -> Result<u32, String> {
        btf.member_offset(s, m)
            .ok_or_else(|| format!("`struct {s}` has no member `{m}` in this kernel's BTF"))
    };

    let lsm = LsmOffsets {
        file_dentry: need("file", "f_path")? + need("path", "dentry")?,
        dentry_name: need("dentry", "d_name")? + need("qstr", "name")?,
        dentry_parent: need("dentry", "d_parent")?,
        bprm_file: need("linux_binprm", "file")?,
    };
    // Sanity gate: these are small in-struct offsets. A bad parse that yields an
    // absurd number must fall back rather than publish a garbage probe offset.
    // `dentry_parent` is the one that can legitimately be 0 on some layouts, so
    // it is bounded but not required to be non-zero.
    for (name, v) in [
        ("file->f_path.dentry", lsm.file_dentry),
        ("dentry->d_name.name", lsm.dentry_name),
        ("linux_binprm->file", lsm.bprm_file),
    ] {
        if v == 0 || v >= 8192 {
            return Err(format!("implausible offset for {name}: {v}"));
        }
    }
    if lsm.dentry_parent >= 8192 {
        return Err(format!(
            "implausible offset for dentry->d_parent: {}",
            lsm.dentry_parent
        ));
    }

    // Identity is optional: a kernel that hides these still gets name matching.
    let identity = (|| {
        Some(IdentityOffsets {
            file_inode: btf.member_offset("file", "f_inode")?,
            file_mode: btf.member_offset("file", "f_mode")?,
            inode_ino: btf.member_offset("inode", "i_ino")?,
            inode_sb: btf.member_offset("inode", "i_sb")?,
            sb_dev: btf.member_offset("super_block", "s_dev")?,
            dentry_inode: btf.member_offset("dentry", "d_inode")?,
        })
    })()
    .filter(|i| {
        // Same gate. `f_mode` and `i_ino` can sit at offset 0 in principle, so
        // only the upper bound is enforced for those.
        [
            i.file_inode,
            i.file_mode,
            i.inode_ino,
            i.inode_sb,
            i.sb_dev,
            i.dentry_inode,
        ]
        .iter()
        .all(|&v| v < 8192)
    });

    Ok(KernelOffsets { lsm, identity })
}

const BTF_MAGIC: u16 = 0xeb9f;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
/// The highest `BTF_KIND_*` this walker knows how to step over. Kinds are dense
/// and only ever appended, so a kernel newer than this build can introduce one
/// — and because an unskippable type aborts the *entire* lookup, that would
/// silently disable offset resolution, and with it file/exec enforcement.
const MAX_KNOWN_KIND: u32 = 19;

/// A minimal view over a parsed BTF blob: the raw type section plus the string
/// section, enough to look up a named struct member's byte offset.
struct Btf<'a> {
    types: &'a [u8],
    strings: &'a [u8],
    /// Byte offset of each type's 12-byte header, indexed by BTF type id. Type
    /// id 0 is `void` and is not stored, so `index[0]` is a placeholder.
    ///
    /// Built up front because member lookup has to *follow* type references now
    /// — a member whose name is empty is an anonymous struct or union, and the
    /// field being looked for may live inside it.
    index: Vec<usize>,
}

impl<'a> Btf<'a> {
    /// Parse just the header and slice out the type + string sections. Only
    /// little-endian BTF is supported (every BPF target Wardyn builds for is LE).
    fn parse(data: &'a [u8]) -> Option<Btf<'a>> {
        // struct btf_header { u16 magic; u8 version; u8 flags; u32 hdr_len;
        //   u32 type_off; u32 type_len; u32 str_off; u32 str_len; }
        if data.len() < 24 || rd16(data, 0)? != BTF_MAGIC {
            return None;
        }
        let hdr_len = rd32(data, 4)? as usize;
        let type_off = rd32(data, 8)? as usize;
        let type_len = rd32(data, 12)? as usize;
        let str_off = rd32(data, 16)? as usize;
        let str_len = rd32(data, 20)? as usize;

        let tstart = hdr_len.checked_add(type_off)?;
        let tend = tstart.checked_add(type_len)?;
        let sstart = hdr_len.checked_add(str_off)?;
        let send = sstart.checked_add(str_len)?;
        if tend > data.len() || send > data.len() {
            return None;
        }
        let mut btf = Btf {
            types: &data[tstart..tend],
            strings: &data[sstart..send],
            index: vec![usize::MAX],
        };
        btf.build_index()?;
        Some(btf)
    }

    /// Walk the type section once, recording where each type starts.
    fn build_index(&mut self) -> Option<()> {
        let mut p = 0usize;
        while p + 12 <= self.types.len() {
            let info = rd32(self.types, p + 4)?;
            let vlen = (info & 0xffff) as usize;
            let kind = (info >> 24) & 0x1f;
            self.index.push(p);
            p += 12 + self.trailing_len(kind, vlen)?;
        }
        Some(())
    }

    /// The `(name_off, kind, vlen, kind_flag)` header of type `id`.
    fn header(&self, id: u32) -> Option<(u32, u32, usize, u32)> {
        let p = *self.index.get(id as usize)?;
        if p == usize::MAX {
            return None;
        }
        let name_off = rd32(self.types, p)?;
        let info = rd32(self.types, p + 4)?;
        Some((
            name_off,
            (info >> 24) & 0x1f,
            (info & 0xffff) as usize,
            (info >> 31) & 1,
        ))
    }

    /// The `size_or_type` word of type `id` — the referenced type for a PTR,
    /// TYPEDEF, CONST, VOLATILE or RESTRICT.
    fn type_ref(&self, id: u32) -> Option<u32> {
        let p = *self.index.get(id as usize)?;
        rd32(self.types, p + 8)
    }

    /// Follow typedefs and cv-qualifiers to the underlying type id. Anonymous
    /// members are usually plain STRUCT/UNION, but a `typedef`'d one is legal
    /// and costs nothing to handle.
    fn strip(&self, mut id: u32) -> Option<u32> {
        for _ in 0..16 {
            let (_, kind, _, _) = self.header(id)?;
            match kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT => {
                    id = self.type_ref(id)?
                }
                _ => return Some(id),
            }
        }
        None
    }

    /// Byte offset of `member` inside the first STRUCT/UNION named `struct_name`
    /// that contains it. Returns `None` if the type or member isn't found.
    fn member_offset(&self, struct_name: &str, member: &str) -> Option<u32> {
        for id in 1..self.index.len() as u32 {
            let (name_off, kind, _, _) = self.header(id)?;
            if (kind == KIND_STRUCT || kind == KIND_UNION) && self.str_eq(name_off, struct_name) {
                if let Some(bits) = self.member_bits(id, member, 0, 0) {
                    return Some(bits / 8);
                }
            }
        }
        None
    }

    /// Bit offset of `member` within type `id`, **descending into anonymous
    /// members**.
    ///
    /// The descent is the point. Linux 6.13 reorganised `struct file` and put
    /// `f_path` inside an anonymous union; a walker that only inspects direct
    /// members finds nothing, reports "no such member", and wardyn falls back to
    /// offsets baked in for 6.8 — on a kernel where they are wrong. The failure
    /// is invisible from the inside: the LSM hook reads a plausible pointer at
    /// the wrong offset, the read fails, the hook fails open, and the feed keeps
    /// looking healthy. Every kernel from 6.13 on was in that state.
    fn member_bits(&self, id: u32, member: &str, base: u32, depth: u32) -> Option<u32> {
        if depth > 8 {
            return None; // pathological nesting; give up rather than loop
        }
        let (_, kind, vlen, kind_flag) = self.header(id)?;
        if kind != KIND_STRUCT && kind != KIND_UNION {
            return None;
        }
        let p = *self.index.get(id as usize)? + 12;
        // Members: vlen × { u32 name_off; u32 type; u32 offset }.
        for i in 0..vlen {
            let m = p + i * 12;
            let mname_off = rd32(self.types, m)?;
            let mtype = rd32(self.types, m + 4)?;
            let moffset = rd32(self.types, m + 8)?;
            // With the struct's kind_flag set, `offset` packs a bitfield size in
            // the high 8 bits; the low 24 are the bit offset. Our fields are
            // never bitfields, but mask anyway for correctness.
            let bit_off = if kind_flag == 1 {
                moffset & 0x00ff_ffff
            } else {
                moffset
            };
            if self.str_eq(mname_off, member) {
                return Some(base + bit_off);
            }
            if self.str_at(mname_off).is_empty() {
                let inner = self.strip(mtype)?;
                if let Some(bits) = self.member_bits(inner, member, base + bit_off, depth + 1) {
                    return Some(bits);
                }
            }
        }
        None
    }

    /// Bytes of trailing per-type data that follow the 12-byte `btf_type` header
    /// for a given kind, so the walker can skip to the next type.
    fn trailing_len(&self, kind: u32, vlen: usize) -> Option<usize> {
        if kind > MAX_KNOWN_KIND {
            return None; // a kind newer than this build: refuse rather than guess
        }
        Some(match kind {
            1 => 4,             // INT: u32
            2 => 0,             // PTR
            3 => 12,            // ARRAY: btf_array
            4 | 5 => vlen * 12, // STRUCT/UNION: btf_member[]
            6 => vlen * 8,      // ENUM: btf_enum[]
            7 => 0,             // FWD
            8 => 0,             // TYPEDEF
            9 => 0,             // VOLATILE
            10 => 0,            // CONST
            11 => 0,            // RESTRICT
            12 => 0,            // FUNC
            13 => vlen * 8,     // FUNC_PROTO: btf_param[]
            14 => 4,            // VAR: btf_var
            15 => vlen * 12,    // DATASEC: btf_var_secinfo[]
            16 => 0,            // FLOAT
            17 => 4,            // DECL_TAG: btf_decl_tag
            18 => 0,            // TYPE_TAG
            19 => vlen * 12,    // ENUM64: btf_enum64[]
            _ => return None,   // unknown kind: can't safely skip
        })
    }

    /// The NUL-terminated string at `off`, for diagnostics.
    fn str_at(&self, off: u32) -> &str {
        let off = off as usize;
        let Some(rest) = self.strings.get(off..) else {
            return "<oob>";
        };
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        core::str::from_utf8(&rest[..end]).unwrap_or("<utf8>")
    }

    /// Whether the NUL-terminated string at `off` in the string section equals `s`.
    fn str_eq(&self, off: u32, s: &str) -> bool {
        let off = off as usize;
        if off >= self.strings.len() {
            return false;
        }
        let rest = &self.strings[off..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        rest.get(..end).is_some_and(|b| b == s.as_bytes())
    }
}

#[inline]
fn rd16(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn rd32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny BTF blob builder, so tests go through [`Btf::parse`] — the same
    /// path the kernel's own blob takes — instead of hand-populating the struct.
    #[derive(Default)]
    struct BtfBuilder {
        types: Vec<u8>,
        strings: Vec<u8>,
        next_id: u32,
    }

    impl BtfBuilder {
        fn new() -> Self {
            BtfBuilder {
                types: Vec::new(),
                strings: vec![0], // index 0 is the empty string (= anonymous)
                next_id: 1,
            }
        }

        fn intern(&mut self, s: &str) -> u32 {
            if s.is_empty() {
                return 0;
            }
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }

        /// Append a STRUCT (or UNION) with `(member name, type id, bit offset)`
        /// members and return its type id. An empty member name is anonymous.
        fn record(
            &mut self,
            kind: u32,
            name: &str,
            size: u32,
            members: &[(&str, u32, u32)],
        ) -> u32 {
            let name_off = self.intern(name);
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types
                .extend_from_slice(&((kind << 24) | members.len() as u32).to_le_bytes());
            self.types.extend_from_slice(&size.to_le_bytes());
            for (mname, mtype, bits) in members {
                let m_off = self.intern(mname);
                self.types.extend_from_slice(&m_off.to_le_bytes());
                self.types.extend_from_slice(&mtype.to_le_bytes());
                self.types.extend_from_slice(&bits.to_le_bytes());
            }
            let id = self.next_id;
            self.next_id += 1;
            id
        }

        fn build(&self) -> Vec<u8> {
            let mut d = Vec::new();
            d.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            d.push(1); // version
            d.push(0); // flags
            d.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
            d.extend_from_slice(&0u32.to_le_bytes()); // type_off
            d.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // type_len
            d.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            d.extend_from_slice(&(self.strings.len() as u32).to_le_bytes()); // str_len
            d.extend_from_slice(&self.types);
            d.extend_from_slice(&self.strings);
            d
        }
    }

    /// Hand-build a tiny BTF blob with one struct `s { a@0, b@64bits }` and check
    /// the walker resolves member bit-offsets to byte offsets.
    #[test]
    fn resolves_member_byte_offset() {
        let mut b = BtfBuilder::new();
        b.record(KIND_STRUCT, "s", 16, &[("a", 0, 0), ("b", 0, 64)]);
        let data = b.build();
        let btf = Btf::parse(&data).expect("parses");
        assert_eq!(btf.member_offset("s", "a"), Some(0));
        assert_eq!(btf.member_offset("s", "b"), Some(8));
        assert_eq!(btf.member_offset("s", "c"), None);
        assert_eq!(btf.member_offset("t", "a"), None);
    }

    /// The kernel-6.13 shape, reduced: `f_path` is not a member of `struct file`
    /// at all — it is a member of an anonymous union that is.
    ///
    /// This is the regression test for a silent failure that had been live on
    /// every kernel from 6.13 onward: the resolver reported "no such member",
    /// wardyn fell back to offsets baked in for 6.8, the LSM hook read the wrong
    /// words, every read failed, the hook failed open, and file and exec
    /// enforcement was off while the feed still looked healthy.
    #[test]
    fn descends_into_anonymous_members() {
        let mut b = BtfBuilder::new();
        let path = b.record(KIND_STRUCT, "path", 16, &[("mnt", 0, 0), ("dentry", 0, 64)]);
        let anon = b.record(KIND_UNION, "", 16, &[("f_path", path, 0)]);
        b.record(
            KIND_STRUCT,
            "file",
            192,
            &[("f_mode", 0, 32), ("", anon, 512), ("f_pos", 0, 896)],
        );
        let data = b.build();
        let btf = Btf::parse(&data).expect("parses");

        assert_eq!(btf.member_offset("file", "f_mode"), Some(4));
        assert_eq!(btf.member_offset("path", "dentry"), Some(8));
        // The whole point: byte 64, reached only by descending.
        assert_eq!(btf.member_offset("file", "f_path"), Some(64));
        // And a member that genuinely is not there is still not there.
        assert_eq!(btf.member_offset("file", "f_nonesuch"), None);
    }

    /// An anonymous member two levels deep still resolves, and a member of a
    /// *named* nested struct does not leak into the parent's namespace — C
    /// scoping, which the descent must not flatten.
    #[test]
    fn descent_respects_c_scoping() {
        let mut b = BtfBuilder::new();
        let inner = b.record(KIND_STRUCT, "", 8, &[("deep", 0, 0)]);
        let middle = b.record(KIND_UNION, "", 8, &[("", inner, 0)]);
        let named = b.record(KIND_STRUCT, "named", 8, &[("hidden", 0, 0)]);
        b.record(
            KIND_STRUCT,
            "outer",
            32,
            &[("", middle, 128), ("sub", named, 192)],
        );
        let data = b.build();
        let btf = Btf::parse(&data).expect("parses");

        assert_eq!(btf.member_offset("outer", "deep"), Some(16));
        // `hidden` belongs to `named`, reached through the *named* member `sub`.
        assert_eq!(btf.member_offset("outer", "hidden"), None);
        assert_eq!(btf.member_offset("named", "hidden"), Some(0));
    }

    /// Resolve against the *running* kernel, when it exposes BTF.
    ///
    /// This is the check that was missing. Every unit test above works on a
    /// blob this file wrote itself, so the walker could pass them all and still
    /// fail on a real `vmlinux` — which is exactly what happened: enforcement
    /// silently degraded to `block~` on every kernel that was not 6.8, and no
    /// test anywhere could have noticed, because none of them had ever seen a
    /// real kernel's BTF.
    #[test]
    fn resolves_against_the_running_kernel() {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            eprintln!("skipping: this host exposes no kernel BTF");
            return;
        }
        let resolved = resolve_offsets().expect("the running kernel's BTF must resolve");
        eprintln!("lsm offsets: {:?}", resolved.lsm);
        eprintln!("identity offsets: {:?}", resolved.identity);
        assert!(
            resolved.identity.is_some(),
            "identity offsets did not resolve on this kernel"
        );
    }

    /// Forensic dump of the running kernel's `struct file` and BTF kind
    /// histogram. Not an assertion — a tool. When a new kernel breaks offset
    /// resolution, this is what says *how* it was reorganised:
    /// `cargo test -p wardyn --bin wardyn dump_running_btf -- --ignored --nocapture`
    #[test]
    #[ignore = "diagnostic, not an assertion"]
    fn dump_running_btf_shape() {
        let Ok(data) = std::fs::read("/sys/kernel/btf/vmlinux") else {
            return;
        };
        let btf = Btf::parse(&data).expect("parses");
        eprintln!(
            "types section: {} bytes, strings: {} bytes",
            btf.types.len(),
            btf.strings.len()
        );
        let mut p = 0usize;
        let mut n = 0u32;
        let mut kinds = std::collections::BTreeMap::<u32, u32>::new();
        while p + 12 <= btf.types.len() {
            let name_off = rd32(btf.types, p).unwrap();
            let info = rd32(btf.types, p + 4).unwrap();
            let vlen = (info & 0xffff) as usize;
            let kind = (info >> 24) & 0x1f;
            p += 12;
            *kinds.entry(kind).or_default() += 1;
            n += 1;
            let Some(t) = btf.trailing_len(kind, vlen) else {
                eprintln!("STOPPED at type #{n}: unknown kind {kind} (vlen={vlen})");
                break;
            };
            if (kind == KIND_STRUCT || kind == KIND_UNION) && btf.str_eq(name_off, "file") {
                eprintln!("--- struct/union `file` (#{n}, kind={kind}, {vlen} members)");
                let mut m = p;
                for _ in 0..vlen.min(80) {
                    let mn = rd32(btf.types, m).unwrap();
                    let mo = rd32(btf.types, m + 8).unwrap();
                    eprintln!("      {:>6} bits  {}", mo, btf.str_at(mn));
                    m += 12;
                }
            }
            p += t;
        }
        eprintln!("walked {n} types; kind histogram: {kinds:?}");
    }

    /// Every BTF kind the walker can meet must be skippable. An unknown kind
    /// aborts the whole lookup — not just that type — so a kernel that
    /// introduces one silently disables offset resolution and therefore file and
    /// exec enforcement. Kinds are dense and only ever appended, so the guard is
    /// simply that the highest one we know about still resolves.
    #[test]
    fn every_known_btf_kind_is_skippable() {
        let btf = Btf {
            types: &[],
            strings: &[],
            index: vec![usize::MAX],
        };
        for kind in 1..=MAX_KNOWN_KIND {
            assert!(
                btf.trailing_len(kind, 1).is_some(),
                "BTF kind {kind} cannot be skipped; offset resolution would abort on it"
            );
        }
    }
}
