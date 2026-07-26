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

/// The four LSM struct offsets, in bytes.
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

/// Resolve the LSM offsets from `/sys/kernel/btf/vmlinux`, or `None` if BTF is
/// unavailable or unparseable (the caller then keeps the built-in 6.8 offsets).
pub fn resolve_lsm_offsets() -> Option<LsmOffsets> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux").ok()?;
    let btf = Btf::parse(&data)?;

    let file_dentry = btf.member_offset("file", "f_path")? + btf.member_offset("path", "dentry")?;
    let dentry_name = btf.member_offset("dentry", "d_name")? + btf.member_offset("qstr", "name")?;
    let dentry_parent = btf.member_offset("dentry", "d_parent")?;
    let bprm_file = btf.member_offset("linux_binprm", "file")?;

    let o = LsmOffsets {
        file_dentry,
        dentry_name,
        dentry_parent,
        bprm_file,
    };
    // Sanity gate: these are small in-struct offsets. A bad parse that yields an
    // absurd number must fall back rather than publish a garbage probe offset.
    let sane = [o.file_dentry, o.dentry_name, o.dentry_parent, o.bprm_file]
        .iter()
        .all(|&v| v > 0 && v < 8192);
    sane.then_some(o)
}

const BTF_MAGIC: u16 = 0xeb9f;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;

/// A minimal view over a parsed BTF blob: the raw type section plus the string
/// section, enough to look up a named struct member's byte offset.
struct Btf<'a> {
    types: &'a [u8],
    strings: &'a [u8],
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
        Some(Btf {
            types: &data[tstart..tend],
            strings: &data[sstart..send],
        })
    }

    /// Byte offset of `member` inside the first STRUCT/UNION named `struct_name`
    /// that contains it. Returns `None` if the type or member isn't found.
    fn member_offset(&self, struct_name: &str, member: &str) -> Option<u32> {
        let mut p = 0usize;
        while p + 12 <= self.types.len() {
            let name_off = rd32(self.types, p)?;
            let info = rd32(self.types, p + 4)?;
            let _size = rd32(self.types, p + 8)?;
            let vlen = (info & 0xffff) as usize;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = (info >> 31) & 1;
            p += 12;

            let trailing = self.trailing_len(kind, vlen)?;
            if (kind == KIND_STRUCT || kind == KIND_UNION) && self.str_eq(name_off, struct_name) {
                // Members: vlen × { u32 name_off; u32 type; u32 offset }.
                let mut m = p;
                for _ in 0..vlen {
                    if m + 12 > self.types.len() {
                        return None;
                    }
                    let mname_off = rd32(self.types, m)?;
                    let moffset = rd32(self.types, m + 8)?;
                    if self.str_eq(mname_off, member) {
                        // With the struct's kind_flag set, `offset` packs a
                        // bitfield size in the high 8 bits; the low 24 are the
                        // bit offset. Our fields are never bitfields, but mask
                        // anyway for correctness.
                        let bit_off = if kind_flag == 1 {
                            moffset & 0x00ff_ffff
                        } else {
                            moffset
                        };
                        return Some(bit_off / 8);
                    }
                    m += 12;
                }
            }
            p += trailing;
        }
        None
    }

    /// Bytes of trailing per-type data that follow the 12-byte `btf_type` header
    /// for a given kind, so the walker can skip to the next type.
    fn trailing_len(&self, kind: u32, vlen: usize) -> Option<usize> {
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

    /// Hand-build a tiny BTF blob with one struct `s { a@0, b@64bits }` and check
    /// the walker resolves member bit-offsets to byte offsets.
    #[test]
    fn resolves_member_byte_offset() {
        let mut strings = vec![0u8]; // index 0 is the empty string
        let str_off = |s: &str, buf: &mut Vec<u8>| {
            let off = buf.len() as u32;
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
            off
        };
        let s_name = str_off("s", &mut strings);
        let a_name = str_off("a", &mut strings);
        let b_name = str_off("b", &mut strings);

        let mut types = Vec::new();
        // btf_type for struct s: name_off, info(kind=STRUCT<<24 | vlen=2), size=16
        types.extend_from_slice(&s_name.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 2).to_le_bytes());
        types.extend_from_slice(&16u32.to_le_bytes());
        // member a: name, type=0, offset=0 bits
        types.extend_from_slice(&a_name.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // member b: name, type=0, offset=64 bits (=> byte 8)
        types.extend_from_slice(&b_name.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&64u32.to_le_bytes());

        let btf = Btf {
            types: &types,
            strings: &strings,
        };
        assert_eq!(btf.member_offset("s", "a"), Some(0));
        assert_eq!(btf.member_offset("s", "b"), Some(8));
        assert_eq!(btf.member_offset("s", "c"), None);
        assert_eq!(btf.member_offset("t", "a"), None);
    }
}
