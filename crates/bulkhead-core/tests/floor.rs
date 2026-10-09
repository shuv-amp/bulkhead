//! Floor: the abort binaries, the loader-v3 layout, snapshots and restores.
//!
//! The abort binary is also deployed through a real loader-v3 `Upgrade` in the
//! program tests (`programs/tests`). These tests catch layout mistakes first,
//! by re-stating the sBPF v3 strict ELF rules (solana-sbpf
//! `Executable::load_with_strict_parser`, SIMD-0189) independently.

use bulkhead_core::floor::*;

/// The sBPF v3 strict parser's rules, restated. Returns the text bytes.
fn strict_v3_text(elf: &[u8]) -> Result<&[u8], &'static str> {
    let u16_at = |o: usize| u16::from_le_bytes([elf[o], elf[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap());
    if elf.len() < 64 || elf[0..4] != *b"\x7fELF" || elf[4] != 2 || elf[5] != 1 || elf[6] != 1 {
        return Err("ident");
    }
    if elf[7] != 0 || elf[8] != 0 || elf[9..16] != [0; 7] {
        return Err("osabi/pad");
    }
    if u16_at(18) != 0xF7 || u32_at(20) != 1 || u64_at(32) != 64 {
        return Err("machine/version/phoff");
    }
    if u32_at(48) != 3 || u16_at(52) != 64 || u16_at(54) != 56 {
        return Err("flags/ehsize/phentsize");
    }
    let phnum = u16_at(56) as usize;
    let table_end = 64 + 56 * phnum;
    if phnum == 0 || table_end > elf.len() {
        return Err("phnum");
    }
    // Expected: optional (PF_R, vaddr 0), then (PF_X, vaddr 2^32).
    let first_flags = u32_at(64 + 4);
    let expected: &[(u32, u64)] = if first_flags == 4 {
        if phnum < 2 {
            return Err("rodata without text");
        }
        &[(4, 0), (1, 1 << 32)]
    } else {
        &[(1, 1 << 32)]
    };
    let mut offset = table_end as u64;
    let mut text = &elf[0..0];
    for (i, &(flags, vaddr)) in expected.iter().enumerate() {
        let ph = 64 + 56 * i;
        let (p_offset, p_filesz) = (u64_at(ph + 8), u64_at(ph + 32));
        if u32_at(ph) != 1 || u32_at(ph + 4) != flags || p_offset != offset {
            return Err("phdr type/flags/offset");
        }
        if p_offset >= elf.len() as u64 || p_offset % 8 != 0 {
            return Err("phdr offset range");
        }
        if u64_at(ph + 16) != vaddr || u64_at(ph + 24) != vaddr || p_filesz != u64_at(ph + 40) {
            return Err("phdr vaddr/paddr/memsz");
        }
        if p_filesz > elf.len() as u64 - p_offset || p_filesz % 8 != 0 || p_filesz >= 1 << 32 {
            return Err("phdr size");
        }
        text = &elf[p_offset as usize..(p_offset + p_filesz) as usize];
        offset += p_filesz;
    }
    let entry = u64_at(24);
    if entry < 1 << 32 || entry + 8 > (1 << 32) + text.len() as u64 || entry % 8 != 0 {
        return Err("entry");
    }
    Ok(text)
}

fn insn(text: &[u8], i: usize) -> (u8, u8, u8, i32) {
    let b = &text[8 * i..8 * i + 8];
    (
        b[0],
        b[1] & 0x0f,
        b[1] >> 4,
        i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    )
}

#[test]
fn murmur3_matches_published_vectors() {
    assert_eq!(murmur3_32(b""), 0);
    assert_eq!(murmur3_32(b"hello"), 0x248b_fa47);
    assert_eq!(
        murmur3_32(b"The quick brown fox jumps over the lazy dog"),
        0x2e4f_f723
    );
    // The syscall id the abort binary calls.
    assert_eq!(murmur3_32(b"sol_log_"), 0x2075_59bd);
}

#[test]
fn abort_binary_passes_the_strict_v3_rules_and_says_why() {
    let text = strict_v3_text(&ABORT_ELF).expect("strict v3 layout");
    assert_eq!(text.len(), 5 * 8);
    assert_eq!(insn(text, 0), (0xb7, 1, 0, 0)); // mov64 r1, 0 (rodata address)
    assert_eq!(insn(text, 1), (0xb7, 2, 0, ABORT_MESSAGE.len() as i32));
    assert_eq!(insn(text, 2), (0x85, 0, 0, 0x2075_59bd)); // syscall sol_log_
    assert_eq!(insn(text, 3), (0xb7, 0, 0, FLOOR_ABORT_CODE as i32));
    assert_eq!(insn(text, 4).0, 0x95); // exit
                                       // rodata holds the message at vaddr 0.
    let ro = &ABORT_ELF[176..176 + ABORT_MESSAGE.len()];
    assert_eq!(ro, ABORT_MESSAGE);
    assert!(deployable_after_simd0500(elf_info(&ABORT_ELF)));
}

#[test]
fn minimal_abort_binary_passes_the_strict_v3_rules() {
    let text = strict_v3_text(&ABORT_ELF_MINIMAL).expect("strict v3 layout");
    assert_eq!(text.len(), 16);
    assert_eq!(insn(text, 0), (0xb7, 0, 0, FLOOR_ABORT_CODE as i32));
    assert_eq!(insn(text, 1).0, 0x95);
    assert_eq!(ABORT_ELF_MINIMAL.len(), 136);
}

#[test]
fn abort_code_is_distinctive() {
    // ASCII "FLOR"; far outside the ranges programs use for their own errors
    // (native programs start at 0/1, Anchor at 6000).
    assert_eq!(&FLOOR_ABORT_CODE.to_be_bytes(), b"FLOR");
    const _: () = assert!(FLOOR_ABORT_CODE > 1_000_000);
}

#[test]
fn only_the_exact_canonical_bytes_count_as_an_abort_binary() {
    assert!(is_canonical_abort(&ABORT_ELF));
    assert!(is_canonical_abort(&ABORT_ELF_MINIMAL));
    for i in 0..ABORT_ELF.len() {
        let mut b = ABORT_ELF;
        b[i] ^= 1;
        assert!(!is_canonical_abort(&b), "flipped byte {i} still accepted");
    }
    assert!(!is_canonical_abort(&ABORT_ELF[..ABORT_ELF.len() - 1]));
    let mut longer = ABORT_ELF.to_vec();
    longer.push(0);
    assert!(!is_canonical_abort(&longer));
    assert!(!is_canonical_abort(&[]));
}

#[test]
fn only_sbpf_v3_passes_the_simd0500_gate() {
    let mut h = ABORT_ELF_MINIMAL;
    for (flags, ok) in [
        (0u32, false),
        (1, false),
        (2, false),
        (3, true),
        (4, false),
        (5, false),
    ] {
        h[48..52].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(
            deployable_after_simd0500(elf_info(&h)),
            ok,
            "e_flags {flags}"
        );
    }
}

#[test]
fn loader_v3_headers_parse_exactly() {
    let key = [7u8; 32];
    let mut buf = vec![1, 0, 0, 0, 1];
    buf.extend_from_slice(&key);
    assert_eq!(buffer_authority(&buf), Some(Some(key)));
    buf[4] = 0;
    assert_eq!(buffer_authority(&buf), Some(None));
    buf[4] = 2;
    assert_eq!(buffer_authority(&buf), None, "bad option tag");
    assert_eq!(buffer_authority(&buf[..36]), None, "short");

    let mut pd = vec![3, 0, 0, 0];
    pd.extend_from_slice(&42u64.to_le_bytes());
    pd.push(1);
    pd.extend_from_slice(&key);
    assert_eq!(
        programdata_header(&pd),
        Some(ProgramDataHeader {
            slot: 42,
            upgrade_authority: Some(key)
        })
    );
    assert_eq!(buffer_authority(&pd), None, "programdata is not a buffer");
    assert_eq!(
        program_programdata(&pd),
        None,
        "programdata is not a program"
    );

    let mut prog = vec![2, 0, 0, 0];
    prog.extend_from_slice(&key);
    assert_eq!(program_programdata(&prog), Some(key));
    assert_eq!(programdata_header(&prog), None);
}

#[test]
fn snapshot_identity_is_exact() {
    let live = [
        0xb7, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert!(snapshot_matches(&live[..16], &live));
    assert!(
        snapshot_matches(&live[..9], &live),
        "trailing zeros may be omitted"
    );
    assert!(
        !snapshot_matches(&live[..8], &live),
        "the dropped 0x95 is not zero"
    );
    assert!(!snapshot_matches(&[], &live));
    let mut tail = live;
    tail[19] = 1;
    assert!(!snapshot_matches(&live[..16], &tail), "nonzero tail");
    let longer = [0u8; 21];
    assert!(
        !snapshot_matches(&longer, &live),
        "buffer longer than programdata"
    );
}

/// Pins found by mutation testing (docs/09 §6): truncated headers are never
/// parsed, a longer program account is still read, and an empty buffer is
/// never a snapshot, even of an all-zero region.
#[test]
fn truncated_loader_headers_are_rejected() {
    // A buffer header cut short after its option tag.
    assert_eq!(buffer_authority(&[1, 0, 0, 0, 0]), None);
    assert_eq!(
        buffer_authority(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        None
    );
    // A programdata header cut short after its option tag.
    let mut pd = vec![3, 0, 0, 0];
    pd.extend_from_slice(&7u64.to_le_bytes());
    pd.push(0);
    assert_eq!(
        programdata_header(&pd),
        None,
        "13 bytes, option None: still too short"
    );
    pd.resize(44, 0);
    assert_eq!(programdata_header(&pd), None);
    pd.resize(45, 0);
    assert!(programdata_header(&pd).is_some());
    // A program account with trailing bytes is still a program account.
    let mut prog = vec![2, 0, 0, 0];
    prog.extend_from_slice(&[9; 32]);
    prog.push(0);
    assert_eq!(program_programdata(&prog), Some([9; 32]));
}

#[test]
fn an_empty_buffer_is_never_a_snapshot() {
    assert!(!snapshot_matches(&[], &[]));
    assert!(!snapshot_matches(&[], &[0, 0, 0, 0]));
}

/// Finding 88: a snapshot is at least as long as the live ELF says it is.
#[test]
fn elf_extent_is_the_declared_length_and_bounds_a_snapshot() {
    use bulkhead_core::floor::{elf_extent, snapshot_restorable, ABORT_ELF, ABORT_ELF_MINIMAL};
    for elf in [&ABORT_ELF[..], &ABORT_ELF_MINIMAL[..]] {
        assert_eq!(
            elf_extent(elf),
            Some(elf.len()),
            "the abort binaries end where they say"
        );
        // Live in a larger programdata (zero tail): the full copy restores...
        let mut live = elf.to_vec();
        live.resize(elf.len() + 4096, 0);
        assert!(snapshot_restorable(elf, &live));
        // ...so does the copy with some of the zero tail...
        assert!(snapshot_restorable(&live[..elf.len() + 100], &live));
        // ...but a copy shorter than the ELF, however identical, does not.
        assert!(!snapshot_restorable(&elf[..elf.len() - 1], &live));
        // A header whose tables run past the bytes is no ELF.
        assert_eq!(elf_extent(&elf[..elf.len() - 1]), None);
    }
    assert_eq!(
        elf_extent(b"not an elf, just bytes long enough to be read as a header.........."),
        None
    );
    assert_eq!(elf_extent(&[]), None);
}
