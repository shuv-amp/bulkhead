//! Loader-v3 and ELF header parsers on arbitrary bytes: they never panic,
//! `snapshot_matches` is exactly "upgrading from this buffer leaves the region
//! unchanged" (copy the buffer, zero the rest), as loader-v3 does, and
//! `elf_extent` agrees with the same rules restated in u128, which cannot
//! overflow and read only inside the input.
#![no_main]
use bulkhead_core::floor::{
    buffer_authority, deployable_after_simd0500, elf_extent, elf_info, program_programdata,
    programdata_header, snapshot_matches, snapshot_restorable,
};
use libfuzzer_sys::fuzz_target;

// Little-endian field at `at`; the caller has checked it lies inside `e`.
fn le(e: &[u8], at: u128, n: usize) -> u128 {
    let at = at as usize;
    e[at..at + n]
        .iter()
        .rev()
        .fold(0, |v, &b| v << 8 | b as u128)
}

// Below sBPF v3, the furthest byte the header, both tables, every segment and
// every section (NOBITS too, finding 115) occupy; None if `e` has too many or
// too small table entries, or if any of them ends past `e`. From v3 (finding
// 116), only the header, the program header table (56-byte entries; none if
// empty), its first segment, and the second if the first is PF_R. None too if
// `e` is not a 64-bit little-endian ELF.
fn extent(e: &[u8]) -> Option<usize> {
    if e.len() < 64 || e[..4] != *b"\x7fELF" || e[4] != 2 || e[5] != 1 {
        return None;
    }
    let len = e.len() as u128;
    if le(e, 0x30, 4) >= 3 {
        let (phoff, phnum) = (le(e, 0x20, 8), le(e, 0x38, 2));
        let end = if phnum == 0 { 64 } else { 64.max(phoff + phnum * 56) };
        if end > len {
            return None;
        }
        let read = if phnum == 0 { 0 } else if le(e, phoff + 4, 4) == 4 { 2 } else { 1 };
        let end = (0..read.min(phnum))
            .map(|i| phoff + i * 56)
            .fold(end, |end, h| end.max(le(e, h + 8, 8) + le(e, h + 32, 8)));
        return (end <= len).then_some(end as usize);
    }
    let (phoff, shoff) = (le(e, 0x20, 8), le(e, 0x28, 8));
    let (phentsize, phnum) = (le(e, 0x36, 2), le(e, 0x38, 2));
    let (shentsize, shnum) = (le(e, 0x3a, 2), le(e, 0x3c, 2));
    if phnum > 64 || shnum > 1024 || (phnum > 0 && phentsize < 56) || (shnum > 0 && shentsize < 64)
    {
        return None;
    }
    let mut end = 64;
    if phnum > 0 {
        end = end.max(phoff + phnum * phentsize);
    }
    if shnum > 0 {
        end = end.max(shoff + shnum * shentsize);
    }
    // Every entry read below lies inside its table, so inside `e` from here.
    if end > len {
        return None;
    }
    for h in (0..phnum).map(|i| phoff + i * phentsize) {
        end = end.max(le(e, h + 8, 8) + le(e, h + 32, 8));
    }
    for h in (0..shnum).map(|i| shoff + i * shentsize) {
        end = end.max(le(e, h + 24, 8) + le(e, h + 32, 8));
    }
    (end <= len).then_some(end as usize)
}

// Raw bytes, so a seed file means exactly what it says: a 2-byte
// little-endian length, then the account data `a` (that many bytes, or all
// that is left), then the region `b`.
fuzz_target!(|data: &[u8]| {
    let Some((len, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let (a, b) = rest.split_at((u16::from_le_bytes(*len) as usize).min(rest.len()));
    let _ = deployable_after_simd0500(elf_info(a));
    let _ = buffer_authority(a);
    let _ = program_programdata(a);
    let _ = programdata_header(a);
    let mut upgraded = b.to_vec();
    let identity = !a.is_empty() && a.len() <= b.len() && {
        upgraded[..a.len()].copy_from_slice(a);
        upgraded[a.len()..].iter_mut().for_each(|x| *x = 0);
        upgraded == b
    };
    assert_eq!(snapshot_matches(a, b), identity);
    let [_, live] = [a, b].map(|x| {
        let e = extent(x);
        assert_eq!(elf_extent(x), e);
        // A copy cut at the extent says the same: nothing the extent counts lies past it.
        // Nor do zeros after the bytes change it, as when anyone extends the
        // programdata (finding 116).
        if let Some(e) = e {
            assert_eq!(elf_extent(&x[..e]), Some(e));
            assert_eq!(elf_extent(&[x, &[0; 4096]].concat()), Some(e));
        }
        e
    });
    assert_eq!(
        snapshot_restorable(a, b),
        identity && live.is_some_and(|e| a.len() >= e)
    );
});
