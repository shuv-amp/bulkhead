//! Loader-v3 and ELF header parsers on arbitrary bytes: they never panic, and
//! `snapshot_matches` is exactly "upgrading from this buffer leaves the region
//! unchanged" (copy the buffer, zero the rest), as loader-v3 does.
#![no_main]
use bulkhead_core::floor::{
    buffer_authority, deployable_after_simd0500, elf_info, program_programdata, programdata_header,
    snapshot_matches,
};
use libfuzzer_sys::fuzz_target;

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
});
