//! Loader-v3 and ELF header parsers on arbitrary bytes: they never panic, and
//! `snapshot_matches` is exactly "upgrading from this buffer leaves the region
//! unchanged" (copy the buffer, zero the rest), as loader-v3 does.
#![no_main]
use bulkhead_core::floor::{
    buffer_authority, deployable_after_simd0500, elf_info, program_programdata, programdata_header,
    snapshot_matches,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Vec<u8>, Vec<u8>)| {
    let (a, b) = input;
    let _ = deployable_after_simd0500(elf_info(&a));
    let _ = buffer_authority(&a);
    let _ = program_programdata(&a);
    let _ = programdata_header(&a);
    let mut upgraded = b.clone();
    let identity = !a.is_empty() && a.len() <= b.len() && {
        upgraded[..a.len()].copy_from_slice(&a);
        upgraded[a.len()..].iter_mut().for_each(|x| *x = 0);
        upgraded == b
    };
    assert_eq!(snapshot_matches(&a, &b), identity);
});
