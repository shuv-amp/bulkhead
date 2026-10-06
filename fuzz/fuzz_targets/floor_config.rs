//! Floor's config account: `load` never panics, and what it accepts survives
//! `store` then `load` unchanged.
#![no_main]
use bulkhead_floor::{Config, CONFIG_LEN};
use libfuzzer_sys::fuzz_target;

// Raw bytes, so a seed file means exactly what it says: the low bit of the
// first byte is the flag, the rest is the account data.
fuzz_target!(|data: &[u8]| {
    let Some((&flag, rest)) = data.split_first() else {
        return;
    };
    let (shape, mut d) = (flag & 1 == 1, rest.to_vec());
    if shape {
        d.resize(CONFIG_LEN, 0);
        d[..8].copy_from_slice(b"FLOORv01");
    }
    if let Ok(c) = Config::load(&d) {
        let mut out = vec![0u8; CONFIG_LEN];
        c.store(&mut out).unwrap();
        assert_eq!(Config::load(&out).unwrap(), c);
    }
});
