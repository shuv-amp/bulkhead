//! Every Vault account type: `load` never panics on any bytes, and whatever it
//! accepts survives `store` then `load` unchanged (so no field is dropped,
//! truncated or misplaced). The discriminator and exact length are set half
//! the time, so the fuzzer reaches the field parsers instead of the gate.
#![no_main]
use bulkhead_vault::{Asset, Backing, Change, Protocol, Ticket, Vault};
use libfuzzer_sys::fuzz_target;

macro_rules! roundtrip {
    ($t:ty, $d:expr) => {{
        if let Ok(x) = <$t>::load($d) {
            let mut out = vec![0u8; <$t>::LEN];
            x.store(&mut out).unwrap();
            assert_eq!(
                <$t>::load(&out).unwrap(),
                x,
                "{} round trip",
                stringify!($t)
            );
        }
    }};
}

fn shaped(d: &[u8], disc: &[u8; 8], len: usize) -> Vec<u8> {
    let mut v = d.to_vec();
    v.resize(len, 0);
    v[..8].copy_from_slice(disc);
    v
}

fuzz_target!(|input: (u8, bool, Vec<u8>)| {
    let (which, shape, d) = input;
    let pick = |disc: &[u8; 8], len| {
        if shape {
            shaped(&d, disc, len)
        } else {
            d.clone()
        }
    };
    match which % 6 {
        0 => roundtrip!(Protocol, &pick(&Protocol::DISC, Protocol::LEN)),
        1 => roundtrip!(Vault, &pick(&Vault::DISC, Vault::LEN)),
        2 => roundtrip!(Asset, &pick(&Asset::DISC, Asset::LEN)),
        3 => {
            let b = pick(&Backing::DISC, Backing::LEN);
            roundtrip!(Backing, &b);
            if let Ok(x) = Backing::load(&b) {
                let _ = x.ledger(); // malformed positions are refused, never a panic
            }
        }
        4 => roundtrip!(Ticket, &pick(&Ticket::DISC, Ticket::LEN)),
        _ => roundtrip!(Change, &pick(&Change::DISC, Change::LEN)),
    }
});
