//! Pyth `PriceUpdateV2` parsing against the documented layout: only a Full
//! verification level is accepted, and every field is read from its offset.
#![no_main]
use bulkhead_vault::{parse_price_update, PriceUpdate};
use libfuzzer_sys::fuzz_target;

const DISC: [u8; 8] = [34, 241, 35, 99, 157, 126, 244, 205]; // sha256("account:PriceUpdateV2")[..8]

fn reference(d: &[u8]) -> Option<PriceUpdate> {
    // [8] disc, [32] write authority, [1] level (1 = Full), then the message.
    if d.len() < 41 || d[..8] != DISC || d[40] != 1 || d.len() < 41 + 84 {
        return None;
    }
    let m = &d[41..];
    let i64_at = |o: usize| i64::from_le_bytes(m[o..o + 8].try_into().unwrap());
    Some(PriceUpdate {
        feed_id: m[0..32].try_into().unwrap(),
        price: i64_at(32),
        conf: u64::from_le_bytes(m[40..48].try_into().unwrap()),
        expo: i32::from_le_bytes(m[48..52].try_into().unwrap()),
        publish_time: i64_at(52),
        ema_price: i64_at(68),
    })
}

// Raw bytes, so a seed file means exactly what it says: the low bit of the
// first byte is the flag, the rest is the account data.
fuzz_target!(|data: &[u8]| {
    let Some((&flag, rest)) = data.split_first() else {
        return;
    };
    let (with_disc, mut d) = (flag & 1 == 1, rest.to_vec());
    if with_disc && d.len() >= 8 {
        d[..8].copy_from_slice(&DISC); // reach past the discriminator
    }
    assert_eq!(parse_price_update(&d), reference(&d));
});
