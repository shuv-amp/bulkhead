//! Pyth `PriceUpdateV2` accounts (pyth-crosschain,
//! `target_chains/solana/pyth_solana_receiver_sdk/src/price_update.rs`):
//!
//! ```text
//! [8]  discriminator  sha256("account:PriceUpdateV2")[..8]
//! [32] write_authority
//! [1|2] verification_level   Borsh enum: 0 = Partial { num_signatures: u8 }, 1 = Full
//! price_message:
//!   [32] feed_id  [8] price i64  [8] conf u64  [4] exponent i32
//!   [8] publish_time i64  [8] prev_publish_time i64  [8] ema_price i64  [8] ema_conf u64
//! [8]  posted_slot
//! ```
//!
//! Only `Full` verification is accepted. Owners: the Pyth receiver
//! (`rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ`) or its Pyth Pro-compatible
//! deployment (`rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp`).

use crate::error::VaultError;
use crate::state::Asset;
use bulkhead_core::ledger::{PricedAsset, Pricing};
use bulkhead_core::price::{conservative, is_usable};
use pinocchio::error::ProgramError;
use pinocchio::{AccountView, Address};

pub const RECEIVER: Address = Address::new_from_array([
    12, 183, 250, 187, 82, 247, 166, 72, 187, 91, 49, 125, 154, 1, 139, 144, 87, 203, 2, 71, 116,
    250, 254, 1, 230, 196, 223, 152, 204, 56, 88, 129,
]);
pub const RECEIVER_PRO: Address = Address::new_from_array([
    12, 183, 250, 122, 93, 166, 40, 251, 172, 169, 154, 234, 153, 247, 191, 59, 220, 54, 137, 104,
    96, 42, 191, 65, 77, 78, 139, 165, 103, 187, 176, 191,
]);
pub const DISCRIMINATOR: [u8; 8] = [34, 241, 35, 99, 157, 126, 244, 205];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceUpdate {
    pub feed_id: [u8; 32],
    pub price: i64,
    pub conf: u64,
    pub expo: i32,
    pub publish_time: i64,
    pub ema_price: i64,
}

/// Parses a fully verified price update; `None` for anything else.
pub fn parse(d: &[u8]) -> Option<PriceUpdate> {
    if d.len() < 8 + 32 + 1 || d[..8] != DISCRIMINATOR {
        return None;
    }
    let o = match d[40] {
        1 => 41,          // Full
        _ => return None, // Partial (or garbage): not accepted
    };
    let m = d.get(o..o + 84)?;
    let i64_at = |x: usize| i64::from_le_bytes(m[x..x + 8].try_into().unwrap());
    Some(PriceUpdate {
        feed_id: m[0..32].try_into().unwrap(),
        price: i64_at(32),
        conf: u64::from_le_bytes(m[40..48].try_into().unwrap()),
        expo: i32::from_le_bytes(m[48..52].try_into().unwrap()),
        publish_time: i64_at(52),
        ema_price: i64_at(68),
    })
}

/// How the ledger may value `asset` right now, given an optional price account.
///
/// - A record that is not allowlisted (delisted): `Unpriced`, not
///   `NotAllowlisted`. Delisting stops new borrowing at once, but the mint
///   may still secure a loan: as `NotAllowlisted` its owner could take it back
///   while the loan stayed open (`docs/09`, finding 56). Fail closed instead:
///   it counts 0 until what its owner owes is repaid. A mint with no record at
///   all never backed anything and stays `NotAllowlisted` (custody.rs).
/// - Allowlisted, but no price account, a stale or too-wide price, or a
///   non-positive price: `Unpriced` (fail closed: collateral counts 0,
///   liabilities make health unknown).
/// - An account that claims to be a Pyth update but for another feed, or at a
///   lower verification level: `BadPriceAccount` (a client bug; refuse loudly).
pub fn pricing(
    asset: &Asset,
    price: Option<&AccountView>,
    now_s: i64,
) -> Result<Pricing, ProgramError> {
    let cfg = &asset.config;
    if !cfg.allowlisted {
        return Ok(Pricing::Unpriced);
    }
    let acc = match price {
        Some(a) if a.owner() == &RECEIVER || a.owner() == &RECEIVER_PRO => a,
        _ => return Ok(Pricing::Unpriced),
    };
    let d = acc.try_borrow()?;
    let p = parse(&d).ok_or(VaultError::BadPriceAccount)?;
    if p.feed_id != cfg.feed_id {
        return Err(VaultError::BadPriceAccount.into());
    }
    if !is_usable(
        p.price,
        p.conf,
        p.publish_time,
        now_s,
        cfg.max_age_s as i64,
        cfg.max_conf_bps,
    ) {
        return Ok(Pricing::Unpriced);
    }
    Ok(
        match conservative(p.price, p.conf, p.ema_price, cfg.conf_mult_bps) {
            Some(b) => Pricing::Priced(PricedAsset {
                lo: b.lo,
                hi: b.hi,
                expo: p.expo,
                decimals: asset.decimals,
                haircut_bps: cfg.haircut_bps,
                liability_bps: cfg.liability_bps,
            }),
            None => Pricing::Unpriced,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(
        level: &[u8],
        feed: [u8; 32],
        price: i64,
        conf: u64,
        expo: i32,
        t: i64,
        ema: i64,
    ) -> Vec<u8> {
        let mut d = DISCRIMINATOR.to_vec();
        d.extend_from_slice(&[9; 32]);
        d.extend_from_slice(level);
        d.extend_from_slice(&feed);
        d.extend_from_slice(&price.to_le_bytes());
        d.extend_from_slice(&conf.to_le_bytes());
        d.extend_from_slice(&expo.to_le_bytes());
        d.extend_from_slice(&t.to_le_bytes());
        d.extend_from_slice(&(t - 1).to_le_bytes());
        d.extend_from_slice(&ema.to_le_bytes());
        d.extend_from_slice(&7u64.to_le_bytes());
        d.extend_from_slice(&123u64.to_le_bytes());
        d
    }

    #[test]
    fn full_updates_parse_and_partial_ones_do_not() {
        let d = update(
            &[1],
            [5; 32],
            15_000_000_000,
            7_500_000,
            -8,
            1_000,
            15_100_000_000,
        );
        let p = parse(&d).unwrap();
        assert_eq!(
            (
                p.feed_id,
                p.price,
                p.conf,
                p.expo,
                p.publish_time,
                p.ema_price
            ),
            (
                [5; 32],
                15_000_000_000,
                7_500_000,
                -8,
                1_000,
                15_100_000_000
            )
        );
        let partial = update(&[0, 13], [5; 32], 1, 1, -8, 1_000, 1);
        assert!(parse(&partial).is_none());
        let mut wrong = d.clone();
        wrong[0] ^= 1;
        assert!(parse(&wrong).is_none());
    }
}
