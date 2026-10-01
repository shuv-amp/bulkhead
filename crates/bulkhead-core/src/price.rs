//! Conservative prices from a Pyth-style update (spot, confidence, EMA).
//!
//! `lo = min(spot, ema) - k` and `hi = max(spot, ema) + k` with
//! `k = ceil(conf * conf_mult_bps / 10_000)`. Collateral is valued at `lo`,
//! liabilities at `hi`. A one-block spike in spot cannot raise `lo` or lower
//! `hi`: the attacker must also move the EMA and keep the confidence tight.
//! The program checks feed id, owner and verification level before calling here.

use crate::consts::BPS;
use crate::math::ceil_div_u128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub lo: u128,
    pub hi: u128,
}

pub fn conservative(price: i64, conf: u64, ema: i64, conf_mult_bps: u32) -> Option<Bounds> {
    if price <= 0 || ema <= 0 {
        return None;
    }
    let k = ceil_div_u128(conf as u128 * conf_mult_bps as u128, BPS);
    let low = price.min(ema) as u128;
    let high = price.max(ema) as u128;
    let lo = low.saturating_sub(k);
    let hi = high.checked_add(k)?;
    Some(Bounds { lo, hi })
}

/// Freshness and confidence gate applied before a price may be used at all.
pub fn is_usable(
    price: i64,
    conf: u64,
    publish_time: i64,
    now: i64,
    max_age_s: i64,
    max_conf_bps: u32,
) -> bool {
    // `checked_sub` rejects a publish time that would overflow the age
    // (for example `now = i64::MAX` and a negative publish time). A future
    // publish time is a negative age and is unusable too.
    let Some(age) = now.checked_sub(publish_time) else {
        return false;
    };
    if price <= 0 || age < 0 || age > max_age_s {
        return false;
    }
    conf as u128 * BPS <= max_conf_bps as u128 * price as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_age_that_would_overflow_is_unusable() {
        assert!(!is_usable(1, 0, -1, i64::MAX, 10, 10_000));
        assert!(!is_usable(1, 0, 100, 90, 10, 10_000));
        assert!(is_usable(1, 0, 100, 105, 10, 10_000));
    }
}
