//! Exact integer valuation.
//!
//! `value_v(amount, mantissa, expo, decimals, weight_bps, round_up)` is the USD
//! value of `amount` base units at price `mantissa * 10^expo`, multiplied by
//! `weight_bps / 10_000`, in units of 1e-18 USD. Collateral is valued with
//! `round_up = false` (floor); liabilities with `round_up = true` (ceil).
//! Any overflow returns `None`, which every caller treats as fail-closed.

use crate::consts::{BPS, VALUE_DECIMALS};
use crate::math::{ceil_div_u128, pow10_u128};

pub fn value_v(
    amount: u128,
    mantissa: u128,
    expo: i32,
    decimals: u8,
    weight_bps: u32,
    round_up: bool,
) -> Option<u128> {
    if amount == 0 || mantissa == 0 || weight_bps == 0 {
        return Some(0);
    }
    let mut num = amount.checked_mul(mantissa)?;
    num = num.checked_mul(weight_bps as u128)?;
    // i64 so an extreme exponent cannot overflow the shift itself.
    let shift = VALUE_DECIMALS as i64 + expo as i64 - decimals as i64;
    if shift.unsigned_abs() > 38 {
        return None; // 10^39 does not fit in u128
    }
    let den;
    if shift >= 0 {
        num = num.checked_mul(pow10_u128(shift as u32)?)?;
        den = BPS;
    } else {
        den = BPS.checked_mul(pow10_u128((-shift) as u32)?)?;
    }
    let v = if round_up {
        ceil_div_u128(num, den)
    } else {
        num / den
    };
    if v > i128::MAX as u128 {
        None
    } else {
        Some(v)
    }
}
