//! Small integer helpers with explicit rounding.

/// `ceil(a / b)` for `b > 0`. Panics are impossible for `b > 0`.
#[inline]
pub fn ceil_div_u128(a: u128, b: u128) -> u128 {
    debug_assert!(b > 0);
    let q = a / b;
    if a % b == 0 {
        q
    } else {
        q + 1
    }
}

/// `10^k` if it fits in `u128` (k <= 38).
#[inline]
pub fn pow10_u128(k: u32) -> Option<u128> {
    10u128.checked_pow(k)
}
