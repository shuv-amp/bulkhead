//! Reference balance: a slow average of the vault balance (or mint supply).
//!
//! The reference moves slowly. Capacity then uses `min(reference, live balance)`,
//! so:
//! - an attacker cannot raise the limit by depositing right before an attack
//!   (the reference moves at most `dt / 24h` of the way toward the balance);
//! - a drain shrinks the limit at once, because the live balance is the cap.
//!
//! The step is linear, `(balance - reference) * min(dt, TAU) / TAU`, truncated
//! toward the old reference, so it never overshoots the balance.

use crate::consts::TAU_S;

pub fn ema_update(reference: u64, last_s: i64, balance: u64, now_s: i64, initialized: bool) -> u64 {
    if !initialized {
        return balance;
    }
    let dt = (now_s - last_s).max(0);
    let f = dt.min(TAU_S) as u128;
    let tau = TAU_S as u128;
    if balance >= reference {
        let step = (balance - reference) as u128 * f / tau;
        reference + step as u64
    } else {
        let step = (reference - balance) as u128 * f / tau;
        reference - step as u64
    }
}
