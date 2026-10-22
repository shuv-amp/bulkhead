//! Reference balance: a slow average of the vault balance (or mint supply).
//!
//! `ema_update` moves the reference at most `dt / 24h` of the way toward the
//! balance, in either direction. The step is linear,
//! `|balance - reference| * min(dt, TAU) / TAU`, truncated toward the old
//! reference, so it never overshoots the balance.
//!
//! Capacity uses `min(reference, live balance, WindowLow::low)`, so:
//! - an attacker cannot raise the limit by depositing right before an attack
//!   (the reference moves slowly), nor by depositing and withdrawing around a
//!   payout in one transaction (the low-water balance remembers the balance
//!   before the deposit);
//! - a drain shrinks the limit at once (the live balance).

use crate::consts::{LOW_WINDOW_S, TAU_S};

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

/// The lowest balance any touch saw (before its operation) in the current
/// and the previous window of `LOW_WINDOW_S`, so it always covers between one
/// and two windows of history. Capacity uses `min(reference, balance, low)`:
/// capital deposited and taken back (backed) within a transaction, or parked
/// for less than a window, cannot lift the base back to a reference still
/// lagging above what is really left (docs/09, finding 65). Unlike dropping
/// the reference itself, a withdrawal that comes straight back lowers the base
/// for at most two windows, not for a day.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowLow {
    pub prev: u64,
    pub cur: u64,
    /// `now_s.div_euclid(LOW_WINDOW_S)` of the window `cur` covers.
    pub window: i64,
}

impl WindowLow {
    /// After a touch with the balance before an operation. `initialized`:
    /// whether any touch came before (else this one starts the history).
    pub fn touch(self, balance: u64, now_s: i64, initialized: bool) -> WindowLow {
        let w = now_s.div_euclid(LOW_WINDOW_S);
        if !initialized || w > self.window.saturating_add(1) {
            // No operation since at least one whole window: the balance has
            // been what it is now throughout.
            WindowLow {
                prev: balance,
                cur: balance,
                window: w,
            }
        } else if w == self.window.saturating_add(1) {
            WindowLow {
                prev: self.cur,
                cur: balance,
                window: w,
            }
        } else {
            WindowLow {
                cur: self.cur.min(balance),
                ..self
            }
        }
    }

    pub fn low(self) -> u64 {
        self.prev.min(self.cur)
    }
}
