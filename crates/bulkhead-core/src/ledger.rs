//! The backed lane: a per-owner shadow ledger.
//!
//! Every owner (wallet or PDA that actually transferred tokens in) has up to
//! `MAX_SLOTS` positions `(mint, net)`. Deposits add what actually arrived.
//! A backed release subtracts what was paid. Unbacked releases never touch it.
//! `net < 0` (a liability) is only possible in allowlisted, priced mints.
//!
//! `backed_amount` answers: of a requested outflow of `amount` of `mint` to this
//! owner, how much can skip the limiter? The answer is the largest `b` such that
//! the owner's ledger stays sound after paying `b`:
//!
//! 1. nobody owes anything and the owner keeps `net >= 0` in this mint:
//!    always sound, no prices needed (G2: taking back your own deposit is
//!    never throttled, frozen or priced);
//! 2. the owner owes something elsewhere, and this mint is NOT allowlisted:
//!    sound while `net >= 0` (it was worth 0 as collateral, so withdrawing it
//!    cannot reduce health);
//! 3. otherwise: this mint must be priced, a new liability needs a free slot,
//!    every liability must be priced, and health after must be `>= 0` (G3).
//!
//! Health = sum of collateral at the low price times the haircut, minus
//! liabilities at the high price times the liability weight. An allowlisted
//! collateral position with no price counts as 0 (only lowers health); a
//! liability with no price makes health unknown (fail closed).
//!
//! Soundness is monotone in `b`, so the largest valid `b` is found by binary
//! search. The on-chain fast path (closed form) is differentially tested
//! against this function.

use crate::consts::MAX_SLOTS;
use crate::value::value_v;

pub type Mint = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PricedAsset {
    /// Conservative low price mantissa (collateral).
    pub lo: u128,
    /// Conservative high price mantissa (liabilities).
    pub hi: u128,
    pub expo: i32,
    pub decimals: u8,
    /// Collateral weight, e.g. 8_500 = count 85% of value.
    pub haircut_bps: u32,
    /// Liability weight, e.g. 10_500 = count 105% of value.
    pub liability_bps: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pricing {
    /// Not on the allowlist: worth 0 as collateral, never borrowable through the backed lane.
    NotAllowlisted,
    /// On the allowlist but no valid price was supplied for this call.
    Unpriced,
    Priced(PricedAsset),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub mint: Mint,
    pub net: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// A backed debit larger than what `backed_amount` allowed.
    Unsound,
    /// No free slot for a new position.
    NoSlot,
    /// Stored positions contain a duplicate mint or a zero entry.
    Malformed,
}

/// Signed value of one position; `None` means unknown (fail closed).
pub fn contribution(net: i128, pricing: &Pricing) -> Option<i128> {
    if net == 0 {
        return Some(0);
    }
    if net > 0 {
        return Some(match pricing {
            Pricing::Priced(a) => {
                match value_v(net as u128, a.lo, a.expo, a.decimals, a.haircut_bps, false) {
                    Some(v) => v as i128,
                    None => 0, // overflow on collateral: count it as worthless
                }
            }
            _ => 0,
        });
    }
    match pricing {
        Pricing::Priced(a) => value_v(
            net.unsigned_abs(),
            a.hi,
            a.expo,
            a.decimals,
            a.liability_bps,
            true,
        )
        .map(|v| -(v as i128)),
        _ => None,
    }
}

/// Fixed-capacity ledger for one owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ledger {
    slots: [Option<Position>; MAX_SLOTS],
}

impl Default for Ledger {
    fn default() -> Self {
        Ledger {
            slots: [None; MAX_SLOTS],
        }
    }
}

impl Ledger {
    /// Rebuild a ledger from stored positions (how the program loads the
    /// Backing account). Rejects duplicates, zero entries and overflow of slots.
    pub fn from_positions(positions: &[(Mint, i128)]) -> Result<Ledger, LedgerError> {
        let mut l = Ledger::default();
        if positions.len() > MAX_SLOTS {
            return Err(LedgerError::NoSlot);
        }
        for (i, (m, net)) in positions.iter().enumerate() {
            if *net == 0 || positions[..i].iter().any(|(k, _)| k == m) {
                return Err(LedgerError::Malformed);
            }
            l.slots[i] = Some(Position {
                mint: *m,
                net: *net,
            });
        }
        Ok(l)
    }

    pub fn positions(&self) -> impl Iterator<Item = &Position> {
        self.slots.iter().flatten()
    }

    pub fn len(&self) -> usize {
        self.positions().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn net(&self, mint: &Mint) -> i128 {
        self.positions()
            .find(|p| &p.mint == mint)
            .map(|p| p.net)
            .unwrap_or(0)
    }

    pub fn has_liability(&self) -> bool {
        self.positions().any(|p| p.net < 0)
    }

    fn slot_of(&self, mint: &Mint) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| matches!(s, Some(p) if &p.mint == mint))
    }

    fn set(&mut self, mint: Mint, net: i128) -> Result<(), LedgerError> {
        match self.slot_of(&mint) {
            Some(i) => {
                self.slots[i] = if net == 0 {
                    None
                } else {
                    Some(Position { mint, net })
                };
                Ok(())
            }
            None if net == 0 => Ok(()),
            None => match self.slots.iter().position(|s| s.is_none()) {
                Some(i) => {
                    self.slots[i] = Some(Position { mint, net });
                    Ok(())
                }
                None => Err(LedgerError::NoSlot),
            },
        }
    }

    /// Record tokens that actually arrived. Returns `false` if there was no
    /// slot: the deposit still happens, the owner just gets no backing for it
    /// (their later withdrawal of it goes through the limiter). Conservative.
    pub fn credit(&mut self, mint: Mint, received: u64) -> bool {
        let n = self.net(&mint);
        match n.checked_add(received as i128) {
            Some(v) => self.set(mint, v).is_ok(),
            None => false,
        }
    }

    /// Health over all positions (see module docs).
    pub fn health<F: Fn(&Mint) -> Pricing>(&self, lookup: &F) -> Option<i128> {
        health_iter(self.positions().copied(), lookup)
    }

    /// Largest `b <= amount` that may be paid through the backed lane.
    pub fn backed_amount<F: Fn(&Mint) -> Pricing>(
        &self,
        mint: &Mint,
        amount: u64,
        lookup: &F,
    ) -> u64 {
        if amount == 0 {
            return 0;
        }
        let n = self.net(mint);
        let others_liab = self.positions().any(|p| &p.mint != mint && p.net < 0);
        if !others_liab && n >= amount as i128 {
            return amount; // G2 fast path: no prices touched
        }
        let h_others = health_iter(
            self.positions().filter(|p| &p.mint != mint).copied(),
            lookup,
        );
        let pj = lookup(mint);
        let present = self.slot_of(mint).is_some();
        let full = self.len() >= MAX_SLOTS;
        let valid = |b: u64| -> bool {
            let after = n - b as i128;
            if !others_liab && after >= 0 {
                return true;
            }
            if after >= 0 && matches!(pj, Pricing::NotAllowlisted) {
                return true;
            }
            if !matches!(pj, Pricing::Priced(_)) {
                return false;
            }
            if after < 0 && !present && full {
                return false;
            }
            let h = match h_others {
                Some(h) => h,
                None => return false,
            };
            match contribution(after, &pj) {
                // Overflow only happens when both terms share a sign; positive overflow is sound.
                Some(c) => h.checked_add(c).map(|t| t >= 0).unwrap_or(c > 0),
                None => false,
            }
        };
        // No collateral anywhere (no position above zero): every payout would
        // create or deepen a liability nothing covers, so nothing is backed.
        // Exactly what the search below returns, without ~64 valuations; the
        // common case of a payout to someone who deposited nothing.
        if self.positions().all(|p| p.net <= 0) {
            return 0;
        }
        // The answer is the largest valid b <= amount: if `amount` itself is
        // valid, it is the answer by definition.
        if valid(amount) {
            return amount;
        }
        // Otherwise search [0, amount - 1]. The valid set is an interval except
        // where a collateral value overflows u128 (it then counts 0, fail
        // closed); there the search may stop below the true maximum, which is
        // conservative. The Python reference runs the identical search.
        let (mut lo, mut hi) = (0u64, amount - 1);
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if valid(mid) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    }

    /// Apply a backed payout of `b`. Re-checks soundness so a program bug that
    /// skips `backed_amount` cannot silently create an unsound ledger.
    pub fn debit_backed<F: Fn(&Mint) -> Pricing>(
        &mut self,
        mint: Mint,
        b: u64,
        lookup: &F,
    ) -> Result<(), LedgerError> {
        if b == 0 {
            return Ok(());
        }
        if self.backed_amount(&mint, b, lookup) != b {
            return Err(LedgerError::Unsound);
        }
        let n = self.net(&mint);
        self.set(mint, n - b as i128)
    }
}

fn health_iter<I: Iterator<Item = Position>, F: Fn(&Mint) -> Pricing>(
    it: I,
    lookup: &F,
) -> Option<i128> {
    let mut total: i128 = 0;
    for p in it {
        let c = contribution(p.net, &lookup(&p.mint))?;
        total = total.checked_add(c)?;
    }
    Some(total)
}
