//! The backed lane at full width: random ledgers (up to 8 of 9 mints, so a
//! full ledger and a mint outside it; any signed amounts) and prices.
//! `backed_amount` never exceeds the request and is sound by the rule as g3
//! restates it (not the core's code), while one unit more and the whole
//! request are not; debiting exactly that amount is always accepted (the
//! program debits what it pays), and asking again for what was granted
//! grants it again.
#![no_main]
use arbitrary::Arbitrary;
use bulkhead_core::consts::MAX_SLOTS;
use bulkhead_core::ledger::{contribution, Ledger, Mint, PricedAsset, Pricing};
use libfuzzer_sys::fuzz_target;

/// One mint more than a ledger holds: full ledgers, and a mint outside them.
const MINTS: usize = MAX_SLOTS + 1;
const _: () = assert!(MINTS <= u8::MAX as usize);

#[derive(Arbitrary, Debug)]
struct Price {
    priced: bool,
    allowlisted: bool,
    lo: u64,
    spread: u32,
    expo: i8,
    decimals: u8,
    haircut_bps: u16,
    liability_extra_bps: u16,
}

#[derive(Arbitrary, Debug)]
struct Input {
    positions: Vec<(u8, i64)>,
    prices: [Price; MINTS],
    mint: u8,
    amount: u64,
}

/// Mint `k` is `[k; 32]`, 1 ≤ k ≤ MINTS; its price is `prices[k - 1]`.
fn mint(i: u8) -> [u8; 32] {
    [i % MINTS as u8 + 1; 32]
}

/// "Sound after paying b", restated from the rules as
/// `g3_backed_amount_is_sound_and_maximal` states them (tests/properties.rs):
/// the ledger after the debit fits its slots, and owes nothing or is priced
/// and healthy; an unallowlisted mint can still be paid from its own balance.
fn sound_after(l: &Ledger, j: &Mint, b: u64, lookup: &dyn Fn(&Mint) -> Pricing) -> bool {
    let n = l.net(j);
    let after = n - b as i128;
    let mut stored: Vec<(Mint, i128)> = l
        .positions()
        .filter(|p| &p.mint != j)
        .map(|p| (p.mint, p.net))
        .collect();
    if after != 0 {
        if stored.len() >= MAX_SLOTS && n == 0 {
            return false;
        }
        stored.push((*j, after));
    }
    if !stored.iter().any(|(_, v)| *v < 0) {
        return true;
    }
    let pj = lookup(j);
    if after >= 0 && matches!(pj, Pricing::NotAllowlisted) && n >= 0 {
        return true;
    }
    if !matches!(pj, Pricing::Priced(_)) {
        return false;
    }
    let mut h: i128 = 0;
    for (m, v) in &stored {
        match contribution(*v, &lookup(m)) {
            Some(c) => match h.checked_add(c) {
                Some(x) => h = x,
                None => return c > 0,
            },
            None => return false,
        }
    }
    h >= 0
}

fuzz_target!(|input: Input| {
    let mut seen = Vec::new();
    let mut positions = Vec::new();
    for (m, net) in input.positions {
        let k = mint(m);
        if net != 0 && !seen.contains(&k) {
            seen.push(k);
            positions.push((k, net as i128));
            if positions.len() == MAX_SLOTS {
                break;
            }
        }
    }
    let ledger = Ledger::from_positions(&positions).expect("distinct, nonzero, at most MAX_SLOTS");
    let prices = &input.prices;
    let lookup = |m: &[u8; 32]| {
        let p = &prices[m[0] as usize - 1];
        if !p.allowlisted {
            return Pricing::NotAllowlisted;
        }
        if !p.priced {
            return Pricing::Unpriced;
        }
        Pricing::Priced(PricedAsset {
            lo: p.lo as u128,
            // `conservative` gives hi >= max(price, ema) >= 1: a debt is never
            // worth 0, which `backed_amount`'s no-collateral shortcut assumes.
            hi: (p.lo as u128 + p.spread as u128).max(1),
            expo: (p.expo % 19) as i32,
            decimals: p.decimals % 19,
            haircut_bps: (p.haircut_bps % 10_001) as u32,
            liability_bps: 10_000 + (p.liability_extra_bps % 10_001) as u32,
        })
    };
    let m = mint(input.mint);
    let backed = ledger.backed_amount(&m, input.amount, &lookup);
    assert!(backed <= input.amount);
    assert!(
        backed == 0 || sound_after(&ledger, &m, backed, &lookup),
        "sound"
    );
    if backed < input.amount {
        assert!(!sound_after(&ledger, &m, backed + 1, &lookup), "maximal");
        assert!(
            !sound_after(&ledger, &m, input.amount, &lookup),
            "all of it"
        );
    }
    if backed > 0 {
        assert_eq!(
            ledger.backed_amount(&m, backed, &lookup),
            backed,
            "the granted amount is granted again"
        );
        let mut after = ledger;
        after
            .debit_backed(m, backed, &lookup)
            .expect("debiting what was granted is sound");
    }
});
