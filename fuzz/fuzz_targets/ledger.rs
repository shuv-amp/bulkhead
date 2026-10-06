//! The backed lane at full width: random ledgers (up to 8 mints, any signed
//! amounts) and prices. `backed_amount` never exceeds the request, debiting
//! exactly that amount is always accepted (the program debits what it pays),
//! and asking again for what was granted grants it again.
#![no_main]
use arbitrary::Arbitrary;
use bulkhead_core::ledger::{Ledger, PricedAsset, Pricing};
use libfuzzer_sys::fuzz_target;

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
    prices: [Price; 4],
    mint: u8,
    amount: u64,
}

fn mint(i: u8) -> [u8; 32] {
    [i % 4 + 1; 32]
}

fuzz_target!(|input: Input| {
    let mut seen = Vec::new();
    let mut positions = Vec::new();
    for (m, net) in input.positions.into_iter().take(8) {
        let k = mint(m);
        if net != 0 && !seen.contains(&k) {
            seen.push(k);
            positions.push((k, net as i128));
        }
    }
    let Ok(ledger) = Ledger::from_positions(&positions) else {
        return;
    };
    let prices = &input.prices;
    let lookup = |m: &[u8; 32]| {
        let p = &prices[(m[0] as usize - 1) % 4];
        if !p.allowlisted {
            return Pricing::NotAllowlisted;
        }
        if !p.priced {
            return Pricing::Unpriced;
        }
        Pricing::Priced(PricedAsset {
            lo: p.lo as u128,
            hi: p.lo as u128 + p.spread as u128,
            expo: (p.expo % 19) as i32,
            decimals: p.decimals % 19,
            haircut_bps: (p.haircut_bps % 10_001) as u32,
            liability_bps: 10_000 + (p.liability_extra_bps % 10_001) as u32,
        })
    };
    let m = mint(input.mint);
    let backed = ledger.backed_amount(&m, input.amount, &lookup);
    assert!(backed <= input.amount);
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
