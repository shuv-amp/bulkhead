//! Exhaustive checks: every input in a small domain, no sampling.
//!
//! These cover the properties that are *pure arithmetic* (products and
//! quotients of symbolic values). Kani could not finish them in 20 minutes even
//! at small width, because SAT solvers are weakest on multiplier/divider
//! circuits (see src/proofs.rs and docs/09-VERIFICATION.md §5). Enumerating
//! every input in a domain is as rigorous as bounded model checking on that
//! domain; the domains are stated on each test. Full-width behaviour is covered
//! by the property tests, the differential runner and docs/03 §10. Two tests
//! are not arithmetic: `g2_and_fail_closed_without_prices` checks the grant
//! when no mint is priced, and `g3_backed_amount_is_exact_on_small_ledgers`
//! pins the backed amount at an edge random worlds seldom reach (Kani not
//! tried for it).

use bulkhead_core::ledger::{Ledger, Mint, PricedAsset, Pricing};
use bulkhead_core::limiter::{
    available_now, capacity_from_ref, cost_ms, request, rescale_windows, Bucket, Decision,
    LimiterParams, LimiterState,
};
use bulkhead_core::value::value_v;

/// Every capacity and window in 1..=64 ms, every amount in 0..=512:
/// `cost_ms` is exactly `ceil(u * W / C)`, i.e. never cheaper and at most one
/// millisecond of rounding.
#[test]
fn cost_is_exact_ceiling() {
    let mut n = 0u64;
    for capacity in 1..=64u64 {
        for window_ms in 1..=64i64 {
            let b = Bucket {
                capacity,
                window_ms,
            };
            for u in 0..=512u64 {
                let c = cost_ms(u, &b) as u128;
                let need = u as u128 * window_ms as u128;
                assert!(c * capacity as u128 >= need, "cheaper: {u} {b:?}");
                assert!(
                    c == 0 || (c - 1) * (capacity as u128) < need,
                    "over: {u} {b:?}"
                );
                n += 1;
            }
        }
    }
    assert_eq!(n, 64 * 64 * 513);
}

/// Every reference in 0..=2048 and every bps in 0..=10_000: the raw capacity
/// never exceeds the reference and never decreases when bps increases.
/// (Checking consecutive bps is enough: monotone steps compose.) With the Kani
/// proof `capacity_clamp_is_monotone`, a tighter (bps, floor, cap) never yields
/// more capacity.
#[test]
fn raw_capacity_is_monotone_in_bps() {
    for r in 0..=2048u64 {
        let mut prev = capacity_from_ref(r, 0, 0, 0);
        assert_eq!(prev, 0);
        for bps in 1..=10_000u16 {
            let c = capacity_from_ref(r, bps, 0, 0);
            assert!(c >= prev && c <= r, "r={r} bps={bps}");
            prev = c;
        }
        assert_eq!(prev, r, "10_000 bps is the whole reference");
    }
}

/// Every amount and mantissa in 0..=40, every exponent in -12..=0, every
/// decimals in 0..=12, and weights at and around every boundary: floor and
/// ceil are the exact floor and ceiling of the rational value, and never
/// overflow in this domain.
#[test]
fn value_rounding_is_exact() {
    let weights = [0u32, 1, 3, 5_000, 9_999, 10_000, 10_001, 15_000, 20_000];
    for amount in 0..=40u128 {
        for mantissa in 0..=40u128 {
            for expo in -12..=0i32 {
                for decimals in 0..=12u8 {
                    for &w in &weights {
                        let f = value_v(amount, mantissa, expo, decimals, w, false).unwrap();
                        let c = value_v(amount, mantissa, expo, decimals, w, true).unwrap();
                        // value = amount * mantissa * w * 10^(18 + expo - decimals) / 10^4
                        let shift = 18 + expo - decimals as i32;
                        let mut num = amount * mantissa * w as u128;
                        let mut den = 10_000u128;
                        if shift >= 0 {
                            num *= 10u128.pow(shift as u32);
                        } else {
                            den *= 10u128.pow((-shift) as u32);
                        }
                        assert!(f * den <= num && num < (f + 1) * den);
                        assert!(c * den >= num && (c == 0 || (c - 1) * den < num));
                        assert_eq!(c == f, num % den == 0);
                    }
                }
            }
        }
    }
}

fn mint(i: u8) -> Mint {
    [i; 32]
}

/// Every own deposit in 1..=64, every other position in -4..=4 (0 excluded),
/// every request in 0..=130, with no prices at all:
/// - G2: an owner who owes nothing gets exactly `min(request, deposit)` backed;
/// - fail closed: an owner who owes something gets nothing backed.
#[test]
fn g2_and_fail_closed_without_prices() {
    let no_prices = |_: &Mint| Pricing::Unpriced;
    for own in 1..=64i128 {
        for other in (-4..=4i128).filter(|&x| x != 0) {
            let l = Ledger::from_positions(&[(mint(1), own), (mint(2), other)]).unwrap();
            for a in 0..=130u64 {
                let b = l.backed_amount(&mint(1), a, &no_prices);
                if other > 0 {
                    assert_eq!(
                        b as i128,
                        (a as i128).min(own),
                        "own={own} other={other} a={a}"
                    );
                } else {
                    assert_eq!(b, 0, "own={own} other={other} a={a}");
                }
            }
        }
    }
}

/// Two priced mints. Every other position in -6..=12 and every own position
/// in -6..=12 (0 is no position), for each mint every (low, high) price in
/// (1, 1), (2, 2), (3, 3) and (1, 3) and every haircut 5_000 or 10_000 with
/// liability weight 10_000 or 15_000, every request in 0..=40: the backed
/// amount is exactly the largest `b <= request` after which the owner owes
/// nothing, or health (collateral floored at its low price and haircut,
/// debts ceiled at their high price and weight) is `>= 0` (G3); 0 if there
/// is none. In 764,280 of the 3,789,056 cases some `b` is valid and one unit
/// more leaves health at exactly -1, an edge the property test's random
/// worlds seldom reach (it missed a bound of `>= -1`). Not covered here: a
/// full ledger, unpriced or unallowlisted mints, a price or weight of 0
/// (with `hi` = 0 the no-collateral shortcut grants less than the rule;
/// docs/09 §2, fuzzing), and other exponents or decimals (`value_v` alone:
/// `value_rounding_is_exact`).
#[test]
fn g3_backed_amount_is_exact_on_small_ledgers() {
    // (low, high) price and (haircut, liability weight) of one mint.
    type Terms = ((u32, u32), (u32, u32));
    // expo = decimals - VALUE_DECIMALS, so a value is units * price * bps / 10^4.
    let priced = |((lo, hi), (h, w)): Terms| {
        Pricing::Priced(PricedAsset {
            lo: lo.into(),
            hi: hi.into(),
            expo: -18,
            decimals: 0,
            haircut_bps: h,
            liability_bps: w,
        })
    };
    let worth = |n: i128, ((lo, hi), (h, w)): Terms| -> i128 {
        if n >= 0 {
            n * i128::from(lo) * i128::from(h) / 10_000
        } else {
            -((-n * i128::from(hi) * i128::from(w) + 9_999) / 10_000)
        }
    };
    let terms: Vec<Terms> = [(1, 1), (2, 2), (3, 3), (1, 3)]
        .into_iter()
        .flat_map(|p| {
            [
                (5_000, 10_000),
                (5_000, 15_000),
                (10_000, 10_000),
                (10_000, 15_000),
            ]
            .map(|hw| (p, hw))
        })
        .collect();
    let (mut checked, mut at_minus_one) = (0u64, 0u64);
    for other in -6..=12i128 {
        for own in -6..=12i128 {
            let mut positions = vec![];
            if other != 0 {
                positions.push((mint(1), other));
            }
            if own != 0 {
                positions.push((mint(2), own));
            }
            let l = Ledger::from_positions(&positions).unwrap();
            for &t1 in &terms {
                for &t2 in &terms {
                    let lookup = |m: &Mint| priced(if *m == mint(1) { t1 } else { t2 });
                    let health = |b: i128| worth(other, t1) + worth(own - b, t2);
                    let valid = |b: i128| (other >= 0 && own - b >= 0) || health(b) >= 0;
                    // The largest valid b <= a, if any, carried from a - 1.
                    let mut best: Option<i128> = None;
                    for a in 0..=40i128 {
                        if valid(a) {
                            best = Some(a);
                        }
                        let b = l.backed_amount(&mint(2), a as u64, &lookup);
                        assert_eq!(
                            b as i128,
                            best.unwrap_or(0),
                            "other={other} own={own} {t1:?} {t2:?} a={a}"
                        );
                        checked += 1;
                        if best.is_some_and(|m| m < a && health(m + 1) == -1) {
                            at_minus_one += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, 19 * 19 * 16 * 16 * 41);
    assert_eq!(at_minus_one, 764_280);
}

/// Every pair of buckets with capacity and window in 1..=3, every sequence of
/// three requests at times 0 <= t1 <= t2 <= t3 <= 6 with amounts in 1..=4:
/// G1 holds for every interval, counting instant payouts and tickets by the
/// time they become payable.
#[test]
fn g1_holds_for_every_three_request_sequence() {
    let mut checked = 0u64;
    let mut queued = 0u64;
    let r = 1..=3u64;
    for (cs, ws, cl, wl) in r.clone().flat_map(|a| {
        let r = r.clone();
        r.clone().flat_map(move |b| {
            let r = r.clone();
            r.clone()
                .flat_map(move |c| r.clone().map(move |d| (a, b as i64, c, d as i64)))
        })
    }) {
        let p = LimiterParams {
            short: Bucket {
                capacity: cs,
                window_ms: ws,
            },
            long: Bucket {
                capacity: cl,
                window_ms: wl,
            },
            min_queue_delay_ms: 0,
            horizon_ms: 1_000,
        };
        for t1 in 0..=6i64 {
            for t2 in t1..=6 {
                for t3 in t2..=6 {
                    for u1 in 1..=4u64 {
                        for u2 in 1..=4u64 {
                            for u3 in 1..=4u64 {
                                let mut s = LimiterState::default();
                                // (request time, payable time, amount)
                                let mut paid = [(0i64, 0i64, 0u64); 3];
                                for (k, &(t, u)) in
                                    [(t1, u1), (t2, u2), (t3, u3)].iter().enumerate()
                                {
                                    let at = match request(&mut s, &p, t, u, 0).unwrap() {
                                        Decision::Instant => t,
                                        Decision::Queued { eta_ms } => {
                                            queued += 1;
                                            eta_ms
                                        }
                                    };
                                    paid[k] = (t, at, u);
                                }
                                for &(start, _, _) in &paid {
                                    for &(_, end, _) in &paid {
                                        if end < start {
                                            continue;
                                        }
                                        let sum: u128 = paid
                                            .iter()
                                            .filter(|&&(t, at, _)| t >= start && at <= end)
                                            .map(|&(_, _, u)| u as u128)
                                            .sum();
                                        let span = (end - start) as u128;
                                        for b in [p.short, p.long] {
                                            let w = b.window_ms as u128;
                                            assert!(
                                                sum * w <= b.capacity as u128 * (w + span),
                                                "{p:?} {paid:?}"
                                            );
                                        }
                                        checked += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // coverage: the domain exercises both outcomes
    assert!(queued > 0 && checked > 1_000_000);
}

/// Every backlog in 0..=200 ms, every old and new window in 1..=48 ms with the
/// new one no shorter, and every capacity pair in 1..=8 with the new one no
/// larger: a tightening applied with `rescale_windows` never raises the
/// instant room, now or at any later time up to two windows on with no
/// request in between. (Before the rescaling existed, a longer window turned
/// a drained bucket partly full; docs/09 §4.)
#[test]
fn a_tightening_never_raises_the_room() {
    let one = |capacity, window_ms| LimiterParams {
        short: Bucket {
            capacity,
            window_ms,
        },
        long: Bucket {
            capacity,
            window_ms,
        },
        min_queue_delay_ms: 0,
        horizon_ms: 0,
    };
    let now = 1_000_000i64;
    let mut n = 0u64;
    for backlog in 0..=200i64 {
        let s = LimiterState {
            tat_short_ms: now + backlog,
            tat_long_ms: now + backlog,
        };
        for wo in 1..=48i64 {
            for wn in wo..=48i64 {
                for co in 1..=8u64 {
                    let old = one(co, wo);
                    let mut sn = s;
                    rescale_windows(&mut sn, &old, &one(1, wn), now);
                    // Exactly the used fraction, rounded toward "used".
                    let bn = sn.tat_short_ms - now;
                    if backlog > 0 && wn != wo {
                        assert!(bn * wo >= backlog * wn && (bn - 1) * wo < backlog * wn);
                    } else {
                        assert_eq!(bn, backlog);
                    }
                    for cn in 1..=co {
                        let new = one(cn, wn);
                        for dt in 0..=2 * wn {
                            let later = now + dt;
                            assert!(
                                available_now(&sn, &new, later) <= available_now(&s, &old, later),
                                "backlog {backlog}, W {wo}->{wn}, C {co}->{cn}, +{dt}"
                            );
                            n += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(n > 10_000_000);
}

// ---------------------------------------------------------------------------
// The backed-amount search at the edges of the valuation (finding 140)
// ---------------------------------------------------------------------------

const A: Mint = [1; 32];
const B: Mint = [2; 32];

fn priced(lo: u128, hi: u128, haircut_bps: u32, liability_bps: u32) -> Pricing {
    Pricing::Priced(bulkhead_core::ledger::PricedAsset {
        lo,
        hi,
        expo: -18,
        decimals: 0,
        haircut_bps,
        liability_bps,
    })
}

/// Independent oracle for "paying `b` of mint `A` leaves this ledger sound":
/// build the ledger after the payment and ask `health`, never `backed_amount`.
fn sound_oracle(net_a: i128, net_b: i128, b: u64, lookup: &impl Fn(&Mint) -> Pricing) -> bool {
    let after = net_a - b as i128;
    let mut positions = Vec::new();
    if after != 0 {
        positions.push((A, after));
    }
    if net_b != 0 {
        positions.push((B, net_b));
    }
    match Ledger::from_positions(&positions) {
        Ok(l) => matches!(l.health(lookup), Some(h) if h >= 0),
        Err(_) => false,
    }
}

/// The one region where the valid set is not an interval (docs/03 §4.4): a
/// collateral whose value overflows u128 counts 0, so paying less can be
/// invalid while paying more is valid. Here `A` overflows at four units and
/// up, and one unit of `B` is owed, so exactly `n − 3 ≤ b ≤ n − 1` is valid.
/// Every `n ≤ 48` and every request up to `n + 8`: the search never returns
/// an invalid amount, never more than the true maximum (found by scanning
/// every `b`), and `debit_backed` accepts what it returns. What it returns
/// below the true maximum is pinned: exactly the requests of `n` or more,
/// which golden E7 shows for `n = 7` (the search is bisection, which cannot
/// see an island of valid amounts below an invalid one).
#[test]
fn overflow_region_search_is_sound_and_never_above_the_true_maximum() {
    let lo_a = u128::MAX / (10_000 * 4) + 1; // 4 · lo_a · 10 000 overflows u128
    let lookup = |m: &Mint| {
        if *m == A {
            priced(lo_a, lo_a, 10_000, 10_000)
        } else {
            priced(1, 1, 10_000, 10_000)
        }
    };
    assert!(value_v(3, lo_a, -18, 0, 10_000, false).is_some());
    assert!(value_v(4, lo_a, -18, 0, 10_000, false).is_none());
    let (mut checked, mut under) = (0u64, 0u64);
    for n in 1..=48i128 {
        let ledger = Ledger::from_positions(&[(A, n), (B, -1)]).unwrap();
        for a in 1..=(n as u64 + 8) {
            let b = ledger.backed_amount(&A, a, &lookup);
            let truth = (0..=a)
                .rev()
                .find(|&x| sound_oracle(n, -1, x, &lookup))
                .unwrap_or(0);
            assert!(
                b <= a && b <= truth,
                "n {n} a {a}: {b} > true maximum {truth}"
            );
            assert!(
                b == 0 || sound_oracle(n, -1, b, &lookup),
                "n {n} a {a}: {b} unsound"
            );
            let mut l2 = ledger;
            assert!(l2.debit_backed(A, b, &lookup).is_ok());
            // Where the search stops short, and where it must not.
            let island = (n - 3).max(0) as u64..=(n - 1).max(0) as u64;
            if island.contains(&a) {
                assert_eq!(b, a, "a request inside the valid island is paid in full");
            }
            if a < *island.start() {
                assert_eq!((b, truth), (0, 0));
            }
            if b < truth {
                under += 1;
                assert!(
                    a >= n as u64,
                    "n {n} a {a}: only a request past the island stops short"
                );
            }
            checked += 1;
        }
    }
    assert_eq!(checked, (1..=48u64).map(|n| n + 8).sum::<u64>());
    assert!(under > 0, "the region must be reached");
}

/// G3 maximality at full width, where no valuation overflows: positions up to
/// `u64::MAX`, prices up to 2^45, every weight extreme, with and without a
/// liability. The valid set is an interval there, so the largest sound `b` is
/// exactly what `backed_amount` returns: `b` is sound (by the independent
/// oracle) and `b + 1` is not. The property tests draw magnitudes only up to
/// 2^50 (finding 140).
#[test]
fn g3_is_maximal_at_full_width_without_overflow() {
    let mut cases = 0u64;
    for &n in &[1u64 << 40, 1 << 63, u64::MAX - 1, u64::MAX] {
        for &lo in &[1u128, 1 << 30, 1 << 45] {
            for &haircut in &[1u32, 5_000, 10_000] {
                for &(net_b, hi_b) in &[
                    (0i128, 1u128),
                    (-1, 1),
                    (-(1 << 30), 1 << 30),
                    (-(1 << 50), 1),
                ] {
                    let lookup = |m: &Mint| {
                        if *m == A {
                            priced(lo, lo + 1, haircut, 10_000)
                        } else {
                            priced(hi_b, hi_b, 10_000, 10_500)
                        }
                    };
                    // Within u128: the whole position is valued, nothing overflows.
                    assert!(value_v(n as u128, lo, -18, 0, haircut, false).is_some());
                    let mut positions = vec![(A, n as i128)];
                    if net_b != 0 {
                        positions.push((B, net_b));
                    }
                    let ledger = Ledger::from_positions(&positions).unwrap();
                    for &a in &[1u64, n - 1, n, n.saturating_add(1), u64::MAX] {
                        let b = ledger.backed_amount(&A, a, &lookup);
                        assert!(b <= a);
                        assert!(
                            b == 0 || sound_oracle(n as i128, net_b, b, &lookup),
                            "unsound: n {n} lo {lo} h {haircut} B {net_b} a {a} b {b}"
                        );
                        if b < a {
                            assert!(
                                !sound_oracle(n as i128, net_b, b + 1, &lookup),
                                "not maximal: n {n} lo {lo} h {haircut} B {net_b} a {a} b {b}"
                            );
                        }
                        let mut l2 = ledger;
                        assert!(l2.debit_backed(A, b, &lookup).is_ok());
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 4 * 3 * 3 * 4 * 5);
}
