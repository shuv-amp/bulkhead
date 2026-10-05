//! Exhaustive checks: every input in a small domain, no sampling.
//!
//! These cover the properties that are *pure arithmetic* (products and
//! quotients of symbolic values). Kani could not finish them in 20 minutes even
//! at small width, because SAT solvers are weakest on multiplier/divider
//! circuits (see src/proofs.rs and docs/09-VERIFICATION.md §5). Enumerating
//! every input in a domain is as rigorous as bounded model checking on that
//! domain; the domains are stated on each test. Full-width behaviour is covered
//! by the property tests, the differential runner and docs/03 §10.

use bulkhead_core::ledger::{Ledger, Mint, Pricing};
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
