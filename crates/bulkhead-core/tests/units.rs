//! Targeted unit tests. Most exist because mutation testing (cargo-mutants)
//! showed a mutant that the property tests did not catch; the others pin a
//! finding's or review item's exact figure or boundary (`docs/09` §2 lists
//! which). Properties check soundness ("never too permissive"); these pin
//! completeness and exact behavior ("permissive exactly where the spec says").

use bulkhead_core::classify::{classify_asset, classify_limits, AssetConfig, Class, LimitConfig};
use bulkhead_core::floor::{deployable_after_simd0500, elf_info};
use bulkhead_core::governance::Abdications;
use bulkhead_core::ledger::{Ledger, Mint, PricedAsset, Pricing};
use bulkhead_core::limiter::{
    capacity_base, lane_always_closed, params_from_config, rescale_windows,
};

fn mint(i: u8) -> Mint {
    [i; 32]
}

fn limits() -> LimitConfig {
    LimitConfig {
        short_bps: 200,
        short_window_s: 3600,
        long_bps: 500,
        long_window_s: 86_400,
        min_queue_delay_s: 21_600,
        short_floor: 1_000,
        long_floor: 1_000,
        short_cap: 5_000_000,
        long_cap: 0,
    }
}

// --- classification completeness -------------------------------------------

#[test]
fn caps_classify_exactly() {
    let old = limits();
    let with = |short_cap: u64, long_cap: u64| LimitConfig {
        short_cap,
        long_cap,
        ..old
    };
    assert_eq!(
        classify_limits(&old, &with(4_000_000, 0)),
        Class::Tighten,
        "lowering a nonzero cap tightens"
    );
    assert_eq!(
        classify_limits(&old, &with(5_000_000, 0)),
        Class::Tighten,
        "same cap is a no-op tighten"
    );
    assert_eq!(
        classify_limits(&old, &with(6_000_000, 0)),
        Class::Loosen,
        "raising a cap loosens"
    );
    assert_eq!(
        classify_limits(&old, &with(0, 0)),
        Class::Loosen,
        "removing a cap loosens"
    );
    assert_eq!(
        classify_limits(&old, &with(5_000_000, 1)),
        Class::Tighten,
        "adding a cap tightens"
    );
    assert_eq!(
        classify_limits(&old, &with(1, 0)),
        Class::Tighten,
        "the smallest nonzero cap tightens"
    );
}

#[test]
fn every_limit_field_classifies_in_both_directions() {
    let old = limits();
    let t = |n: LimitConfig| classify_limits(&old, &n);
    assert_eq!(
        t(LimitConfig {
            short_bps: 199,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        t(LimitConfig {
            short_bps: 201,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        t(LimitConfig {
            short_window_s: 3601,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        t(LimitConfig {
            short_window_s: 3599,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        t(LimitConfig {
            long_bps: 499,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        t(LimitConfig {
            long_bps: 501,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        t(LimitConfig {
            long_window_s: 86_401,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        t(LimitConfig {
            long_window_s: 86_399,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        t(LimitConfig {
            min_queue_delay_s: 21_601,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        t(LimitConfig {
            min_queue_delay_s: 21_599,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        t(LimitConfig {
            short_floor: 999,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        t(LimitConfig {
            short_floor: 1_001,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        t(LimitConfig {
            long_floor: 999,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        t(LimitConfig {
            long_floor: 1_001,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(t(old), Class::Tighten);
}

#[test]
fn every_asset_field_classifies_in_both_directions() {
    let old = AssetConfig {
        allowlisted: true,
        haircut_bps: 8_500,
        liability_bps: 10_500,
        conf_mult_bps: 20_000,
        max_age_s: 60,
        max_conf_bps: 100,
        feed_id: [7; 32],
    };
    let c = |n: AssetConfig| classify_asset(Some(&old), &n);
    assert_eq!(
        c(AssetConfig {
            haircut_bps: 8_000,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        c(AssetConfig {
            haircut_bps: 9_000,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        c(AssetConfig {
            liability_bps: 11_000,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        c(AssetConfig {
            liability_bps: 10_000,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        c(AssetConfig {
            conf_mult_bps: 30_000,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        c(AssetConfig {
            conf_mult_bps: 10_000,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        c(AssetConfig {
            max_age_s: 30,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        c(AssetConfig {
            max_age_s: 120,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        c(AssetConfig {
            max_conf_bps: 50,
            ..old
        }),
        Class::Tighten
    );
    assert_eq!(
        c(AssetConfig {
            max_conf_bps: 200,
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        c(AssetConfig {
            feed_id: [8; 32],
            ..old
        }),
        Class::Loosen
    );
    assert_eq!(
        c(AssetConfig {
            allowlisted: false,
            haircut_bps: 10_000,
            ..old
        }),
        Class::Tighten
    );
    let disabled = AssetConfig {
        allowlisted: false,
        ..old
    };
    assert_eq!(
        classify_asset(Some(&disabled), &old),
        Class::Loosen,
        "re-enabling loosens"
    );
    assert_eq!(
        classify_asset(None, &old),
        Class::Loosen,
        "a new asset loosens"
    );
}

// --- Floor ELF gate ------------------------------------------------------------

fn header(len: usize) -> Vec<u8> {
    let mut h = vec![0u8; len.max(52)];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2; // 64-bit
    h[5] = 1; // little-endian
    h[18..20].copy_from_slice(&0xF7u16.to_le_bytes());
    h[48..52].copy_from_slice(&3u32.to_le_bytes());
    h.truncate(len);
    h
}

#[test]
fn elf_gate_rejects_every_malformed_header() {
    assert!(
        deployable_after_simd0500(elf_info(&header(52))),
        "exactly 52 bytes is enough"
    );
    assert!(elf_info(&header(51)).is_none(), "51 bytes is not");
    for byte in 0..4 {
        let mut h = header(64);
        h[byte] ^= 0xFF;
        assert!(elf_info(&h).is_none(), "bad magic byte {byte}");
    }
    let mut h32 = header(64);
    h32[4] = 1; // 32-bit class
    assert!(elf_info(&h32).is_none());
    let mut be = header(64);
    be[5] = 2; // big-endian
    assert!(elf_info(&be).is_none());
    let mut v0 = header(64);
    v0[48..52].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(elf_info(&v0).map(|i| i.e_flags), Some(0));
    assert!(!deployable_after_simd0500(elf_info(&v0)));
}

// --- abdication ------------------------------------------------------------------

#[test]
fn abdication_is_exact() {
    let m = Abdications::default().abdicate(4);
    assert!(m.is_abdicated(4));
    for k in (0..40u8).filter(|&k| k != 4) {
        assert!(!m.is_abdicated(k), "kind {k} must stay available");
    }
    assert_eq!(m.abdicate(40), m, "out-of-range kinds are ignored");
    assert!(
        !Abdications(u32::MAX).is_abdicated(32),
        "kind 32 does not exist"
    );
    assert!(Abdications(u32::MAX).is_abdicated(31));
}

// --- ledger bookkeeping -----------------------------------------------------------

fn usdc() -> Pricing {
    Pricing::Priced(PricedAsset {
        lo: 99_980_000,
        hi: 100_020_000,
        expo: -8,
        decimals: 6,
        haircut_bps: 9_900,
        liability_bps: 10_100,
    })
}

#[test]
fn ledger_bookkeeping_is_exact() {
    let mut l = Ledger::default();
    assert!(l.is_empty() && !l.has_liability());
    assert_eq!(l.len(), 0);
    assert!(l.credit(mint(1), 500));
    assert!(!l.is_empty() && l.len() == 1);
    let lookup = |m: &Mint| {
        if *m == mint(1) {
            usdc()
        } else {
            Pricing::NotAllowlisted
        }
    };
    // debit part of it: the position remains with the exact remainder
    l.debit_backed(mint(1), 200, &lookup).unwrap();
    assert_eq!(l.net(&mint(1)), 300);
    assert_eq!(l.len(), 1);
    // debit to exactly zero: the slot is freed
    l.debit_backed(mint(1), 300, &lookup).unwrap();
    assert_eq!(l.net(&mint(1)), 0);
    assert!(l.is_empty(), "a zero position must not occupy a slot");
    // a liability is visible
    let l2 = Ledger::from_positions(&[(mint(2), 10), (mint(1), -5)]).unwrap();
    assert!(l2.has_liability());
    let l3 = Ledger::from_positions(&[(mint(2), 10)]).unwrap();
    assert!(!l3.has_liability());
}

#[test]
fn health_sum_cannot_overflow_with_eight_positions() {
    // value_v multiplies by the weight before dividing by 10_000, so any Some(v)
    // is at most u128::MAX / 10_000 (+1 when rounding up). Eight of those can't
    // reach i128::MAX, so the overflow branches in health are defense in depth.
    use bulkhead_core::consts::MAX_SLOTS;
    use bulkhead_core::value::value_v;
    let per_position = u128::MAX / 10_000 + 1;
    assert!((MAX_SLOTS as u128) * per_position < i128::MAX as u128);
    // the largest representable value is reachable and within the bound
    let top = value_v(u128::MAX / 10_000, 1, -18, 0, 10_000, true).unwrap();
    assert!(top <= per_position);
    // one step more overflows the intermediate product and fails closed
    assert_eq!(
        value_v(u128::MAX / 10_000 + 1, 1, -18, 0, 10_000, false),
        None
    );
}

// --- limiter exactness ---------------------------------------------------------

use bulkhead_core::limiter::{
    cost_ms, request, Bucket, Decision, LimiterError, LimiterParams, LimiterState,
};

fn params(d_ms: i64) -> LimiterParams {
    LimiterParams {
        short: Bucket {
            capacity: 1_000,
            window_ms: 60_000,
        },
        long: Bucket {
            capacity: 100_000,
            window_ms: 86_400_000,
        },
        min_queue_delay_ms: d_ms,
        horizon_ms: 30 * 86_400_000,
    }
}

#[test]
fn cost_saturates_instead_of_wrapping() {
    let b = Bucket {
        capacity: 1,
        window_ms: 30 * 86_400_000,
    };
    assert_eq!(cost_ms(u64::MAX, &b), bulkhead_core::consts::COST_MAX_MS);
    // exactly at the boundary the exact value is kept
    let b2 = Bucket {
        capacity: 1,
        window_ms: 1,
    };
    assert_eq!(cost_ms(1 << 61, &b2), 1 << 61);
    assert_eq!(
        cost_ms((1 << 61) + 1, &b2),
        bulkhead_core::consts::COST_MAX_MS
    );
    // a saturated request is rejected by the horizon, never wrapped into an instant payout
    let p = LimiterParams {
        short: b,
        ..params(0)
    };
    let mut s = LimiterState::default();
    assert_eq!(
        request(&mut s, &p, 1_000, u64::MAX, 0),
        Err(LimiterError::QueueFull)
    );
    assert_eq!(s, LimiterState::default());
}

#[test]
fn freeze_boundary_is_exclusive() {
    let p = params(0);
    let mut s = LimiterState::default();
    // frozen_until == now means the freeze has ended: instant is allowed
    assert_eq!(request(&mut s, &p, 5_000, 10, 5_000), Ok(Decision::Instant));
    // one millisecond earlier the lane is frozen
    let mut s2 = LimiterState::default();
    assert!(matches!(
        request(&mut s2, &p, 4_999, 10, 5_000),
        Ok(Decision::Queued { eta_ms: 5_000 })
    ));
}

#[test]
fn eta_is_the_exact_conformance_time_when_no_delay() {
    // short bucket: 1,000 per minute. After using the burst, a request of 500 conforms
    // exactly when the bucket has refilled 500, i.e. 30 s later.
    let p = params(0);
    let mut s = LimiterState::default();
    assert_eq!(request(&mut s, &p, 0, 1_000, 0), Ok(Decision::Instant));
    assert_eq!(
        request(&mut s, &p, 0, 500, 0),
        Ok(Decision::Queued { eta_ms: 30_000 })
    );
    // the long bucket dominates when it is the tighter one
    let p2 = LimiterParams {
        long: Bucket {
            capacity: 1_000,
            window_ms: 3_600_000,
        },
        ..params(0)
    };
    let mut s2 = LimiterState::default();
    assert_eq!(request(&mut s2, &p2, 0, 1_000, 0), Ok(Decision::Instant));
    assert_eq!(
        request(&mut s2, &p2, 0, 500, 0),
        Ok(Decision::Queued { eta_ms: 1_800_000 })
    );
}

// --- price usability and value edges ------------------------------------------

use bulkhead_core::price::is_usable;
use bulkhead_core::value::value_v;

#[test]
fn price_usability_boundaries() {
    let (p, conf) = (15_000_000_000i64, 1_500_000u64); // $150, conf 0.01% of price
    assert!(
        is_usable(p, conf, 1_000, 1_000, 60, 100),
        "published this second"
    );
    assert!(
        is_usable(p, conf, 940, 1_000, 60, 100),
        "exactly max_age old is still usable"
    );
    assert!(
        !is_usable(p, conf, 939, 1_000, 60, 100),
        "one second older is stale"
    );
    assert!(
        !is_usable(p, conf, 1_001, 1_000, 60, 100),
        "a future publish time is rejected"
    );
    assert!(
        !is_usable(0, conf, 1_000, 1_000, 60, 100),
        "zero price is rejected"
    );
    assert!(
        !is_usable(-1, conf, 1_000, 1_000, 60, 100),
        "negative price is rejected"
    );
    // confidence exactly at the limit (1% of price) passes, one unit more fails
    assert!(is_usable(p, 150_000_000, 1_000, 1_000, 60, 100));
    assert!(!is_usable(p, 150_000_001, 1_000, 1_000, 60, 100));
}

#[test]
fn value_edges() {
    // zero inputs are zero even when the exponent would overflow the scale
    assert_eq!(value_v(0, 1, 30, 0, 1, false), Some(0));
    assert_eq!(value_v(1, 0, 30, 0, 1, false), Some(0));
    assert_eq!(value_v(1, 1, 30, 0, 0, false), Some(0));
    // a negative decimal shift: 1 token with 12 decimals at $1.00 (expo -8) = 1e18 value units
    assert_eq!(
        value_v(1_000_000_000_000, 100_000_000, -8, 12, 10_000, false),
        Some(1_000_000_000_000_000_000)
    );
    // shift of exactly +38 still fits: 1 * 1 * 1 * 10^38 / 10^4
    assert_eq!(value_v(1, 1, 20, 0, 1, false), Some(10u128.pow(34)));
    // shift of +39 does not
    assert_eq!(value_v(1, 1, 21, 0, 1, false), None);
}

#[test]
fn queue_horizon_boundary_is_inclusive() {
    // min delay 0; the first request uses the burst, the second must wait exactly W
    let p = LimiterParams {
        short: Bucket {
            capacity: 1_000,
            window_ms: 60_000,
        },
        long: Bucket {
            capacity: 1_000_000,
            window_ms: 86_400_000,
        },
        min_queue_delay_ms: 0,
        horizon_ms: 60_000,
    };
    let mut s = LimiterState::default();
    assert_eq!(request(&mut s, &p, 0, 1_000, 0), Ok(Decision::Instant));
    // needs a full window of refill: eta - now == horizon, accepted
    assert_eq!(
        request(&mut s, &p, 0, 1_000, 0),
        Ok(Decision::Queued { eta_ms: 60_000 })
    );
    // one more unit would need more than the horizon: rejected, state unchanged
    let before = s;
    assert_eq!(request(&mut s, &p, 0, 1, 0), Err(LimiterError::QueueFull));
    assert_eq!(s, before);
}

#[test]
fn crediting_zero_never_occupies_a_slot() {
    // A transfer-fee mint can deliver 0; the ledger must not store a zero position
    // (every "net < 0" / "net > 0" check in the ledger relies on that invariant).
    let mut l = Ledger::default();
    assert!(l.credit(mint(9), 0));
    assert!(l.is_empty());
    assert_eq!(l.len(), 0);
}

// --- limiter parameters from a vault's stored configuration ----------------
// (Exercised on-chain by every release; pinned here because mutation testing
// runs the core's tests only.)

#[test]
fn params_from_config_is_exact() {
    use bulkhead_core::limiter::{capacity_from_ref, params_from_config};
    let c = LimitConfig {
        short_bps: 200,
        short_window_s: 3_600,
        long_bps: 500,
        long_window_s: 86_400,
        min_queue_delay_s: 21_600,
        short_floor: 7,
        long_floor: 11,
        short_cap: 0,
        long_cap: 400_000,
    };
    let p = params_from_config(&c, 10_000_000);
    assert_eq!(p.short.capacity, capacity_from_ref(10_000_000, 200, 7, 0));
    assert_eq!(p.short.capacity, 200_000);
    assert_eq!(
        p.long.capacity, 400_000,
        "the cap applies (5% would be 500,000)"
    );
    assert_eq!(p.short.window_ms, 3_600_000);
    assert_eq!(p.long.window_ms, 86_400_000);
    assert_eq!(p.min_queue_delay_ms, 21_600_000);
    assert_eq!(p.horizon_ms, 604_800_000);
    // A reference of 0 leaves only the floors.
    let p0 = params_from_config(&c, 0);
    assert_eq!((p0.short.capacity, p0.long.capacity), (7, 11));
}

#[test]
fn limit_configs_are_valid_exactly_within_bounds() {
    use bulkhead_core::limiter::config_is_valid;
    let ok = limits();
    assert!(config_is_valid(&ok));
    let with = |f: fn(&mut LimitConfig)| {
        let mut c = ok;
        f(&mut c);
        config_is_valid(&c)
    };
    assert!(with(|c| c.short_bps = 10_000));
    assert!(!with(|c| c.short_bps = 10_001));
    assert!(with(|c| c.long_bps = 10_000));
    assert!(!with(|c| c.long_bps = 10_001));
    assert!(with(|c| c.short_window_s = 1));
    assert!(!with(|c| c.short_window_s = 0));
    assert!(with(|c| c.long_window_s = 1));
    assert!(!with(|c| c.long_window_s = 0));
    assert!(
        with(|c| c.short_bps = 0),
        "a closed short lane is a valid configuration"
    );
}

/// A1: capacities come from the lower of the 24h reference and the live
/// balance, exactly, in both directions.
#[test]
fn capacity_base_is_the_lower_of_reference_and_live_balance() {
    assert_eq!(capacity_base(100, 40), 40); // money left: counts at once
    assert_eq!(capacity_base(40, 100), 40); // money arrived: the reference lags
    assert_eq!(capacity_base(7, 7), 7);
    assert_eq!(capacity_base(0, u64::MAX), 0);
    assert_eq!(capacity_base(u64::MAX, 0), 0);
    assert_eq!(capacity_base(u64::MAX, u64::MAX), u64::MAX);
}

/// `rescale_windows` touches only a bucket with a backlog, and refuses a
/// window no valid config has (zero or negative) instead of dividing by it or
/// wrapping it to a huge unsigned value. An unchanged window keeps the backlog.
#[test]
fn rescale_windows_leaves_what_it_cannot_scale() {
    let p = |short, long| LimiterParams {
        short: Bucket {
            capacity: 1,
            window_ms: short,
        },
        long: Bucket {
            capacity: 1,
            window_ms: long,
        },
        min_queue_delay_ms: 0,
        horizon_ms: 0,
    };
    let now = 1_000;
    let busy = LimiterState {
        tat_short_ms: now + 500,
        tat_long_ms: now + 700,
    };
    let mut s = busy;
    rescale_windows(&mut s, &p(0, -5), &p(100, 100), now);
    assert_eq!(s, busy);
    let mut s = busy;
    rescale_windows(&mut s, &p(100, 100), &p(0, -5), now);
    assert_eq!(s, busy);
    // Same windows: the same backlog. Twice as long: twice the backlog.
    let mut s = busy;
    rescale_windows(&mut s, &p(100, 100), &p(100, 200), now);
    assert_eq!(
        s,
        LimiterState {
            tat_short_ms: now + 500,
            tat_long_ms: now + 1_400
        }
    );
    // No backlog: nothing to scale.
    let idle = LimiterState {
        tat_short_ms: now,
        tat_long_ms: 0,
    };
    let mut s = idle;
    rescale_windows(&mut s, &p(100, 100), &p(400, 400), now);
    assert_eq!(s, idle);
}

/// Found by the coverage-guided limiter fuzzer: a backlog of ~6.7 days in a
/// 1-second window, then the window lengthened to u32::MAX seconds, scales
/// past `COST_MAX_MS` and saturates there. The used fraction then drops a
/// little (from ~578 000 windows to ~537 000), but saturation only happens far
/// beyond one full window, so the bucket stays full: no instant room, new
/// requests refused, and shortening the window back gives no room either.
#[test]
fn rescale_windows_saturation_keeps_the_bucket_full() {
    use bulkhead_core::consts::COST_MAX_MS;
    use bulkhead_core::limiter::available_now;
    let p = |w_ms: i64| LimiterParams {
        short: Bucket {
            capacity: 31_885_837_205_504,
            window_ms: w_ms,
        },
        long: Bucket {
            capacity: 31_885_837_205_504,
            window_ms: w_ms,
        },
        min_queue_delay_ms: 0,
        horizon_ms: 604_800_000,
    };
    let (short, huge) = (1_000, u32::MAX as i64 * 1_000);
    let now = 1_700_000_000_000;
    let mut s = LimiterState::default();
    let r = request(&mut s, &p(short), now, 18_446_744_073_709_539_080, 0);
    assert!(matches!(r, Ok(Decision::Queued { .. })));
    rescale_windows(&mut s, &p(short), &p(huge), now);
    assert_eq!(s.tat_long_ms, now + COST_MAX_MS, "saturated");
    assert!(
        s.tat_long_ms - now > huge,
        "still more than one full window"
    );
    assert_eq!(available_now(&s, &p(huge), now), 0);
    let before = s;
    assert_eq!(
        request(&mut s, &p(huge), now, 1, 0),
        Err(LimiterError::QueueFull)
    );
    assert_eq!(s, before);
    rescale_windows(&mut s, &p(huge), &p(short), now);
    assert!(s.tat_long_ms - now > short);
    assert_eq!(available_now(&s, &p(short), now), 0);
}

// --- a vault created after the seal (genesis.rs, GenesisOnly) ----------------

/// `lane_always_closed` is exactly "some bucket has no bps and no floor",
/// checked against what the limiter does with the config: a closed lane has a
/// bucket of capacity 0 at every reference (the soundness direction Kani also
/// proves), and any other config opens both buckets for a large enough
/// reference, so it must be refused after the seal. Mutation testing found no
/// core test of this rule (all 9 of its mutants survived).
#[test]
fn lane_always_closed_is_exactly_a_bucket_without_bps_or_floor() {
    for bits in 0u8..16 {
        let mut cfg = limits();
        cfg.short_cap = 0;
        cfg.long_cap = 0;
        cfg.short_bps = if bits & 1 != 0 { 200 } else { 0 };
        cfg.short_floor = if bits & 2 != 0 { 1_000 } else { 0 };
        cfg.long_bps = if bits & 4 != 0 { 500 } else { 0 };
        cfg.long_floor = if bits & 8 != 0 { 1_000 } else { 0 };
        let open_at = |r: u64| {
            let p = params_from_config(&cfg, r);
            p.short.capacity > 0 && p.long.capacity > 0
        };
        let refs = [0, 1, 49, 10_000, u64::MAX];
        let closed_everywhere = refs.iter().all(|&r| !open_at(r));
        assert_eq!(
            lane_always_closed(&cfg),
            closed_everywhere,
            "bits {bits:04b}"
        );
        if !closed_everywhere {
            assert!(
                open_at(u64::MAX),
                "bits {bits:04b}: an open config opens at a large reference"
            );
        }
    }
    // A cap only lowers a capacity: it never closes a lane on its own, so a
    // config with bps and a 1-unit cap is still open.
    let mut capped = limits();
    capped.short_cap = 1;
    capped.long_cap = 1;
    assert!(!lane_always_closed(&capped));
}

/// Finding 102: G1 counts payouts by request time. At the defaults (2%/1h,
/// 5%/24h, 6h delay) a single request for 6.25% of a 10M vault,
/// `C_l·(W_l+D)/W_l`, is a ticket payable in one go 6h later; one unit more
/// is not. What the queue gives is 6h in public to cancel it.
#[test]
fn one_request_can_queue_a_long_window_plus_the_delay() {
    let cfg = LimitConfig {
        short_bps: 200,
        short_window_s: 3_600,
        long_bps: 500,
        long_window_s: 86_400,
        min_queue_delay_s: 21_600,
        short_floor: 0,
        long_floor: 0,
        short_cap: 0,
        long_cap: 0,
    };
    let p = params_from_config(&cfg, 10_000_000);
    let t = 1_800_000_000_000;
    let mut s = LimiterState::default();
    assert_eq!(
        request(&mut s, &p, t, 625_000, 0),
        Ok(Decision::Queued {
            eta_ms: t + 21_600_000
        })
    );
    let mut s = LimiterState::default();
    assert!(
        matches!(request(&mut s, &p, t, 625_001, 0), Ok(Decision::Queued { eta_ms }) if eta_ms > t + 21_600_000)
    );
}

/// Finding 102: the largest single lump. A request is refused only when its
/// ETA is past the 7-day horizon, so one request for `min_k C_k·(W_k+horizon)/W_k`,
/// 40% of a 10M vault at the defaults, is a single ticket due at exactly
/// +7d; one unit more is `QueueFull`.
#[test]
fn one_request_can_queue_up_to_the_horizon() {
    let cfg = LimitConfig {
        short_bps: 200,
        short_window_s: 3_600,
        long_bps: 500,
        long_window_s: 86_400,
        min_queue_delay_s: 21_600,
        short_floor: 0,
        long_floor: 0,
        short_cap: 0,
        long_cap: 0,
    };
    let p = params_from_config(&cfg, 10_000_000);
    let t = 1_800_000_000_000;
    let mut s = LimiterState::default();
    assert_eq!(
        request(&mut s, &p, t, 4_000_000, 0),
        Ok(Decision::Queued {
            eta_ms: t + 604_800_000
        })
    );
    let mut s = LimiterState::default();
    assert_eq!(
        request(&mut s, &p, t, 4_000_001, 0),
        Err(LimiterError::QueueFull)
    );
    assert_eq!(s, LimiterState::default(), "a refusal changes nothing");
}

/// Findings 96 and 107: the guardian-set shape, at every boundary. At least two
/// to undo a stop, two keys more than that (so after any two faults short of a
/// rogue quorum the others can eject a rogue), at most 8.
#[test]
fn guardian_set_shape_is_exact() {
    use bulkhead_core::governance::guardian_set_ok;
    for (count, threshold, ok) in [
        (4, 2, true),
        (5, 3, true),
        (8, 6, true),
        (8, 2, true),
        (3, 2, false), // threshold + 1: a lost key and a rogue lock it
        (4, 3, false),
        (8, 7, false),
        (2, 2, false), // n-of-n
        (3, 3, false),
        (8, 8, false),
        (3, 1, false), // one key alone could undo a stop
        (4, 1, false),
        (9, 8, false), // more than 8 guardians
        (0, 0, false),
        (8, 255, false), // threshold + 2 saturates, never wraps
    ] {
        assert_eq!(
            guardian_set_ok(count, threshold),
            ok,
            "{threshold}-of-{count}"
        );
    }
}

// --- guardian sets (one parser for Floor and the Vault) ---------------------

use bulkhead_core::governance::{
    alive_mask, guardian_index, signer_bits, GuardianSet, GuardianSetError, SignerError,
};

/// `[count][keys][threshold][interval]` for keys `1..=count` (as bytes).
fn encoded_set(count: u8, threshold: u8, interval: i64) -> Vec<u8> {
    let mut b = vec![count];
    for i in 1..=count {
        b.extend_from_slice(&[i; 32]);
    }
    b.push(threshold);
    b.extend_from_slice(&interval.to_le_bytes());
    b
}

#[test]
fn a_guardian_set_parses_exactly() {
    const DAY: i64 = 86_400;
    let none = [0u8; 32];
    let owner = [0xAA; 32];
    let mut b = encoded_set(4, 2, 7 * DAY);
    b.extend_from_slice(&[0xEE; 5]); // what follows the set is not its business
    let (s, used) = GuardianSet::parse(&b, [&owner, &none]).unwrap();
    assert_eq!(
        (s.count, s.threshold, s.interval_s, used),
        (4, 2, 7 * DAY, 1 + 128 + 1 + 8)
    );
    assert_eq!(&s.keys[..4], &[[1; 32], [2; 32], [3; 32], [4; 32]]);
    assert!(s.contains(&[2; 32]) && !s.contains(&[5; 32]) && !s.contains(&[0; 32]));
    assert!(s.keys[4..].iter().all(|k| *k == [0; 32]));
    // Both interval bounds are accepted, one second past either is not.
    for (iv, ok) in [
        (DAY, true),
        (30 * DAY, true),
        (DAY - 1, false),
        (30 * DAY + 1, false),
    ] {
        let r = GuardianSet::parse(&encoded_set(4, 2, iv), [&owner, &none]);
        assert_eq!(r.is_ok(), ok, "interval {iv}");
        if !ok {
            assert_eq!(r.unwrap_err(), GuardianSetError::BadInterval);
        }
    }
}

#[test]
fn a_guardian_set_is_refused_for_each_rule_in_order() {
    use GuardianSetError::*;
    const WEEK: i64 = 7 * 86_400;
    let (none, owner) = ([0u8; 32], [0xAA; 32]);
    let parse =
        |b: &[u8], recovery: &[u8; 32]| GuardianSet::parse(b, [&owner, recovery]).map(|_| ());
    assert_eq!(parse(&[], &none), Err(Truncated));
    assert_eq!(parse(&encoded_set(1, 2, WEEK), &none), Err(BadCount));
    assert_eq!(parse(&encoded_set(9, 2, WEEK), &none), Err(BadCount));
    let full = encoded_set(4, 2, WEEK);
    assert_eq!(parse(&full[..full.len() - 1], &none), Err(Truncated));
    for (i, bad) in [(0usize, [0u8; 32]), (1, owner), (2, [1; 32])] {
        let mut b = full.clone();
        b[1 + 32 * i..33 + 32 * i].copy_from_slice(&bad); // zero, the owner, a repeat
        assert_eq!(parse(&b, &none), Err(BadKey), "key {i}");
    }
    assert_eq!(parse(&full, &[2; 32]), Err(BadKey), "the recovery key");
    assert_eq!(
        parse(&encoded_set(3, 3, WEEK), &none),
        Err(BadThreshold),
        "n-of-n"
    );
    assert_eq!(parse(&encoded_set(3, 1, WEEK), &none), Err(BadThreshold));
    // A set too small for any threshold is BadThreshold, not BadCount: the
    // count rule is only the bitmap's size (finding 107 changed the threshold).
    for count in [2, 3] {
        assert_eq!(
            parse(&encoded_set(count, 2, WEEK), &none),
            Err(BadThreshold),
            "2-of-{count}"
        );
    }
    // The whole encoding must be present before any key is judged: a short
    // payload with a bad key is Truncated (the Vault used to say BadKey).
    let mut b = full.clone();
    b[1..33].copy_from_slice(&[0; 32]);
    assert_eq!(parse(&b[..b.len() - 1], &none), Err(Truncated));
}

#[test]
fn guardian_bitmaps_only_name_current_guardians() {
    let keys = [
        [1u8; 32], [2; 32], [3; 32], [0; 32], [0; 32], [0; 32], [0; 32], [0; 32],
    ];
    assert_eq!(guardian_index(&keys, 3, &[3; 32]), Some(2));
    assert_eq!(guardian_index(&keys, 2, &[3; 32]), None, "beyond the count");
    assert_eq!(
        guardian_index(&keys, 3, &[0; 32]),
        None,
        "an empty slot is nobody"
    );
    assert_eq!(
        guardian_index(&keys, 9, &[3; 32]),
        Some(2),
        "a count above 8 reads 8 slots, as alive_mask does"
    );
    let (t, iv) = (1_000_000, 86_400);
    let beats = [t, t - iv, t - iv - 1, t, t, t, t, t];
    assert_eq!(
        alive_mask(&beats, 3, iv, t),
        0b011,
        "slot 2 is a second late; slots 3.. are empty"
    );
    assert_eq!(
        alive_mask(&beats, 9, iv, t),
        alive_mask(&beats, 8, iv, t),
        "a count above 8 reads 8 slots"
    );
    let s = |k: u8, signed: bool| ([k; 32], signed);
    assert_eq!(
        signer_bits(&keys, 3, [s(1, true), s(3, true), s(1, true)]),
        Ok(0b101)
    );
    assert_eq!(
        signer_bits(&keys, 3, [s(1, true), s(2, false)]),
        Err(SignerError::NotSigner)
    );
    assert_eq!(
        signer_bits(&keys, 3, [s(4, true)]),
        Err(SignerError::NotGuardian)
    );
    assert_eq!(
        signer_bits(&keys, 2, [s(3, true)]),
        Err(SignerError::NotGuardian),
        "beyond the count"
    );
    assert_eq!(signer_bits(&keys, 3, []), Ok(0));
}
