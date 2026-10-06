//! Property tests for the guarantees in docs/03-MECHANISM.md.
//!
//! Zero dependencies: a SplitMix64 generator drives every case, so runs are
//! reproducible from the seed printed on failure. `BULKHEAD_CASES` scales the
//! number of cases (default 3_000 per property; CI runs 20_000).

use bulkhead_core::classify::{classify_asset, classify_limits, AssetConfig, Class, LimitConfig};
use bulkhead_core::consts::MIN_LOOSEN_DELAY_S;
use bulkhead_core::consts::{MAX_SLOTS, MIN_UPGRADE_DELAY_S, TAU_S};
use bulkhead_core::ema::ema_update;
use bulkhead_core::floor::{
    can_restore, deployable_after_simd0500, elf_info, snapshot_matches, upgrade_eta, RestoreSource,
};
use bulkhead_core::governance::{self, Abdications, GovError, Schedule, CHANGE_EXPIRY_S};
use bulkhead_core::ledger::{contribution, Ledger, LedgerError, Mint, PricedAsset, Pricing};
use bulkhead_core::limiter::{
    available_now, capacity_from_ref, max_unbacked_over, request, rescale_windows, reset_backlog,
    Bucket, Decision, LimiterError, LimiterParams, LimiterState,
};
use bulkhead_core::price::conservative;
use bulkhead_core::value::value_v;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        match (hi - lo).checked_add(1) {
            Some(span) => lo + self.next() % span,
            None => self.next(), // full u64 range
        }
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() as f64 / u64::MAX as f64) < p
    }
}

/// Pick from a slice with a pre-drawn random number (keeps the borrow checker
/// happy when the slice itself calls the generator).
fn pick<T: Copy>(xs: &[T], roll: u64) -> T {
    xs[(roll % xs.len() as u64) as usize]
}

fn cases() -> u64 {
    std::env::var("BULKHEAD_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000)
}

fn mint(i: u64) -> Mint {
    let mut m = [0u8; 32];
    m[..8].copy_from_slice(&i.to_le_bytes());
    m
}

// ---------------------------------------------------------------------------
// Limiter
// ---------------------------------------------------------------------------

struct Paid {
    requested_at: i64,
    paid_at: i64,
    amount: u64,
}

fn random_params(r: &mut Rng) -> LimiterParams {
    let w1 = pick(
        &[1_000, 60_000, 3_600_000, r.range(1, 7_200_000) as i64],
        r.next(),
    );
    let w2 = pick(
        &[3_600_000, 86_400_000, r.range(1, 3 * 86_400_000) as i64],
        r.next(),
    );
    LimiterParams {
        short: Bucket {
            capacity: r.range(1, 1_000_000_000_000),
            window_ms: w1,
        },
        long: Bucket {
            capacity: r.range(1, 5_000_000_000_000),
            window_ms: w2,
        },
        min_queue_delay_ms: pick(
            &[0, 60_000, 21_600_000, r.range(0, 86_400_000) as i64],
            r.next(),
        ),
        horizon_ms: pick(&[86_400_000, 604_800_000, 1 << 50], r.next()),
    }
}

/// G1: amounts requested in [t0, t0+T] and paid by t0+T never exceed
/// C_k * (W_k + T) / W_k for either bucket. Exercises freezes, cancellations,
/// and resets (only when no ticket is pending, as the program enforces).
#[test]
fn g1_dual_bucket_bound_holds_with_freezes_cancels_and_resets() {
    let mut r = Rng(0xB01D);
    let (mut n_instant, mut n_queued, mut n_resets, mut n_frozen_queued) = (0u64, 0u64, 0u64, 0u64);
    for case in 0..cases() {
        let p = random_params(&mut r);
        let mut s = LimiterState::default();
        let mut now: i64 = 1_700_000_000_000;
        let mut frozen_until: i64 = 0;
        let mut tickets: Vec<(i64, i64, u64, bool)> = Vec::new(); // (requested, eta, amount, cancelled)
        let mut paid: Vec<Paid> = Vec::new();
        for _ in 0..r.range(1, 80) {
            now += pick(
                &[
                    0,
                    1,
                    1_000,
                    60_000,
                    600_000,
                    3_600_000,
                    r.range(0, 86_400_000) as i64,
                ],
                r.next(),
            );
            if r.chance(0.05) {
                frozen_until = now + pick(&[60_000, 3_600_000, 86_400_000], r.next());
            }
            if r.chance(0.05) {
                // cancel a random pending ticket (never paid, no refund)
                if let Some(t) = tickets.iter_mut().find(|t| !t.3 && t.1 > now) {
                    t.3 = true;
                }
            }
            if r.chance(0.05) {
                let pending = tickets.iter().filter(|t| !t.3 && t.1 > now).count() as u32;
                let res = reset_backlog(&mut s, &p, now, pending);
                assert_eq!(res.is_ok(), pending == 0, "case {case}");
                n_resets += res.is_ok() as u64;
            }
            let c = p.short.capacity.max(1);
            let amount = pick(
                &[
                    1,
                    c / 10 + 1,
                    c / 2 + 1,
                    c,
                    c * 3,
                    r.range(1, c.saturating_mul(20)),
                ],
                r.next(),
            );
            match request(&mut s, &p, now, amount, frozen_until) {
                Ok(Decision::Instant) => {
                    assert!(now >= frozen_until, "instant while frozen, case {case}");
                    n_instant += 1;
                    paid.push(Paid {
                        requested_at: now,
                        paid_at: now,
                        amount,
                    });
                }
                Ok(Decision::Queued { eta_ms }) => {
                    assert!(
                        eta_ms >= now + p.min_queue_delay_ms,
                        "eta before min delay, case {case}"
                    );
                    assert!(
                        eta_ms - now <= p.horizon_ms,
                        "eta beyond horizon, case {case}"
                    );
                    if now < frozen_until {
                        assert!(eta_ms >= frozen_until, "eta inside freeze, case {case}");
                        n_frozen_queued += 1;
                    }
                    n_queued += 1;
                    tickets.push((now, eta_ms, amount, false));
                }
                Err(LimiterError::QueueFull) => {}
                Err(e) => panic!("unexpected {e:?} case {case}"),
            }
        }
        for t in tickets.iter().filter(|t| !t.3) {
            paid.push(Paid {
                requested_at: t.0,
                paid_at: t.1,
                amount: t.2,
            });
        }
        paid.sort_by_key(|x| x.paid_at);
        let mut starts: Vec<i64> = paid.iter().map(|x| x.requested_at).collect();
        starts.sort();
        starts.dedup();
        for &t0 in &starts {
            let mut sum: u128 = 0;
            for x in paid.iter().filter(|x| x.requested_at >= t0) {
                sum += x.amount as u128;
                let t = (x.paid_at - t0) as u128;
                for b in [&p.short, &p.long] {
                    let lhs = sum * b.window_ms as u128;
                    let rhs = b.capacity as u128 * (b.window_ms as u128 + t);
                    assert!(
                        lhs <= rhs,
                        "G1 violated case {case}: sum {sum} t {t} bucket {b:?}"
                    );
                }
            }
        }
    }
    // the property must actually exercise every path
    assert!(n_instant > 100 && n_queued > 100 && n_resets > 10 && n_frozen_queued > 10,
        "weak coverage: instant {n_instant} queued {n_queued} resets {n_resets} frozen {n_frozen_queued}");
    eprintln!("G1 coverage: instant {n_instant} queued {n_queued} resets {n_resets} frozen-queued {n_frozen_queued}");
}

/// Queue order: without freezes, cancels or resets, ETAs never go backwards.
#[test]
fn tickets_are_fifo() {
    let mut r = Rng(0xF1F0);
    for case in 0..cases() {
        let p = random_params(&mut r);
        let mut s = LimiterState::default();
        let mut now = 1_000_000_000i64;
        let mut last_eta = i64::MIN;
        for _ in 0..r.range(1, 60) {
            now += r.range(0, 3_600_000) as i64;
            let amount = r.range(1, p.short.capacity.saturating_mul(4));
            if let Ok(Decision::Queued { eta_ms }) = request(&mut s, &p, now, amount, 0) {
                assert!(eta_ms >= last_eta, "FIFO broken case {case}");
                last_eta = eta_ms;
            }
        }
    }
}

/// `available_now` is exact: that amount is instant, one more is not.
#[test]
fn available_now_is_exact() {
    let mut r = Rng(0xA7A1);
    for case in 0..cases() {
        let p = random_params(&mut r);
        let mut s = LimiterState::default();
        let mut now = 5_000_000i64;
        for _ in 0..r.range(0, 10) {
            now += r.range(0, 600_000) as i64;
            let _ = request(&mut s, &p, now, r.range(1, p.short.capacity), 0);
        }
        now += r.range(0, 600_000) as i64;
        let a = available_now(&s, &p, now);
        if a > 0 {
            let mut s2 = s;
            assert_eq!(
                request(&mut s2, &p, now, a, 0),
                Ok(Decision::Instant),
                "case {case}"
            );
        }
        if a < u64::MAX {
            let mut s3 = s;
            assert_ne!(
                request(&mut s3, &p, now, a + 1, 0),
                Ok(Decision::Instant),
                "case {case}"
            );
        }
    }
}

#[test]
fn lane_closed_and_zero_amount() {
    let p = LimiterParams {
        short: Bucket {
            capacity: 0,
            window_ms: 3_600_000,
        },
        long: Bucket {
            capacity: 10,
            window_ms: 86_400_000,
        },
        min_queue_delay_ms: 0,
        horizon_ms: 1,
    };
    let mut s = LimiterState::default();
    assert_eq!(request(&mut s, &p, 1, 1, 0), Err(LimiterError::LaneClosed));
    assert_eq!(request(&mut s, &p, 1, 0, 0), Err(LimiterError::ZeroAmount));
    assert_eq!(s, LimiterState::default());
}

// ---------------------------------------------------------------------------
// EMA, value, price
// ---------------------------------------------------------------------------

#[test]
fn ema_moves_toward_balance_and_never_overshoots() {
    let mut r = Rng(0xE3A);
    for _ in 0..cases() {
        let reference = r.next();
        let balance = r.next();
        let last = r.range(0, 1 << 40) as i64;
        let now = last + r.range(0, 3 * TAU_S as u64) as i64;
        let v = ema_update(reference, last, balance, now, true);
        assert!(v >= reference.min(balance) && v <= reference.max(balance));
        if now - last >= TAU_S {
            assert_eq!(v, balance);
        }
        assert_eq!(ema_update(reference, last, balance, last, true), reference);
        assert_eq!(ema_update(reference, last, balance, now, false), balance);
    }
}

#[test]
fn value_rounding_and_monotonicity() {
    let mut r = Rng(0x7A1);
    for _ in 0..cases() {
        let amount = r.range(0, 1 << 60) as u128;
        let mant = r.range(0, 1 << 40) as u128;
        let expo = r.range(0, 20) as i32 - 12;
        let dec = r.range(0, 12) as u8;
        let w = r.range(0, 20_000) as u32;
        let (f, c) = (
            value_v(amount, mant, expo, dec, w, false),
            value_v(amount, mant, expo, dec, w, true),
        );
        if let (Some(f), Some(c)) = (f, c) {
            assert!(f <= c && c <= f + 1);
            if let Some(f2) = value_v(amount + 1, mant, expo, dec, w, false) {
                assert!(f2 >= f);
            }
            if let Some(f3) = value_v(amount, mant + 1, expo, dec, w, false) {
                assert!(f3 >= f);
            }
        }
    }
    assert_eq!(value_v(u128::MAX, 2, 0, 0, 10_000, false), None);
    assert_eq!(value_v(1, 1, 30, 0, 10_000, false), None); // shift 48 > 38
}

#[test]
fn conservative_price_brackets_spot_and_ema() {
    let mut r = Rng(0x9A1C);
    for _ in 0..cases() {
        let price = r.range(1, i64::MAX as u64) as i64;
        let ema = r.range(1, i64::MAX as u64) as i64;
        let conf = r.next();
        let mult = r.range(0, 40_000) as u32;
        let b = conservative(price, conf, ema, mult).unwrap();
        assert!(b.lo <= price.min(ema) as u128);
        assert!(b.hi >= price.max(ema) as u128);
    }
    assert!(conservative(0, 1, 5, 10_000).is_none());
    assert!(conservative(5, 1, -1, 10_000).is_none());
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

struct World {
    ledger: Ledger,
    pricing: Vec<(Mint, Pricing)>,
}

fn random_pricing(r: &mut Rng) -> Pricing {
    let roll = r.range(0, 99);
    if roll < 20 {
        return Pricing::NotAllowlisted;
    }
    if roll < 30 {
        return Pricing::Unpriced;
    }
    let mid = pick(
        &[
            100_000_000u128,
            99_980_000,
            15_000_000_000,
            r.range(1, 1 << 36) as u128,
        ],
        r.next(),
    );
    let spread = pick(&[0u128, mid / 1000, mid / 50], r.next());
    Pricing::Priced(PricedAsset {
        lo: mid - spread,
        hi: mid + spread,
        expo: pick(&[-8, -6, -10], r.next()),
        decimals: pick(&[6u8, 9, 8], r.next()),
        haircut_bps: pick(
            &[8_000u32, 8_500, 9_900, 10_000, r.range(0, 10_000) as u32],
            r.next(),
        ),
        liability_bps: pick(
            &[10_000u32, 10_100, 10_500, r.range(10_000, 20_000) as u32],
            r.next(),
        ),
    })
}

fn random_world(r: &mut Rng, allow_liabilities: bool) -> World {
    let n = r.range(0, MAX_SLOTS as u64);
    let mut stored = Vec::new();
    let mut pricing = Vec::new();
    for i in 1..=10u64 {
        pricing.push((mint(i), random_pricing(r)));
    }
    let mut ids: Vec<u64> = (1..=10).collect();
    for k in 0..n as usize {
        let swap_with = k + (r.next() as usize % (ids.len() - k));
        ids.swap(k, swap_with);
        let mag = pick(
            &[1u64, 1_000_000, 1_000_000_000, r.range(1, 1 << 50)],
            r.next(),
        ) as i128;
        let negative = allow_liabilities && r.chance(0.3);
        stored.push((mint(ids[k]), if negative { -mag } else { mag }));
    }
    World {
        ledger: Ledger::from_positions(&stored).unwrap(),
        pricing,
    }
}

fn lookup_of(w: &World) -> impl Fn(&Mint) -> Pricing + '_ {
    move |m: &Mint| {
        w.pricing
            .iter()
            .find(|(k, _)| k == m)
            .map(|(_, p)| *p)
            .unwrap_or(Pricing::NotAllowlisted)
    }
}

/// Independent statement of "sound after paying b" (third formulation, after
/// the Rust binary search and the Python reference).
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
    let any_liab = stored.iter().any(|(_, v)| *v < 0);
    if !any_liab {
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

/// G2: an owner who owes nothing gets at least min(amount, own deposit)
/// back through the backed lane, with no prices at all.
#[test]
fn g2_own_deposit_always_comes_back_without_prices() {
    let mut r = Rng(0x62);
    for case in 0..cases() {
        let w = random_world(&mut r, false);
        let no_prices = |_: &Mint| Pricing::Unpriced;
        for (m, net) in w
            .ledger
            .positions()
            .map(|p| (p.mint, p.net))
            .collect::<Vec<_>>()
        {
            let a = r.range(0, u64::MAX);
            let b = w.ledger.backed_amount(&m, a, &no_prices);
            let expect = (a as i128).min(net) as u64;
            assert!(b >= expect, "G2 case {case}: got {b} want >= {expect}");
        }
    }
}

/// G3 + maximality: the backed amount is sound, and one more unit is not.
#[test]
fn g3_backed_amount_is_sound_and_maximal() {
    let mut r = Rng(0x63);
    let (mut partial, mut with_liab_positive) = (0u64, 0u64);
    for case in 0..cases() {
        let w = random_world(&mut r, true);
        let lookup = lookup_of(&w);
        let j = mint(r.range(1, 10));
        let a = pick(
            &[
                1u64,
                1_000_000,
                1_000_000_000,
                r.range(0, 1 << 52),
                u64::MAX,
            ],
            r.next(),
        );
        let b = w.ledger.backed_amount(&j, a, &lookup);
        assert!(b <= a);
        assert!(
            b == 0 || sound_after(&w.ledger, &j, b, &lookup),
            "unsound case {case}"
        );
        partial += (b > 0 && b < a) as u64;
        with_liab_positive += (b > 0 && w.ledger.has_liability()) as u64;
        if b < a {
            assert!(
                !sound_after(&w.ledger, &j, b + 1, &lookup),
                "not maximal case {case} b {b}"
            );
        }
        // applying it through the checked debit must succeed
        let mut l2 = w.ledger;
        assert!(l2.debit_backed(j, b, &lookup).is_ok());
        if b < a {
            let mut l3 = w.ledger;
            assert_eq!(
                l3.debit_backed(j, b + 1, &lookup),
                Err(LedgerError::Unsound)
            );
        }
    }
    assert!(
        partial > 50 && with_liab_positive > 50,
        "weak coverage: partial {partial} liab {with_liab_positive}"
    );
    eprintln!("G3 coverage: partial {partial} with-liabilities {with_liab_positive}");
}

/// backed(a) == min(a, backed(u64::MAX)): the valid set is an interval.
#[test]
fn backed_amount_is_monotone_in_request() {
    let mut r = Rng(0x64);
    for case in 0..cases() {
        let w = random_world(&mut r, true);
        let lookup = lookup_of(&w);
        let j = mint(r.range(1, 10));
        let top = w.ledger.backed_amount(&j, u64::MAX, &lookup);
        let a = r.range(0, 1 << 52);
        assert_eq!(
            w.ledger.backed_amount(&j, a, &lookup),
            a.min(top),
            "case {case}"
        );
    }
}

/// Fail closed: removing a price, lowering a collateral price or raising a
/// liability price never increases the backed amount.
#[test]
fn fail_closed_and_price_monotone() {
    let mut r = Rng(0x65);
    for case in 0..cases() {
        let w = random_world(&mut r, true);
        let j = mint(r.range(1, 10));
        let a = r.range(0, 1 << 52);
        let base = w.ledger.backed_amount(&j, a, &lookup_of(&w));
        let victim = mint(r.range(1, 10));
        for variant in 0..3 {
            let mut w2 = World {
                ledger: w.ledger,
                pricing: w.pricing.clone(),
            };
            for (m, p) in w2.pricing.iter_mut() {
                if *m != victim {
                    continue;
                }
                if let Pricing::Priced(pa) = *p {
                    *p = match variant {
                        0 => Pricing::Unpriced,
                        1 => Pricing::Priced(PricedAsset {
                            lo: pa.lo / 2,
                            ..pa
                        }),
                        _ => Pricing::Priced(PricedAsset {
                            hi: pa.hi.saturating_mul(2),
                            ..pa
                        }),
                    };
                }
            }
            let after = w2.ledger.backed_amount(&j, a, &lookup_of(&w2));
            assert!(
                after <= base,
                "fail-closed broken case {case} variant {variant}: {after} > {base}"
            );
        }
    }
}

/// The Drift pattern: collateral that is not allowlisted backs nothing.
#[test]
fn junk_collateral_backs_nothing() {
    let cvt = mint(99);
    let usdc = mint(1);
    let mut l = Ledger::default();
    assert!(l.credit(cvt, 750_000_000_000_000_000));
    let lookup = |m: &Mint| {
        if *m == usdc {
            Pricing::Priced(PricedAsset {
                lo: 99_980_000,
                hi: 100_020_000,
                expo: -8,
                decimals: 6,
                haircut_bps: 9_900,
                liability_bps: 10_100,
            })
        } else {
            Pricing::NotAllowlisted
        }
    };
    assert_eq!(l.backed_amount(&usdc, 71_400_000_000_000, &lookup), 0);
    // and withdrawing your own junk is fine (it was worth 0 anyway)
    assert_eq!(
        l.backed_amount(&cvt, 750_000_000_000_000_000, &lookup),
        750_000_000_000_000_000
    );
}

#[test]
fn from_positions_rejects_malformed() {
    assert_eq!(
        Ledger::from_positions(&[(mint(1), 0)]),
        Err(LedgerError::Malformed)
    );
    assert_eq!(
        Ledger::from_positions(&[(mint(1), 5), (mint(1), 6)]),
        Err(LedgerError::Malformed)
    );
    let nine: Vec<(Mint, i128)> = (1..=9).map(|i| (mint(i), 1)).collect();
    assert_eq!(Ledger::from_positions(&nine), Err(LedgerError::NoSlot));
}

// ---------------------------------------------------------------------------
// Classification soundness
// ---------------------------------------------------------------------------

fn random_limits(r: &mut Rng) -> LimitConfig {
    LimitConfig {
        short_bps: r.range(0, 10_000) as u16,
        short_window_s: r.range(1, 7_200) as u32,
        long_bps: r.range(0, 10_000) as u16,
        long_window_s: r.range(1, 3 * 86_400) as u32,
        min_queue_delay_s: r.range(0, 86_400) as u32,
        short_floor: r.range(0, 1_000_000),
        long_floor: r.range(0, 1_000_000),
        short_cap: if r.chance(0.5) {
            0
        } else {
            r.range(1, 1 << 40)
        },
        long_cap: if r.chance(0.5) {
            0
        } else {
            r.range(1, 1 << 40)
        },
    }
}

fn params_of(c: &LimitConfig, reference: u64) -> LimiterParams {
    LimiterParams {
        short: Bucket {
            capacity: capacity_from_ref(reference, c.short_bps, c.short_floor, c.short_cap),
            window_ms: c.short_window_s as i64 * 1000,
        },
        long: Bucket {
            capacity: capacity_from_ref(reference, c.long_bps, c.long_floor, c.long_cap),
            window_ms: c.long_window_s as i64 * 1000,
        },
        min_queue_delay_ms: c.min_queue_delay_s as i64 * 1000,
        horizon_ms: 1 << 40,
    }
}

/// A change classified Tighten can never raise the G1 bound for any
/// reference balance or horizon.
#[test]
fn tighten_never_raises_the_bound() {
    let mut r = Rng(0xC1A5);
    let mut tightened = 0;
    for _ in 0..cases() * 4 {
        let old = random_limits(&mut r);
        let mut new = old;
        // nudge a few fields in random directions
        for _ in 0..r.range(1, 3) {
            match r.range(0, 8) {
                0 => new.short_bps = r.range(0, 10_000) as u16,
                1 => new.short_window_s = r.range(1, 7_200) as u32,
                2 => new.long_bps = r.range(0, 10_000) as u16,
                3 => new.long_window_s = r.range(1, 3 * 86_400) as u32,
                4 => new.short_floor = r.range(0, 1_000_000),
                5 => new.long_floor = r.range(0, 1_000_000),
                6 => {
                    new.short_cap = if r.chance(0.3) {
                        0
                    } else {
                        r.range(1, 1 << 40)
                    }
                }
                7 => {
                    new.long_cap = if r.chance(0.3) {
                        0
                    } else {
                        r.range(1, 1 << 40)
                    }
                }
                _ => new.min_queue_delay_s = r.range(0, 86_400) as u32,
            }
        }
        if classify_limits(&old, &new) != Class::Tighten {
            continue;
        }
        tightened += 1;
        for _ in 0..5 {
            let reference = r.next() >> r.range(0, 40);
            let t = r.range(0, 30 * 86_400_000) as i64;
            let (po, pn) = (params_of(&old, reference), params_of(&new, reference));
            assert!(
                max_unbacked_over(&pn, t) <= max_unbacked_over(&po, t),
                "tighten raised bound: {old:?} -> {new:?}"
            );
            assert!(pn.min_queue_delay_ms >= po.min_queue_delay_ms);
        }
    }
    assert!(
        tightened > 100,
        "generator produced too few tightenings ({tightened})"
    );
}

/// A random tightening of `old`: a few fields moved, kept only if Tighten.
fn tightened(r: &mut Rng, old: &LimitConfig) -> Option<LimitConfig> {
    let mut new = *old;
    for _ in 0..r.range(1, 3) {
        match r.range(0, 5) {
            0 => new.short_window_s = new.short_window_s.saturating_mul(r.range(1, 1_000) as u32),
            1 => new.long_window_s = new.long_window_s.saturating_mul(r.range(1, 1_000) as u32),
            2 => new.short_bps = r.range(0, new.short_bps as u64) as u16,
            3 => new.long_bps = r.range(0, new.long_bps as u64) as u16,
            _ => {
                new.min_queue_delay_s = new
                    .min_queue_delay_s
                    .saturating_add(r.range(0, 86_400) as u32)
            }
        }
    }
    (classify_limits(old, &new) == Class::Tighten).then_some(new)
}

/// A tightening, applied with `rescale_windows`, never raises the instant
/// room: not at the moment it applies, and not at any later time with no
/// request in between (the room then refills no faster than before). This
/// is the property a longer window broke before backlogs were rescaled.
#[test]
fn a_tightening_never_raises_the_instant_room_now_or_later() {
    let mut r = Rng(0x7167_4E5E);
    let mut checked = 0u64;
    let mut drained = 0u64;
    for _ in 0..cases() * 4 {
        let old = random_limits(&mut r);
        let Some(new) = tightened(&mut r, &old) else {
            continue;
        };
        let reference = r.next() >> r.range(0, 40);
        let (po, pn) = (params_of(&old, reference), params_of(&new, reference));
        // A realistic state: requests under the old limits.
        let mut s = LimiterState::default();
        let mut t = r.range(0, 1 << 40) as i64;
        if po.short.capacity > 0 && po.long.capacity > 0 {
            for _ in 0..r.range(0, 6) {
                t += r.range(0, 2 * po.short.window_ms as u64) as i64;
                let amount = match r.range(0, 3) {
                    0 => available_now(&s, &po, t).max(1),
                    1 => r.range(1, po.short.capacity.max(1)),
                    _ => {
                        let shift = r.range(0, 63);
                        r.range(1, u64::MAX >> shift)
                    }
                };
                let _ = request(&mut s, &po, t, amount, 0);
            }
        }
        if available_now(&s, &po, t) == 0 {
            drained += 1;
        }
        let mut sn = s;
        rescale_windows(&mut sn, &po, &pn, t);
        let far = r.range(0, 1 << 36) as i64;
        for dt in [
            0,
            1,
            1_000,
            po.short.window_ms,
            pn.short.window_ms,
            po.long.window_ms,
            pn.long.window_ms,
            far,
        ] {
            let later = t + dt;
            assert!(
                available_now(&sn, &pn, later) <= available_now(&s, &po, later),
                "tightening raised the room at +{dt} ms: {old:?} -> {new:?}, state {s:?} -> {sn:?}"
            );
        }
        checked += 1;
    }
    assert!(
        checked > 1_000 && drained > 100,
        "too few useful cases: {checked} checked, {drained} drained"
    );
}

/// The attack the rescaling stops: a stolen admin key drains the burst, then
/// lengthens the windows (a tightening, applied at once), over and over. All
/// it is paid, at any horizon, stays within the G1 bound of the limits it
/// started from.
#[test]
fn a_thief_who_only_tightens_is_held_to_the_starting_g1_bound() {
    let mut r = Rng(0x7419_E000);
    let mut paid_more_than_one_burst = 0u64;
    for _ in 0..cases() {
        let start = random_limits(&mut r);
        let reference = r.range(1, 1 << 50);
        let p0 = params_of(&start, reference);
        if p0.short.capacity == 0 || p0.long.capacity == 0 {
            continue;
        }
        let t0 = r.range(0, 1 << 40) as i64;
        let (mut cfg, mut s, mut t, mut paid) = (start, LimiterState::default(), t0, 0u128);
        for _ in 0..r.range(1, 12) {
            let p = params_of(&cfg, reference);
            let room = available_now(&s, &p, t);
            if room > 0 && request(&mut s, &p, t, room, 0) == Ok(Decision::Instant) {
                paid += room as u128;
                if paid > p0.short.capacity.min(p0.long.capacity) as u128 {
                    paid_more_than_one_burst += 1;
                }
            }
            if let Some(next) = tightened(&mut r, &cfg) {
                rescale_windows(&mut s, &p, &params_of(&next, reference), t);
                cfg = next;
            }
            let (any, roll) = (r.range(0, 1 << 30), r.next());
            t += pick(&[0, 0, 1, 1_000, 60_000, any], roll) as i64;
        }
        assert!(
            paid <= max_unbacked_over(&p0, t - t0),
            "paid {paid} in {} ms; G1 of the starting limits is {} ({start:?})",
            t - t0,
            max_unbacked_over(&p0, t - t0)
        );
    }
    assert!(
        paid_more_than_one_burst > 10,
        "time passed in too few cases: {paid_more_than_one_burst}"
    );
}

/// A Tighten asset change never raises collateral value or lowers liability value.
#[test]
fn tighten_asset_never_adds_value() {
    let mut r = Rng(0xA55E);
    let mut tightened = 0;
    for _ in 0..cases() * 4 {
        let feed = [r.range(0, 2) as u8; 32];
        let old = AssetConfig {
            allowlisted: r.chance(0.8),
            haircut_bps: r.range(0, 10_000) as u32,
            liability_bps: r.range(10_000, 20_000) as u32,
            conf_mult_bps: r.range(0, 40_000) as u32,
            max_age_s: r.range(0, 600) as u32,
            max_conf_bps: r.range(0, 1_000) as u32,
            feed_id: feed,
        };
        let mut new = old;
        match r.range(0, 5) {
            0 => new.haircut_bps = r.range(0, 10_000) as u32,
            1 => new.liability_bps = r.range(10_000, 20_000) as u32,
            2 => new.conf_mult_bps = r.range(0, 40_000) as u32,
            3 => new.allowlisted = r.chance(0.5),
            _ => new.feed_id = [r.range(0, 2) as u8; 32],
        }
        if classify_asset(Some(&old), &new) != Class::Tighten {
            continue;
        }
        tightened += 1;
        let price = r.range(1, 1 << 40) as i64;
        let ema = r.range(1, 1 << 40) as i64;
        let conf = r.range(0, 1 << 30);
        let pricing = |c: &AssetConfig| {
            if !c.allowlisted {
                return Pricing::NotAllowlisted;
            }
            let b = conservative(price, conf, ema, c.conf_mult_bps).unwrap();
            Pricing::Priced(PricedAsset {
                lo: b.lo,
                hi: b.hi,
                expo: -8,
                decimals: 6,
                haircut_bps: c.haircut_bps,
                liability_bps: c.liability_bps,
            })
        };
        for net in [r.range(1, 1 << 50) as i128, -(r.range(1, 1 << 50) as i128)] {
            let o = contribution(net, &pricing(&old));
            let n = contribution(net, &pricing(&new));
            // None = unknown liability = most conservative; treat as -infinity.
            let rank = |x: Option<i128>| x.unwrap_or(i128::MIN);
            assert!(
                rank(n) <= rank(o),
                "asset tighten added value: {old:?} -> {new:?}"
            );
        }
    }
    assert!(tightened > 100);
}

// ---------------------------------------------------------------------------
// Floor
// ---------------------------------------------------------------------------

fn header(machine: u16, flags: u32) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2;
    h[5] = 1;
    h[18..20].copy_from_slice(&machine.to_le_bytes());
    h[48..52].copy_from_slice(&flags.to_le_bytes());
    h
}

#[test]
fn simd0500_gate() {
    assert!(deployable_after_simd0500(elf_info(&header(0xF7, 3))));
    assert!(!deployable_after_simd0500(elf_info(&header(0xF7, 0)))); // v0: blocked after SIMD-0500
    assert!(!deployable_after_simd0500(elf_info(&header(0x107, 2))));
    assert!(elf_info(&header(0x3E, 3)).is_none()); // x86-64 is not a Solana program
    assert!(elf_info(&header(0xF7, 3)[..40]).is_none());
}

#[test]
fn upgrade_delay_is_a_floor() {
    assert_eq!(upgrade_eta(1_000, 0), 1_000 + MIN_UPGRADE_DELAY_S);
    assert_eq!(
        upgrade_eta(1_000, MIN_UPGRADE_DELAY_S * 2),
        1_000 + MIN_UPGRADE_DELAY_S * 2
    );
    let a = [1u8; 32];
    let b = [2u8; 32];
    let p = RestoreSource::Proposed;
    assert!(can_restore(p, &a, &a, true, false, 0, 100, 200)); // approved buffer + quorum: fast
    assert!(can_restore(p, &a, &a, true, true, 0, 100, 200)); // the quorum overrides one veto
    assert!(!can_restore(p, &b, &a, true, false, 0, 100, 200)); // a different buffer: waits
    assert!(!can_restore(p, &a, &a, false, false, 0, 100, 200)); // no quorum: waits
    assert!(can_restore(p, &b, &a, false, false, 100, 100, 200)); // delay passed, no veto
    assert!(!can_restore(p, &b, &a, false, true, 100, 100, 200)); // vetoed
    assert!(!can_restore(p, &b, &a, false, false, 200, 100, 200)); // expired
    let s = RestoreSource::Snapshot;
    assert!(can_restore(s, &b, &a, true, true, 0, 100, 200)); // snapshot: quorum is enough
    assert!(!can_restore(s, &a, &a, false, false, 150, 100, 200)); // and always needed
}

/// Snapshot identity against a direct model of loader-v3 `Upgrade` (copy the
/// buffer to the front, zero-fill the rest), on random programs up to 300
/// bytes, with the edits that matter: truncation, one flipped byte, a nonzero
/// tail, an empty buffer, a buffer longer than the program.
#[test]
fn snapshot_matches_iff_upgrade_leaves_program_unchanged() {
    let mut rng = Rng(0x5a1a);
    let (mut yes, mut no) = (0u32, 0u32);
    for _ in 0..cases() * 4 {
        let len = rng.range(0, 300) as usize;
        let mut region: Vec<u8> = (0..len).map(|_| rng.range(0, 255) as u8).collect();
        region.extend(std::iter::repeat_n(0, rng.range(0, 40) as usize));
        let cut = rng.range(0, region.len() as u64 + 2) as usize;
        let mut buf = region[..cut.min(region.len())].to_vec();
        if cut > region.len() {
            buf.push(0);
        }
        match rng.range(0, 3) {
            0 if !buf.is_empty() => {
                let i = rng.range(0, buf.len() as u64 - 1) as usize;
                buf[i] ^= 1 << rng.range(0, 7);
            }
            1 if region.len() > buf.len() => {
                let i = rng.range(buf.len() as u64, region.len() as u64 - 1) as usize;
                region[i] = rng.range(1, 255) as u8;
            }
            _ => {}
        }
        let identity = buf.len() <= region.len() && {
            let mut after = vec![0u8; region.len()];
            after[..buf.len()].copy_from_slice(&buf);
            after == region
        };
        let expect = !buf.is_empty() && identity;
        assert_eq!(snapshot_matches(&buf, &region), expect);
        if expect {
            yes += 1
        } else {
            no += 1
        }
    }
    // Coverage scales with depth: each outcome is at least 5% of the cases.
    let total = (yes + no) as u64;
    assert!(
        yes as u64 * 20 >= total && no as u64 * 20 >= total,
        "coverage: {yes} matches, {no} mismatches"
    );
}

/// Ejection, stated directly: a current guardian can be ejected exactly when a
/// live quorum (threshold ≥ 2) of the *other* guardians approves and at least
/// `threshold` guardians remain.
#[test]
fn eject_matches_its_definition() {
    let mut rng = Rng(0xe1ec7);
    let mut ejected = 0u32;
    for _ in 0..cases() * 10 {
        let count = rng.range(0, 9) as u8;
        let th = rng.range(0, 9) as u8;
        let target = rng.range(0, 9) as u8;
        let (ap, al) = (rng.range(0, 255) as u8, rng.range(0, 255) as u8);
        let others_live = (0..count)
            .filter(|&i| i != target && (ap as u16) >> i & 1 == 1 && (al as u16) >> i & 1 == 1)
            .count() as u8;
        let expect = count <= 8 && target < count && th >= 2 && count > th && others_live >= th;
        assert_eq!(
            governance::can_eject(ap, al, th, target, count),
            expect,
            "ap={ap:08b} al={al:08b} th={th} target={target} count={count}"
        );
        ejected += expect as u32;
    }
    assert!(
        ejected as u64 * 100 >= cases() * 10,
        "coverage: {ejected} ejections (at least 1%)"
    );
}

// ---------------------------------------------------------------------------
// Governance (G4, G5)
// ---------------------------------------------------------------------------

/// A loosening can never execute before now + 72h, whatever delay is requested;
/// vetoed, executed, abdicated or expired changes never execute.
#[test]
fn governance_loosen_never_early_and_never_after_veto_or_expiry() {
    let mut r = Rng(0x60F);
    for _ in 0..cases() * 5 {
        let now = r.range(0, 1 << 40) as i64;
        let delay = r.range(0, 30 * 86_400) as i64;
        let s = governance::schedule(now, Class::Loosen, delay);
        assert!(s.executable_s >= now + MIN_LOOSEN_DELAY_S);
        assert_eq!(s.expires_s, s.executable_s + CHANGE_EXPIRY_S);
        let t = now + r.range(0, 20 * 86_400) as i64;
        let (v, ex, ab) = (r.chance(0.3), r.chance(0.2), r.chance(0.1));
        let res = governance::can_execute(&s, t, v, ex, ab);
        if res.is_ok() {
            assert!(t >= now + MIN_LOOSEN_DELAY_S && t < s.expires_s && !v && !ex && !ab);
        }
        let tight = governance::schedule(now, Class::Tighten, delay);
        assert_eq!(tight.executable_s, now);
    }
}

#[test]
fn governance_freeze_quorum_heartbeat_abdication() {
    let mut r = Rng(0x61F);
    for _ in 0..cases() * 5 {
        let now = r.range(0, 1 << 40) as i64;
        let cur = r.range(0, 1 << 41) as i64;
        let secs = r.range(0, 200_000) as i64 - 10;
        match governance::freeze_until(cur, now, secs) {
            Ok(u) => {
                assert!(secs > 0 && secs <= 86_400);
                assert!(u >= cur, "a freeze never shortens an existing freeze");
                assert!(u <= cur.max(now + 86_400));
            }
            Err(e) => assert_eq!(e, GovError::InvalidDuration),
        }
        let (ap, al, th) = (r.next() as u8, r.next() as u8, (r.next() % 9) as u8);
        if governance::quorum(ap, al, th) {
            assert!(th > 0 && (ap & al).count_ones() >= th as u32);
        }
        // dead guardians never count
        assert!(!governance::quorum(ap, 0, th));
        let last = r.range(0, 1 << 40) as i64;
        let interval = r.range(0, 40 * 86_400) as i64;
        let t = last + r.range(0, 40 * 86_400) as i64;
        if governance::guardian_alive(last, interval, t) {
            assert!(t - last <= interval && (86_400..=30 * 86_400).contains(&interval));
        }
        let mask = Abdications(r.next() as u32);
        let k = (r.next() % 40) as u8;
        let m2 = mask.abdicate(k);
        assert_eq!(m2.0 & mask.0, mask.0, "abdication never clears a bit");
        if k < 32 {
            assert!(m2.is_abdicated(k));
            let s = Schedule {
                executable_s: 0,
                expires_s: i64::MAX,
            };
            assert_eq!(
                governance::can_execute(&s, 1, false, false, m2.is_abdicated(k)),
                Err(GovError::Abdicated)
            );
        }
    }
}
