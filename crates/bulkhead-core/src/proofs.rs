//! Kani proof harnesses (bounded model checking, github.com/model-checking/kani).
//!
//! Random tests sample inputs; these harnesses check a property for **every**
//! input in the stated domain. Run with `scripts/prove.sh`.
//!
//! Two kinds of harness, labelled on each:
//! - **FULL**: every value of the Rust types involved (e.g. every u64), except
//!   the explicitly stated time bounds (years ≤ ~35,000).
//! - **SMALL-WIDTH**: paths that multiply and divide *symbolic* 128-bit
//!   values. SAT solvers cannot finish symbolic 128-bit multiplier/divider
//!   circuits at full width, so these check every input with amounts,
//!   capacities and windows below 2^20. The branch logic does not depend on
//!   width.
//!
//! Properties that are *pure arithmetic* (cost rounding, value rounding, bps
//! monotonicity, two-payout G1, the G2 search) did not finish in 20 minutes
//! even at small width; SAT solvers are weakest on multiplier/divider
//! equivalence. They are checked instead by exhaustive enumeration of every
//! input in a small domain (`tests/exhaustive.rs`), which is as rigorous as
//! bounded model checking on that domain. Full-width arithmetic is covered by
//! the property tests, 6.9M differential cases, and the written overflow
//! arguments in docs/03 §10.

use crate::classify::{classify_limits, Class, LimitConfig};
use crate::ema::ema_update;
use crate::floor::{
    buffer_authority, can_restore, deployable_after_simd0500, elf_info, programdata_header,
    snapshot_matches, RestoreSource,
};
use crate::governance::{
    alive_mask, can_eject, can_execute, freeze_until, guardian_alive, guardian_set_ok, quorum,
    schedule, signer_bits, Abdications,
};
use crate::limiter::{
    clamp_capacity, lane_always_closed, params_from_config, request, reset_backlog, Bucket,
    Decision, LimiterParams, LimiterState,
};
use crate::price::conservative;

const MAX_TIME_MS: i64 = 1 << 50; // ~35,000 years of unix milliseconds
const SMALL: u64 = 1 << 20; // small-width domain bound

fn small_params() -> LimiterParams {
    let p = LimiterParams {
        short: Bucket {
            capacity: kani::any(),
            window_ms: kani::any(),
        },
        long: Bucket {
            capacity: kani::any(),
            window_ms: kani::any(),
        },
        min_queue_delay_ms: kani::any(),
        horizon_ms: kani::any(),
    };
    kani::assume(p.short.capacity > 0 && p.short.capacity < SMALL);
    kani::assume(p.long.capacity > 0 && p.long.capacity < SMALL);
    kani::assume(p.short.window_ms > 0 && p.short.window_ms < SMALL as i64);
    kani::assume(p.long.window_ms > 0 && p.long.window_ms < SMALL as i64);
    kani::assume(p.min_queue_delay_ms >= 0 && p.min_queue_delay_ms < SMALL as i64);
    kani::assume(p.horizon_ms > 0 && p.horizon_ms < SMALL as i64);
    p
}

// ---------------------------------------------------------------------------
// FULL domain
// ---------------------------------------------------------------------------

/// FULL. `reset_backlog` refuses with pending tickets; otherwise each TAT is
/// unchanged or clamped to exactly "empty at now" (never more capacity than
/// a just-emptied bucket, which is what keeps G1 valid across resets).
#[kani::proof]
fn reset_never_exceeds_an_empty_bucket() {
    let p = LimiterParams {
        short: Bucket {
            capacity: kani::any(),
            window_ms: kani::any(),
        },
        long: Bucket {
            capacity: kani::any(),
            window_ms: kani::any(),
        },
        min_queue_delay_ms: kani::any(),
        horizon_ms: kani::any(),
    };
    kani::assume(p.short.window_ms > 0 && p.short.window_ms <= MAX_TIME_MS);
    kani::assume(p.long.window_ms > 0 && p.long.window_ms <= MAX_TIME_MS);
    let mut s = LimiterState {
        tat_short_ms: kani::any(),
        tat_long_ms: kani::any(),
    };
    let now: i64 = kani::any();
    kani::assume(now >= 0 && now <= MAX_TIME_MS);
    kani::assume(s.tat_short_ms >= 0 && s.tat_short_ms <= MAX_TIME_MS * 2);
    kani::assume(s.tat_long_ms >= 0 && s.tat_long_ms <= MAX_TIME_MS * 2);
    let before = s;
    let pending: u32 = kani::any();
    let r = reset_backlog(&mut s, &p, now, pending);
    if pending != 0 {
        assert!(r.is_err() && s == before);
    } else {
        assert!(r.is_ok());
        assert!(s.tat_short_ms == before.tat_short_ms || s.tat_short_ms == now + p.short.window_ms);
        assert!(s.tat_long_ms == before.tat_long_ms || s.tat_long_ms == now + p.long.window_ms);
        assert!(s.tat_short_ms <= before.tat_short_ms && s.tat_long_ms <= before.tat_long_ms);
    }
}

/// FULL (every u64 raw, floor and cap). Capacity respects floor and cap, and a
/// tighter floor or cap never yields more. (The multiply-divide before the clamp
/// is monotone in bps; that arithmetic step is checked exhaustively in
/// `tests/exhaustive.rs`, see module docs.)
#[kani::proof]
fn capacity_clamp_is_monotone() {
    let raw: u64 = kani::any();
    let (floor, cap): (u64, u64) = (kani::any(), kani::any());
    let (raw2, floor2, cap2): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let c = clamp_capacity(raw, floor, cap);
    if cap > 0 {
        assert!(c <= cap);
    } else {
        assert!(c >= floor && c >= raw);
    }
    let cap_tighter = cap2 == cap || (cap == 0 && cap2 > 0) || (cap2 > 0 && cap2 <= cap);
    if raw2 <= raw && floor2 <= floor && cap_tighter {
        assert!(clamp_capacity(raw2, floor2, cap2) <= c);
    }
}

/// FULL. A limits change classified Tighten never shortens a window or delay,
/// and never raises bps, floors or caps (so, with the harness above, never
/// raises any capacity).
#[kani::proof]
fn classify_tighten_is_sound() {
    let any_cfg = || LimitConfig {
        short_bps: kani::any(),
        short_window_s: kani::any(),
        long_bps: kani::any(),
        long_window_s: kani::any(),
        min_queue_delay_s: kani::any(),
        short_floor: kani::any(),
        long_floor: kani::any(),
        short_cap: kani::any(),
        long_cap: kani::any(),
    };
    let (old, new) = (any_cfg(), any_cfg());
    if classify_limits(&old, &new) == Class::Tighten {
        assert!(new.short_bps <= old.short_bps && new.long_bps <= old.long_bps);
        assert!(new.short_floor <= old.short_floor && new.long_floor <= old.long_floor);
        assert!(new.short_window_s >= old.short_window_s && new.long_window_s >= old.long_window_s);
        assert!(new.min_queue_delay_s >= old.min_queue_delay_s);
        let tighter = |o: u64, n: u64| n == o || (o == 0 && n > 0) || (n > 0 && n <= o);
        assert!(tighter(old.short_cap, new.short_cap) && tighter(old.long_cap, new.long_cap));
    }
}

/// FULL. A config `lane_always_closed` accepts has a bucket of capacity 0 at
/// every reference balance, so `request` refuses every unbacked amount
/// (`LaneClosed`). The Vault relies on it for vaults created after the seal.
#[kani::proof]
fn a_closed_lane_stays_closed_at_every_balance() {
    let cfg = LimitConfig {
        short_bps: kani::any(),
        short_window_s: kani::any(),
        long_bps: kani::any(),
        long_window_s: kani::any(),
        min_queue_delay_s: kani::any(),
        short_floor: kani::any(),
        long_floor: kani::any(),
        short_cap: kani::any(),
        long_cap: kani::any(),
    };
    let reference: u64 = kani::any();
    if lane_always_closed(&cfg) {
        let p = params_from_config(&cfg, reference);
        assert!(p.short.capacity == 0 || p.long.capacity == 0);
    }
}

/// FULL (every i64 price/EMA, u64 confidence, u32 multiplier). Bounds bracket
/// spot and EMA; `None` exactly for non-positive inputs.
#[kani::proof]
#[kani::solver(kissat)]
fn conservative_price_brackets() {
    let (price, ema): (i64, i64) = (kani::any(), kani::any());
    let conf: u64 = kani::any();
    let mult: u32 = kani::any();
    match conservative(price, conf, ema, mult) {
        Some(b) => {
            assert!(price > 0 && ema > 0);
            assert!(b.lo <= price.min(ema) as u128 && b.hi >= price.max(ema) as u128);
        }
        None => {
            assert!(price <= 0 || ema <= 0);
        }
    }
}

/// SMALL-WIDTH (prices and confidence < 2^16, multiplier < 2^12). The
/// widening is exactly `k = ceil(conf * mult / 10_000)` on both sides (`lo`
/// saturates at 0), stated without a division: k is the least integer with
/// `k * 10_000 >= conf * mult`. (At full width the u128 product did not finish
/// within CI's hour, and at 2^20 it took 10 minutes; the property test checks
/// it at full width.)
#[kani::proof]
#[kani::solver(kissat)]
fn conservative_price_widening_is_exact() {
    let (price, ema): (i64, i64) = (kani::any(), kani::any());
    let conf: u64 = kani::any();
    let mult: u32 = kani::any();
    kani::assume(price > 0 && price < 1 << 16 && ema > 0 && ema < 1 << 16);
    kani::assume(conf < 1 << 16 && mult < 1 << 12);
    let b = conservative(price, conf, ema, mult).unwrap();
    let k = b.hi - price.max(ema) as u128;
    let p = conf as u128 * mult as u128;
    assert!(k * crate::consts::BPS >= p);
    assert!(k == 0 || (k - 1) * crate::consts::BPS < p);
    assert!(b.lo == (price.min(ema) as u128).saturating_sub(k));
}

/// FULL (every 64-byte header). Exactly the BPF-machine ELFs with e_flags == 3
/// pass the SIMD-0500 gate (e_flags 4 is sBPF V4, which agave does not enable).
#[kani::proof]
fn elf_gate_is_total() {
    let h: [u8; 64] = kani::any();
    let info = elf_info(&h);
    let v3 = h[0] == 0x7f
        && h[1] == b'E'
        && h[2] == b'L'
        && h[3] == b'F'
        && h[4] == 2
        && h[5] == 1
        && u16::from_le_bytes([h[18], h[19]]) == crate::consts::EM_BPF
        && u32::from_le_bytes([h[48], h[49], h[50], h[51]]) == 3;
    assert!(deployable_after_simd0500(info) == v3);
}

/// FULL (every byte value; buffer ≤ 6 bytes, programdata region ≤ 8 bytes).
/// Semantic check of the snapshot rule against a model of loader-v3 `Upgrade`
/// (copy the buffer to the front, zero-fill the rest): `snapshot_matches` is
/// true exactly when upgrading from the buffer leaves the region unchanged.
#[kani::proof]
#[kani::unwind(10)]
fn snapshot_matches_iff_upgrade_is_identity() {
    let buf: [u8; 6] = kani::any();
    let region: [u8; 8] = kani::any();
    let (n, m): (usize, usize) = (kani::any(), kani::any());
    kani::assume(n <= 6 && m <= 8);
    let (b, r) = (&buf[..n], &region[..m]);
    let upgrade_fits = n <= m;
    let mut after = [0u8; 8];
    if upgrade_fits {
        after[..n].copy_from_slice(b); // Upgrade: copy, then the rest is zero
    }
    let identity = upgrade_fits && after[..m] == *r;
    assert!(snapshot_matches(b, r) == (n > 0 && identity));
}

/// FULL. Restore rules: a snapshot needs exactly a live quorum; a proposed
/// buffer is fast only if the quorum approved that exact buffer, and otherwise
/// needs no veto and `eta ≤ now < expires`.
#[kani::proof]
fn restore_rules_are_exact() {
    let (b, a): (u8, u8) = (kani::any(), kani::any());
    let (q, v): (bool, bool) = (kani::any(), kani::any());
    let (now, eta, exp): (i64, i64, i64) = (kani::any(), kani::any(), kani::any());
    let snap = can_restore(
        RestoreSource::Snapshot,
        &[b; 32],
        &[a; 32],
        q,
        v,
        now,
        eta,
        exp,
    );
    assert!(snap == q);
    let prop = can_restore(
        RestoreSource::Proposed,
        &[b; 32],
        &[a; 32],
        q,
        v,
        now,
        eta,
        exp,
    );
    assert!(prop == ((q && b == a) || (!v && now >= eta && now < exp)));
}

/// FULL. Ejection: only a current guardian, never by its own vote, only by a
/// live quorum of the others, never below the threshold, never with a
/// threshold under 2.
#[kani::proof]
fn eject_rules_hold() {
    let (ap, al, th, target, count): (u8, u8, u8, u8, u8) = (
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    if can_eject(ap, al, th, target, count) {
        assert!(target < count && count <= 8);
        assert!(th >= 2 && count > th);
        let members = ((1u16 << count) - 1) as u8;
        let others = ap & members & !(1u8 << target) & al;
        assert!(others.count_ones() >= th as u32);
    }
    if target < 8 {
        let with_self = ap | (1u8 << target);
        let without_self = ap & !(1u8 << target);
        assert!(
            can_eject(with_self, al, th, target, count)
                == can_eject(without_self, al, th, target, count)
        );
    }
}

/// FULL. Every guardian in an accepted set can be ejected by a live quorum of
/// the others (finding 96), and ejection is reachable in exactly the sets
/// larger than their threshold, so a set an ejection has shrunk to
/// `threshold + 1` keys can still eject (refusing that, option (a) of
/// AUD-2, would leave a rogue in place). An accepted set keeps a margin of
/// at least two keys over its threshold, and two is enough (finding 107).
#[kani::proof]
fn accepted_sets_can_eject_anyone() {
    let (count, th, target): (u8, u8, u8) = (kani::any(), kani::any(), kani::any());
    kani::assume(target < count);
    let reachable = can_eject(0xFF, 0xFF, th, target, count);
    assert!(reachable == (count <= 8 && th >= 2 && count > th));
    if guardian_set_ok(count, th) {
        assert!(reachable && count >= 4 && count >= th + 2);
    }
    if (2..=6).contains(&th) {
        assert!(guardian_set_ok(th + 2, th) && !guardian_set_ok(th + 1, th));
    }
}

/// FULL. Live honest guardians at least `threshold` strong eject any rogue,
/// wherever the slots sit and whoever else is alive: lost keys still inside
/// their heartbeat interval, other rogues. An ejection removes one rogue and
/// leaves the honest guardians as they were, so they eject every rogue in
/// turn (the slot shift is the programs' `eject`, tested in LiteSVM).
#[kani::proof]
fn an_honest_live_quorum_ejects_any_rogue() {
    let (count, th, honest, rogue, alive, target): (u8, u8, u8, u8, u8, u8) = (
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    kani::assume(count <= 8 && th >= 2 && target < count);
    let members = ((1u16 << count) - 1) as u8;
    kani::assume(honest & !members == 0 && honest & rogue == 0 && honest & !alive == 0);
    kani::assume(rogue & (1 << target) != 0);
    kani::assume(honest.count_ones() >= th as u32);
    assert!(can_eject(honest, alive, th, target, count));
}

/// FULL (AUD-2, finding 107). In every accepted set, any two faulty keys,
/// lost or rogue in any slots, leave a live honest quorum, unless the rogues
/// are a quorum themselves (two rogues in a 2-of-n set are; out of scope,
/// 04 T7). That quorum restores or unfreezes alone and ejects each rogue,
/// and the rogues alone eject no honest guardian. One lost key and one
/// rogue locked a 2-of-3 set for good.
#[kani::proof]
fn accepted_sets_survive_any_two_faults() {
    let (count, th, lost, rogue, alive, target): (u8, u8, u8, u8, u8, u8) = (
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    kani::assume(guardian_set_ok(count, th) && target < count);
    let members = ((1u16 << count) - 1) as u8;
    let faulty = lost | rogue;
    kani::assume(faulty & !members == 0 && lost & rogue == 0 && faulty.count_ones() <= 2);
    kani::assume(rogue.count_ones() < th as u32);
    let honest = members & !faulty;
    kani::assume(honest & !alive == 0);
    assert!(honest.count_ones() >= th as u32);
    assert!(quorum(honest, alive, th));
    if rogue & (1 << target) != 0 {
        assert!(can_eject(honest, alive, th, target, count));
    }
    if honest & (1 << target) != 0 {
        assert!(!can_eject(rogue, alive, th, target, count));
    }
}

/// FULL. The guardian bitmaps never set a bit for an empty slot: liveness
/// over any heartbeats, count and times, and the bits of up to 3 signers
/// whose keys may be any guardian slot, any empty slot or no slot at all.
#[kani::proof]
#[kani::unwind(34)]
fn guardian_bitmaps_stay_within_the_set() {
    let (beats, count, interval, now): ([i64; 8], u8, i64, i64) =
        (kani::any(), kani::any(), kani::any(), kani::any());
    let members = if count >= 8 { 0xFF } else { (1u8 << count) - 1 };
    assert!(alive_mask(&beats, count, interval, now) & !members == 0);
    let mut keys = [[0u8; 32]; 8];
    for (i, k) in keys.iter_mut().enumerate() {
        *k = [i as u8 + 1; 32];
    }
    let signer = || -> ([u8; 32], bool) { ([kani::any::<u8>(); 32], kani::any()) };
    let signers = [signer(), signer(), signer()];
    if let Ok(bits) = signer_bits(&keys, count, signers) {
        assert!(bits & !members == 0);
        assert!(signers.iter().all(|(_, signed)| *signed));
    }
}

/// FULL (every 48-byte prefix of any length). The loader-v3 parsers never
/// panic, and accept only their own account kind.
#[kani::proof]
fn loader_parsers_are_total() {
    let data: [u8; 48] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 48);
    let d = &data[..n];
    if buffer_authority(d).is_some() {
        assert!(n >= 37 && d[0] == 1 && d[1] == 0 && d[2] == 0 && d[3] == 0 && d[4] <= 1);
    }
    if let Some(h) = programdata_header(d) {
        assert!(n >= 45 && d[0] == 3 && d[1] == 0 && d[2] == 0 && d[3] == 0);
        assert!(h.upgrade_authority.is_some() == (d[12] == 1));
    }
}

/// FULL. G4: a loosening is never executable before now + 72h, whatever delay is
/// requested; nothing executes after veto, execution, abdication or expiry.
#[kani::proof]
fn governance_g4_holds() {
    let now: i64 = kani::any();
    let delay: i64 = kani::any();
    let t: i64 = kani::any();
    kani::assume(
        now >= 0 && now <= 1 << 45 && delay >= 0 && delay <= 1 << 40 && t >= 0 && t <= 1 << 46,
    );
    let s = schedule(now, Class::Loosen, delay);
    let (v, ex, ab): (bool, bool, bool) = (kani::any(), kani::any(), kani::any());
    if can_execute(&s, t, v, ex, ab).is_ok() {
        assert!(t >= now + crate::consts::MIN_LOOSEN_DELAY_S);
        assert!(t < s.expires_s);
        assert!(!v && !ex && !ab);
    }
}

/// FULL. G5 building blocks: a freeze never shortens an existing freeze and adds
/// at most 24h; quorum never counts a dead guardian; liveness needs a recent
/// heartbeat; abdication never clears a bit.
#[kani::proof]
fn governance_g5_building_blocks() {
    let (cur, now, secs): (i64, i64, i64) = (kani::any(), kani::any(), kani::any());
    kani::assume(cur >= 0 && cur <= 1 << 45 && now >= 0 && now <= 1 << 45);
    if let Ok(u) = freeze_until(cur, now, secs) {
        assert!(u >= cur && u <= cur.max(now + crate::consts::MAX_FREEZE_S));
    }
    let (ap, al, th): (u8, u8, u8) = (kani::any(), kani::any(), kani::any());
    if quorum(ap, al, th) {
        assert!(th > 0 && (ap & al).count_ones() >= th as u32);
    }
    let (last, interval, t): (i64, i64, i64) = (kani::any(), kani::any(), kani::any());
    kani::assume(last >= 0 && last <= 1 << 45 && t >= 0 && t <= 1 << 45);
    if guardian_alive(last, interval, t) {
        assert!(t >= last && t - last <= interval);
    }
    let (mask, k): (u32, u8) = (kani::any(), kani::any());
    let m2 = Abdications(mask).abdicate(k);
    assert!(m2.0 & mask == mask);
}

// ---------------------------------------------------------------------------
// SMALL-WIDTH domain (symbolic multiply/divide)
// ---------------------------------------------------------------------------

/// SMALL-WIDTH (reference and balance < 2^20; every time up to 2^40 s). The
/// reference stays between the old reference and the balance, and equals the
/// balance once 24h have passed. (Full width timed out at 20 min: the step is a
/// symbolic u128 product divided by 86,400. The exact step is the property
/// test's: restating it here did not finish within 15 minutes.)
#[kani::proof]
#[kani::solver(kissat)]
fn ema_is_bounded() {
    let (r, bal): (u64, u64) = (kani::any(), kani::any());
    kani::assume(r < SMALL && bal < SMALL);
    let (last, now): (i64, i64) = (kani::any(), kani::any());
    kani::assume(last >= 0 && last <= 1 << 40 && now >= 0 && now <= 1 << 40);
    let v = ema_update(r, last, bal, now, true);
    assert!(v >= r.min(bal) && v <= r.max(bal));
    if now - last >= crate::consts::TAU_S {
        assert!(v == bal);
    }
}

/// SMALL-WIDTH. Every outcome of `request` obeys the rules: instant only when
/// unfrozen and conforming to both buckets; tickets respect the minimum delay,
/// the freeze, the horizon and their own conformance time; TAT never decreases;
/// errors leave the state untouched. (That an admitted request is charged its
/// full cost, G1's inductive step, is the property test
/// `an_admitted_request_charges_its_full_cost_to_both_buckets` and the
/// exhaustive G1 check: stated here, with `request`'s own u128 division, it
/// did not finish within 20 minutes, even with fixed buckets.)
#[kani::proof]
#[kani::solver(kissat)]
fn request_rules_hold_for_all_inputs() {
    let p = small_params();
    let mut s = LimiterState {
        tat_short_ms: kani::any(),
        tat_long_ms: kani::any(),
    };
    let now: i64 = kani::any();
    let frozen_until: i64 = kani::any();
    kani::assume(now >= 0 && now < 1 << 30 && frozen_until >= 0 && frozen_until < 1 << 30);
    kani::assume(s.tat_short_ms >= 0 && s.tat_short_ms <= now + p.horizon_ms + p.short.window_ms);
    kani::assume(s.tat_long_ms >= 0 && s.tat_long_ms <= now + p.horizon_ms + p.long.window_ms);
    let before = s;
    let u: u64 = kani::any();
    kani::assume(u < SMALL);
    match request(&mut s, &p, now, u, frozen_until) {
        Ok(Decision::Instant) => {
            assert!(now >= frozen_until);
            assert!(s.tat_short_ms - now <= p.short.window_ms);
            assert!(s.tat_long_ms - now <= p.long.window_ms);
            assert!(s.tat_short_ms >= before.tat_short_ms && s.tat_long_ms >= before.tat_long_ms);
        }
        Ok(Decision::Queued { eta_ms }) => {
            assert!(eta_ms >= now + p.min_queue_delay_ms);
            assert!(eta_ms - now <= p.horizon_ms);
            if now < frozen_until {
                assert!(eta_ms >= frozen_until);
            }
            assert!(s.tat_short_ms >= before.tat_short_ms && s.tat_long_ms >= before.tat_long_ms);
            assert!(eta_ms >= s.tat_short_ms - p.short.window_ms);
            assert!(eta_ms >= s.tat_long_ms - p.long.window_ms);
        }
        Err(_) => {
            assert!(s == before);
        }
    }
}
