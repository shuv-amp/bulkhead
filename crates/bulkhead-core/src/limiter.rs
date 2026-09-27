//! Unbacked-lane limiter: two GCRA buckets with FIFO reservations.
//!
//! A bucket is one timestamp, the theoretical arrival time (TAT). A request of
//! `u` costs `ceil(u * W / C)` milliseconds. It conforms when the new TAT is at
//! most `W` ahead of now. The short bucket (default 2% per hour) bounds the
//! burst; the long bucket (default 5% per day) bounds a patient attacker who
//! takes only the refill. A request is instant only if it conforms to both and
//! the lane is not frozen; otherwise it becomes a ticket with an ETA.
//!
//! Guarantee (G1, proved in docs/03-MECHANISM.md): the total amount requested
//! in `[t0, t0 + T]` and paid by `t0 + T` is at most `C_k * (W_k + T) / W_k`
//! for each bucket `k`. Queued requests reserve capacity, cancelled tickets do
//! not refund it, and `reset_backlog` is only legal with zero pending tickets;
//! each of those rules is needed for the bound.

use crate::classify::LimitConfig;
use crate::consts::{BPS, COST_MAX_MS, QUEUE_HORIZON_S};
use crate::math::ceil_div_u128;

/// One token bucket: capacity in base units and window in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub capacity: u64,
    pub window_ms: i64,
}

/// Limiter parameters for one vault or mint gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimiterParams {
    /// Burst bucket (default: 2% of the reference balance per hour).
    pub short: Bucket,
    /// Daily cap bucket (default: 5% of the reference balance per 24 hours).
    pub long: Bucket,
    /// No ticket settles earlier than `created + min_queue_delay_ms` (default 6 hours).
    pub min_queue_delay_ms: i64,
    /// Requests whose ETA would be further out than this are rejected (default 7 days).
    pub horizon_ms: i64,
}

/// Mutable limiter state: one TAT per bucket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LimiterState {
    pub tat_short_ms: i64,
    pub tat_long_ms: i64,
}

/// What happens to an unbacked request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Paid now.
    Instant,
    /// Becomes a ticket, payable (unless cancelled) at `eta_ms`.
    Queued { eta_ms: i64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimiterError {
    ZeroAmount,
    /// A bucket has capacity 0: the unbacked lane is closed.
    LaneClosed,
    /// The ETA would exceed the queue horizon. State is unchanged.
    QueueFull,
    /// `reset_backlog` called while tickets are pending.
    TicketsPending,
}

impl LimiterError {
    pub fn code(&self) -> &'static str {
        match self {
            LimiterError::ZeroAmount => "ZeroAmount",
            LimiterError::LaneClosed => "LaneClosed",
            LimiterError::QueueFull => "QueueFull",
            LimiterError::TicketsPending => "TicketsPending",
        }
    }
}

/// The limiter parameters a vault runs with right now: capacities from the
/// reference balance, windows and delays converted from seconds to ms, and the
/// constant queue horizon. A capacity of 0 closes the unbacked lane.
pub fn params_from_config(cfg: &LimitConfig, reference: u64) -> LimiterParams {
    LimiterParams {
        short: Bucket {
            capacity: capacity_from_ref(reference, cfg.short_bps, cfg.short_floor, cfg.short_cap),
            window_ms: cfg.short_window_s as i64 * 1_000,
        },
        long: Bucket {
            capacity: capacity_from_ref(reference, cfg.long_bps, cfg.long_floor, cfg.long_cap),
            window_ms: cfg.long_window_s as i64 * 1_000,
        },
        min_queue_delay_ms: cfg.min_queue_delay_s as i64 * 1_000,
        horizon_ms: QUEUE_HORIZON_S * 1_000,
    }
}

/// Whether a limits configuration is acceptable at all (checked when a vault
/// is created and when a change is proposed): bps ≤ 10 000, windows > 0.
pub fn config_is_valid(cfg: &LimitConfig) -> bool {
    cfg.short_bps as u128 <= BPS
        && cfg.long_bps as u128 <= BPS
        && cfg.short_window_s > 0
        && cfg.long_window_s > 0
}

/// `C = clamp(floor(reference * bps / 10_000), floor, cap)`; `cap == 0` means no cap.
/// The raw product saturates at `u64::MAX`. (The program also rejects
/// `bps > 10_000` at config time; the differential runner found that an earlier
/// version truncated here instead of saturating when `bps > 10_000`.)
pub fn capacity_from_ref(reference: u64, bps: u16, floor: u64, cap: u64) -> u64 {
    let wide = reference as u128 * bps as u128 / BPS;
    let raw = if wide > u64::MAX as u128 {
        u64::MAX
    } else {
        wide as u64
    };
    clamp_capacity(raw, floor, cap)
}

/// The clamp step of `capacity_from_ref`, split out so the floor/cap logic can
/// be proved for every u64 separately from the multiply-divide.
pub fn clamp_capacity(raw: u64, floor: u64, cap: u64) -> u64 {
    let mut c = if raw < floor { floor } else { raw };
    if cap > 0 && c > cap {
        c = cap;
    }
    c
}

/// Time cost of `amount` in bucket `b`, rounded up, saturated at `COST_MAX_MS`.
/// Requires `b.capacity > 0` and `b.window_ms > 0`.
pub fn cost_ms(amount: u64, b: &Bucket) -> i64 {
    let num = amount as u128 * b.window_ms as u128; // < 2^64 * 2^63, fits u128
    let c = ceil_div_u128(num, b.capacity as u128);
    if c > COST_MAX_MS as u128 {
        COST_MAX_MS
    } else {
        c as i64
    }
}

/// Submit an unbacked request of `amount` at `now_ms`.
/// `frozen_until_ms > now_ms` means the lane is frozen.
pub fn request(
    state: &mut LimiterState,
    p: &LimiterParams,
    now_ms: i64,
    amount: u64,
    frozen_until_ms: i64,
) -> Result<Decision, LimiterError> {
    if amount == 0 {
        return Err(LimiterError::ZeroAmount);
    }
    if p.short.capacity == 0 || p.long.capacity == 0 {
        return Err(LimiterError::LaneClosed);
    }
    let nt_short = state.tat_short_ms.max(now_ms) + cost_ms(amount, &p.short);
    let nt_long = state.tat_long_ms.max(now_ms) + cost_ms(amount, &p.long);
    let frozen = now_ms < frozen_until_ms;
    if !frozen && nt_short - now_ms <= p.short.window_ms && nt_long - now_ms <= p.long.window_ms {
        state.tat_short_ms = nt_short;
        state.tat_long_ms = nt_long;
        return Ok(Decision::Instant);
    }
    let mut eta = (now_ms + p.min_queue_delay_ms)
        .max(nt_short - p.short.window_ms)
        .max(nt_long - p.long.window_ms);
    if frozen {
        eta = eta.max(frozen_until_ms);
    }
    if eta - now_ms > p.horizon_ms {
        return Err(LimiterError::QueueFull);
    }
    state.tat_short_ms = nt_short;
    state.tat_long_ms = nt_long;
    Ok(Decision::Queued { eta_ms: eta })
}

/// After an incident is cleaned up (every ticket settled or cancelled), clamp
/// each bucket to "just emptied" so honest flows resume at the refill rate.
/// This never grants more than a fresh empty bucket, which is why G1 survives it.
pub fn reset_backlog(
    state: &mut LimiterState,
    p: &LimiterParams,
    now_ms: i64,
    pending_tickets: u32,
) -> Result<(), LimiterError> {
    if pending_tickets != 0 {
        return Err(LimiterError::TicketsPending);
    }
    let cap_short = now_ms + p.short.window_ms;
    let cap_long = now_ms + p.long.window_ms;
    if state.tat_short_ms > cap_short {
        state.tat_short_ms = cap_short;
    }
    if state.tat_long_ms > cap_long {
        state.tat_long_ms = cap_long;
    }
    Ok(())
}

/// Largest amount that would be paid instantly right now (ignoring freezes).
/// This is the "worst case right now" number on the status page.
pub fn available_now(state: &LimiterState, p: &LimiterParams, now_ms: i64) -> u64 {
    fn one(tat: i64, b: &Bucket, now: i64) -> u128 {
        let backlog = tat.max(now) - now;
        let room = b.window_ms - backlog;
        if room <= 0 {
            0
        } else {
            room as u128 * b.capacity as u128 / b.window_ms as u128
        }
    }
    let a = one(state.tat_short_ms, &p.short, now_ms).min(one(state.tat_long_ms, &p.long, now_ms));
    if a > u64::MAX as u128 {
        u64::MAX
    } else {
        a as u64
    }
}

/// G1 bound: most unbacked value an attacker starting at a full bucket can be
/// paid within `t_ms`: `min_k C_k * (W_k + t) / W_k` (floored).
pub fn max_unbacked_over(p: &LimiterParams, t_ms: i64) -> u128 {
    let t = t_ms.max(0) as u128;
    let one = |b: &Bucket| b.capacity as u128 * (b.window_ms as u128 + t) / b.window_ms as u128;
    one(&p.short).min(one(&p.long))
}
