//! The limiter at full width, with overflow checks on: random parameters and
//! random sequences of requests, resets and window changes. Checked at every
//! step: no arithmetic overflow anywhere; an instant payout only unfrozen and
//! within both windows; a ticket never early, never past the horizon; errors
//! change nothing; `available_now` is exact (that much is instant, one more is
//! not); and a window change keeps the used fraction (rounded toward "used"), except
//! where it saturates at `COST_MAX_MS`, which leaves the bucket full.
#![no_main]
use arbitrary::Arbitrary;
use bulkhead_core::consts::COST_MAX_MS;
use bulkhead_core::limiter::{
    available_now, max_unbacked_over, request, rescale_windows, reset_backlog, Bucket, Decision,
    LimiterParams, LimiterState,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Request {
        dt: u32,
        amount: u64,
        freeze_for: u32,
    },
    Reset {
        dt: u32,
        pending: u8,
    },
    Windows {
        short_s: u32,
        long_s: u32,
    },
}

#[derive(Arbitrary, Debug)]
struct Input {
    caps: (u64, u64),
    windows_s: (u32, u32),
    delay_s: u32,
    start_ms: u32,
    ops: Vec<Op>,
}

fn params(c: (u64, u64), w_s: (u32, u32), delay_s: u32) -> LimiterParams {
    LimiterParams {
        short: Bucket {
            capacity: c.0.max(1),
            window_ms: w_s.0.max(1) as i64 * 1_000,
        },
        long: Bucket {
            capacity: c.1.max(1),
            window_ms: w_s.1.max(1) as i64 * 1_000,
        },
        min_queue_delay_ms: delay_s as i64 * 1_000,
        horizon_ms: 604_800_000,
    }
}

fuzz_target!(|input: Input| {
    let mut p = params(input.caps, input.windows_s, input.delay_s);
    let mut s = LimiterState::default();
    let mut now: i64 = 1_700_000_000_000 + input.start_ms as i64;
    let mut frozen_until: i64 = 0;
    for op in input.ops.into_iter().take(64) {
        match op {
            Op::Request {
                dt,
                amount,
                freeze_for,
            } => {
                now += dt as i64;
                if freeze_for % 4 == 0 {
                    frozen_until = frozen_until.max(now + freeze_for as i64);
                }
                let room = available_now(&s, &p, now);
                // Exactness, unfrozen: `room` is instant and `room + 1` is not.
                if now >= frozen_until && room > 0 {
                    let mut probe = s;
                    assert_eq!(
                        request(&mut probe, &p, now, room, frozen_until),
                        Ok(Decision::Instant)
                    );
                }
                if now >= frozen_until && room < u64::MAX {
                    let mut probe = s;
                    assert_ne!(
                        request(&mut probe, &p, now, room + 1, frozen_until),
                        Ok(Decision::Instant)
                    );
                }
                let before = s;
                match request(&mut s, &p, now, amount, frozen_until) {
                    Ok(Decision::Instant) => {
                        assert!(now >= frozen_until);
                        assert!(
                            s.tat_short_ms - now <= p.short.window_ms
                                && s.tat_long_ms - now <= p.long.window_ms
                        );
                    }
                    Ok(Decision::Queued { eta_ms }) => {
                        assert!(
                            eta_ms >= now + p.min_queue_delay_ms && eta_ms - now <= p.horizon_ms
                        );
                        if now < frozen_until {
                            assert!(eta_ms >= frozen_until);
                        }
                    }
                    Err(_) => assert_eq!(s, before),
                }
            }
            Op::Reset { dt, pending } => {
                now += dt as i64;
                let before = s;
                if reset_backlog(&mut s, &p, now, pending as u32 % 2).is_ok() {
                    assert!(s.tat_short_ms <= before.tat_short_ms.max(now + p.short.window_ms));
                    assert!(
                        s.tat_short_ms <= now + p.short.window_ms
                            || s.tat_short_ms == before.tat_short_ms
                    );
                } else {
                    assert_eq!(s, before);
                }
            }
            Op::Windows { short_s, long_s } => {
                let next = params(
                    (p.short.capacity, p.long.capacity),
                    (short_s, long_s),
                    (p.min_queue_delay_ms / 1_000) as u32,
                );
                let before = s;
                rescale_windows(&mut s, &p, &next, now);
                for (b, a, wo, wn) in [
                    (
                        before.tat_short_ms,
                        s.tat_short_ms,
                        p.short.window_ms,
                        next.short.window_ms,
                    ),
                    (
                        before.tat_long_ms,
                        s.tat_long_ms,
                        p.long.window_ms,
                        next.long.window_ms,
                    ),
                ] {
                    if b <= now {
                        assert_eq!(a, b);
                    } else {
                        let (bo, bn) = ((b - now) as i128, (a - now) as i128);
                        if a - now == COST_MAX_MS {
                            // Saturated (units.rs rescale_windows_saturation_keeps_the_bucket_full):
                            // only reachable far past one full window, so the bucket stays full.
                            assert!(bn > wn as i128, "saturated but not full");
                        } else {
                            assert!(
                                bn * wo as i128 >= bo * wn as i128,
                                "fraction kept, rounded toward used"
                            );
                        }
                    }
                }
                p = next;
            }
        }
        let _ = max_unbacked_over(&p, now);
    }
});
