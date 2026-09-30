//! Scenario: an honest liquidation cascade on a -30% day (docs/15 section 4,
//! item 3). No attacker: every payout is a legitimate liquidation. The
//! question is whether Bulkhead's limiter delays liquidations while prices
//! are still falling, which a lending protocol would see as bad debt.
//!
//! Everything that decides an outcome runs through the real core: the
//! liquidator's backing (`Ledger::backed_amount` at `conservative` prices),
//! the reference (`ema_update`), the capacity base, and the limiter
//! (`request`). Only the market is synthetic, and every input is stated:
//!
//! - a SOL collateral vault of 1,000,000 SOL at $150;
//! - price path: -20% in a fast leg (2 hours, 30 minutes or 10 minutes),
//!   then down to -30% by hour 24;
//! - Pyth's EMA modelled as an exponential average with a 1-hour time
//!   constant; confidence 0.25% of spot in the fast leg, 0.08% after;
//!   `conf_mult_bps` 2.0 (the G-10 example);
//! - weights as in golden G-11 (USDC haircut 99%, SOL liability 105%);
//! - liquidation bonus 5%;
//! - a share `S` of the vault is seized over the day, in proportion to how
//!   far the price fell in each 1-minute step, as requests of at most
//!   1,000 SOL each.
//!
//! Run with `--nocapture` to see the numbers; docs/08 reports them.

use bulkhead_core::classify::LimitConfig;
use bulkhead_core::ema::ema_update;
use bulkhead_core::ledger::{Ledger, Mint, PricedAsset, Pricing};
use bulkhead_core::limiter::{
    capacity_base, params_from_config, request, Decision, LimiterError, LimiterState,
};
use bulkhead_core::price::conservative;

const SOL: u64 = 1_000_000_000;
const MINUTE: i64 = 60;
const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;
const STEP: i64 = MINUTE;
const CHUNK: u64 = 1_000 * SOL;
const VAULT: u64 = 1_000_000 * SOL;
const BONUS_BPS: u128 = 500;
const CONF_MULT_BPS: u32 = 20_000;

const USDC_MINT: Mint = [1; 32];
const SOL_MINT: Mint = [2; 32];

fn limits(short_bps: u16, long_bps: u16, short_cap: u64, long_cap: u64) -> LimitConfig {
    LimitConfig {
        short_bps,
        short_window_s: 3_600,
        long_bps,
        long_window_s: 86_400,
        min_queue_delay_s: 21_600,
        short_floor: 0,
        long_floor: 0,
        short_cap,
        long_cap,
    }
}

fn defaults() -> LimitConfig {
    limits(200, 500, 0, 0)
}

/// A1b calibration: absolute caps at 2% / 5% of the honest vault.
fn defaults_with_caps() -> LimitConfig {
    limits(200, 500, VAULT / 50, VAULT / 20)
}

/// Spot in dollars at `t` seconds: 150 -> 120 over the fast leg, -> 105 by
/// hour 24, flat after.
fn spot_usd(t: i64, fast_s: i64) -> f64 {
    let t = t as f64;
    let (f, d) = (fast_s as f64, DAY as f64);
    if t <= f {
        150.0 - 30.0 * t / f
    } else if t <= d {
        120.0 - 15.0 * (t - f) / (d - f)
    } else {
        105.0
    }
}

/// Price feed per step: (spot, conf, ema) as Pyth mantissas with expo -8.
fn feed(steps: usize, fast_s: i64) -> Vec<(i64, u64, i64)> {
    let mut out = Vec::with_capacity(steps + 1);
    let mut ema = spot_usd(0, fast_s);
    let alpha = 1.0 - (-(STEP as f64) / HOUR as f64).exp();
    for i in 0..=steps {
        let t = i as i64 * STEP;
        let s = spot_usd(t, fast_s);
        if i > 0 {
            ema += (s - ema) * alpha;
        }
        let conf = s * if t <= fast_s { 0.0025 } else { 0.0008 };
        out.push(((s * 1e8) as i64, (conf * 1e8) as u64, (ema * 1e8) as i64));
    }
    out
}

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

fn sol(spot: i64, conf: u64, ema: i64) -> Pricing {
    let b = conservative(spot, conf, ema, CONF_MULT_BPS).expect("positive prices");
    Pricing::Priced(PricedAsset {
        lo: b.lo,
        hi: b.hi,
        expo: -8,
        decimals: 9,
        haircut_bps: 8_500,
        liability_bps: 10_500,
    })
}

#[derive(Debug, Default)]
struct Outcome {
    seized: u64,
    backed: u64,
    unbacked: u64,
    instant: u64,
    queued: u64,
    rejected: u64,
    /// Longest wait of any queued liquidation payout, in seconds.
    max_wait_s: i64,
    /// Dollars the liquidators lose to the price falling while they wait:
    /// sum over queued payouts of amount * (spot at request - spot at ETA).
    /// A rational liquidator refuses that trade; the protocol keeps the debt.
    exposure_usd: f64,
}

impl Outcome {
    fn delayed(&self) -> u64 {
        self.queued + self.rejected
    }
}

fn run(share_bps: u64, fast_s: i64, cfg: &LimitConfig) -> Outcome {
    let steps = (DAY / STEP) as usize;
    let prices = feed(steps, fast_s);
    let total_drop = (prices[0].0 - prices[steps].0) as u128;
    let to_seize = VAULT as u128 * share_bps as u128 / 10_000;

    let (mut balance, mut reference, mut ref_at) = (VAULT, VAULT, 0i64);
    let mut lim = LimiterState::default();
    let mut pending: Vec<(i64, u64)> = Vec::new(); // (eta_s, amount)
    let mut o = Outcome::default();
    let mut seized_so_far: u128 = 0;

    for (i, &(spot, conf, ema)) in prices.iter().enumerate().skip(1) {
        let now = i as i64 * STEP;

        // Queued payouts whose ETA has come leave the vault.
        pending.retain(|&(eta, amount)| {
            if eta <= now {
                reference = ema_update(reference, ref_at, balance, eta, true);
                ref_at = eta;
                balance -= amount;
                false
            } else {
                true
            }
        });

        // Seizures proportional to the fall so far (rounding carried forward).
        let fallen = (prices[0].0 - spot) as u128;
        let target = to_seize * fallen / total_drop;
        let mut left = (target - seized_so_far) as u64;
        seized_so_far = target;

        while left > 0 {
            let seized = left.min(CHUNK);
            left -= seized;
            // The liquidator repays debt worth seized / (1 + bonus) in USDC:
            // lamports * spot_e8 / 1e11 is USDC base units.
            let repay = (seized as u128 * spot as u128 * 10_000
                / (100_000_000_000 * (10_000 + BONUS_BPS))) as u64;
            let mut ledger = Ledger::default();
            assert!(ledger.credit(USDC_MINT, repay));
            let lookup = |m: &Mint| {
                if *m == USDC_MINT {
                    usdc()
                } else {
                    sol(spot, conf, ema)
                }
            };
            let b = ledger.backed_amount(&SOL_MINT, seized, &lookup);
            let u = seized - b;

            reference = ema_update(reference, ref_at, balance, now, true);
            ref_at = now;
            balance -= b;
            o.seized += seized;
            o.backed += b;
            o.unbacked += u;
            if u == 0 {
                continue;
            }
            let p = params_from_config(cfg, capacity_base(reference, balance));
            match request(&mut lim, &p, now * 1_000, u, 0) {
                Ok(Decision::Instant) => {
                    balance -= u;
                    o.instant += u;
                }
                Ok(Decision::Queued { eta_ms }) => {
                    let eta = (eta_ms + 999) / 1_000;
                    pending.push((eta, u));
                    o.queued += u;
                    o.max_wait_s = o.max_wait_s.max(eta - now);
                    let drop = spot_usd(now, fast_s) - spot_usd(eta, fast_s);
                    o.exposure_usd += u as f64 / SOL as f64 * drop.max(0.0);
                }
                Err(LimiterError::QueueFull) => o.rejected += u,
                Err(e) => panic!("unexpected limiter error {e:?}"),
            }
        }
    }
    assert_eq!(o.backed + o.unbacked, o.seized);
    assert_eq!(o.instant + o.queued + o.rejected, o.unbacked);
    o
}

fn sol_units(x: u64) -> String {
    format!("{:.0}", x as f64 / SOL as f64)
}

fn report(name: &str, share_bps: u64, fast_s: i64, o: &Outcome) {
    println!(
        "{name:<10} fast leg {:>4}m  S={:>4.1}%  seized {:>7}  unbacked {:>6} ({:>4.1}%)  instant {:>6}  queued {:>6}  rejected {:>5}  max wait {:>4.1}h  liquidator exposure ${:>11.0}",
        fast_s / MINUTE,
        share_bps as f64 / 100.0,
        sol_units(o.seized),
        sol_units(o.unbacked),
        o.unbacked as f64 * 100.0 / o.seized.max(1) as f64,
        sol_units(o.instant),
        sol_units(o.queued),
        sol_units(o.rejected),
        o.max_wait_s as f64 / 3_600.0,
        o.exposure_usd,
    );
}

/// Smallest share of the vault (in 1% steps) whose cascade delays at least
/// one liquidation, or `None` if even 60% does not.
fn first_delayed_share(fast_s: i64, cfg: &LimitConfig) -> Option<u64> {
    (1..=60u64)
        .map(|p| p * 100)
        .find(|&s| run(s, fast_s, cfg).delayed() > 0)
}

/// More than the bonus is unbacked. The liquidator's repayment backs only
/// what it covers at the conservative *high* SOL price times the 105%
/// liability weight, against USDC at 99%; while the price falls, Pyth's EMA
/// sits above spot, so `hi` is above spot and backing shrinks further.
#[test]
fn crash_unbacked_share_of_a_liquidation_exceeds_the_bonus() {
    let bonus_share = BONUS_BPS as f64 / (10_000 + BONUS_BPS) as f64;
    for fast_s in [2 * HOUR, 30 * MINUTE, 10 * MINUTE] {
        let o = run(1_000, fast_s, &defaults());
        report("defaults", 1_000, fast_s, &o);
        let share = o.unbacked as f64 / o.seized as f64;
        assert!(
            share > 2.0 * bonus_share,
            "unbacked share {share:.4} vs bonus share {bonus_share:.4}"
        );
    }
}

/// The sizing question from docs/15: at which cascade size do the default
/// limits (and the A1b caps) start delaying honest liquidations, how does
/// that depend on how fast the price falls, and what would a lending market
/// have to set instead? Prints the numbers docs/08 reports.
#[test]
fn crash_cascade_sizing_table() {
    let legs = [2 * HOUR, 30 * MINUTE, 10 * MINUTE];
    for fast_s in legs {
        for share in [1_000u64, 2_000, 3_000, 4_000] {
            let d = run(share, fast_s, &defaults());
            let c = run(share, fast_s, &defaults_with_caps());
            report("defaults", share, fast_s, &d);
            report("+A1b caps", share, fast_s, &c);
            // Caps never pay more instantly than no caps.
            assert!(c.instant <= d.instant);
        }
    }

    let thresholds: Vec<(i64, Option<u64>, Option<u64>)> = legs
        .iter()
        .map(|&f| {
            (
                f,
                first_delayed_share(f, &defaults()),
                first_delayed_share(f, &defaults_with_caps()),
            )
        })
        .collect();
    for (f, d, c) in &thresholds {
        println!(
            "fast leg {:>4}m: defaults first delay a liquidation at S = {:?}%, with A1b caps at S = {:?}%",
            f / MINUTE,
            d.map(|s| s / 100),
            c.map(|s| s / 100)
        );
    }
    // A faster crash never lets a bigger cascade through.
    for w in thresholds.windows(2) {
        let (slow, fast) = (w[0].1.unwrap_or(u64::MAX), w[1].1.unwrap_or(u64::MAX));
        assert!(fast <= slow, "{:?} then {:?}", w[0], w[1]);
    }
    // The numbers docs/08 reports. The A1b caps change nothing here: the
    // capacity base only falls during a cascade, so the caps never bind.
    let firsts: Vec<(Option<u64>, Option<u64>)> =
        thresholds.iter().map(|&(_, d, c)| (d, c)).collect();
    assert_eq!(
        firsts,
        vec![
            (Some(4_300), Some(4_300)),
            (Some(2_200), Some(2_200)),
            (Some(1_700), Some(1_700)),
        ]
    );

    // Smallest limits on a 1:2.5 ladder (the defaults' ratio) that absorb a
    // 30% cascade in the 10-minute crash with nothing delayed.
    let needed = (200u16..=5_000)
        .step_by(100)
        .map(|short| (short, short * 5 / 2))
        .find(|&(s, l)| run(3_000, 10 * MINUTE, &limits(s, l, 0, 0)).delayed() == 0);
    let (short, long) = needed.expect("some ladder up to 50%/h absorbs it");
    println!(
        "a 30% cascade in a 10-minute crash needs at least {:.0}%/h and {:.1}%/day",
        short as f64 / 100.0,
        long as f64 / 100.0
    );
    assert_eq!((short, long), (400, 1_000));
}
