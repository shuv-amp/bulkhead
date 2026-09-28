//! Adversarial scenarios: an attacker who knows every rule and picks the
//! inputs the core is fed (timing, request sizes, the vault balance the
//! reference follows). Each test states the attack, runs it through the real
//! core functions, and asserts what it gets. Findings are reported in
//! docs/15-ADVERSARIAL-REVIEW.md; run with `--nocapture` to see the numbers.

use bulkhead_core::classify::LimitConfig;
use bulkhead_core::ema::ema_update;
use bulkhead_core::limiter::{
    available_now, max_unbacked_over, params_from_config, request, Decision, LimiterState,
};

const USDC: u64 = 1_000_000;
const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;

fn defaults() -> LimitConfig {
    LimitConfig {
        short_bps: 200,
        short_window_s: 3_600,
        long_bps: 500,
        long_window_s: 86_400,
        min_queue_delay_s: 21_600,
        short_floor: 0,
        long_floor: 0,
        short_cap: 0,
        long_cap: 0,
    }
}

/// A vault as the program sees it: live balance, reference (EMA), limiter.
struct Vault {
    balance: u64,
    reference: u64,
    ref_at: i64,
    lim: LimiterState,
    /// If true, capacities come from `min(reference, balance)` (the proposed
    /// mitigation); otherwise from the reference alone (current programs).
    min_with_balance: bool,
}

impl Vault {
    fn new(balance: u64, min_with_balance: bool) -> Vault {
        Vault {
            balance,
            reference: balance,
            ref_at: 0,
            lim: LimiterState::default(),
            min_with_balance,
        }
    }

    /// Every program instruction touches the reference with the balance
    /// *before* the operation (`touch_reference`).
    fn touch(&mut self, now: i64) {
        self.reference = ema_update(self.reference, self.ref_at, self.balance, now, true);
        self.ref_at = now;
    }

    fn capacity_base(&self) -> u64 {
        if self.min_with_balance {
            self.reference.min(self.balance)
        } else {
            self.reference
        }
    }

    /// Backed flows (own deposits in, own deposits out) never meet the limiter.
    fn backed_in(&mut self, now: i64, amount: u64) {
        self.touch(now);
        self.balance += amount;
    }

    fn backed_out(&mut self, now: i64, amount: u64) {
        self.touch(now);
        self.balance -= amount;
    }

    /// An unbacked payout the attacker sizes to exactly what is instant now.
    fn drain_instant(&mut self, now: i64) -> u64 {
        self.touch(now);
        let p = params_from_config(&defaults(), self.capacity_base());
        let want = available_now(&self.lim, &p, now * 1_000).min(self.balance);
        if want == 0 {
            return 0;
        }
        match request(&mut self.lim, &p, now * 1_000, want, 0) {
            Ok(Decision::Instant) => {
                self.balance -= want;
                want
            }
            other => panic!("available_now said {want} was instant, got {other:?}"),
        }
    }
}

/// Attacker drains every `step` seconds for `span` seconds from `start`.
fn drain_for(v: &mut Vault, start: i64, span: i64, step: i64) -> u64 {
    let mut total = 0;
    let mut t = start;
    while t <= start + span {
        total += v.drain_instant(t);
        t += step;
    }
    total
}

/// Honest traffic touches the vault every hour.
fn hourly_touches(v: &mut Vault, from: i64, to: i64) {
    let mut t = from;
    while t < to {
        v.touch(t);
        t += HOUR;
    }
}

/// The advertised 24-hour bound measured on the vault that is actually there.
fn bound_24h_on(balance: u64) -> u128 {
    max_unbacked_over(&params_from_config(&defaults(), balance), DAY * 1_000)
}

/// Finding A1. A whale parks a large *backed* deposit for three days so the
/// reference climbs toward it, then takes it back instantly (G2: own deposits
/// are never throttled or frozen). The capacities are still sized for the
/// inflated reference, so the unbacked lane pays several times the advertised
/// share of the vault that is left. The whale needs capital, not a stolen key;
/// paired with a stolen admin key (the Drift class) it multiplies the drain.
#[test]
fn finding_a1_reference_inflation_multiplies_the_unbacked_drain() {
    let (vault, whale) = (10_000_000 * USDC, 90_000_000 * USDC);
    let mut v = Vault::new(vault, false);
    v.backed_in(0, whale);
    hourly_touches(&mut v, HOUR, 3 * DAY);
    v.backed_out(3 * DAY, whale);
    let taken = drain_for(&mut v, 3 * DAY, DAY, 60);
    let bound = bound_24h_on(vault);
    eprintln!(
        "A1: reference {} USDC over a {} USDC vault; 24h unbacked drain {} USDC vs advertised {} USDC ({:.1}x)",
        v.reference / USDC,
        vault / USDC,
        taken / USDC,
        bound / USDC as u128,
        taken as f64 / bound as f64
    );
    assert!(
        taken as u128 >= 4 * bound,
        "expected a multiple of the bound, got {taken}"
    );
}

/// The same attack when capacities come from `min(reference, live balance)`:
/// the whale's exit shrinks the capacity at once, and the drain stays within
/// the advertised bound on the vault that is left. A deposit before an attack
/// still can't raise the capacity (the reference still lags upward).
#[test]
fn mitigation_a1_min_of_reference_and_balance_restores_the_bound() {
    let (vault, whale) = (10_000_000 * USDC, 90_000_000 * USDC);
    let mut v = Vault::new(vault, true);
    v.backed_in(0, whale);
    hourly_touches(&mut v, HOUR, 3 * DAY);
    v.backed_out(3 * DAY, whale);
    let taken = drain_for(&mut v, 3 * DAY, DAY, 60);
    let bound = bound_24h_on(vault);
    eprintln!(
        "A1 mitigated: 24h unbacked drain {} USDC vs advertised {} USDC",
        taken / USDC,
        bound / USDC as u128
    );
    assert!(taken as u128 <= bound);

    // And a deposit one minute before the attack still buys almost nothing
    // (golden G-8's property): the burst stays within 1% of 2% of the vault
    // that was there before the deposit.
    let mut w = Vault::new(vault, true);
    w.backed_in(0, whale);
    let burst = w.drain_instant(60);
    assert!(burst <= vault / 50 + vault / 5_000, "burst {burst}");
}

/// Finding A1, honest variant. After an honest bank run through the backed
/// lane (S4), the limiter is still sized for the vault before the run, so the
/// first attacker afterwards gets a burst several times 2% of what is left.
#[test]
fn finding_a1_after_a_bank_run_the_burst_is_sized_for_the_old_vault() {
    let vault = 10_000_000 * USDC;
    let mut v = Vault::new(vault, false);
    hourly_touches(&mut v, 0, DAY);
    // 90% of depositors leave within the hour, all backed.
    for i in 0..9 {
        v.backed_out(DAY + i * 300, vault / 10);
    }
    let left = v.balance;
    let burst = v.drain_instant(DAY + HOUR);
    let advertised = left / 50; // 2% of the vault that is left
    eprintln!(
        "A1 bank run: {} USDC left, instant burst {} USDC ({:.1}x the 2% burst)",
        left / USDC,
        burst / USDC,
        burst as f64 / advertised as f64
    );
    assert!(burst >= 5 * advertised);

    let mut m = Vault::new(vault, true);
    hourly_touches(&mut m, 0, DAY);
    for i in 0..9 {
        m.backed_out(DAY + i * 300, vault / 10);
    }
    assert!(m.drain_instant(DAY + HOUR) <= m.balance / 49);
}

/// SplitMix64, as in the property tests.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The cluster clock is not guaranteed to be strictly monotonic between
/// slots. An attacker who lands requests while `unix_timestamp` steps back
/// must not gain: at every step, what has been paid instantly stays within G1
/// over the *real* elapsed span (latest time seen minus the first request).
#[test]
fn clock_stepping_backwards_never_beats_g1() {
    let cases: u64 = std::env::var("BULKHEAD_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);
    let mut rng = Rng(0xB01C_4EAD);
    let mut worst = 0f64;
    for _ in 0..cases {
        let reference = (1 + rng.below(1_000_000)) * USDC;
        let p = params_from_config(&defaults(), reference);
        let mut st = LimiterState::default();
        let start = rng.below(1_000_000) as i64 * 1_000;
        let (mut now, mut latest, mut paid) = (start, start, 0u128);
        for _ in 0..200 {
            // Mostly forward, sometimes back by up to 30 s, never before start.
            now = if rng.below(4) == 0 {
                (now - rng.below(30_000) as i64).max(start)
            } else {
                now + rng.below(600_000) as i64
            };
            latest = latest.max(now);
            let amount = 1 + rng.below(p.short.capacity.max(1) * 2);
            if let Ok(Decision::Instant) = request(&mut st, &p, now, amount, 0) {
                paid += amount as u128;
            }
            let bound = max_unbacked_over(&p, latest - start);
            assert!(paid <= bound, "paid {paid} > G1 {bound}");
            worst = worst.max(paid as f64 / bound as f64);
        }
    }
    eprintln!("clock steps back: worst paid/G1 = {worst:.4} over {cases} sessions");
}
