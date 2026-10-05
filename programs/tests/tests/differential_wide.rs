//! Program ↔ model differential, wide (docs/09-VERIFICATION.md §7).
//!
//! `differential.rs` runs one fixed limit configuration through deposits,
//! releases, settlements, cancels and vault freezes. This one draws a limit
//! configuration per seed (floors and caps included, some of them far above
//! the vault's balance) and adds every other instruction that changes what can
//! leave the vault: protocol-wide freezes, quorum unfreezes of either scope,
//! ticket extensions, backlog resets, lifeboat moves in and out, and limit
//! changes (a tightening applies at once; a loosening only waits). A
//! `quote_release` is compared with the release that follows it, and every
//! field of `attest` is compared with the same figures computed from
//! `bulkhead-core` after every step.
//!
//! Depth: `BULKHEAD_PROGRAM_STEPS` steps per seed (default 250) and
//! `BULKHEAD_PROGRAM_SEEDS` seeds (default 24); `BULKHEAD_PROGRAM_SEED0` moves
//! the first seed.

mod common;

use bulkhead_core::classify::{classify_limits, Class, LimitConfig};
use bulkhead_core::ema::ema_update;
use bulkhead_core::ledger::{Ledger, PricedAsset, Pricing};
use bulkhead_core::limiter::{available_now, capacity_base, max_unbacked_over, params_from_config, request, rescale_windows, reset_backlog, Decision, LimiterState};
use common::vault::*;
use common::*;
use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::collections::BTreeMap;

const USDC: u64 = 1_000_000;

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
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// A limit configuration the program accepts, weighted to the edges: a closed
/// lane, a window of one minute or a week, a queue delay past the horizon, and
/// floors and caps below, near and far above the vault's balance.
fn random_limits(rng: &mut Rng) -> LimitConfig {
    let bps = [0u16, 1, 50, 200, 500, 2_500, 10_000];
    let amounts = [0u64, 1, 1_000 * USDC, 100_000 * USDC, 2_000_000 * USDC, 50_000_000 * USDC];
    LimitConfig {
        short_bps: if rng.below(8) == 0 { rng.pick(&bps) } else { rng.pick(&[100, 200, 500, 1_000]) },
        short_window_s: rng.pick(&[60, 600, 3_600, 7_200]),
        long_bps: if rng.below(8) == 0 { rng.pick(&bps) } else { rng.pick(&[300, 500, 2_000]) },
        long_window_s: rng.pick(&[3_600, 86_400, 604_800]),
        min_queue_delay_s: rng.pick(&[0, 600, 21_600, 604_800, 700_000]),
        short_floor: if rng.below(3) == 0 { rng.pick(&amounts) } else { 0 },
        long_floor: if rng.below(3) == 0 { rng.pick(&amounts) } else { 0 },
        short_cap: if rng.below(3) == 0 { rng.pick(&amounts) } else { 0 },
        long_cap: if rng.below(3) == 0 { rng.pick(&amounts) } else { 0 },
    }
}

fn limits_of(c: &LimitConfig) -> Limits {
    Limits {
        short_bps: c.short_bps,
        short_window_s: c.short_window_s,
        long_bps: c.long_bps,
        long_window_s: c.long_window_s,
        min_queue_delay_s: c.min_queue_delay_s,
        short_floor: c.short_floor,
        long_floor: c.long_floor,
        short_cap: c.short_cap,
        long_cap: c.long_cap,
    }
}

struct Ticket {
    amount: u64,
    eta: i64,
    extended: i64,
    account: Address,
    recipient: Address,
}

/// The host model of one USDC vault, built only from `bulkhead-core`.
struct Model {
    cfg: LimitConfig,
    balance: u64,
    lifeboat: u64,
    reference: u64,
    ref_at: i64,
    ref_init: bool,
    limiter: LimiterState,
    protocol_frozen: i64,
    vault_frozen: i64,
    ledgers: BTreeMap<[u8; 32], Ledger>,
    tickets: BTreeMap<u64, Ticket>,
    /// Bumped by every applied limits change (finding 34).
    limits_version: u32,
    /// Pending loosenings: change id -> (limits, version when proposed, executable, expires).
    pending: BTreeMap<u64, (LimitConfig, u32, i64, i64)>,
    next_change_id: u64,
}

impl Model {
    fn frozen_until(&self) -> i64 {
        self.protocol_frozen.max(self.vault_frozen)
    }
    /// The reference as the program sees it after `touch_reference` at `now`.
    fn touched(&self, now: i64) -> u64 {
        ema_update(self.reference, self.ref_at, self.balance, now, self.ref_init)
    }
    fn touch(&mut self, now: i64) {
        self.reference = self.touched(now);
        self.ref_at = now;
        self.ref_init = true;
    }
    fn queued(&self) -> u64 {
        self.tickets.values().map(|t| t.amount).sum()
    }
}

#[test]
fn program_matches_the_core_model_with_caps_freezes_and_the_lifeboat() {
    let steps = env_u64("BULKHEAD_PROGRAM_STEPS", 250);
    let seeds = env_u64("BULKHEAD_PROGRAM_SEEDS", 24);
    let first = env_u64("BULKHEAD_PROGRAM_SEED0", 0);
    let mut totals = BTreeMap::<&'static str, u64>::new();
    for seed in first..first + seeds {
        for (k, v) in run(0x5EED_0000 + seed, steps) {
            *totals.entry(k).or_default() += v;
        }
    }
    println!("program-vs-model (wide): {} steps; {totals:?}", steps * seeds);
    // Coverage: every operation and outcome occurred, so a pass is not vacuous.
    for k in [
        "deposit", "release", "backed", "instant", "queued", "refused", "quote", "settle", "cancel",
        "freeze_vault", "freeze_protocol", "unfreeze", "extend", "extend_refused", "reset", "reset_refused",
        "lifeboat_in", "lifeboat_out", "lifeboat_refused", "insufficient", "tighten", "loosen_waits",
        "loosen_executed", "loosen_stale", "loosen_early",
    ] {
        let n = totals.get(k).copied().unwrap_or(0);
        assert!(n >= 10, "{k} occurred only {n} times: {totals:?}");
    }
}

fn run(seed: u64, steps: u64) -> BTreeMap<&'static str, u64> {
    let mut rng = Rng(seed);
    let mut c = BTreeMap::<&'static str, u64>::new();
    let mut count = |k: &'static str| *c.entry(k).or_default() += 1;
    let cfg = random_limits(&mut rng);

    let mut env = Env::new();
    let m = Market::new(&mut env);
    let usdc = m.create_vault(&mut env, 6, limits_of(&cfg), [1; 32], None);
    let ix = m.upsert_asset_ix(&env, &usdc, &asset_bytes(true, 9_900, 10_100, 20_000, 60, 100, [1; 32]));
    env.ok(&[ix], &[&m.admin]);
    let lifeboat = pda(&[b"lifeboat-tokens", m.protocol.as_ref(), usdc.mint.as_ref()], &m.vault_program);

    let users: Vec<Keypair> = (0..5).map(|_| Keypair::new()).collect();
    let mut accounts = Vec::new();
    for u in &users {
        env.fund(u);
        let a = env.token_account(&usdc.mint, &u.pubkey(), &usdc.token_program);
        env.mint_to(&usdc.mint, &usdc.mint_authority, &a, 50_000_000 * USDC, &usdc.token_program);
        accounts.push(a);
    }
    let outsider = Keypair::new();
    let outsider_acc = env.token_account(&usdc.mint, &outsider.pubkey(), &usdc.token_program);

    let mut md = Model {
        cfg,
        balance: 0,
        lifeboat: 0,
        reference: 0,
        ref_at: 0,
        ref_init: false,
        limiter: LimiterState::default(),
        protocol_frozen: 0,
        vault_frozen: 0,
        ledgers: BTreeMap::new(),
        tickets: BTreeMap::new(),
        limits_version: 0,
        pending: BTreeMap::new(),
        next_change_id: 0,
    };
    let um = usdc.mint.to_bytes();
    let priced = || {
        let b = bulkhead_core::price::conservative(100_000_000, 20_000, 100_000_000, 20_000).unwrap();
        PricedAsset { lo: b.lo, hi: b.hi, expo: -8, decimals: 6, haircut_bps: 9_900, liability_bps: 10_100 }
    };
    let lookup = move |x: &[u8; 32]| if *x == um { Pricing::Priced(priced()) } else { Pricing::NotAllowlisted };

    // Genesis deposits (some vaults start small, so floors and caps above the
    // balance matter), then the seal.
    let scale = rng.pick(&[1_000u64, 100_000, 3_000_000]);
    for (i, u) in users.iter().enumerate() {
        let amount = (1 + rng.below(scale)) * USDC;
        env.ok(&[m.deposit_ix(&env, &usdc, &u.pubkey(), &accounts[i], amount)], &[u]);
        md.touch(env.time);
        md.balance += amount;
        md.ledgers.entry(u.pubkey().to_bytes()).or_default().credit(um, amount);
    }
    env.ok(&[m.propose_seal_ix()], &[&m.admin]);
    env.advance(3 * DAY);
    env.ok(&[m.execute_seal_ix(&[&usdc])], &[]);

    let mut last_heartbeat = env.time - 3 * DAY;
    for step in 0..steps {
        let jump = match rng.below(10) {
            0..=5 => rng.below(600) as i64,
            6..=8 => rng.below(4 * 3_600) as i64,
            _ => 3_600 + rng.below(48 * 3_600) as i64,
        };
        env.advance(jump);
        if env.time - last_heartbeat > 2 * DAY {
            for k in &m.g {
                let hb = m.vault_ix(14, &[], vec![AccountMeta::new(m.protocol, false), AccountMeta::new_readonly(k.pubkey(), true)]);
                env.ok(&[hb], &[k]);
            }
            last_heartbeat = env.time;
        }
        let t = env.time;
        env.set_price(&usdc.price, [1; 32], 100_000_000, 20_000, -8, 100_000_000, t);
        let now = env.time;
        let limits = format!("{:?}", md.cfg);
        let at = |what: &str| format!("seed {seed} step {step} ({what}), limits {limits}");
        match rng.below(40) {
            // Deposit.
            0..=5 => {
                let i = rng.below(users.len() as u64) as usize;
                let size = rng.pick(&[1_000u64, 200_000, 2_000_000]);
                let amount = (1 + rng.below(size)) * USDC;
                env.ok(&[m.deposit_ix(&env, &usdc, &users[i].pubkey(), &accounts[i], amount)], &[&users[i]]);
                md.touch(now);
                md.balance += amount;
                md.ledgers.entry(users[i].pubkey().to_bytes()).or_default().credit(um, amount);
                count("deposit");
            }
            // Quote, then the release itself (a user's own withdrawal or an admin payout).
            6..=19 => {
                let admin = rng.below(3) == 0;
                let (owner, recipient, signer) = if admin && rng.below(2) == 0 {
                    (outsider.pubkey(), outsider_acc, None)
                } else {
                    let i = rng.below(users.len() as u64) as usize;
                    (users[i].pubkey(), accounts[i], if admin { None } else { Some(i) })
                };
                let amount = match rng.below(6) {
                    0 => 1 + rng.below(1_000 * USDC),
                    1 | 2 => (1 + rng.below(20_000)) * USDC,
                    3 => (1 + rng.below(200_000)) * USDC,
                    4 => (1 + rng.below(2_000_000)) * USDC,
                    _ => (1 + rng.below(20_000_000)) * USDC,
                };
                let prices = vec![(usdc.asset, usdc.price)];
                let ledger = md.ledgers.get(&owner.to_bytes()).copied().unwrap_or_default();

                // The model: exactly the program's order of checks.
                let backed = ledger.backed_amount(&um, amount, &lookup);
                let unbacked = amount - backed;
                let reference = md.touched(now);
                let params = params_from_config(&md.cfg, capacity_base(reference, md.balance));
                let mut lim = md.limiter;
                let decision = if unbacked > 0 {
                    request(&mut lim, &params, now * 1_000, unbacked, md.frozen_until() * 1_000).map(Some).map_err(|_| "limiter")
                } else {
                    Ok(None)
                };
                let decision = match decision {
                    Ok(d) => {
                        let instant = if d == Some(Decision::Instant) { unbacked } else { 0 };
                        if backed + instant > md.balance { Err("insufficient") } else { Ok(d) }
                    }
                    e => e,
                };
                let expected = decision.map(|d| match d {
                    None => (backed, 0, 0, 0),
                    Some(Decision::Instant) => (backed, unbacked, 0, 0),
                    Some(Decision::Queued { eta_ms }) => (backed, 0, unbacked, (eta_ms + 999).div_euclid(1_000)),
                });

                // quote_release: same answer, nothing written.
                let mut q = vec![AccountMeta::new_readonly(m.caller, false)];
                q.extend(m.release_accounts(&env, &usdc, &recipient, &owner, &prices));
                let quote = env.send(&[m.vault_ix(23, &amount.to_le_bytes(), q)], &[]);
                match (&quote, &expected) {
                    (Ok(meta), Ok(e)) => {
                        let o = outcome(meta);
                        assert_eq!((o.backed, o.instant, o.queued, o.eta_s), *e, "{}", at("quote"));
                    }
                    (Err(f), Err(why)) => {
                        if *why == "insufficient" {
                            assert_eq!(custom_code(f), Some(verr::INSUFFICIENT_BALANCE), "{}", at("quote error"));
                        }
                    }
                    (q, e) => panic!("{}: quote {:?} vs model {e:?}", at("quote"), q.as_ref().map(outcome).map_err(|f| f.err.clone())),
                }
                count("quote");
                assert_eq!(env.balance(&usdc.vault_tokens), md.balance, "{}", at("a quote moves no tokens"));

                let ix = match signer {
                    Some(_) => m.withdraw_ix(&env, &usdc, &owner, &recipient, amount, &prices),
                    None => m.admin_payout_ix(&env, &usdc, &recipient, &owner, amount, &prices),
                };
                let (id, ticket) = m.next_ticket(&env);
                let signers: Vec<&Keypair> = match signer {
                    Some(i) => vec![&users[i]],
                    None => vec![&m.admin],
                };
                let result = env.send(&[ix], &signers);
                match (&result, expected) {
                    (Ok(meta), Ok((b, instant, queued, eta))) => {
                        let o = outcome(meta);
                        assert_eq!((o.backed, o.instant, o.queued, o.eta_s), (b, instant, queued, eta), "{}", at("release"));
                        md.touch(now);
                        md.limiter = lim;
                        let mut l = ledger;
                        l.debit_backed(um, backed, &lookup).unwrap();
                        md.ledgers.insert(owner.to_bytes(), l);
                        md.balance -= b + instant;
                        if queued > 0 {
                            md.tickets.insert(id, Ticket { amount: queued, eta, extended: 0, account: ticket, recipient });
                            count("queued");
                        }
                        count("release");
                        if b > 0 {
                            count("backed");
                        }
                        if instant > 0 {
                            count("instant");
                        }
                    }
                    (Err(f), Err(why)) => {
                        if why == "insufficient" {
                            assert_eq!(custom_code(f), Some(verr::INSUFFICIENT_BALANCE), "{}", at("release error"));
                            count("insufficient");
                        }
                        count("refused");
                    }
                    (r, e) => panic!("{}: program {:?} vs model {e:?}", at("release"), r.as_ref().map(outcome).map_err(|f| f.err.clone())),
                }
            }
            // Settle a due ticket.
            20..=22 => {
                let due = md.tickets.iter().find(|(_, tk)| tk.eta <= now).map(|(&id, tk)| (id, tk.amount, tk.account, tk.recipient));
                if let Some((id, amount, account, recipient)) = due {
                    let r = env.send(&[m.settle_ix(&usdc, &account, &recipient, &env.payer.pubkey())], &[]);
                    if now < md.frozen_until() || amount > md.balance {
                        assert!(r.is_err(), "{}", at("settle must fail: frozen or short"));
                    } else {
                        r.unwrap_or_else(|e| panic!("{}: {:?}", at("settle"), e.err));
                        md.touch(now);
                        md.balance -= amount;
                        md.tickets.remove(&id);
                        count("settle");
                    }
                }
            }
            // A guardian cancels a ticket. The reservation is not refunded.
            23 => {
                if let Some((&id, tk)) = md.tickets.iter().next() {
                    let g = m.g[0].pubkey();
                    env.ok(&[m.cancel_ix(&usdc, &tk.account, &g, &env.payer.pubkey())], &[&m.g[0]]);
                    md.tickets.remove(&id);
                    count("cancel");
                }
            }
            // A guardian extends a ticket: at most 24h a call and 7 days in total.
            24..=25 => {
                if !md.tickets.is_empty() {
                    let k = rng.below(md.tickets.len() as u64) as usize;
                    let (&id, _) = md.tickets.iter().nth(k).unwrap();
                    let secs = rng.pick(&[0i64, 1, 3_600, 86_400, 86_401]);
                    let tk = md.tickets.get_mut(&id).unwrap();
                    let ix = m.vault_ix(11, &secs.to_le_bytes(), vec![
                        AccountMeta::new_readonly(m.protocol, false),
                        AccountMeta::new(tk.account, false),
                        AccountMeta::new_readonly(m.g[2].pubkey(), true),
                    ]);
                    let r = env.send(&[ix], &[&m.g[2]]);
                    let legal = secs > 0 && secs <= 86_400 && tk.extended + secs <= 604_800;
                    assert_eq!(r.is_ok(), legal, "{}", at("extend"));
                    if legal {
                        tk.eta += secs;
                        tk.extended += secs;
                        count("extend");
                    } else {
                        count("extend_refused");
                    }
                }
            }
            // reset_backlog: legal only with no pending tickets.
            26 => {
                let ix = m.vault_ix(16, &[], vec![
                    AccountMeta::new_readonly(m.protocol, false),
                    AccountMeta::new(usdc.vault, false),
                    AccountMeta::new_readonly(m.admin.pubkey(), true),
                ]);
                let r = env.send(&[ix], &[&m.admin]);
                let params = params_from_config(&md.cfg, md.reference);
                let mut lim = md.limiter;
                match reset_backlog(&mut lim, &params, now * 1_000, md.tickets.len() as u32) {
                    Ok(()) => {
                        r.unwrap_or_else(|e| panic!("{}: {:?}", at("reset"), e.err));
                        md.limiter = lim;
                        count("reset");
                    }
                    Err(_) => {
                        assert_eq!(r.map_err(|f| custom_code(&f)).err(), Some(Some(verr::TICKETS_PENDING)), "{}", at("reset refused"));
                        count("reset_refused");
                    }
                }
            }
            // Freezes: one vault, or the whole protocol.
            27..=28 => {
                let secs = 1 + rng.below(86_400) as i64;
                let whole = rng.below(2) == 0;
                let g = if whole { &m.g[2] } else { &m.g[1] };
                env.ok(&[m.freeze_ix(&g.pubkey(), if whole { None } else { Some(&usdc) }, secs)], &[g]);
                if whole {
                    md.protocol_frozen = md.protocol_frozen.max(now + secs);
                    count("freeze_protocol");
                } else {
                    md.vault_frozen = md.vault_frozen.max(now + secs);
                    count("freeze_vault");
                }
            }
            // A guardian quorum unfreezes one scope.
            29 => {
                let whole = rng.below(2) == 0;
                let gs = [m.g[0].pubkey(), m.g[1].pubkey()];
                env.ok(&[m.unfreeze_ix(if whole { None } else { Some(&usdc) }, &gs)], &[&m.g[0], &m.g[1]]);
                if whole {
                    md.protocol_frozen = md.protocol_frozen.min(now);
                } else {
                    md.vault_frozen = md.vault_frozen.min(now);
                }
                count("unfreeze");
            }
            // The admin moves tokens into the lifeboat (sometimes more than the vault holds).
            30..=32 => {
                let amount = match rng.below(4) {
                    0 => md.balance + 1 + rng.below(1_000 * USDC),
                    1 => md.balance,
                    _ => rng.below(md.balance / 3 + 1),
                };
                let mv = m.vault_ix(24, &amount.to_le_bytes(), vec![
                    AccountMeta::new_readonly(m.protocol, false),
                    AccountMeta::new(usdc.vault, false),
                    AccountMeta::new(usdc.vault_tokens, false),
                    AccountMeta::new(lifeboat, false),
                    AccountMeta::new_readonly(usdc.mint, false),
                    AccountMeta::new_readonly(usdc.token_program, false),
                    AccountMeta::new_readonly(m.admin.pubkey(), true),
                    AccountMeta::new(env.payer.pubkey(), true),
                    AccountMeta::new_readonly(SYSTEM, false),
                ]);
                let r = env.send(&[mv], &[&m.admin]);
                if amount > md.balance {
                    assert!(r.is_err(), "{}", at("lifeboat move beyond the balance"));
                    count("lifeboat_refused");
                } else {
                    r.unwrap_or_else(|e| panic!("{}: {:?}", at("lifeboat in"), e.err));
                    md.touch(now);
                    md.balance -= amount;
                    md.lifeboat += amount;
                    count("lifeboat_in");
                }
            }
            // The admin returns lifeboat tokens to the vault.
            33..=34 => {
                if md.lifeboat > 0 {
                    let amount = if rng.below(2) == 0 { md.lifeboat } else { 1 + rng.below(md.lifeboat) };
                    let back = m.vault_ix(25, &amount.to_le_bytes(), vec![
                        AccountMeta::new_readonly(m.protocol, false),
                        AccountMeta::new(usdc.vault, false),
                        AccountMeta::new(usdc.vault_tokens, false),
                        AccountMeta::new(lifeboat, false),
                        AccountMeta::new_readonly(usdc.mint, false),
                        AccountMeta::new_readonly(usdc.token_program, false),
                        AccountMeta::new_readonly(m.admin.pubkey(), true),
                    ]);
                    env.send(&[back], &[&m.admin]).unwrap_or_else(|e| panic!("{}: {:?}", at("lifeboat out"), e.err));
                    md.touch(now);
                    md.balance += amount;
                    md.lifeboat -= amount;
                    count("lifeboat_out");
                }
            }
            // The admin changes the limits. A tightening (a longer window, lower
            // bps, a lower floor or cap) applies at once and keeps each bucket's
            // used fraction; a loosening only becomes a 72h proposal.
            35..=36 => {
                let mut next = md.cfg;
                for _ in 0..1 + rng.below(2) {
                    match rng.below(6) {
                        0 => next.short_window_s = next.short_window_s.saturating_mul(rng.pick(&[1, 2, 4, 24])).min(30 * 86_400),
                        1 => next.long_window_s = next.long_window_s.saturating_mul(rng.pick(&[1, 2, 7])).min(30 * 86_400),
                        2 => next.short_bps = (next.short_bps as u64 * rng.below(11) / 10) as u16,
                        3 => next.long_bps = (next.long_bps as u64 * rng.below(11) / 10) as u16,
                        4 => next.short_window_s = (next.short_window_s / rng.pick(&[1, 2, 4])).max(1),
                        _ => next.min_queue_delay_s = next.min_queue_delay_s.saturating_add(rng.pick(&[0, 600, 3_600])),
                    }
                }
                let vault = usdc.vault;
                let lim = limits_of(&next);
                let r = env.send(&[m.propose_change_ix(&env, 0, &vault, &lim.bytes(), Some(&vault))], &[&m.admin]);
                r.unwrap_or_else(|e| panic!("{}: {:?}", at("set limits"), e.err));
                if classify_limits(&md.cfg, &next) == Class::Tighten {
                    rescale_windows(&mut md.limiter, &params_from_config(&md.cfg, 0), &params_from_config(&next, 0), now * 1_000);
                    md.cfg = next;
                    md.limits_version += 1;
                    count("tighten");
                } else {
                    let executable = now + 3 * DAY;
                    md.pending.insert(md.next_change_id, (next, md.limits_version, executable, executable + 7 * DAY));
                    md.next_change_id += 1;
                    count("loosen_waits");
                }
            }
            // Anyone executes a pending loosening: too early, expired, stale
            // (the limits changed since it was proposed), or applied.
            37..=39 => {
                if !md.pending.is_empty() {
                    let k = rng.below(md.pending.len() as u64) as usize;
                    let (&id, &(next, base, executable, expires)) = md.pending.iter().nth(k).unwrap();
                    let exec = m.vault_ix(20, &[], vec![
                        AccountMeta::new(m.protocol, false),
                        AccountMeta::new(m.change_address(id), false),
                        AccountMeta::new(usdc.vault, false),
                        AccountMeta::new(env.payer.pubkey(), true),
                        AccountMeta::new_readonly(usdc.mint, false),
                        AccountMeta::new_readonly(usdc.token_program, false),
                        AccountMeta::new_readonly(SYSTEM, false),
                    ]);
                    let r = env.send(&[exec], &[]);
                    let expected = if now < executable {
                        Some(verr::CHANGE_NOT_EXECUTABLE)
                    } else if now >= expires {
                        Some(verr::CHANGE_EXPIRED)
                    } else if base != md.limits_version {
                        Some(verr::CHANGE_STALE)
                    } else {
                        None
                    };
                    match expected {
                        None => {
                            r.unwrap_or_else(|e| panic!("{}: {:?}", at("execute change"), e.err));
                            rescale_windows(&mut md.limiter, &params_from_config(&md.cfg, 0), &params_from_config(&next, 0), now * 1_000);
                            md.cfg = next;
                            md.limits_version += 1;
                            md.pending.remove(&id);
                            count("loosen_executed");
                        }
                        Some(code) => {
                            assert_eq!(r.map_err(|f| custom_code(&f)).err(), Some(Some(code)), "{}", at("execute change refused"));
                            count(match code {
                                verr::CHANGE_STALE => "loosen_stale",
                                verr::CHANGE_EXPIRED => "loosen_expired",
                                _ => "loosen_early",
                            });
                            if code != verr::CHANGE_NOT_EXECUTABLE {
                                md.pending.remove(&id);
                            }
                        }
                    }
                }
            }
            // Time passes with nothing sent.
            _ => {}
        }

        // Every attest field equals the core's figures for the model's state.
        let a = m.attest(&mut env, &usdc);
        let reference = md.touched(now);
        let params = params_from_config(&md.cfg, capacity_base(reference, md.balance));
        let instant = if now < md.frozen_until() { 0 } else { available_now(&md.limiter, &params, now * 1_000).min(md.balance) };
        let cap = |x: u128| x.min(u64::MAX as u128) as u64;
        assert_eq!(
            (a.available_now, a.worst_1h, a.worst_24h, a.balance, a.frozen_until, a.queued, a.pending as usize),
            (
                instant,
                cap(max_unbacked_over(&params, 3_600_000)),
                cap(max_unbacked_over(&params, 86_400_000)),
                md.balance,
                md.frozen_until(),
                md.queued(),
                md.tickets.len()
            ),
            "{}",
            at("attest")
        );
        // The lifeboat token account exists from the first move on.
        let held = if env.svm.get_account(&lifeboat).is_some() { env.balance(&lifeboat) } else { 0 };
        assert_eq!(held, md.lifeboat, "{}", at("lifeboat balance"));
    }
    for u in &users {
        let d = env.account(&m.backing(&u.pubkey())).data;
        let mut chain = Vec::new();
        for i in 0..8 {
            let o = 8 + 64 + 1 + 48 * i;
            let mint: [u8; 32] = d[o..o + 32].try_into().unwrap();
            let net = i128::from_le_bytes(d[o + 32..o + 48].try_into().unwrap());
            if net != 0 {
                chain.push((mint, net));
            }
        }
        let model: Vec<([u8; 32], i128)> = md.ledgers[&u.pubkey().to_bytes()].positions().map(|p| (p.mint, p.net)).collect();
        assert_eq!(chain, model, "seed {seed}: ledger of {}", u.pubkey());
    }
    c
}
