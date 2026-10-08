//! Program ↔ model differential (docs/09-VERIFICATION.md §7).
//!
//! Random operation sequences run on-chain (Vault through Harbor, on the real
//! runtime) and, in parallel, in a host model built only from `bulkhead-core`.
//! After every step the test compares the release outcome, the vault balance,
//! every owner's backing ledger, the queue, and checks invariants:
//! - I12: no token leaves the vault except through release or settle, in the
//!   amounts the model predicts;
//! - I14: `queued_amount` equals the sum of pending tickets;
//! - I11: guardian instructions (freeze, cancel) never move tokens.
//!
//! Depth: `BULKHEAD_PROGRAM_STEPS` steps per seed (default 250) and
//! `BULKHEAD_PROGRAM_SEEDS` seeds (default 4).

mod common;

use bulkhead_core::classify::LimitConfig;
use bulkhead_core::ema::{ema_update, WindowLow};
use bulkhead_core::ledger::{Ledger, PricedAsset, Pricing};
use bulkhead_core::limiter::{capacity_base, params_from_config, request, Decision, LimiterState};
use common::vault::*;
use common::*;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::collections::BTreeMap;

const USDC: u64 = 1_000_000;
const SOL: u64 = 1_000_000_000;

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

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// The host model of one USDC vault (plus a priced SOL vault for collateral).
struct Model {
    balance: u64,
    reference: u64,
    ref_at: i64,
    ref_init: bool,
    /// The low-water balance (finding 65), touched as the program does.
    low: WindowLow,
    limiter: LimiterState,
    frozen_until: i64,
    ledgers: BTreeMap<[u8; 32], Ledger>,
    tickets: BTreeMap<u64, (u64, i64)>, // id -> (amount, eta)
}

fn cfg() -> LimitConfig {
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

#[test]
fn program_matches_the_core_model_on_random_sequences() {
    let steps = env_u64("BULKHEAD_PROGRAM_STEPS", 250);
    let seeds = env_u64("BULKHEAD_PROGRAM_SEEDS", 4);
    let mut totals = [0u64; 8];
    for seed in 0..seeds {
        let t = run(0xB0B + seed, steps);
        for (a, b) in totals.iter_mut().zip(t) {
            *a += b;
        }
    }
    println!(
        "program-vs-model: {} steps; deposits {} | releases {} (backed {} instant {} queued {} refused {}) | settles {} | cancels {} ",
        steps * seeds, totals[0], totals[1], totals[2], totals[3], totals[4], totals[5], totals[6], totals[7]
    );
    // Coverage: every path was exercised, each many times.
    assert!(totals.iter().all(|&x| x >= 10), "every operation and outcome occurred often: {totals:?}");
}

/// Returns counters: deposits, releases, backed, instant, queued, refused, settles, cancels.
fn run(seed: u64, steps: u64) -> [u64; 8] {
    let mut rng = Rng(seed);
    let mut env = Env::new();
    let m = Market::new(&mut env);
    let usdc = m.create_vault(&mut env, 6, Limits::default_limits(), [1; 32], None);
    let sol = m.create_vault(&mut env, 9, Limits::default_limits(), [2; 32], None);
    let ix = m.upsert_asset_ix(&env, &usdc, &asset_bytes(true, 9_900, 10_100, 20_000, 60, 100, [1; 32]));
    env.ok(&[ix], &[&m.admin]);
    let ix = m.upsert_asset_ix(&env, &sol, &asset_bytes(true, 8_500, 10_500, 20_000, 60, 100, [2; 32]));
    env.ok(&[ix], &[&m.admin]);

    let users: Vec<Keypair> = (0..6).map(|_| Keypair::new()).collect();
    let mut usdc_acc = Vec::new();
    for u in &users {
        env.fund(u);
        let a = env.token_account(&usdc.mint, &u.pubkey(), &usdc.token_program);
        env.mint_to(&usdc.mint, &usdc.mint_authority, &a, 50_000_000 * USDC, &usdc.token_program);
        let s = env.token_account(&sol.mint, &u.pubkey(), &sol.token_program);
        env.mint_to(&sol.mint, &sol.mint_authority, &s, 100_000 * SOL, &sol.token_program);
        usdc_acc.push((a, s));
    }
    let outsider = Keypair::new();
    let outsider_acc = env.token_account(&usdc.mint, &outsider.pubkey(), &usdc.token_program);

    let mut md = Model {
        balance: 0,
        reference: 0,
        ref_at: 0,
        ref_init: false,
        low: WindowLow::default(),
        limiter: LimiterState::default(),
        frozen_until: 0,
        ledgers: BTreeMap::new(),
        tickets: BTreeMap::new(),
    };
    let set_prices = |env: &mut Env| {
        let t = env.time;
        env.set_price(&usdc.price, [1; 32], 100_000_000, 20_000, -8, 100_000_000, t);
        env.set_price(&sol.price, [2; 32], 15_000_000_000, 7_500_000, -8, 15_100_000_000, t);
    };
    let priced = |usdc_side: bool| -> PricedAsset {
        let (p, c, e, h, l, d) = if usdc_side {
            (100_000_000i64, 20_000u64, 100_000_000i64, 9_900u32, 10_100u32, 6u8)
        } else {
            (15_000_000_000, 7_500_000, 15_100_000_000, 8_500, 10_500, 9)
        };
        let b = bulkhead_core::price::conservative(p, c, e, 20_000).unwrap();
        PricedAsset { lo: b.lo, hi: b.hi, expo: -8, decimals: d, haircut_bps: h, liability_bps: l }
    };
    let (um, sm) = (usdc.mint.to_bytes(), sol.mint.to_bytes());
    let lookup = move |x: &[u8; 32]| {
        if *x == um {
            Pricing::Priced(priced(true))
        } else if *x == sm {
            Pricing::Priced(priced(false))
        } else {
            Pricing::NotAllowlisted
        }
    };

    // Genesis deposits, then seal.
    for (i, u) in users.iter().enumerate() {
        let amount = (1 + rng.below(3_000_000)) * USDC;
        let ix = m.deposit_ix(&env, &usdc, &u.pubkey(), &usdc_acc[i].0, amount);
        env.ok(&[ix], &[u]);
        md.low = md.low.touch(md.balance, env.time, md.ref_init);
        md.reference = ema_update(md.reference, md.ref_at, md.balance, env.time, md.ref_init);
        md.ref_at = env.time;
        md.ref_init = true;
        md.balance += amount;
        md.ledgers.entry(u.pubkey().to_bytes()).or_default().credit(um, amount);
    }
    for (i, u) in users.iter().enumerate().take(3) {
        let ix = m.deposit_ix(&env, &sol, &u.pubkey(), &usdc_acc[i].1, 10 * SOL);
        env.ok(&[ix], &[u]);
        md.ledgers.entry(u.pubkey().to_bytes()).or_default().credit(sm, 10 * SOL);
    }
    env.ok(&[m.propose_seal_ix()], &[&m.admin]);
    env.advance(3 * DAY);
    env.ok(&[m.execute_seal_ix(&[&usdc, &sol])], &[]);

    let mut c = [0u64; 8];
    let mut ticket_accounts: BTreeMap<u64, (Address, Address)> = BTreeMap::new(); // id -> (ticket, recipient)
    let mut last_heartbeat = env.time - 3 * DAY; // registered at genesis, 72h ago
    for step in 0..steps {
        // Mostly minutes to hours; sometimes long enough for tickets to come due.
        let jump = match rng.below(10) {
            0..=5 => rng.below(600) as i64,
            6..=8 => rng.below(4 * 3_600) as i64,
            _ => 6 * 3_600 + rng.below(48 * 3_600) as i64,
        };
        env.advance(jump);
        // Guardians stay alive the way a real guardian service does: a heartbeat
        // well inside the 7-day interval (a dead guardian can't revive itself).
        if env.time - last_heartbeat > 2 * DAY {
            for k in &m.g {
                let hb = m.vault_ix(14, &[], vec![
                    solana_instruction::AccountMeta::new(m.protocol, false),
                    solana_instruction::AccountMeta::new_readonly(k.pubkey(), true),
                ]);
                env.ok(&[hb], &[k]);
            }
            last_heartbeat = env.time;
        }
        set_prices(&mut env);
        let now = env.time;
        let vault_before = env.balance(&usdc.vault_tokens);
        match rng.below(20) {
            // Deposit.
            0..=3 => {
                let i = rng.below(users.len() as u64) as usize;
                let amount = (1 + rng.below(500_000)) * USDC;
                let ix = m.deposit_ix(&env, &usdc, &users[i].pubkey(), &usdc_acc[i].0, amount);
                env.ok(&[ix], &[&users[i]]);
                md.low = md.low.touch(md.balance, now, md.ref_init);
                md.reference = ema_update(md.reference, md.ref_at, md.balance, now, md.ref_init);
                md.ref_at = now;
                md.balance += amount;
                md.ledgers.entry(users[i].pubkey().to_bytes()).or_default().credit(um, amount);
                c[0] += 1;
            }
            // Withdraw (user) or admin payout (to a user or an outsider).
            4..=13 => {
                let admin = rng.below(3) == 0;
                let (owner, recipient, signer) = if admin && rng.below(2) == 0 {
                    (outsider.pubkey(), outsider_acc, None)
                } else {
                    let i = rng.below(users.len() as u64) as usize;
                    (users[i].pubkey(), usdc_acc[i].0, if admin { None } else { Some(i) })
                };
                let amount = match rng.below(6) {
                    0 => 1 + rng.below(1_000) * USDC,
                    1 | 2 => (1 + rng.below(20_000)) * USDC,
                    3 => (1 + rng.below(200_000)) * USDC,
                    4 => (1 + rng.below(2_000_000)) * USDC,
                    _ => (1 + rng.below(20_000_000)) * USDC,
                };
                let ledger = md.ledgers.get(&owner.to_bytes()).copied().unwrap_or_default();
                let mut prices = vec![(usdc.asset, usdc.price)];
                for p in ledger.positions() {
                    if p.mint == sm {
                        prices.push((sol.asset, sol.price));
                    }
                }
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

                // The model.
                let backed = ledger.backed_amount(&um, amount, &lookup);
                let unbacked = amount - backed;
                let reference = ema_update(md.reference, md.ref_at, md.balance, now, md.ref_init);
                let low = md.low.touch(md.balance, now, md.ref_init);
                let params = params_from_config(&cfg(), capacity_base(reference, md.balance.min(low.low())));
                let mut lim = md.limiter;
                let decision = if unbacked > 0 {
                    request(&mut lim, &params, now * 1_000, unbacked, md.frozen_until * 1_000).map(Some)
                } else {
                    Ok(None)
                };
                // The vault pays only what it physically holds: backed claims can
                // exceed the balance once unbacked outflow (bounded by G1) or
                // lending has taken tokens out. Bulkhead never blocks such a
                // payout; the token transfer simply can't be made.
                let pays = match decision {
                    Ok(Some(Decision::Instant)) => backed + unbacked,
                    Ok(_) => backed,
                    Err(_) => 0,
                };
                let decision = if decision.is_ok() && pays > md.balance { Err(()) } else { decision.map_err(|_| ()) };
                match (&result, decision) {
                    (Ok(meta), Ok(d)) => {
                        let o = outcome(meta);
                        let (instant, queued, eta) = match d {
                            None => (0, 0, 0),
                            Some(Decision::Instant) => (unbacked, 0, 0),
                            Some(Decision::Queued { eta_ms }) => (0, unbacked, (eta_ms + 999) / 1_000),
                        };
                        assert_eq!(
                            (o.backed, o.instant, o.queued, o.eta_s),
                            (backed, instant, queued, eta),
                            "seed {seed} step {step}: outcome"
                        );
                        md.reference = reference;
                        md.low = low;
                        md.ref_at = now;
                        md.limiter = lim;
                        let mut l = ledger;
                        l.debit_backed(um, backed, &lookup).unwrap();
                        md.ledgers.insert(owner.to_bytes(), l);
                        md.balance -= backed + instant;
                        if queued > 0 {
                            md.tickets.insert(id, (queued, eta));
                            ticket_accounts.insert(id, (ticket, recipient));
                            c[4] += 1;
                        }
                        c[1] += 1;
                        c[2] += (backed > 0) as u64;
                        c[3] += (instant > 0) as u64;
                    }
                    (Err(_), Err(_)) => c[5] += 1, // refused on both sides (queue full, lane closed, or not enough tokens)
                    (r, d) => panic!("seed {seed} step {step}: program {:?} vs model {:?}", r.as_ref().map(outcome).map_err(|e| e.err.clone()), d),
                }
            }
            // Settle a due ticket.
            14..=16 => {
                if let Some((&id, &(amount, eta))) = md.tickets.iter().find(|(_, (_, eta))| *eta <= now) {
                    let (ticket, recipient) = ticket_accounts[&id];
                    let ix = m.settle_ix(&usdc, &ticket, &recipient, &env.payer.pubkey());
                    let r = env.send(&[ix], &[]);
                    if now < md.frozen_until || amount > md.balance {
                        assert!(r.is_err(), "frozen, or not enough tokens: no settlement");
                    } else {
                        r.unwrap_or_else(|e| panic!("seed {seed} step {step}: settle {:?}", e.err));
                        md.low = md.low.touch(md.balance, now, md.ref_init);
                        md.reference = ema_update(md.reference, md.ref_at, md.balance, now, md.ref_init);
                        md.ref_at = now;
                        md.balance -= amount;
                        md.tickets.remove(&id);
                        c[6] += 1;
                    }
                    let _ = eta;
                }
            }
            // A guardian cancels a ticket (no refund of the reservation).
            17 => {
                if let Some(&id) = md.tickets.keys().next() {
                    let (ticket, _) = ticket_accounts[&id];
                    let g = m.g[0].pubkey();
                    let ix = m.cancel_ix(&usdc, &ticket, ticket_id(&env, &ticket), &g, &env.payer.pubkey());
                    env.ok(&[ix], &[&m.g[0]]);
                    md.tickets.remove(&id);
                    c[7] += 1;
                    assert_eq!(env.balance(&usdc.vault_tokens), vault_before, "I11: a cancel moves no tokens");
                }
            }
            // A guardian freezes the vault for a while (and heartbeats keep it alive).
            _ => {
                let g = m.g[1].pubkey();
                let secs = 1 + rng.below(3_600) as i64;
                let ix = m.freeze_ix(&g, Some(&usdc), secs);
                env.ok(&[ix], &[&m.g[1]]);
                md.frozen_until = md.frozen_until.max(now + secs);
                assert_eq!(env.balance(&usdc.vault_tokens), vault_before, "I11: a freeze moves no tokens");
            }
        }
        // I12: the vault holds exactly what the model says.
        assert_eq!(env.balance(&usdc.vault_tokens), md.balance, "seed {seed} step {step}: I12 balance");
        // I14: the queue equals the sum of pending tickets.
        let a = m.attest(&mut env, &usdc);
        let pending: u64 = md.tickets.values().map(|x| x.0).sum();
        assert_eq!((a.queued, a.pending as usize), (pending, md.tickets.len()), "seed {seed} step {step}: I14");
    }
    // Every owner's ledger on-chain equals the model's.
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
