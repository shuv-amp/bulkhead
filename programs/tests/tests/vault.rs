//! The Vault program on the real runtime (LiteSVM, mainnet features, the
//! mainnet token program), driven through Harbor's CPIs like an integrator.
//!
//! Scenarios (docs/08-SCENARIOS.md): S1 compromised admin, S4 bank run,
//! S7 slow loosening, S9 honest borrower, plus the seal, tickets, freezes,
//! the lifeboat, the custody policy and every account check we can reach.
//! Numbers are checked against `bulkhead-core` computed in the test.

mod common;

use bulkhead_core::ema::ema_update;
use bulkhead_core::ledger::{Ledger, PricedAsset, Pricing};
use bulkhead_core::limiter::{capacity_base, params_from_config, request, Decision, LimiterState};
use common::vault::*;
use common::*;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;

const USDC: u64 = 1_000_000; // 6 decimals
const SOL: u64 = 1_000_000_000; // 9 decimals
const USDC_FEED: [u8; 32] = [1; 32];
const SOL_FEED: [u8; 32] = [2; 32];

/// A sealed market: USDC and SOL vaults, both assets allowlisted and priced.
struct World {
    env: Env,
    m: Market,
    usdc: VaultRef,
    sol: VaultRef,
}

fn usdc_cfg() -> Vec<u8> {
    asset_bytes(true, 9_900, 10_100, 20_000, 60, 100, USDC_FEED)
}
fn sol_cfg() -> Vec<u8> {
    asset_bytes(true, 8_500, 10_500, 20_000, 60, 100, SOL_FEED)
}

impl World {
    fn new() -> World {
        let mut env = Env::new();
        let m = Market::new(&mut env);
        let usdc = m.create_vault(&mut env, 6, Limits::default_limits(), USDC_FEED, None);
        let sol = m.create_vault(&mut env, 9, Limits::default_limits(), SOL_FEED, None);
        let ix = m.upsert_asset_ix(&env, &usdc, &usdc_cfg());
        env.ok(&[ix], &[&m.admin]);
        let ix = m.upsert_asset_ix(&env, &sol, &sol_cfg());
        env.ok(&[ix], &[&m.admin]);
        let mut w = World { env, m, usdc, sol };
        w.refresh_prices();
        w
    }

    fn with_transfer_fee_mint() -> World {
        let mut env = Env::new();
        let m = Market::new(&mut env);
        let (mint, mint_authority) = env.create_fee_mint(6, 1_000, 1_000_000 * USDC);
        let usdc = m.create_vault_for(&mut env, mint, mint_authority, 6, Limits::default_limits(), USDC_FEED, token_2022());
        let sol = m.create_vault(&mut env, 9, Limits::default_limits(), SOL_FEED, None);
        let ix = m.upsert_asset_ix(&env, &usdc, &usdc_cfg());
        env.ok(&[ix], &[&m.admin]);
        let ix = m.upsert_asset_ix(&env, &sol, &sol_cfg());
        env.ok(&[ix], &[&m.admin]);
        let mut w = World { env, m, usdc, sol };
        w.refresh_prices();
        w
    }

    /// USDC $1.00 ± 0.0002; SOL $150.00 ± 0.075 with EMA $151.00 (golden G-10).
    fn refresh_prices(&mut self) {
        let t = self.env.time;
        let (up, sp) = (self.usdc.price, self.sol.price);
        self.env.set_price(&up, USDC_FEED, 100_000_000, 20_000, -8, 100_000_000, t);
        self.env.set_price(&sp, SOL_FEED, 15_000_000_000, 7_500_000, -8, 15_100_000_000, t);
    }

    fn user(&mut self) -> Keypair {
        let k = Keypair::new();
        self.env.fund(&k);
        k
    }

    fn account(&mut self, v: &str, owner: &Address) -> Address {
        let (mint, program) = match v {
            "usdc" => (self.usdc.mint, self.usdc.token_program),
            _ => (self.sol.mint, self.sol.token_program),
        };
        self.env.token_account(&mint, owner, &program)
    }

    /// `user` deposits `amount` of `v` through Harbor; returns their token account.
    fn deposit(&mut self, v: &str, user: &Keypair, amount: u64) -> Address {
        let acc = self.account(v, &user.pubkey());
        let vr = if v == "usdc" { &self.usdc } else { &self.sol };
        self.env.mint_to(&vr.mint, &vr.mint_authority, &acc, amount, &vr.token_program);
        let ix = self.m.deposit_ix(&self.env, vr, &user.pubkey(), &acc, amount);
        self.env.ok(&[ix], &[user]);
        acc
    }

    fn seal(&mut self) {
        self.env.ok(&[self.m.propose_seal_ix()], &[&self.m.admin]);
        self.env.advance(3 * DAY);
        let ix = self.m.execute_seal_ix(&[&self.usdc, &self.sol]);
        self.env.ok(&[ix], &[]);
        self.refresh_prices();
    }

    fn usdc_prices(&self, with_price: bool) -> Vec<(Address, Address)> {
        vec![(self.usdc.asset, if with_price { self.usdc.price } else { SYSTEM })]
    }

    fn priced_asset(&self, usdc: bool) -> PricedAsset {
        // What the program derives: lo/hi from bulkhead-core's conservative bounds.
        let (p, c, e, cfg) = if usdc {
            (100_000_000i64, 20_000u64, 100_000_000i64, (9_900u32, 10_100u32, 6u8))
        } else {
            (15_000_000_000, 7_500_000, 15_100_000_000, (8_500, 10_500, 9))
        };
        let b = bulkhead_core::price::conservative(p, c, e, 20_000).unwrap();
        PricedAsset { lo: b.lo, hi: b.hi, expo: -8, decimals: cfg.2, haircut_bps: cfg.0, liability_bps: cfg.1 }
    }
}

// ---------------------------------------------------------------------------
// S4: a bank run. Own deposits come back instantly, with no prices, even frozen.
// ---------------------------------------------------------------------------

#[test]
fn s4_bank_run_every_depositor_gets_their_own_deposit_back_instantly() {
    let mut w = World::new();
    let mut users = Vec::new();
    for i in 0..20u64 {
        let u = w.user();
        let amount = (300_000 + i * 20_000) * USDC;
        let acc = w.deposit("usdc", &u, amount);
        users.push((u, acc, amount));
    }
    let tvl: u64 = users.iter().map(|x| x.2).sum();
    w.seal();
    // A guardian freezes the whole protocol: the unbacked lane stops...
    let g0 = w.m.g[0].pubkey();
    let fz = w.m.freeze_ix(&g0, None, 86_400);
    w.env.ok(&[fz], &[&w.m.g[0]]);
    // ...and still every depositor withdraws their own funds at once, without prices.
    let mut out = 0u64;
    for (u, acc, amount) in users.iter() {
        let ix = w.m.withdraw_ix(&w.env, &w.usdc, &u.pubkey(), acc, *amount, &w.usdc_prices(false));
        let m = w.env.ok(&[ix], &[u]);
        assert_eq!(outcome(&m), Outcome { backed: *amount, instant: 0, queued: 0, ticket_id: outcome(&m).ticket_id, eta_s: 0 });
        assert_eq!(w.env.balance(acc), *amount);
        out += amount;
        w.env.advance(60);
    }
    assert_eq!(out, tvl, "100% of TVL left within 20 minutes, during a freeze, none of it queued");
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 0);
}

// ---------------------------------------------------------------------------
// S9: an honest borrower is 100% backed at conservative prices.
// ---------------------------------------------------------------------------

#[test]
fn s9_honest_borrower_is_backed_exactly_as_the_core_computes() {
    let mut w = World::new();
    let lender = w.user();
    w.deposit("usdc", &lender, 5_000_000 * USDC);
    let borrower = w.user();
    w.deposit("sol", &borrower, 10 * SOL);
    w.seal();

    // Expected: bulkhead-core with the same prices and weights.
    let ledger = Ledger::from_positions(&[(w.sol.mint.to_bytes(), 10 * SOL as i128)]).unwrap();
    let (usdc_pa, sol_pa) = (w.priced_asset(true), w.priced_asset(false));
    let (um, sm) = (w.usdc.mint.to_bytes(), w.sol.mint.to_bytes());
    let lookup = |m: &[u8; 32]| {
        if *m == um {
            Pricing::Priced(usdc_pa)
        } else if *m == sm {
            Pricing::Priced(sol_pa)
        } else {
            Pricing::NotAllowlisted
        }
    };
    let ask = 1_200 * USDC; // well within 10 SOL × $149.85 × 85%
    let expected = ledger.backed_amount(&um, ask, &lookup);
    assert_eq!(expected, ask, "within the haircut: fully backed");

    let to = w.account("usdc", &borrower.pubkey());
    let prices = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, ask, &prices);
    let m = w.env.ok(&[ix], &[&borrower]);
    assert_eq!(outcome(&m).backed, expected);
    assert_eq!((outcome(&m).instant, outcome(&m).queued), (0, 0));
    assert_eq!(w.env.balance(&to), ask);

    // Asking for more than the collateral supports: exactly the core's answer is
    // backed, the rest goes to the limiter.
    let big = 5_000 * USDC;
    let ledger2 = Ledger::from_positions(&[(sm, 10 * SOL as i128), (um, -(ask as i128))]).unwrap();
    let expected2 = ledger2.backed_amount(&um, big, &lookup);
    let prices = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, big, &prices);
    let m = w.env.ok(&[ix], &[&borrower]);
    assert_eq!(outcome(&m).backed, expected2);
    assert_eq!(outcome(&m).backed + outcome(&m).instant + outcome(&m).queued, big);
}

/// A freeze stops only the unbacked lane (T7, `04`): a borrower whose
/// collateral covers the loan is still paid at once, and only the part the
/// ledger can't back waits, until after the freeze.
#[test]
fn a_backed_borrow_is_paid_during_a_freeze_and_only_the_unbacked_rest_waits() {
    let mut w = World::new();
    let lender = w.user();
    w.deposit("usdc", &lender, 5_000_000 * USDC);
    let borrower = w.user();
    w.deposit("sol", &borrower, 10 * SOL);
    w.seal();
    let g0 = w.m.g[0].pubkey();
    let fz = w.m.freeze_ix(&g0, None, 86_400);
    w.env.ok(&[fz], &[&w.m.g[0]]);
    let frozen_until = w.env.time + 86_400;

    let to = w.account("usdc", &borrower.pubkey());
    let prices = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
    let ask = 1_200 * USDC;
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, ask, &prices);
    let m = w.env.ok(&[ix], &[&borrower]);
    assert_eq!((outcome(&m).backed, outcome(&m).instant, outcome(&m).queued), (ask, 0, 0));
    assert_eq!(w.env.balance(&to), ask, "paid during the freeze");

    // Beyond what the collateral supports: the backed part is paid, the rest
    // becomes a ticket that can't come due before the freeze ends.
    let big = 5_000 * USDC;
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, big, &prices);
    let m = w.env.ok(&[ix], &[&borrower]);
    let o = outcome(&m);
    assert!(o.backed > 0 && o.backed < big);
    assert_eq!(o.instant, 0, "nothing unbacked is paid while frozen");
    assert_eq!(o.backed + o.queued, big);
    assert!(o.eta_s >= frozen_until, "the ticket waits for the freeze to end");
    assert_eq!(w.env.balance(&to), ask + o.backed);
}

#[test]
fn omitting_a_price_never_increases_what_is_backed() {
    let mut w = World::new();
    let lender = w.user();
    w.deposit("usdc", &lender, 5_000_000 * USDC);
    let borrower = w.user();
    w.deposit("sol", &borrower, 10 * SOL);
    w.seal();
    let to = w.account("usdc", &borrower.pubkey());
    // SOL's price omitted (placeholder): the SOL collateral counts 0 → nothing backed.
    let prices = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, SYSTEM)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, 1_000 * USDC, &prices);
    let m = w.env.ok(&[ix], &[&borrower]);
    assert_eq!(outcome(&m).backed, 0, "fail closed (G7)");
}

#[test]
fn an_allowlisted_asset_cannot_be_made_to_look_unlisted_by_omission() {
    let mut w = World::new();
    let lender = w.user();
    w.deposit("usdc", &lender, 5_000_000 * USDC);
    let borrower = w.user();
    w.deposit("sol", &borrower, 10 * SOL);
    w.seal();
    let to = w.account("usdc", &borrower.pubkey());
    // Pass some other account where SOL's asset PDA must be.
    let fake = Address::new_unique();
    let prices = vec![(w.usdc.asset, w.usdc.price), (fake, w.sol.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, 1_000 * USDC, &prices);
    assert_eq!(w.env.fails(&[ix], &[&borrower]), verr::WRONG_ADDRESS);
    // And leaving the pair out entirely is refused too.
    let prices = vec![(w.usdc.asset, w.usdc.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, 1_000 * USDC, &prices);
    assert_eq!(w.env.fails(&[ix], &[&borrower]), verr::BAD_PRICE_ACCOUNT);
}

#[test]
fn a_price_for_the_wrong_feed_is_refused() {
    let mut w = World::new();
    let lender = w.user();
    w.deposit("usdc", &lender, 5_000_000 * USDC);
    let borrower = w.user();
    w.deposit("sol", &borrower, 10 * SOL);
    w.seal();
    let to = w.account("usdc", &borrower.pubkey());
    let prices = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.usdc.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, 1_000 * USDC, &prices);
    assert_eq!(w.env.fails(&[ix], &[&borrower]), verr::BAD_PRICE_ACCOUNT);
}

// ---------------------------------------------------------------------------
// S1: a compromised admin. Golden G-1 on-chain, then freeze and cancel.
// ---------------------------------------------------------------------------

#[test]
fn s1_compromised_admin_gets_exactly_the_burst_then_a_public_queue() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let attacker = Keypair::new();
    let loot = w.account("usdc", &attacker.pubkey());

    // The same requests, in the same state, through the core model.
    let cfg = bulkhead_core::classify::LimitConfig {
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
    // The model tracks the reference balance exactly as the program must: an
    // EMA of the vault balance, updated before every release. Capacities come
    // from the lower of the reference and the balance before the release.
    let mut model = LimiterState::default();
    let (mut reference, mut ref_at, mut ref_init) = (0u64, 0i64, false);
    let mut balance = 10_000_000 * USDC;
    // Deposits touched it at genesis with the pre-deposit balance of 0.
    reference = ema_update(reference, ref_at, 0, T0, ref_init);
    ref_at = T0;
    ref_init = true;

    // Golden G-1: one request per minute, the Drift cadence.
    let requests = [150_000, 50_000, 10_000, 400_000, 1_000_000];
    let mut tickets = Vec::new();
    for (minute, amount) in requests.iter().enumerate() {
        let amount = amount * USDC;
        let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &loot, &attacker.pubkey(), amount, &w.usdc_prices(true));
        let (id, ticket) = w.m.next_ticket(&w.env);
        let m = w.env.ok(&[ix], &[&w.m.admin]);
        let o = outcome(&m);
        assert_eq!(o.backed, 0, "the attacker has no deposits: nothing is backed");
        reference = ema_update(reference, ref_at, balance, w.env.time, ref_init);
        ref_at = w.env.time;
        let params = params_from_config(&cfg, capacity_base(reference, balance));
        match request(&mut model, &params, w.env.time * 1_000, amount, 0).unwrap() {
            Decision::Instant => {
                assert_eq!((o.instant, o.queued), (amount, 0), "minute {minute}");
                balance -= amount;
            }
            Decision::Queued { eta_ms } => {
                assert_eq!((o.instant, o.queued, o.ticket_id), (0, amount, id), "minute {minute}");
                assert_eq!(o.eta_s, (eta_ms + 999) / 1_000, "ETA never early");
                tickets.push((ticket, o.eta_s));
            }
        }
        w.env.advance(60);
        w.refresh_prices();
    }
    assert_eq!(w.env.balance(&loot), 200_000 * USDC, "exactly the 2% burst left instantly");
    assert_eq!(tickets.len(), 3, "the other three requests wait in public (G-1)");

    // A guardian freezes; while frozen, due tickets can't settle.
    let g0 = w.m.g[0].pubkey();
    let fz = w.m.freeze_ix(&g0, None, 86_400);
    w.env.ok(&[fz], &[&w.m.g[0]]);
    w.env.advance(7 * 3_600);
    let settle = w.m.settle_ix(&w.usdc, &tickets[0].0, &loot, &w.env.payer.pubkey());
    assert_eq!(w.env.fails(&[settle], &[]), verr::FROZEN);
    // Guardians cancel every ticket: the attacker keeps only the burst.
    for (t, _) in &tickets {
        let ix = w.m.cancel_ix(&w.usdc, t, &g0, &w.env.payer.pubkey());
        w.env.ok(&[ix], &[&w.m.g[0]]);
    }
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!((a.pending, a.queued), (0, 0));
    assert_eq!(w.env.balance(&loot), 200_000 * USDC);
}

#[test]
fn junk_collateral_backs_nothing_but_its_owner_can_take_it_back() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    // A junk token with its own vault but no asset listing (the Drift CVT pattern).
    let cvt = w.m.create_vault(&mut w.env, 6, Limits::default_limits(), [9; 32], None);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    let attacker = w.user();
    let cvt_acc = w.env.token_account(&cvt.mint, &attacker.pubkey(), &cvt.token_program);
    w.env.mint_to(&cvt.mint, &cvt.mint_authority, &cvt_acc, 750_000_000 * USDC, &cvt.token_program);
    let ix = w.m.deposit_ix(&w.env, &cvt, &attacker.pubkey(), &cvt_acc, 750_000_000 * USDC);
    w.env.ok(&[ix], &[&attacker]);
    w.env.advance(3 * DAY);
    let ix = w.m.execute_seal_ix(&[&w.usdc, &w.sol, &cvt]);
    w.env.ok(&[ix], &[]);
    w.refresh_prices();

    // E5: 71.4M USDC against 750M CVT: nothing backed; the limiter decides.
    let loot = w.account("usdc", &attacker.pubkey());
    let prices = vec![(w.usdc.asset, w.usdc.price), (cvt.asset, SYSTEM)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &attacker.pubkey(), &loot, 71_400_000 * USDC, &prices);
    // Beyond the 7-day horizon: refused outright, state unchanged.
    assert_eq!(w.env.fails(&[ix], &[&attacker]), verr::QUEUE_FULL);
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &attacker.pubkey(), &loot, 1_000_000 * USDC, &prices);
    let o = outcome(&w.env.ok(&[ix], &[&attacker]));
    assert_eq!(o.backed, 0);
    assert_eq!(o.instant, 0, "above the burst, so all of it is a ticket");
    // E6: taking the junk back is fine (it was worth nothing).
    let prices = vec![(cvt.asset, SYSTEM)];
    let ix = w.m.withdraw_ix(&w.env, &cvt, &attacker.pubkey(), &cvt_acc, 750_000_000 * USDC, &prices);
    let o = outcome(&w.env.ok(&[ix], &[&attacker]));
    assert_eq!(o.backed, 750_000_000 * USDC);
}

// ---------------------------------------------------------------------------
// Tickets
// ---------------------------------------------------------------------------

#[test]
fn a_ticket_settles_after_its_eta_to_its_stored_recipient_only() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let payee = w.user();
    let to = w.account("usdc", &payee.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &payee.pubkey(), 300_000 * USDC, &w.usdc_prices(true));
    let (_, ticket) = w.m.next_ticket(&w.env);
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!(o.queued, 300_000 * USDC);
    let early = w.m.settle_ix(&w.usdc, &ticket, &to, &w.env.payer.pubkey());
    assert_eq!(w.env.fails(&[early], &[]), verr::TICKET_NOT_DUE);
    w.env.advance(o.eta_s - w.env.time);
    // Someone else's account can't receive it.
    let other = w.account("usdc", &Keypair::new().pubkey());
    let wrong = w.m.settle_ix(&w.usdc, &ticket, &other, &w.env.payer.pubkey());
    assert!(w.env.send(&[wrong], &[]).is_err());
    let ok = w.m.settle_ix(&w.usdc, &ticket, &to, &w.env.payer.pubkey());
    w.env.ok(&[ok], &[]);
    assert_eq!(w.env.balance(&to), 300_000 * USDC);
    assert!(w.env.svm.get_account(&ticket).map(|a| a.lamports == 0).unwrap_or(true), "ticket closed");
}

#[test]
fn reset_backlog_is_refused_while_tickets_are_pending() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let payee = w.user();
    let to = w.account("usdc", &payee.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &payee.pubkey(), 2_000_000 * USDC, &w.usdc_prices(true));
    let (_, ticket) = w.m.next_ticket(&w.env);
    w.env.ok(&[ix], &[&w.m.admin]);
    let reset = w.m.vault_ix(
        16,
        &[],
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        ],
    );
    assert_eq!(w.env.fails(std::slice::from_ref(&reset), &[&w.m.admin]), verr::TICKETS_PENDING);
    let g0 = w.m.g[0].pubkey();
    let cancel = w.m.cancel_ix(&w.usdc, &ticket, &g0, &w.env.payer.pubkey());
    w.env.ok(&[cancel], &[&w.m.g[0]]);
    w.env.ok(&[reset], &[&w.m.admin]);
}

// ---------------------------------------------------------------------------
// Freezes, guardians
// ---------------------------------------------------------------------------

#[test]
fn freezes_are_short_repeatable_and_only_a_live_quorum_unfreezes() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let g0 = w.m.g[0].pubkey();
    let too_long = w.m.freeze_ix(&g0, None, 86_401);
    assert_eq!(w.env.fails(&[too_long], &[&w.m.g[0]]), verr::FREEZE_TOO_LONG);
    let fz = w.m.freeze_ix(&g0, Some(&w.usdc), 3_600);
    w.env.ok(&[fz], &[&w.m.g[0]]);
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!(a.available_now, 0, "frozen: nothing unbacked is instant");
    // The admin can freeze but not unfreeze; one guardian is not a quorum.
    let admin_key = w.m.admin.pubkey();
    let ix = w.m.unfreeze_ix(Some(&w.usdc), &[admin_key]);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::NOT_GUARDIAN);
    let ix = w.m.unfreeze_ix(Some(&w.usdc), &[g0]);
    assert_eq!(w.env.fails(&[ix], &[&w.m.g[0]]), verr::NO_QUORUM);
    let g1 = w.m.g[1].pubkey();
    let ix = w.m.unfreeze_ix(Some(&w.usdc), &[g0, g1]);
    w.env.ok(&[ix], &[&w.m.g[0], &w.m.g[1]]);
    assert!(w.m.attest(&mut w.env, &w.usdc).available_now > 0);
}

#[test]
fn attestation_reports_the_live_worst_case() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert!(a.sealed);
    assert_eq!(a.balance, 10_000_000 * USDC);
    assert_eq!(a.available_now, 200_000 * USDC, "2% burst");
    assert_eq!(a.worst_1h, 400_000 * USDC, "golden G-6: 1 hour");
    assert_eq!(a.worst_24h, 1_000_000 * USDC, "golden G-6: 24 hours = 10%");
    assert_eq!(a.live_guardians, 3);
}

// ---------------------------------------------------------------------------
// Genesis and seal
// ---------------------------------------------------------------------------

#[test]
fn nothing_can_be_released_before_the_seal_and_the_seal_waits_72h() {
    let mut w = World::new();
    let u = w.user();
    let acc = w.deposit("usdc", &u, 1_000 * USDC);
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &u.pubkey(), &acc, 1_000 * USDC, &w.usdc_prices(false));
    assert_eq!(w.env.fails(&[ix], &[&u]), verr::NOT_SEALED);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY - 10);
    let ix = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::SEAL_NOT_EXECUTABLE);
}

#[test]
fn a_guardian_can_veto_the_seal() {
    let mut w = World::new();
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    let veto = w.m.vault_ix(
        6,
        &[],
        vec![AccountMeta::new(w.m.protocol, false), AccountMeta::new_readonly(w.m.g[2].pubkey(), true)],
    );
    w.env.ok(&[veto], &[&w.m.g[2]]);
    w.env.advance(3 * DAY);
    let ix = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::SEAL_NOT_EXECUTABLE);
}

#[test]
fn imported_backing_must_be_covered_by_the_balance_at_seal() {
    let mut w = World::new();
    let owner = Keypair::new().pubkey();
    let import = w.m.vault_ix(
        3,
        &(1_000 * USDC).to_le_bytes(),
        vec![
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(w.m.backing(&owner), false),
            AccountMeta::new_readonly(owner, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    w.env.ok(&[import], &[&w.m.admin]);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let ix = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::IMPORT_EXCEEDS_BALANCE);
}

/// A pre-seal deposit covers `imported` by itself, so the old seal check
/// (imported ≤ balance) passed while total backing claims were twice the tokens.
#[test]
fn pre_seal_deposits_cannot_hide_an_uncovered_import() {
    let mut w = World::new();
    let u = w.user();
    w.deposit("usdc", &u, 1_000 * USDC);
    let owner = Keypair::new().pubkey();
    let import = w.m.vault_ix(
        3,
        &(1_000 * USDC).to_le_bytes(),
        vec![
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(w.m.backing(&owner), false),
            AccountMeta::new_readonly(owner, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    w.env.ok(&[import], &[&w.m.admin]);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let ix = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::IMPORT_EXCEEDS_BALANCE, "2,000 of claims, 1,000 of tokens");
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &w.usdc.vault_tokens, 1_000 * USDC, &w.usdc.token_program);
    let ix = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    w.env.ok(&[ix], &[]);
}

#[test]
fn harbor_will_not_sign_for_a_different_vault_program() {
    let mut env = Env::new();
    let harbor = Address::new_unique();
    let wrong = Address::new_unique();
    env.svm.add_program(wrong, &so("bulkhead_vault")).unwrap();
    env.svm.add_program(harbor, &so("bulkhead_harbor")).unwrap();
    let caller = pda(&[b"bulkhead-caller"], &harbor);
    let ix = solana_instruction::Instruction {
        program_id: harbor,
        accounts: vec![
            AccountMeta::new_readonly(wrong, false),
            AccountMeta::new_readonly(caller, false),
        ],
        data: vec![2], // withdraw; rejected before any Vault account is touched
    };
    match env.send(&[ix], &[]) {
        Ok(m) => panic!("expected IncorrectProgramId, succeeded\n{}", m.logs.join("\n")),
        Err(e) => {
            let text = format!("{:?}", e.err);
            assert!(
                text.contains("IncorrectProgramId"),
                "{text}\n{}",
                e.meta.logs.join("\n")
            );
        }
    }
}

#[test]
fn only_the_protocol_itself_can_release() {
    let mut w = World::new();
    let u = w.user();
    let acc = w.deposit("usdc", &u, 1_000 * USDC);
    w.seal();
    // Calling the Vault directly: the caller PDA did not sign.
    let mut accounts = vec![AccountMeta::new_readonly(w.m.caller, false)];
    accounts.extend(w.m.release_accounts(&w.env, &w.usdc, &acc, &u.pubkey(), &w.usdc_prices(false)));
    let ix = w.m.vault_ix(8, &(1_000 * USDC).to_le_bytes(), accounts);
    assert_eq!(w.env.fails(&[ix], &[]), verr::WRONG_CALLER);
}

#[test]
fn a_mint_with_a_permanent_delegate_cannot_become_a_vault() {
    let mut env = Env::new();
    let m = Market::new(&mut env);
    // Token-2022 mint with the PermanentDelegate extension (type 12).
    let mint = Keypair::new();
    let authority = Keypair::new();
    let size = 165 + 1 + 4 + 32; // base padded to 165, account type, one TLV entry
    let lamports = env.svm.minimum_balance_for_rent_exemption(size);
    let t22 = token_2022();
    let create = solana_system_interface::instruction::create_account(&env.payer.pubkey(), &mint.pubkey(), lamports, size as u64, &t22);
    let mut d = vec![35u8]; // InitializePermanentDelegate
    d.extend_from_slice(authority.pubkey().as_ref());
    let init_delegate = solana_instruction::Instruction { program_id: t22, accounts: vec![AccountMeta::new(mint.pubkey(), false)], data: d };
    let mut d = vec![20u8, 6]; // InitializeMint2
    d.extend_from_slice(authority.pubkey().as_ref());
    d.push(0);
    let init_mint = solana_instruction::Instruction { program_id: t22, accounts: vec![AccountMeta::new(mint.pubkey(), false)], data: d };
    env.ok(&[create, init_delegate, init_mint], &[&mint]);
    let vault = pda(&[b"vault", m.protocol.as_ref(), mint.pubkey().as_ref()], &m.vault_program);
    let vault_tokens = pda(&[b"vault-tokens", m.protocol.as_ref(), mint.pubkey().as_ref()], &m.vault_program);
    let ix = m.vault_ix(
        1,
        &Limits::default_limits().bytes(),
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new_readonly(m.admin.pubkey(), true),
            AccountMeta::new(m.protocol, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(vault_tokens, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(t22, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    assert_eq!(env.fails(&[ix], &[&m.admin]), verr::EXTENSION_NOT_ALLOWED);
}

/// MintCloseAuthority with a real authority can close the mint at supply 0 and
/// reopen the address with an extension this policy refuses. No authority is fine.
#[test]
fn a_mint_close_authority_is_refused_unless_it_is_unset() {
    fn mint_with_close_authority(env: &mut Env, authority: Option<&Address>) -> (Keypair, Address) {
        let mint = Keypair::new();
        let mint_authority = Keypair::new();
        let size = 165 + 1 + 4 + 32;
        let lamports = env.svm.minimum_balance_for_rent_exemption(size);
        let t22 = token_2022();
        let create = solana_system_interface::instruction::create_account(
            &env.payer.pubkey(),
            &mint.pubkey(),
            lamports,
            size as u64,
            &t22,
        );
        let mut d = vec![25u8]; // InitializeMintCloseAuthority, COption<Pubkey>
        match authority {
            Some(k) => {
                d.extend_from_slice(&1u32.to_le_bytes());
                d.extend_from_slice(k.as_ref());
            }
            None => d.extend_from_slice(&0u32.to_le_bytes()),
        }
        let init_close = solana_instruction::Instruction {
            program_id: t22,
            accounts: vec![AccountMeta::new(mint.pubkey(), false)],
            data: d,
        };
        let mut d = vec![20u8, 6]; // InitializeMint2
        d.extend_from_slice(mint_authority.pubkey().as_ref());
        d.push(0);
        let init_mint = solana_instruction::Instruction {
            program_id: t22,
            accounts: vec![AccountMeta::new(mint.pubkey(), false)],
            data: d,
        };
        env.ok(&[create, init_close, init_mint], &[&mint]);
        (mint, t22)
    }
    let mut env = Env::new();
    let m = Market::new(&mut env);
    let authority = Keypair::new();
    let (mint, t22) = mint_with_close_authority(&mut env, Some(&authority.pubkey()));
    let vault = pda(&[b"vault", m.protocol.as_ref(), mint.pubkey().as_ref()], &m.vault_program);
    let vault_tokens = pda(&[b"vault-tokens", m.protocol.as_ref(), mint.pubkey().as_ref()], &m.vault_program);
    let ix = m.vault_ix(
        1,
        &Limits::default_limits().bytes(),
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new_readonly(m.admin.pubkey(), true),
            AccountMeta::new(m.protocol, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(vault_tokens, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(t22, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    assert_eq!(env.fails(&[ix], &[&m.admin]), verr::EXTENSION_NOT_ALLOWED);
    let (mint, t22) = mint_with_close_authority(&mut env, None);
    let vault = pda(&[b"vault", m.protocol.as_ref(), mint.pubkey().as_ref()], &m.vault_program);
    let vault_tokens = pda(&[b"vault-tokens", m.protocol.as_ref(), mint.pubkey().as_ref()], &m.vault_program);
    let ix = m.vault_ix(
        1,
        &Limits::default_limits().bytes(),
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new_readonly(m.admin.pubkey(), true),
            AccountMeta::new(m.protocol, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(vault_tokens, false),
            AccountMeta::new_readonly(mint.pubkey(), false),
            AccountMeta::new_readonly(t22, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    env.ok(&[ix], &[&m.admin]);
}

// ---------------------------------------------------------------------------
// S7: tighten instantly, loosen only after 72h, vetoable
// ---------------------------------------------------------------------------

#[test]
fn s7_tightening_is_instant_loosening_waits_72h_and_a_guardian_can_veto() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let vault = w.usdc.vault;
    // Tighten: halve the burst. Applies at once.
    let mut tighter = Limits::default_limits();
    tighter.short_bps = 100;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 100_000 * USDC);
    // Loosen: 10% an hour. A public proposal that waits.
    let mut looser = Limits::default_limits();
    looser.short_bps = 1_000;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    let change = w.m.change_address(0);
    let exec = w.m.vault_ix(
        20,
        &[],
        vec![
            AccountMeta::new(w.m.protocol, false),
            AccountMeta::new(change, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    assert_eq!(w.env.fails(std::slice::from_ref(&exec), &[]), verr::CHANGE_NOT_EXECUTABLE);
    let veto = w.m.vault_ix(
        19,
        &[],
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(change, false),
            AccountMeta::new_readonly(w.m.g[1].pubkey(), true),
        ],
    );
    w.env.ok(&[veto], &[&w.m.g[1]]);
    w.env.advance(3 * DAY);
    assert_eq!(w.env.fails(&[exec], &[]), verr::CHANGE_VETOED);
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 100_000 * USDC, "still the tighter limit");
}

#[test]
fn an_unvetoed_loosening_executes_after_the_delay() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let vault = w.usdc.vault;
    let mut looser = Limits::default_limits();
    looser.short_bps = 300;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let exec = w.m.vault_ix(
        20,
        &[],
        vec![
            AccountMeta::new(w.m.protocol, false),
            AccountMeta::new(w.m.change_address(0), false),
            AccountMeta::new(vault, false),
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    w.env.ok(&[exec], &[]);
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 300_000 * USDC);
}

/// A1 on the real runtime: after a large backed withdrawal, the burst is sized
/// from what is left (min of the 24h reference and the live balance), not from
/// the reference that still remembers the money that left.
#[test]
fn after_a_large_backed_withdrawal_the_burst_shrinks_at_once() {
    let mut w = World::new();
    let small = w.user();
    let whale = w.user();
    w.deposit("usdc", &small, 1_000_000 * USDC);
    let whale_acc = w.deposit("usdc", &whale, 9_000_000 * USDC);
    w.seal();
    w.env.advance(2 * DAY); // the reference catches up with 10M
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 200_000 * USDC);
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 9_000_000 * USDC, &w.usdc_prices(false));
    let m = w.env.ok(&[ix], &[&whale]);
    assert_eq!(outcome(&m).backed, 9_000_000 * USDC, "own deposit: backed and instant");
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!(a.balance, 1_000_000 * USDC);
    // Before the fix this stayed at ~200,000 (sized for the 10M that left).
    assert_eq!(a.available_now, 20_000 * USDC, "2% of the 1M that is left");
    // The payout path, not only the view: 25,000 unbacked is above the 20,000
    // burst, so it queues. Sized from the reference alone it would be instant.
    let attacker = Keypair::new();
    let loot = w.account("usdc", &attacker.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &loot, &attacker.pubkey(), 25_000 * USDC, &w.usdc_prices(true));
    let m = w.env.ok(&[ix], &[&w.m.admin]);
    let o = outcome(&m);
    assert_eq!((o.backed, o.instant, o.queued), (0, 0, 25_000 * USDC), "above the 20,000 burst: queued");
    assert_eq!(w.env.balance(&loot), 0);
}

#[test]
fn a_delay_below_72h_is_refused_and_an_abdicated_kind_is_gone_forever() {
    let mut w = World::new();
    w.seal();
    let zero = Address::default();
    let ix = w.m.propose_change_ix(&w.env, 5, &zero, &(DAY).to_le_bytes(), None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::DELAY_BELOW_MINIMUM);
    let too_long = (31 * DAY).to_le_bytes();
    let ix = w.m.propose_change_ix(&w.env, 5, &zero, &too_long, None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::DELAY_ABOVE_MAXIMUM);
    let ix = w.m.propose_change_ix(&w.env, 5, &zero, &(30 * DAY).to_le_bytes(), None);
    w.env.ok(&[ix], &[&w.m.admin]);
    let d = w.env.account(&w.m.protocol).data;
    assert_eq!(i64::from_le_bytes(d[436..444].try_into().unwrap()), 30 * DAY, "raised at once, to the cap");
    let harbor = Address::new_unique();
    w.env.svm.add_program(harbor, &so("bulkhead_harbor")).unwrap();
    let ix = w.m.register_ix(&w.env, harbor, 30 * DAY + 1);
    assert_eq!(w.env.fails(&[ix], &[]), verr::DELAY_ABOVE_MAXIMUM);
    let ix = w.m.register_ix(&w.env, harbor, 30 * DAY);
    w.env.ok(&[ix], &[]);
    let abdicate = |w: &World, kind: u8, guardians: &[Address]| {
        let mut a = vec![AccountMeta::new(w.m.protocol, false), AccountMeta::new_readonly(w.m.admin.pubkey(), true)];
        a.extend(guardians.iter().map(|g| AccountMeta::new_readonly(*g, true)));
        w.m.vault_ix(17, &[kind], a)
    };
    let (g0, g1) = (w.m.g[0].pubkey(), w.m.g[1].pubkey());
    // A3: the admin key alone (possibly stolen) can't abdicate, nor with one guardian.
    let ix = abdicate(&w, 3, &[]);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::NO_QUORUM);
    let ix = abdicate(&w, 3, &[g0]);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin, &w.m.g[0]]), verr::NO_QUORUM);
    // With a live guardian quorum, "set admin" (kind 3) is gone forever.
    let ix = abdicate(&w, 3, &[g0, g1]);
    w.env.ok(&[ix], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]);
    let new_admin = Keypair::new().pubkey();
    let ix = w.m.propose_change_ix(&w.env, 3, &new_admin, &[], None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::ABDICATED);
}

#[test]
fn an_abdicated_kind_can_still_be_tightened_but_never_loosened() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let vault = w.usdc.vault;
    let (g0, g1) = (w.m.g[0].pubkey(), w.m.g[1].pubkey());
    let abdicate = w.m.vault_ix(
        17,
        &[0], // SetLimits
        vec![
            AccountMeta::new(w.m.protocol, false),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
            AccountMeta::new_readonly(g0, true),
            AccountMeta::new_readonly(g1, true),
        ],
    );
    w.env.ok(&[abdicate], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]);
    // Tightening still applies at once: making things safer never waits.
    let mut tighter = Limits::default_limits();
    tighter.short_bps = 100;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 100_000 * USDC);
    // Loosening is refused forever.
    let mut looser = Limits::default_limits();
    looser.short_bps = 300;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::ABDICATED);
}

/// A floor above the balance must not make attest promise more than the vault holds.
#[test]
fn attest_never_reports_more_than_the_balance() {
    let mut w = World::new();
    let depositor = w.user();
    w.deposit("usdc", &depositor, 1_000 * USDC);
    let vault = w.usdc.vault;
    let mut floors = Limits::default_limits();
    floors.short_floor = 1_000_000 * USDC;
    floors.long_floor = 1_000_000 * USDC;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &floors.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    w.seal();
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!(a.balance, 1_000 * USDC);
    assert_eq!(a.available_now, 1_000 * USDC, "the balance, not the 1,000,000 floor");
}

/// Byte 165 of a 355-byte multisig is a signer byte. It must not be read as an account type.
#[test]
fn a_token_multisig_is_not_a_token_account() {
    let mut w = World::new();
    let u = w.user();
    let _acc = w.deposit("usdc", &u, 1_000 * USDC);
    w.seal();
    let fake = Address::new_unique();
    let mut data = vec![0u8; 355];
    data[..32].copy_from_slice(w.usdc.mint.as_ref());
    data[32..64].copy_from_slice(u.pubkey().as_ref());
    data[108] = 1;
    data[165] = 2;
    let lamports = w.env.svm.minimum_balance_for_rent_exemption(data.len());
    w.env
        .svm
        .set_account(
            fake,
            solana_account::Account {
                lamports,
                data,
                owner: token_2022(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &u.pubkey(), &fake, 1, &w.usdc_prices(false));
    assert_eq!(w.env.fails(&[ix], &[&u]), verr::WRONG_ACCOUNT_TYPE);
}

// ---------------------------------------------------------------------------
// Lifeboat
// ---------------------------------------------------------------------------

#[test]
fn the_lifeboat_moves_instantly_in_but_leaves_only_slowly_to_the_committed_destination() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let mv = w.m.vault_ix(
        24,
        &(4_000_000 * USDC).to_le_bytes(),
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(w.usdc.vault_tokens, false),
            AccountMeta::new(lifeboat, false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    w.env.ok(&[mv], &[&w.m.admin]);
    assert_eq!(w.env.balance(&lifeboat), 4_000_000 * USDC);

    // Exit: proposed (the destination is ≥ 72h old), waits 72h, goes only there.
    let propose = w.m.vault_ix(
        26,
        &(4_000_000 * USDC).to_le_bytes(),
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        ],
    );
    w.env.ok(&[propose], &[&w.m.admin]);
    let dest_owner = w.m.destination.pubkey();
    let dest = w.account("usdc", &dest_owner);
    let thief = w.account("usdc", &Keypair::new().pubkey());
    let exit = |to: Address| {
        w.m.vault_ix(
            27,
            &[],
            vec![
                AccountMeta::new_readonly(w.m.protocol, false),
                AccountMeta::new(w.usdc.vault, false),
                AccountMeta::new(lifeboat, false),
                AccountMeta::new_readonly(w.usdc.mint, false),
                AccountMeta::new(to, false),
                AccountMeta::new_readonly(w.usdc.token_program, false),
            ],
        )
    };
    let early = exit(dest);
    assert_eq!(w.env.fails(&[early], &[]), verr::CHANGE_NOT_EXECUTABLE);
    w.env.advance(3 * DAY);
    let wrong = exit(thief);
    assert!(w.env.send(&[wrong], &[]).is_err(), "only the committed destination");
    let right = exit(dest);
    w.env.ok(&[right], &[]);
    assert_eq!(w.env.balance(&dest), 4_000_000 * USDC);
}

#[test]
fn a_release_cannot_pay_the_lifeboat() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let mv = w.m.vault_ix(24, &(1 * USDC).to_le_bytes(), vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(w.usdc.vault_tokens, false),
        AccountMeta::new(lifeboat, false),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        AccountMeta::new(w.env.payer.pubkey(), true),
        AccountMeta::new_readonly(SYSTEM, false),
    ]);
    w.env.ok(&[mv], &[&w.m.admin]);
    // The lifeboat is a vault-owned token account. Paying it through release
    // would move tokens there without updating lifeboat_amount, so a later
    // exit would not see them.
    let pay = w.m.admin_payout_ix(&w.env, &w.usdc, &lifeboat, &w.usdc.vault, 1_000 * USDC, &w.usdc_prices(true));
    assert_eq!(w.env.fails(&[pay], &[&w.m.admin]), verr::DUPLICATE_ACCOUNT);
    assert_eq!(w.env.balance(&lifeboat), 1 * USDC);
}

#[test]
fn a_release_cannot_pay_any_account_the_vault_owns() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    // Anyone can open a token account whose owner is the vault PDA. No
    // instruction moves tokens out of one, so a payout there is stranded.
    let (mint, vault, program) = (w.usdc.mint, w.usdc.vault, w.usdc.token_program);
    let stray = w.env.token_account(&mint, &vault, &program);
    let pay = w.m.admin_payout_ix(&w.env, &w.usdc, &stray, &vault, 1_000 * USDC, &w.usdc_prices(true));
    assert_eq!(w.env.fails(&[pay], &[&w.m.admin]), verr::DUPLICATE_ACCOUNT);
    assert_eq!(w.env.balance(&stray), 0);
}

#[test]
fn a_quote_cannot_promise_more_than_the_vault_holds() {
    let mut w = World::new();
    let whale = w.user();
    let to = w.deposit("usdc", &whale, 1_000_000 * USDC);
    w.seal();
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let mv = w.m.vault_ix(24, &(900_000 * USDC).to_le_bytes(), vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(w.usdc.vault_tokens, false),
        AccountMeta::new(lifeboat, false),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        AccountMeta::new(w.env.payer.pubkey(), true),
        AccountMeta::new_readonly(SYSTEM, false),
    ]);
    w.env.ok(&[mv], &[&w.m.admin]);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 100_000 * USDC);

    let too_much = 1_000_000 * USDC;
    let mut quote_accounts = vec![AccountMeta::new_readonly(w.m.caller, false)];
    quote_accounts.extend(w.m.release_accounts(&w.env, &w.usdc, &to, &whale.pubkey(), &w.usdc_prices(true)));
    let quote = w.m.vault_ix(23, &too_much.to_le_bytes(), quote_accounts);
    assert_eq!(w.env.fails(&[quote], &[]), verr::INSUFFICIENT_BALANCE);
    let pay = w.m.withdraw_ix(&w.env, &w.usdc, &whale.pubkey(), &to, too_much, &w.usdc_prices(true));
    assert_eq!(w.env.fails(&[pay], &[&whale]), verr::INSUFFICIENT_BALANCE);

    let ok = w.m.withdraw_ix(&w.env, &w.usdc, &whale.pubkey(), &to, 100_000 * USDC, &w.usdc_prices(true));
    w.env.ok(&[ok], &[&whale]);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 0);
}

#[test]
fn sealing_counts_the_spendable_lifeboat_balance_after_token_2022_fees() {
    let mut w = World::with_transfer_fee_mint();
    let depositor = w.user();
    w.deposit("usdc", &depositor, 1_000 * USDC);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 900 * USDC);

    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let mv = w.m.vault_ix(24, &(900 * USDC).to_le_bytes(), vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(w.usdc.vault_tokens, false),
        AccountMeta::new(lifeboat, false),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        AccountMeta::new(w.env.payer.pubkey(), true),
        AccountMeta::new_readonly(SYSTEM, false),
    ]);
    w.env.ok(&[mv], &[&w.m.admin]);
    assert_eq!(w.env.balance(&lifeboat), 810 * USDC);

    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let seal = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    assert_eq!(w.env.fails(&[seal], &[]), verr::IMPORT_EXCEEDS_BALANCE,
        "the seal must reject 900 in backing claims against 810 spendable tokens");
}

#[test]
fn a_guardian_quorum_can_return_funds_from_the_lifeboat() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let mv = w.m.vault_ix(
        24,
        &(10_000_000 * USDC).to_le_bytes(),
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(w.usdc.vault_tokens, false),
            AccountMeta::new(lifeboat, false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    w.env.ok(&[mv], &[&w.m.admin]);
    // A compromised admin parked everything in the lifeboat; two guardians bring it back.
    let back = w.m.vault_ix(
        25,
        &(10_000_000 * USDC).to_le_bytes(),
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(w.usdc.vault_tokens, false),
            AccountMeta::new(lifeboat, false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
            AccountMeta::new_readonly(w.m.g[0].pubkey(), true),
            AccountMeta::new_readonly(w.m.g[1].pubkey(), true),
        ],
    );
    w.env.ok(&[back], &[&w.m.g[0], &w.m.g[1]]);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 10_000_000 * USDC);
}

#[test]
fn a_quorum_ejects_a_guardian_who_freezes_forever() {
    let mut w = World::new();
    w.seal();
    let (g0, g1, g2) = (w.m.g[0].pubkey(), w.m.g[1].pubkey(), w.m.g[2].pubkey());
    let fz = w.m.freeze_ix(&g0, None, 86_400);
    w.env.ok(&[fz], &[&w.m.g[0]]);
    let eject = w.m.vault_ix(15, &[0], vec![AccountMeta::new(w.m.protocol, false), AccountMeta::new_readonly(g1, true), AccountMeta::new_readonly(g2, true)]);
    w.env.ok(&[eject], &[&w.m.g[1], &w.m.g[2]]);
    let ix = w.m.unfreeze_ix(None, &[g1, g2]);
    w.env.ok(&[ix], &[&w.m.g[1], &w.m.g[2]]);
    let fz = w.m.freeze_ix(&g0, None, 86_400);
    assert_eq!(w.env.fails(&[fz], &[&w.m.g[0]]), verr::NOT_GUARDIAN, "the ejected guardian has no powers left");
    let again = w.m.vault_ix(15, &[0], vec![AccountMeta::new(w.m.protocol, false), AccountMeta::new_readonly(g1, true), AccountMeta::new_readonly(g2, true)]);
    assert_eq!(w.env.fails(&[again], &[&w.m.g[1], &w.m.g[2]]), verr::CANNOT_EJECT, "never below the threshold");
}

// ---------------------------------------------------------------------------
// Compute: the targets in docs/05-PROGRAM-SPEC.md §6 (measured through Harbor,
// so each figure includes the protocol's own CPI overhead).
// ---------------------------------------------------------------------------

#[test]
fn compute_units_are_within_the_spec_targets() {
    let mut w = World::new();
    let lender = w.user();
    w.deposit("usdc", &lender, 5_000_000 * USDC);
    let u = w.user();
    let usdc_acc = w.account("usdc", &u.pubkey());
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &usdc_acc, 1_000 * USDC, &w.usdc.token_program);
    let ix = w.m.deposit_ix(&w.env, &w.usdc, &u.pubkey(), &usdc_acc, 1_000 * USDC);
    let first_deposit = w.env.ok(&[ix], &[&u]).compute_units_consumed;
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &usdc_acc, 1_000 * USDC, &w.usdc.token_program);
    let ix = w.m.deposit_ix(&w.env, &w.usdc, &u.pubkey(), &usdc_acc, 1_000 * USDC);
    let deposit = w.env.ok(&[ix], &[&u]).compute_units_consumed;
    let sol_acc = w.deposit("sol", &u, 10 * SOL);
    let _ = sol_acc;
    w.seal();

    // G2 fast path: own USDC back, no prices.
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &u.pubkey(), &usdc_acc, 500 * USDC, &[(w.usdc.asset, SYSTEM), (w.sol.asset, SYSTEM)]);
    let g2 = w.env.ok(&[ix], &[&u]).compute_units_consumed;
    // Priced borrow beyond own USDC: search with two price pairs.
    let prices = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &u.pubkey(), &usdc_acc, 2_500 * USDC, &prices);
    let priced = w.env.ok(&[ix], &[&u]).compute_units_consumed;
    // Unbacked payout that becomes a ticket, then its settlement.
    let payee = w.user();
    let to = w.account("usdc", &payee.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &payee.pubkey(), 200_000 * USDC, &w.usdc_prices(true));
    let (_, ticket) = w.m.next_ticket(&w.env);
    let ticketed = w.env.ok(&[ix], &[&w.m.admin]);
    let eta = outcome(&ticketed).eta_s;
    w.env.advance(eta - w.env.time);
    let ix = w.m.settle_ix(&w.usdc, &ticket, &to, &w.env.payer.pubkey());
    let settle = w.env.ok(&[ix], &[]).compute_units_consumed;
    let attest_ix = w.m.vault_ix(
        22,
        &[],
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new_readonly(w.usdc.vault, false),
            AccountMeta::new_readonly(w.usdc.vault_tokens, false),
        ],
    );
    let attest = w.env.ok(&[attest_ix], &[]).compute_units_consumed;
    println!("CU  deposit (new ledger) {first_deposit}  deposit {deposit}  release G2 {g2}  release priced {priced}  release to ticket {}  settle {settle}  attest {attest}", ticketed.compute_units_consumed);
    assert!(deposit <= 25_000 + 12_000, "deposit incl. Harbor CPI");
    assert!(g2 <= 35_000 + 12_000, "G2 path incl. Harbor CPI");
    assert!(priced <= 90_000, "priced search");
    assert!(settle <= 20_000);
}

// ---------------------------------------------------------------------------
// S8: the one-transaction attack (44% of incidents finish in one transaction).
// A stop button fires at best in the next slot; the limit is inside the
// transaction.
// ---------------------------------------------------------------------------

#[test]
fn s8_one_transaction_drain_gets_only_the_burst() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();

    // Legacy custody: the admin key controls the pool's token account. One
    // transaction, one instruction, everything is gone.
    let legacy_admin = w.user();
    let legacy_pool = w.account("usdc", &legacy_admin.pubkey());
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &legacy_pool, 10_000_000 * USDC, &w.usdc.token_program);
    let thief = Keypair::new();
    let thief_acc = w.account("usdc", &thief.pubkey());
    let mut d = vec![12u8];
    d.extend_from_slice(&(10_000_000 * USDC).to_le_bytes());
    d.push(6);
    let drain = solana_instruction::Instruction {
        program_id: w.usdc.token_program,
        accounts: vec![
            AccountMeta::new(legacy_pool, false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new(thief_acc, false),
            AccountMeta::new_readonly(legacy_admin.pubkey(), true),
        ],
        data: d,
    };
    w.env.ok(&[drain], &[&legacy_admin]);
    assert_eq!(w.env.balance(&thief_acc), 10_000_000 * USDC, "legacy: 100% in one transaction");

    // Bulkhead: the same attacker packs ten payouts into ONE transaction. The
    // burst is 2% of what is in the vault at each payout: 100,000 of the 10M,
    // then 99,000 of the 9.9M left fill it exactly; the rest queue.
    let attacker = Keypair::new();
    let loot = w.account("usdc", &attacker.pubkey());
    let mut ixs = Vec::new();
    for k in 0..10u64 {
        let amount = if k == 1 { 99_000 } else { 100_000 } * USDC;
        // Each payout names its own ticket (payer, nonce k): ten in one
        // transaction, built from the same state, never collide.
        ixs.push(w.m.admin_payout_with(&w.env, &w.usdc, &loot, &attacker.pubkey(), amount, &w.usdc_prices(true), k));
    }
    let m = w.env.ok(&ixs, &[&w.m.admin]);
    assert_eq!(w.env.balance(&loot), 199_000 * USDC, "Bulkhead: only the 2% burst inside the transaction");
    assert!(m.compute_units_consumed < 1_400_000);
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!((a.pending, a.queued), (8, 800_000 * USDC), "the rest waits in public");

    // The stop button fires in the next slot: too late for legacy, in time here.
    w.env.next_slot();
    let g0 = w.m.g[0].pubkey();
    let fz = w.m.freeze_ix(&g0, None, 86_400);
    w.env.ok(&[fz], &[&w.m.g[0]]);
    for nonce in 2..10u64 {
        let t = w.m.ticket_pda(&w.env.payer.pubkey(), nonce);
        let ix = w.m.cancel_ix(&w.usdc, &t, &g0, &w.env.payer.pubkey());
        w.env.ok(&[ix], &[&w.m.g[0]]);
    }
    assert_eq!(w.env.balance(&loot), 199_000 * USDC);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 9_801_000 * USDC, "98% stays");
}

#[test]
fn lengthening_a_window_is_a_tightening_that_grants_no_new_burst() {
    // G1 against a stolen admin key: a window lengthening is classified as a
    // tightening, so it applies at once. If the bucket kept its backlog in
    // milliseconds, a drained bucket would look partly empty under the longer
    // window, and repeating the change would pay the burst again and again.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let vault = w.usdc.vault;
    let thief = w.user();
    let to = w.account("usdc", &thief.pubkey());
    let burst = w.m.attest(&mut w.env, &w.usdc).available_now;
    assert_eq!(burst, 200_000 * USDC);
    let mut paid = 0;
    let mut limits = Limits::default_limits();
    for _ in 0..6 {
        let now = w.m.attest(&mut w.env, &w.usdc).available_now;
        if now > 0 {
            let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &thief.pubkey(), now, &w.usdc_prices(true));
            w.env.ok(&[ix], &[&w.m.admin]);
            paid += now;
        }
        // "Tighten": both windows four times longer, same bps.
        limits.short_window_s *= 4;
        limits.long_window_s *= 4;
        let ix = w.m.propose_change_ix(&w.env, 0, &vault, &limits.bytes(), Some(&vault));
        w.env.ok(&[ix], &[&w.m.admin]);
        w.env.next_slot();
    }
    assert_eq!(w.env.balance(&to), paid);
    // Everything above happened in the same second: G1 at T = 0 is one burst.
    assert!(paid <= burst, "a stolen admin key took {} USDC instantly; G1 allows {}", paid / USDC, burst / USDC);
}

fn create_vault_ix(w: &mut World, limits: &Limits) -> Instruction {
    let (mint, _) = w.env.create_mint(6, &token_program());
    let vault = pda(&[b"vault", w.m.protocol.as_ref(), mint.as_ref()], &w.m.vault_program);
    let vault_tokens = pda(&[b"vault-tokens", w.m.protocol.as_ref(), mint.as_ref()], &w.m.vault_program);
    w.m.vault_ix(1, &limits.bytes(), vec![
        AccountMeta::new(w.env.payer.pubkey(), true),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(vault_tokens, false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(SYSTEM, false),
    ])
}

fn import_ix(w: &World, owner: &Address, amount: u64) -> Instruction {
    w.m.vault_ix(3, &amount.to_le_bytes(), vec![
        AccountMeta::new(w.env.payer.pubkey(), true),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(w.m.backing(owner), false),
        AccountMeta::new_readonly(*owner, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ])
}

#[test]
fn nothing_loosens_while_the_seal_is_under_review() {
    // The seal waits 72h so anyone can review what is sealed (T19). If the
    // admin could still loosen in that window, a minute before the seal it
    // could swap in its own guardians (nobody left to veto), open the limits,
    // add a vault and import backing, and seal all of it unreviewed.
    let mut w = World::new();
    let u = w.user();
    w.deposit("usdc", &u, 1_000_000 * USDC);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY - 60);
    let vault = w.usdc.vault;
    let zero = Address::default();

    let puppets = [Keypair::new(), Keypair::new()];
    let mut guardians = vec![2u8];
    for k in &puppets {
        guardians.extend_from_slice(k.pubkey().as_ref());
    }
    guardians.push(2);
    guardians.extend_from_slice(&(7 * DAY).to_le_bytes());
    let ix = w.m.propose_change_ix(&w.env, 2, &zero, &guardians, None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::SEAL_UNDER_REVIEW, "guardian swap");
    let mut looser = Limits::default_limits();
    looser.short_bps = 10_000;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::SEAL_UNDER_REVIEW, "looser limits");
    let ix = import_ix(&w, &Keypair::new().pubkey(), 1);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::SEAL_UNDER_REVIEW, "an import");
    let ix = create_vault_ix(&mut w, &Limits::default_limits());
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::SEAL_UNDER_REVIEW, "a new vault");

    // Making things safer never waits.
    let mut tighter = Limits::default_limits();
    tighter.short_bps = 100;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);

    // A guardian's veto ends the review; the admin may change things again,
    // and the seal it proposes next waits a full 72h from then.
    let veto = w.m.vault_ix(6, &[], vec![AccountMeta::new(w.m.protocol, false), AccountMeta::new_readonly(w.m.g[0].pubkey(), true)]);
    w.env.ok(&[veto], &[&w.m.g[0]]);
    let ix = import_ix(&w, &Keypair::new().pubkey(), 1);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &w.usdc.vault_tokens, 1, &w.usdc.token_program);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY - 1);
    let seal = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    assert_eq!(w.env.fails(&[seal.clone()], &[]), verr::SEAL_NOT_EXECUTABLE);
    w.env.advance(1);
    w.env.ok(&[seal], &[]);
}

#[test]
fn after_the_seal_a_new_vault_starts_with_its_unbacked_lane_closed() {
    // Creating a vault applied its limits at once, even after the seal: an
    // admin key alone could open an instant 100%-an-hour lane on a new mint.
    let mut w = World::new();
    let u = w.user();
    w.deposit("usdc", &u, 1_000_000 * USDC);
    w.seal();
    let ix = create_vault_ix(&mut w, &Limits::default_limits());
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::GENESIS_ONLY);
    // A floor alone opens a bucket: no bps but a floor is still an open lane.
    let mut floor_only = Limits::default_limits();
    floor_only.short_bps = 0;
    floor_only.short_floor = 1;
    let ix = create_vault_ix(&mut w, &floor_only);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::GENESIS_ONLY, "a floor alone");
    // Closing the long bucket closes the lane too.
    let mut long_closed = Limits::default_limits();
    long_closed.long_bps = 0;
    let ix = create_vault_ix(&mut w, &long_closed);
    w.env.ok(&[ix], &[&w.m.admin]);
    // A closed lane (either bucket at capacity 0) is accepted; opening it is a
    // loosening, so it waits 72h like any other.
    let mut closed = Limits::default_limits();
    closed.short_bps = 0;
    let ix = create_vault_ix(&mut w, &closed);
    let vault = ix.accounts[3].pubkey;
    w.env.ok(&[ix], &[&w.m.admin]);
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &Limits::default_limits().bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    let d = w.env.account(&vault).data;
    assert_eq!(u16::from_le_bytes(d[8 + 32 * 4..8 + 32 * 4 + 2].try_into().unwrap()), 0, "still closed: the opening is only a proposal");
}

#[test]
fn only_a_live_guardian_cancels_a_ticket_not_the_admin() {
    // A stolen admin key could cancel every honest queued withdrawal, without
    // end and with no counter: each cancel also keeps its reservation, so the
    // lane stays full (A4). Cancelling is a guardian's brake; the admin keeps
    // freeze.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let payee = w.user();
    let to = w.account("usdc", &payee.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &payee.pubkey(), 2_000_000 * USDC, &w.usdc_prices(true));
    let (_, ticket) = w.m.next_ticket(&w.env);
    w.env.ok(&[ix], &[&w.m.admin]);
    let admin = w.m.admin.pubkey();
    let by_admin = w.m.cancel_ix(&w.usdc, &ticket, &admin, &w.env.payer.pubkey());
    assert_eq!(w.env.fails(&[by_admin], &[&w.m.admin]), verr::NOT_GUARDIAN);
    let g0 = w.m.g[0].pubkey();
    let by_guardian = w.m.cancel_ix(&w.usdc, &ticket, &g0, &w.env.payer.pubkey());
    w.env.ok(&[by_guardian], &[&w.m.g[0]]);
}

/// Execute change `id`; `target` is the vault (SetLimits), the asset PDA
/// (UpsertAsset), or anything for a protocol-level change.
fn execute_change_ix(w: &World, id: u64, target: &Address) -> Instruction {
    w.m.vault_ix(20, &[], vec![
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new(w.m.change_address(id), false),
        AccountMeta::new(*target, false),
        AccountMeta::new(w.env.payer.pubkey(), true),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ])
}

fn short_bps(w: &World, vault: &Address) -> u16 {
    let d = w.env.account(vault).data;
    u16::from_le_bytes(d[8 + 128..8 + 130].try_into().unwrap())
}

#[test]
fn a_stale_loosening_cannot_undo_a_later_tightening() {
    // A loosening stores only its payload. Executed after a tightening of the
    // same vault, it used to replace the whole config and silently undo the
    // tightening, which was never part of what the 72h review saw.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let vault = w.usdc.vault;
    let mut looser = Limits::default_limits();
    looser.short_bps = 1_000;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    // An emergency tightening while it waits.
    let mut tighter = Limits::default_limits();
    tighter.short_bps = 50;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 0, &vault)], &[]), verr::CHANGE_STALE);
    assert_eq!(short_bps(&w, &vault), 50, "the tightening stands");
}

#[test]
fn two_pending_loosenings_of_one_vault_cannot_both_execute() {
    // "Last executed wins" let anyone pick the order of overlapping changes.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let vault = w.usdc.vault;
    for bps in [300u16, 1_000] {
        let mut l = Limits::default_limits();
        l.short_bps = bps;
        let ix = w.m.propose_change_ix(&w.env, 0, &vault, &l.bytes(), Some(&vault));
        w.env.ok(&[ix], &[&w.m.admin]);
    }
    w.env.advance(3 * DAY);
    w.env.ok(&[execute_change_ix(&w, 0, &vault)], &[]);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 1, &vault)], &[]), verr::CHANGE_STALE);
    assert_eq!(short_bps(&w, &vault), 300);
}

#[test]
fn an_older_guardian_set_cannot_bring_back_an_ejected_guardian() {
    // A quorum ejects a guardian; a SetGuardians proposed before the ejection,
    // still naming it, must not restore it.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let zero = Address::default();
    let mut set = vec![3u8];
    for k in &w.m.g {
        set.extend_from_slice(k.pubkey().as_ref());
    }
    set.push(2);
    set.extend_from_slice(&(7 * DAY).to_le_bytes());
    let ix = w.m.propose_change_ix(&w.env, 2, &zero, &set, None);
    w.env.ok(&[ix], &[&w.m.admin]);
    let eject = w.m.vault_ix(15, &[2], vec![
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new_readonly(w.m.g[0].pubkey(), true),
        AccountMeta::new_readonly(w.m.g[1].pubkey(), true),
    ]);
    w.env.ok(&[eject], &[&w.m.g[0], &w.m.g[1]]);
    w.env.advance(3 * DAY);
    let protocol = w.m.protocol;
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 0, &protocol)], &[]), verr::CHANGE_STALE);
}

#[test]
fn a_change_to_one_thing_does_not_stale_a_change_to_another() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let new_admin = Keypair::new().pubkey();
    let ix = w.m.propose_change_ix(&w.env, 3, &new_admin, &[], None);
    w.env.ok(&[ix], &[&w.m.admin]);
    // Raising the delay (a tightening of another kind) and tightening a vault.
    let zero = Address::default();
    let ix = w.m.propose_change_ix(&w.env, 5, &zero, &(4 * DAY).to_le_bytes(), None);
    w.env.ok(&[ix], &[&w.m.admin]);
    let vault = w.usdc.vault;
    let mut tighter = Limits::default_limits();
    tighter.short_bps = 100;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let protocol = w.m.protocol;
    w.env.ok(&[execute_change_ix(&w, 0, &protocol)], &[]);
    let d = w.env.account(&protocol).data;
    assert_eq!(&d[8 + 64..8 + 96], new_admin.as_ref(), "the admin changed");
}

#[test]
fn a_stale_asset_loosening_cannot_undo_a_later_asset_tightening() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let (asset, mint, program) = (w.usdc.asset, w.usdc.mint, w.usdc.token_program);
    let upsert = |w: &World, cfg: &[u8]| {
        let mut ix = w.m.propose_change_ix(&w.env, 1, &mint, cfg, Some(&asset));
        ix.accounts.push(AccountMeta::new_readonly(mint, false));
        ix.accounts.push(AccountMeta::new_readonly(program, false));
        ix
    };
    // Loosen: a larger haircut allowance. Then tighten: a smaller one.
    let ix = upsert(&w, &asset_bytes(true, 9_950, 10_100, 20_000, 60, 100, USDC_FEED));
    w.env.ok(&[ix], &[&w.m.admin]);
    let ix = upsert(&w, &asset_bytes(true, 9_000, 10_100, 20_000, 60, 100, USDC_FEED));
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 0, &asset)], &[]), verr::CHANGE_STALE);
}

#[test]
fn queued_releases_built_from_the_same_state_do_not_collide() {
    // A ticket used to be named by the protocol's next id, so two users who
    // read the same state raced for one address and the second failed. Each
    // payer now names its own ticket.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let (a, b) = (w.user(), w.user());
    let (ta, tb) = (w.account("usdc", &a.pubkey()), w.account("usdc", &b.pubkey()));
    // Drain the burst first, so both of the next payouts are queued.
    let drain = w.m.admin_payout_ix(&w.env, &w.usdc, &ta, &a.pubkey(), 200_000 * USDC, &w.usdc_prices(true));
    w.env.ok(&[drain], &[&w.m.admin]);
    let first = w.m.admin_payout_with(&w.env, &w.usdc, &ta, &a.pubkey(), 1_000 * USDC, &w.usdc_prices(true), 7);
    let second = w.m.admin_payout_with(&w.env, &w.usdc, &tb, &b.pubkey(), 1_000 * USDC, &w.usdc_prices(true), 8);
    let o1 = outcome(&w.env.ok(&[first], &[&w.m.admin]));
    let o2 = outcome(&w.env.ok(&[second], &[&w.m.admin]));
    assert_eq!((o1.queued, o2.queued), (1_000 * USDC, 1_000 * USDC));
    assert_eq!(o2.ticket_id, o1.ticket_id + 1, "ids still count up");
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!(a.pending, 2);
    // A payer reusing its own nonce is refused, and nothing else is.
    let again = w.m.admin_payout_with(&w.env, &w.usdc, &tb, &b.pubkey(), 1_000 * USDC, &w.usdc_prices(true), 8);
    assert!(w.env.send(&[again], &[&w.m.admin]).is_err());
}

fn cancel_change_ix(w: &World, id: u64, signer: &Address) -> Instruction {
    w.m.vault_ix(21, &[], vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.m.change_address(id), false),
        AccountMeta::new_readonly(*signer, true),
    ])
}

fn protocol_admin(w: &World) -> Address {
    let d = w.env.account(&w.m.protocol).data;
    Address::from(<[u8; 32]>::try_from(&d[8 + 64..8 + 96]).unwrap())
}

#[test]
fn a_recovery_key_replaces_a_stolen_admin_key_that_cannot_stop_it() {
    // A4: a thief holding the admin key could cancel every rotation of the
    // admin, since only the admin could propose or cancel one. A separate
    // recovery key (the Morpho V2 owner / curator split) proposes the new
    // admin; it waits the delay, any guardian can veto it, and the admin
    // cannot cancel it.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let zero = Address::default();
    let recovery = w.user();
    // With no recovery key yet, the admin may set one: a 72h change.
    let ix = w.m.propose_change_ix(&w.env, 6, &recovery.pubkey(), &[], None);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let protocol = w.m.protocol;
    w.env.ok(&[execute_change_ix(&w, 0, &protocol)], &[]);

    // The admin key is stolen. The recovery key proposes a new admin.
    let fresh = Keypair::new().pubkey();
    let mut ix = w.m.propose_change_ix(&w.env, 3, &fresh, &[], None);
    ix.accounts[1].pubkey = recovery.pubkey();
    w.env.ok(&[ix], &[&recovery]);
    let thief = w.m.admin.pubkey();
    // The thief cannot cancel it, cannot replace the recovery key, and its own
    // rival rotation would only race a guardian veto.
    assert_eq!(w.env.fails(&[cancel_change_ix(&w, 1, &thief)], &[&w.m.admin]), verr::NOT_ADMIN);
    let ix = w.m.propose_change_ix(&w.env, 6, &Keypair::new().pubkey(), &[], None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::NOT_ADMIN);
    w.env.advance(3 * DAY);
    w.env.ok(&[execute_change_ix(&w, 1, &protocol)], &[]);
    assert_eq!(protocol_admin(&w), fresh);
    // The old key is no longer the admin.
    let mut tighter = Limits::default_limits();
    tighter.short_bps = 100;
    let vault = w.usdc.vault;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::NOT_ADMIN);
    let _ = zero;
}

#[test]
fn the_recovery_key_can_only_replace_the_admin_or_itself() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let recovery = w.user();
    let ix = w.m.propose_change_ix(&w.env, 6, &recovery.pubkey(), &[], None);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let protocol = w.m.protocol;
    w.env.ok(&[execute_change_ix(&w, 0, &protocol)], &[]);
    let vault = w.usdc.vault;
    // Not limits, not guardians: it has no say over risk or the brakes.
    let mut looser = Limits::default_limits();
    looser.short_bps = 1_000;
    let mut ix = w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    ix.accounts[1].pubkey = recovery.pubkey();
    assert_eq!(w.env.fails(&[ix], &[&recovery]), verr::NOT_ADMIN);
    // The admin and the recovery key stay distinct, in both directions.
    let admin = w.m.admin.pubkey();
    let mut ix = w.m.propose_change_ix(&w.env, 6, &admin, &[], None);
    ix.accounts[1].pubkey = recovery.pubkey();
    assert_eq!(w.env.fails(&[ix], &[&recovery]), verr::INVALID_INSTRUCTION);
    let ix = w.m.propose_change_ix(&w.env, 3, &recovery.pubkey(), &[], None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::INVALID_INSTRUCTION);
    // It may replace itself; the admin may not, once one exists.
    let next = Keypair::new().pubkey();
    let mut ix = w.m.propose_change_ix(&w.env, 6, &next, &[], None);
    ix.accounts[1].pubkey = recovery.pubkey();
    w.env.ok(&[ix], &[&recovery]);
}

#[test]
fn a_thief_cannot_pre_empt_the_recovery_key_with_its_own_rotation() {
    // With no guardian awake to veto, a thief who proposed its own new admin
    // first would execute first and make the recovery key's change stale,
    // again and again. A recovery proposal therefore stales every earlier
    // admin proposal at once, and later ones run after it.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let recovery = w.user();
    let ix = w.m.propose_change_ix(&w.env, 6, &recovery.pubkey(), &[], None);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let protocol = w.m.protocol;
    w.env.ok(&[execute_change_ix(&w, 0, &protocol)], &[]);
    // The thief proposes first (id 1), then the recovery key (id 2).
    let accomplice = Keypair::new().pubkey();
    let ix = w.m.propose_change_ix(&w.env, 3, &accomplice, &[], None);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(60);
    let fresh = Keypair::new().pubkey();
    let mut ix = w.m.propose_change_ix(&w.env, 3, &fresh, &[], None);
    ix.accounts[1].pubkey = recovery.pubkey();
    w.env.ok(&[ix], &[&recovery]);
    w.env.advance(3 * DAY);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 1, &protocol)], &[]), verr::CHANGE_STALE);
    w.env.ok(&[execute_change_ix(&w, 2, &protocol)], &[]);
    assert_eq!(protocol_admin(&w), fresh);
}

#[test]
fn a_stolen_recovery_key_is_replaced_by_the_admin_with_a_live_quorum() {
    // A stolen recovery key can propose a new admin as often as it likes; each
    // proposal stales the admin's own rotations, the guardians must veto every
    // one, and only that key could replace itself. The admin and a live
    // quorum replace it at once.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let stolen = w.user();
    let ix = w.m.propose_change_ix(&w.env, 6, &stolen.pubkey(), &[], None);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let protocol = w.m.protocol;
    w.env.ok(&[execute_change_ix(&w, 0, &protocol)], &[]);
    // The thief proposes itself the admin (change 1) and a recovery key of its own (2).
    let accomplice = Keypair::new().pubkey();
    let mut ix = w.m.propose_change_ix(&w.env, 3, &accomplice, &[], None);
    ix.accounts[1].pubkey = stolen.pubkey();
    w.env.ok(&[ix], &[&stolen]);
    let mut ix = w.m.propose_change_ix(&w.env, 6, &accomplice, &[], None);
    ix.accounts[1].pubkey = stolen.pubkey();
    w.env.ok(&[ix], &[&stolen]);
    let (admin, g0, g1, g2) = (w.m.admin.pubkey(), w.m.g[0].pubkey(), w.m.g[1].pubkey(), w.m.g[2].pubkey());
    let fresh = Keypair::new().pubkey();
    // Neither the admin alone, nor with too few guardians, nor a quorum without
    // the admin; and the admin cannot be its own recovery key.
    let ix = w.m.replace_recovery_ix(&admin, &fresh, &[]);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::NO_QUORUM);
    let ix = w.m.replace_recovery_ix(&admin, &fresh, &[g0]);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin, &w.m.g[0]]), verr::NO_QUORUM);
    let ix = w.m.replace_recovery_ix(&g2, &fresh, &[g0, g1]);
    assert_eq!(w.env.fails(&[ix], &[&w.m.g[2], &w.m.g[0], &w.m.g[1]]), verr::NOT_ADMIN);
    let ix = w.m.replace_recovery_ix(&admin, &admin, &[g0, g1]);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]), verr::INVALID_INSTRUCTION);
    let ix = w.m.replace_recovery_ix(&admin, &fresh, &[g0, g1]);
    w.env.ok(&[ix], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]);
    // The stolen key can propose nothing more, and what it proposed is stale.
    let mut ix = w.m.propose_change_ix(&w.env, 3, &accomplice, &[], None);
    ix.accounts[1].pubkey = stolen.pubkey();
    assert_eq!(w.env.fails(&[ix], &[&stolen]), verr::NOT_ADMIN);
    w.env.advance(3 * DAY);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 1, &protocol)], &[]), verr::CHANGE_STALE);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 2, &protocol)], &[]), verr::CHANGE_STALE);
    assert_eq!(protocol_admin(&w), admin);
}

#[test]
fn every_account_substitution_is_refused() {
    use common::sweep::{any, role, Sweep};
    let mut w = World::new();
    // A second protocol on the same Vault program, with its own vault.
    let other = Market::with_ids(&mut w.env, w.m.vault_program, Address::new_unique());
    let other_vault = other.create_vault(&mut w.env, 6, Limits::default_limits(), USDC_FEED, None);
    let mut s = Sweep::for_market(&w.env, &w.m, &w.sol, &other, &other_vault);

    let whale = w.user();
    let whale_acc = w.deposit("usdc", &whale, 10_000_000 * USDC);
    let sol_whale = w.user();
    w.deposit("sol", &sol_whale, 100_000 * SOL);
    // The other market is sealed too, so it can hold a queued ticket.
    let other_whale = w.user();
    let other_acc = w.env.token_account(
        &other_vault.mint,
        &other_whale.pubkey(),
        &other_vault.token_program,
    );
    w.env.mint_to(
        &other_vault.mint,
        &other_vault.mint_authority,
        &other_acc,
        10_000_000 * USDC,
        &other_vault.token_program,
    );
    let ix = other.deposit_ix(
        &w.env,
        &other_vault,
        &other_whale.pubkey(),
        &other_acc,
        10_000_000 * USDC,
    );
    w.env.ok(&[ix], &[&other_whale]);
    w.env.ok(&[other.propose_seal_ix()], &[&other.admin]);
    w.seal();
    let ix = other.execute_seal_ix(&[&other_vault]);
    w.env.ok(&[ix], &[]);
    // Look-alikes a missing check would accept: a stranger's token accounts of
    // both mints, a queued ticket on the other vault, and one in the other market.
    let stranger = Keypair::new().pubkey();
    let stranger_usdc = w.account("usdc", &stranger);
    let stranger_sol = w.account("sol", &stranger);
    s.decoy("a stranger's USDC account", stranger_usdc);
    s.decoy("a stranger's SOL account", stranger_sol);
    let sol_payee = w.account("sol", &stranger);
    let ix = w.m.admin_payout_ix(
        &w.env,
        &w.sol,
        &sol_payee,
        &stranger,
        5_000 * SOL,
        &[(w.sol.asset, w.sol.price)],
    );
    let (_, sol_ticket) = w.m.next_ticket(&w.env);
    w.env.ok(&[ix], &[&w.m.admin]);
    s.decoy("a ticket on the SOL vault", sol_ticket);
    let other_payee = w
        .env
        .token_account(&other_vault.mint, &stranger, &other_vault.token_program);
    let ix = other.admin_payout_ix(
        &w.env,
        &other_vault,
        &other_payee,
        &stranger,
        500_000 * USDC,
        &[(other_vault.asset, other_vault.price)],
    );
    let (_, other_ticket) = other.next_ticket(&w.env);
    w.env.ok(&[ix], &[&other.admin]);
    s.decoy("a ticket in the other market", other_ticket);
    let (admin, g0, g1, g2) = (
        w.m.admin.pubkey(),
        w.m.g[0].pubkey(),
        w.m.g[1].pubkey(),
        w.m.g[2].pubkey(),
    );
    let guardians = vec![g0, g1, g2];
    let freezers = vec![admin, g0, g1, g2];
    let protocol_vaults = vec![w.usdc.vault, w.sol.vault];
    // Harbor's slots before the Vault's own accounts: program, caller, signer.
    const H: usize = 3;
    let payer_free = |at| any(at, "rent payer: any funded signer");
    let harbor_user = any(
        2,
        "Harbor's own user slot (demo integration); the Vault checks its own source authority",
    );
    let unqueued = [
        any(H + 8, "ticket PDA: only used when part of a release is queued"),
        any(H + 9, "system program: only used to create a ticket"),
        any(H + 11, "price account: an owner taking back a deposit, or a payee owing nothing, needs no price (G2)"),
    ];

    // --- custody -----------------------------------------------------------
    w.env.mint_to(
        &w.usdc.mint,
        &w.usdc.mint_authority,
        &whale_acc,
        1_000 * USDC,
        &w.usdc.token_program,
    );
    let ix =
        w.m.deposit_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 1_000 * USDC);
    s.run(
        &mut w.env,
        "deposit",
        ix,
        &[&whale],
        &[harbor_user, payer_free(H + 7)],
    );

    let ix = w.m.withdraw_ix(
        &w.env,
        &w.usdc,
        &whale.pubkey(),
        &whale_acc,
        1_000 * USDC,
        &w.usdc_prices(true),
    );
    let mut ok = vec![payer_free(H + 7)];
    ok.extend(unqueued.iter().map(|a| any(a.at, a.why)));
    s.run(&mut w.env, "withdraw (backed)", ix, &[&whale], &ok);

    let payee = w.user();
    let payee_acc = w.account("usdc", &payee.pubkey());
    let ix = w.m.admin_payout_ix(
        &w.env,
        &w.usdc,
        &payee_acc,
        &payee.pubkey(),
        10_000 * USDC,
        &w.usdc_prices(true),
    );
    s.run(&mut w.env, "admin payout (instant)", ix, &[], &ok);

    let ix = w.m.admin_payout_ix(
        &w.env,
        &w.usdc,
        &payee_acc,
        &payee.pubkey(),
        1_000_000 * USDC,
        &w.usdc_prices(true),
    );
    let (_, t1) = w.m.next_ticket(&w.env);
    s.run(
        &mut w.env,
        "admin payout (queued)",
        ix,
        &[],
        &[any(H + 11, "price account: the payee owes nothing")],
    );

    // --- tickets: extend, settle -------------------------------------------
    let ix = w.m.vault_ix(
        11,
        &3_600i64.to_le_bytes(),
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(t1, false),
            AccountMeta::new_readonly(g2, true),
        ],
    );
    s.run(
        &mut w.env,
        "extend ticket",
        ix,
        &[],
        &[
            role(
                1,
                vec![sol_ticket],
                "any queued ticket of this protocol (another market's is refused)",
            ),
            role(2, guardians.clone(), "any live guardian"),
        ],
    );

    let ix = w.m.admin_payout_ix(
        &w.env,
        &w.usdc,
        &payee_acc,
        &payee.pubkey(),
        100_000 * USDC,
        &w.usdc_prices(true),
    );
    let (_, t2) = w.m.next_ticket(&w.env);
    w.env.ok(&[ix], &[&w.m.admin]);
    // Past the ticket's ETA, heartbeating on the way (a guardian silent
    // longer than its 7-day interval stops counting).
    for _ in 0..4 {
        w.env.advance(2 * DAY);
        for g in [&w.m.g[0], &w.m.g[1], &w.m.g[2]] {
            let hb = w.m.vault_ix(
                14,
                &[],
                vec![
                    AccountMeta::new(w.m.protocol, false),
                    AccountMeta::new_readonly(g.pubkey(), true),
                ],
            );
            w.env.ok(&[hb], &[g]);
        }
    }
    w.refresh_prices();
    let ix =
        w.m.settle_ix(&w.usdc, &t2, &payee_acc, &w.env.payer.pubkey());
    s.run(&mut w.env, "settle ticket", ix, &[], &[]);

    // --- brakes -------------------------------------------------------------
    let ix = w.m.freeze_ix(&g0, Some(&w.usdc), 60);
    s.run(
        &mut w.env,
        "freeze (vault)",
        ix,
        &[],
        &[
            role(1, freezers.clone(), "a live guardian or the admin"),
            role(2, protocol_vaults.clone(), "any vault of this protocol"),
        ],
    );
    let ix = w.m.vault_ix(
        14,
        &[],
        vec![
            AccountMeta::new(w.m.protocol, false),
            AccountMeta::new_readonly(g0, true),
        ],
    );
    s.run(
        &mut w.env,
        "heartbeat",
        ix,
        &[],
        &[role(
            1,
            guardians.clone(),
            "each guardian heartbeats for itself",
        )],
    );
    let ix = w.m.freeze_ix(&g0, None, 60);
    s.run(
        &mut w.env,
        "freeze (protocol)",
        ix,
        &[],
        &[role(1, freezers.clone(), "a live guardian or the admin")],
    );
    let ix = w.m.cancel_ix(&w.usdc, &t1, &g0, &w.env.payer.pubkey());
    s.run(
        &mut w.env,
        "cancel ticket",
        ix,
        &[],
        &[role(3, guardians.clone(), "any live guardian")],
    );
    let ix = w.m.unfreeze_ix(None, &[g1, g2]);
    s.run(
        &mut w.env,
        "unfreeze (protocol)",
        ix,
        &[],
        &[
            any(1, "the vault slot is unused for the protocol scope"),
            role(2, guardians.clone(), "any quorum"),
            role(3, guardians.clone(), "any quorum"),
        ],
    );
    let ix = w.m.vault_ix(
        16,
        &[],
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new_readonly(admin, true),
        ],
    );
    s.run(
        &mut w.env,
        "reset backlog",
        ix,
        &[],
        &[
            role(1, protocol_vaults.clone(), "any vault of this protocol"),
            role(2, freezers.clone(), "the admin or a live guardian"),
        ],
    );

    // --- governance: propose, veto, cancel, execute -------------------------
    let mut looser = Limits::default_limits();
    looser.short_bps = 300;
    let vault = w.usdc.vault;
    let ix =
        w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    s.run(&mut w.env, "propose change", ix, &[], &[payer_free(0)]);
    let ix = w.m.vault_ix(
        19,
        &[],
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.m.change_address(0), false),
            AccountMeta::new_readonly(g1, true),
        ],
    );
    s.run(
        &mut w.env,
        "veto change",
        ix,
        &[],
        &[role(2, guardians.clone(), "any live guardian")],
    );
    let ix =
        w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    let ix = cancel_change_ix(&w, 1, &admin);
    s.run(&mut w.env, "cancel change", ix, &[], &[]);
    let ix =
        w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault));
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    w.refresh_prices();
    let ix = execute_change_ix(&w, 2, &vault);
    s.run(
        &mut w.env,
        "execute change",
        ix,
        &[],
        &[
            payer_free(3),
            any(4, "mint: read only for an asset change"),
            any(5, "token program: read only for an asset change"),
            any(6, "system program: unused here"),
        ],
    );

    // --- lifeboat: move, return, propose / veto / execute an exit ----------
    let lifeboat = pda(
        &[
            b"lifeboat-tokens",
            w.m.protocol.as_ref(),
            w.usdc.mint.as_ref(),
        ],
        &w.m.vault_program,
    );
    let mv = |w: &World, tag: u8, signers: Vec<AccountMeta>| {
        let mut a = vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(w.usdc.vault_tokens, false),
            AccountMeta::new(lifeboat, false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
        ];
        a.extend(signers);
        w.m.vault_ix(tag, &(1_000 * USDC).to_le_bytes(), a)
    };
    let ix = mv(
        &w,
        24,
        vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    s.run(
        &mut w.env,
        "lifeboat move",
        ix,
        &[],
        &[
            payer_free(7),
            any(
                8,
                "system program: only used to create the lifeboat account",
            ),
        ],
    );
    let ix = mv(
        &w,
        24,
        vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    w.env.ok(&[ix], &[&w.m.admin]);
    let ix = mv(&w, 25, vec![AccountMeta::new_readonly(admin, true)]);
    s.run(&mut w.env, "lifeboat return (admin)", ix, &[], &[]);
    let ix = mv(
        &w,
        25,
        vec![
            AccountMeta::new_readonly(g0, true),
            AccountMeta::new_readonly(g2, true),
        ],
    );
    s.run(
        &mut w.env,
        "lifeboat return (quorum)",
        ix,
        &[],
        &[
            role(6, guardians.clone(), "any quorum"),
            role(7, guardians.clone(), "any quorum"),
        ],
    );
    let ix = mv(
        &w,
        24,
        vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    w.env.ok(&[ix], &[&w.m.admin]);
    let propose_exit = |w: &World| {
        w.m.vault_ix(
            26,
            &(1_000 * USDC).to_le_bytes(),
            vec![
                AccountMeta::new_readonly(w.m.protocol, false),
                AccountMeta::new(w.usdc.vault, false),
                AccountMeta::new_readonly(w.m.admin.pubkey(), true),
            ],
        )
    };
    let ix = propose_exit(&w);
    s.run(&mut w.env, "propose lifeboat exit", ix, &[], &[]);
    let ix = w.m.vault_ix(
        28,
        &[],
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new_readonly(g0, true),
        ],
    );
    s.run(
        &mut w.env,
        "veto lifeboat exit",
        ix,
        &[],
        &[
            role(
                1,
                protocol_vaults.clone(),
                "a veto where no exit is pending changes nothing: the next proposal clears it",
            ),
            role(2, guardians.clone(), "any live guardian"),
        ],
    );
    let ix = propose_exit(&w);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let dest_owner = w.m.destination.pubkey();
    let dest = w.account("usdc", &dest_owner);
    let ix = w.m.vault_ix(
        27,
        &[],
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(lifeboat, false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
        ],
    );
    s.run(&mut w.env, "execute lifeboat exit", ix, &[], &[]);

    // --- guardians: eject, abdicate ------------------------------------------
    for g in [&w.m.g[0], &w.m.g[1], &w.m.g[2]] {
        let hb = w.m.vault_ix(
            14,
            &[],
            vec![
                AccountMeta::new(w.m.protocol, false),
                AccountMeta::new_readonly(g.pubkey(), true),
            ],
        );
        w.env.ok(&[hb], &[g]);
    }
    let ix = w.m.vault_ix(
        17,
        &[4],
        vec![
            AccountMeta::new(w.m.protocol, false),
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new_readonly(g0, true),
            AccountMeta::new_readonly(g1, true),
        ],
    );
    s.run(
        &mut w.env,
        "abdicate",
        ix,
        &[],
        &[
            role(2, guardians.clone(), "any quorum"),
            role(3, guardians.clone(), "any quorum"),
        ],
    );
    let ix = w.m.replace_recovery_ix(&admin, &Address::new_unique(), &[g0, g1]);
    s.run(
        &mut w.env,
        "replace recovery",
        ix,
        &[],
        &[
            role(2, guardians.clone(), "any quorum"),
            role(3, guardians.clone(), "any quorum"),
        ],
    );
    let ix = w.m.vault_ix(
        15,
        &[2],
        vec![
            AccountMeta::new(w.m.protocol, false),
            AccountMeta::new_readonly(g0, true),
            AccountMeta::new_readonly(g1, true),
        ],
    );
    s.run(&mut w.env, "eject", ix, &[], &[]);

    // --- before the seal: create vault, assets, imports, the seal ------------
    let mut p = World::new();
    let other_p = Market::with_ids(&mut p.env, p.m.vault_program, Address::new_unique());
    let other_pv = other_p.create_vault(&mut p.env, 6, Limits::default_limits(), USDC_FEED, None);
    let mut sp = Sweep::for_market(&p.env, &p.m, &p.sol, &other_p, &other_pv);
    let ix = create_vault_ix(&mut p, &Limits::default_limits());
    let (third_vault, third_tokens, third_mint) = (
        ix.accounts[3].pubkey,
        ix.accounts[4].pubkey,
        ix.accounts[5].pubkey,
    );
    sp.run(&mut p.env, "create vault", ix, &[], &[payer_free(0)]);
    let ix = p.m.upsert_asset_ix(&p.env, &p.usdc, &usdc_cfg());
    sp.run(
        &mut p.env,
        "upsert asset",
        ix,
        &[],
        &[
            payer_free(0),
            any(
                6,
                "system program: only used when the asset account is created",
            ),
        ],
    );
    let owner = p.user();
    p.env.mint_to(
        &p.usdc.mint,
        &p.usdc.mint_authority,
        &p.usdc.vault_tokens,
        5 * USDC,
        &p.usdc.token_program,
    );
    let ix = import_ix(&p, &owner.pubkey(), 5 * USDC);
    let p_vaults = vec![p.usdc.vault, p.sol.vault, third_vault];
    sp.run(&mut p.env, "import backing", ix, &[], &[payer_free(0), role(3, p_vaults, "the admin imports into any vault of its protocol; the seal checks each vault's coverage")]);
    let ix = p.m.propose_seal_ix();
    sp.run(&mut p.env, "propose seal", ix, &[], &[]);
    let ix = p.m.vault_ix(
        6,
        &[],
        vec![
            AccountMeta::new(p.m.protocol, false),
            AccountMeta::new_readonly(p.m.g[0].pubkey(), true),
        ],
    );
    let pg: Vec<Address> = p.m.g.iter().map(|k| k.pubkey()).collect();
    sp.run(
        &mut p.env,
        "veto seal",
        ix,
        &[],
        &[role(1, pg, "any live guardian")],
    );
    let ix = p.m.propose_seal_ix();
    p.env.ok(&[ix], &[&p.m.admin]);
    p.env.advance(3 * DAY);
    // The seal lists every vault: the two of the world and the one created above.
    let mut ix = p.m.execute_seal_ix(&[&p.usdc, &p.sol]);
    let third_lifeboat = pda(
        &[
            b"lifeboat-tokens",
            p.m.protocol.as_ref(),
            third_mint.as_ref(),
        ],
        &p.m.vault_program,
    );
    ix.accounts
        .push(AccountMeta::new_readonly(third_vault, false));
    ix.accounts
        .push(AccountMeta::new_readonly(third_tokens, false));
    ix.accounts
        .push(AccountMeta::new_readonly(third_lifeboat, false));
    sp.run(&mut p.env, "execute seal", ix, &[], &[]);

    // --- registration: by the protocol's caller PDA (through Harbor's CPI),
    // and directly by the protocol program's upgrade authority --------------
    let harbor2 = Address::new_unique();
    p.env.svm.add_program(harbor2, &so("bulkhead_harbor")).unwrap();
    let ix = p.m.register_ix(&p.env, harbor2, 3 * DAY);
    sp.run(&mut p.env, "register (caller PDA)", ix, &[], &[
        any(2, "rent payer: any funded signer"),
        any(5, "programdata: read only when the registrar is the upgrade authority, not the caller PDA"),
    ]);
    let team = Keypair::new();
    p.env.fund(&team);
    let (program, programdata) = p.env.deploy(&honest_v1(), &team, 4096);
    let mut args = Vec::new();
    args.extend_from_slice(p.m.admin.pubkey().as_ref());
    args.push(3);
    for k in &p.m.g {
        args.extend_from_slice(k.pubkey().as_ref());
    }
    args.push(2);
    args.extend_from_slice(&(7 * DAY).to_le_bytes());
    args.extend_from_slice(&(3 * DAY).to_le_bytes());
    args.extend_from_slice(p.m.destination.pubkey().as_ref());
    let protocol2 = pda(&[b"protocol", program.as_ref()], &p.m.vault_program);
    let ix = p.m.vault_ix(0, &args, vec![
        AccountMeta::new(p.env.payer.pubkey(), true),
        AccountMeta::new(protocol2, false),
        AccountMeta::new_readonly(program, false),
        AccountMeta::new_readonly(programdata, false),
        AccountMeta::new_readonly(team.pubkey(), true),
        AccountMeta::new_readonly(SYSTEM, false),
    ]);
    sp.run(&mut p.env, "register (upgrade authority)", ix, &[&team], &[any(0, "rent payer: any funded signer")]);

    let total = s.attempts + sp.attempts;
    println!(
        "{total} substitutions over {} transactions; {} needed a key nobody here holds",
        s.runs + sp.runs,
        s.unsignable + sp.unsignable
    );
    let mut all = s.unexpected;
    all.extend(sp.unexpected);
    assert!(
        all.is_empty(),
        "accepted substitutions ({}):\n{}",
        all.len(),
        all.join("\n")
    );
}

#[test]
fn unlisting_collateral_does_not_free_it_while_its_loan_is_open() {
    // Code review, 7 Oct: turning an asset's allowlisting off was a tightening
    // (applied at once), and the ledger let an owner take back an unlisted
    // mint whatever they owed. With only the admin key: deposit collateral,
    // borrow against it, unlist it, take it back through the backed lane (no
    // limiter), keep the loan; repeat.
    let mut w = World::new();
    let lender = w.user();
    w.deposit("usdc", &lender, 5_000_000 * USDC);
    let borrower = w.user();
    w.deposit("sol", &borrower, 10 * SOL);
    w.seal();
    let usdc_to = w.account("usdc", &borrower.pubkey());
    let prices = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &usdc_to, 1_200 * USDC, &prices);
    assert_eq!(outcome(&w.env.ok(&[ix], &[&borrower])).backed, 1_200 * USDC, "a backed loan against 10 SOL");

    // The admin unlists SOL.
    let (asset, mint, program) = (w.sol.asset, w.sol.mint, w.sol.token_program);
    let mut ix = w.m.propose_change_ix(&w.env, 1, &mint, &asset_bytes(false, 8_500, 10_500, 20_000, 60, 100, SOL_FEED), Some(&asset));
    ix.accounts.push(AccountMeta::new_readonly(mint, false));
    ix.accounts.push(AccountMeta::new_readonly(program, false));
    let applied = w.env.send(&[ix], &[&w.m.admin]).is_ok();

    // The borrower asks for all 10 SOL back while the 1,200 USDC loan is open.
    let sol_to = w.account("sol", &borrower.pubkey());
    let prices = vec![(w.sol.asset, w.sol.price), (w.usdc.asset, w.usdc.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.sol, &borrower.pubkey(), &sol_to, 10 * SOL, &prices);
    let r = w.env.send(&[ix], &[&borrower]);
    let backed = r.as_ref().map(|m| outcome(m).backed).unwrap_or(0);
    assert_eq!(backed, 0, "unlisting applied: {applied}; the collateral of an open loan came back through the backed lane");
    assert!(applied, "delisting is a tightening: it still applies at once");

    // Repaid, the owner owes nothing: all of the delisted SOL comes back
    // through the backed lane (G2), whatever it is worth.
    let left = w.env.balance(&w.sol.vault_tokens);
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &usdc_to, 1_200 * USDC, &w.usdc.token_program);
    let ix = w.m.deposit_ix(&w.env, &w.usdc, &borrower.pubkey(), &usdc_to, 1_200 * USDC);
    w.env.ok(&[ix], &[&borrower]);
    let back = left.min(10 * SOL - r.as_ref().map(|m| { let o = outcome(m); o.instant + o.queued }).unwrap_or(0));
    let ix = w.m.withdraw_ix(&w.env, &w.sol, &borrower.pubkey(), &sol_to, back, &[(w.sol.asset, w.sol.price)]);
    let o = outcome(&w.env.ok(&[ix], &[&borrower]));
    assert_eq!(o.backed, back, "repaid: the owner's own deposit comes back in full");
}

#[test]
fn a_guardian_never_becomes_the_admin() {
    // Code review, 7 Oct (finding 57): parse_guardian_set kept the admin off
    // the guardian list, but an admin rotation could name a guardian.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 1_000_000 * USDC);
    w.seal();
    let g1 = w.m.g[1].pubkey();
    let ix = w.m.propose_change_ix(&w.env, 3, &g1, &[], None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::INVALID_INSTRUCTION);
    let fresh = Keypair::new().pubkey();
    let ix = w.m.propose_change_ix(&w.env, 3, &fresh, &[], None);
    w.env.ok(&[ix], &[&w.m.admin]);
}

#[test]
fn an_admin_rotation_is_refused_at_execution_if_its_key_became_a_guardian() {
    // Finding 57, the execution-time check: both changes were valid when
    // proposed (the new admin was not a guardian yet; the new guardian set did
    // not hold the current admin), but executing the guardian set first makes
    // the new admin a guardian.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 1_000_000 * USDC);
    w.seal();
    let x = Keypair::new();
    w.env.fund(&x);
    let ix = w.m.propose_change_ix(&w.env, 3, &x.pubkey(), &[], None);
    let admin_change = 0;
    w.env.ok(&[ix], &[&w.m.admin]);
    let mut set = vec![3u8];
    for k in [w.m.g[0].pubkey(), w.m.g[1].pubkey(), x.pubkey()] {
        set.extend_from_slice(k.as_ref());
    }
    set.push(2);
    set.extend_from_slice(&(7 * DAY).to_le_bytes());
    let zero = Address::default();
    let ix = w.m.propose_change_ix(&w.env, 2, &zero, &set, None);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    w.env.ok(&[execute_change_ix(&w, 1, &zero)], &[]);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, admin_change, &zero)], &[]), verr::INVALID_INSTRUCTION);
}
