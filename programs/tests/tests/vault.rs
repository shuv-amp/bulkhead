//! The Vault program on the real runtime (LiteSVM, mainnet features, the
//! mainnet token program), driven through Harbor's CPIs like an integrator.
//!
//! Scenarios (docs/08-SCENARIOS.md): S1 compromised admin, S4 bank run,
//! S7 slow loosening, S9 honest borrower, plus the seal, tickets, freezes,
//! the lifeboat, the custody policy and every account check we can reach.
//! Numbers are checked against `bulkhead-core` computed in the test.

mod common;

use bulkhead_core::ema::{ema_update, WindowLow};
use bulkhead_core::ledger::{Ledger, PricedAsset, Pricing};
use bulkhead_core::limiter::{capacity_base, params_from_config, request, Decision, LimiterState};
use common::vault::*;
use common::*;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;

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
/// Finding 90: a freeze stops new loans. A loan is bounded by haircuts and
/// Pyth, not by the limiter, so a forged or manipulated price drained it
/// through a lane no freeze reached. While frozen, only the owner's own
/// balance of the mint is backed: a lender's own deposit still leaves at once
/// (G2), a borrow waits behind the freeze, and after it the same borrow is
/// backed again.
fn a_freeze_stops_new_loans_but_never_own_deposits() {
    let mut w = World::new();
    let lender = w.user();
    let lender_acc = w.deposit("usdc", &lender, 5_000_000 * USDC);
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
    let o = outcome(&m);
    assert_eq!((o.backed, o.instant, o.queued), (0, 0, ask), "the borrow waits");
    assert!(o.eta_s >= frozen_until, "behind the freeze");
    assert_eq!(w.env.balance(&to), 0);

    // The lender's own deposit leaves at once, frozen or not (G2).
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &lender.pubkey(), &lender_acc, 1_000_000 * USDC, &w.usdc_prices(false));
    let m = w.env.ok(&[ix], &[&lender]);
    assert_eq!(outcome(&m).backed, 1_000_000 * USDC);
    assert_eq!(w.env.balance(&lender_acc), 1_000_000 * USDC);

    // After the freeze, the same kind of borrow is backed again.
    w.env.advance(86_400 + 1);
    w.refresh_prices();
    let prices = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &to, 600 * USDC, &prices);
    let m = w.env.ok(&[ix], &[&borrower]);
    assert_eq!(outcome(&m).backed, 600 * USDC);
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
    let mut low = WindowLow::default();
    let mut balance = 10_000_000 * USDC;
    // Deposits touched it at genesis with the pre-deposit balance of 0.
    low = low.touch(0, T0, ref_init);
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
        low = low.touch(balance, w.env.time, ref_init);
        reference = ema_update(reference, ref_at, balance, w.env.time, ref_init);
        ref_at = w.env.time;
        let params = params_from_config(&cfg, capacity_base(reference, balance.min(low.low())));
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
        let ix = w.m.cancel_ix(&w.usdc, t, ticket_id(&w.env, t), &g0, &w.env.payer.pubkey());
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

/// Finding 75: a ticket settled while the vault is short fails with the
/// Vault's own error, not the token program's.
#[test]
fn a_ticket_settled_while_the_vault_is_short_fails_with_insufficient_balance() {
    let mut w = World::new();
    let whale = w.user();
    let whale_acc = w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let payee = w.user();
    let to = w.account("usdc", &payee.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &payee.pubkey(), 300_000 * USDC, &w.usdc_prices(true));
    let (_, ticket) = w.m.next_ticket(&w.env);
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!(o.queued, 300_000 * USDC);
    // The whale's own deposit leaves at once, ticket or not (G2).
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 10_000_000 * USDC, &w.usdc_prices(false));
    w.env.ok(&[ix], &[&whale]);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 0);
    w.env.advance(o.eta_s - w.env.time);
    let settle = w.m.settle_ix(&w.usdc, &ticket, &to, &w.env.payer.pubkey());
    assert_eq!(w.env.fails(&[settle], &[]), verr::INSUFFICIENT_BALANCE);
}

/// Finding 75: if the cluster clock steps back, the reference timestamp stays
/// where it was, or the next update would count the gap twice.
#[test]
fn the_reference_timestamp_never_moves_back() {
    let ref_updated_s = |w: &World| {
        read_vault(&w.env, &w.usdc.vault).ref_updated_s
    };
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    w.env.advance(3_600);
    w.deposit("usdc", &whale, USDC);
    let t = w.env.time;
    assert_eq!(ref_updated_s(&w), t);
    w.env.time -= 600;
    w.env.next_slot();
    w.deposit("usdc", &whale, USDC);
    assert_eq!(ref_updated_s(&w), t, "not moved back to {}", t - 600);
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
    let cancel = w.m.cancel_ix(&w.usdc, &ticket, ticket_id(&w.env, &ticket), &g0, &w.env.payer.pubkey());
    w.env.ok(&[cancel], &[&w.m.g[0]]);
    w.env.ok(&[reset], &[&w.m.admin]);
}

/// Finding 102: G1 counts payouts when they are requested, not when they land.
/// A request is refused only past the 7-day horizon, so one request for
/// `min_k C_k·(W_k+horizon)/W_k`, 40% of a 10M vault, is a single ticket due at
/// exactly +7d and paid in one transfer. One unit more is refused.
#[test]
fn one_request_for_40_percent_is_paid_in_one_transfer_after_seven_days() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    w.env.advance(2 * DAY);
    let user = Keypair::new();
    let to = w.account("usdc", &user.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &user.pubkey(), 4_000_000 * USDC + 1, &w.usdc_prices(false));
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::QUEUE_FULL);
    let (_, ticket) = w.m.next_ticket(&w.env);
    let t_req = w.env.time;
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &user.pubkey(), 4_000_000 * USDC, &w.usdc_prices(false));
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!((o.instant, o.queued), (0, 4_000_000 * USDC));
    assert_eq!(o.eta_s - t_req, 7 * DAY, "queued exactly at the horizon");
    // attest's worst case bounds payouts not yet requested; the ticket is in `queued`.
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!((a.worst_1h, a.worst_24h, a.queued), (400_000 * USDC, 1_000_000 * USDC, 4_000_000 * USDC));
    w.env.advance(7 * DAY - 1);
    let ix = w.m.settle_ix(&w.usdc, &ticket, &to, &w.env.payer.pubkey());
    assert_eq!(w.env.fails(std::slice::from_ref(&ix), &[]), verr::TICKET_NOT_DUE);
    w.env.advance(1);
    w.env.ok(&[ix], &[]);
    assert_eq!(w.env.balance(&to), 4_000_000 * USDC, "40% of the vault in one transfer");
}

/// Finding 102: tickets do not expire, and a queued ticket does not lower the
/// capacity base (the tokens are still in the vault), so due tickets requested
/// days apart add up with no cap but G1 from the first request to the
/// settlement. Nineteen requests a day apart (625,000, then 500,000 a day,
/// then 875,000, due a day later) are settled together 19 days after the
/// first: the whole 10M vault, in one transaction that fits a legacy packet.
#[test]
fn tickets_requested_over_eighteen_days_land_in_one_transaction() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    w.env.advance(2 * DAY);
    let user = Keypair::new();
    let to = w.account("usdc", &user.pubkey());
    let payer = w.env.payer.pubkey();
    let mut settles = Vec::new();
    let mut total = 0;
    for day in 0..19 {
        let (ask, delay) = match day {
            0 => (625_000 * USDC, 6 * 3_600),
            18 => (875_000 * USDC, DAY),
            _ => (500_000 * USDC, 6 * 3_600),
        };
        let (_, ticket) = w.m.next_ticket(&w.env);
        let t_req = w.env.time;
        let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &user.pubkey(), ask, &w.usdc_prices(false));
        let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
        assert_eq!((o.instant, o.queued, o.eta_s - t_req), (0, ask, delay), "day {day}");
        settles.push(w.m.settle_ix(&w.usdc, &ticket, &to, &payer));
        total += ask;
        w.env.advance(if day == 18 { DAY - 1 } else { DAY });
    }
    // Not a second earlier: the last ticket is due exactly 19 days after the first request.
    assert_eq!(w.env.fails(&settles[18..], &[]), verr::TICKET_NOT_DUE);
    w.env.advance(1);
    let size = legacy_tx_size(&solana_message::Message::new(&settles, Some(&payer)));
    assert!(size <= PACKET, "{size} B");
    w.env.ok(&settles, &[]);
    assert_eq!(total, 10_000_000 * USDC);
    assert_eq!(w.env.balance(&to), total, "the whole vault in one transaction");
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 0);
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

/// Harbor's withdraw needs the user's signature, not just the user's token
/// account as recipient. Without it anyone could release a user's balance
/// on their own timing: the Vault backs the user's own balance, signed or
/// not.
#[test]
fn harbor_withdraw_needs_the_users_signature() {
    let mut w = World::new();
    let u = w.user();
    let acc = w.deposit("usdc", &u, 1_000 * USDC);
    w.seal();
    let mut ix = w.m.withdraw_ix(&w.env, &w.usdc, &u.pubkey(), &acc, 1_000 * USDC, &w.usdc_prices(false));
    ix.accounts.iter_mut().filter(|a| a.pubkey == u.pubkey()).for_each(|a| a.is_signer = false);
    let vault_called = format!("Program {} invoke", w.m.vault_program);
    match w.env.send(&[ix], &[]) {
        Ok(m) => panic!("expected MissingRequiredSignature, succeeded\n{}", m.logs.join("\n")),
        Err(e) => {
            let logs = e.meta.logs.join("\n");
            assert_eq!(
                e.err,
                TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature),
                "{logs}"
            );
            // Harbor refused it: the Vault was never called.
            assert!(!logs.contains(&vault_called), "{logs}");
        }
    }
    assert_eq!(w.env.balance(&acc), 0);
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &u.pubkey(), &acc, 1_000 * USDC, &w.usdc_prices(false));
    let m = w.env.ok(&[ix], &[&u]);
    assert!(m.logs.join("\n").contains(&vault_called), "signed, Harbor calls the Vault");
    assert_eq!(w.env.balance(&acc), 1_000 * USDC, "signed, it pays");
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
    assert_eq!(read_protocol(&w.env, &w.m.protocol).loosen_delay_s, 30 * DAY, "raised at once, to the cap");
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

/// Issue #67: abdicating assets before the seal binds `upsert_asset` too.
/// It applied a looser config at once, which the seal then made permanent.
#[test]
fn an_abdicated_asset_kind_cannot_be_upserted_before_the_seal() {
    let mut w = World::new();
    // Before the abdication the genesis path works (World::new listed both).
    let ix = w.m.upsert_asset_ix(&w.env, &w.usdc, &usdc_cfg());
    w.env.ok(&[ix], &[&w.m.admin]);
    let (g0, g1) = (w.m.g[0].pubkey(), w.m.g[1].pubkey());
    let ix = w.m.vault_ix(17, &[1], vec![
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        AccountMeta::new_readonly(g0, true),
        AccountMeta::new_readonly(g1, true),
    ]);
    w.env.ok(&[ix], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]);
    let ix = w.m.upsert_asset_ix(&w.env, &w.usdc, &usdc_cfg());
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::ABDICATED);
    let ix = w.m.upsert_asset_ix(&w.env, &w.sol, &sol_cfg());
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::ABDICATED);
}

/// Finding 92: once limits are abdicated, a new vault before the seal starts
/// with its unbacked lane closed, as after the seal: an open lane is a
/// loosening of the abdicated kind that the seal would make permanent.
#[test]
fn abdicated_limits_keep_a_new_vaults_lane_closed_before_the_seal() {
    let mut w = World::new();
    let (g0, g1) = (w.m.g[0].pubkey(), w.m.g[1].pubkey());
    let ix = w.m.vault_ix(17, &[0], vec![
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        AccountMeta::new_readonly(g0, true),
        AccountMeta::new_readonly(g1, true),
    ]);
    w.env.ok(&[ix], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]);
    let ix = create_vault_ix(&mut w, &Limits::default_limits());
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::ABDICATED);
    let mut closed = Limits::default_limits();
    closed.short_bps = 0;
    let ix = create_vault_ix(&mut w, &closed);
    w.env.ok(&[ix], &[&w.m.admin]);
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
    // Tightening still applies at once: making things safer never waits. But
    // it is final now, so the admin alone may not (a stolen key would close
    // the vault for good); a live guardian quorum co-signs (finding 88).
    let mut tighter = Limits::default_limits();
    tighter.short_bps = 100;
    let ix = w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::NO_QUORUM);
    let mut ix = w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    ix.accounts.push(AccountMeta::new_readonly(g0, true));
    ix.accounts.push(AccountMeta::new_readonly(g1, true));
    w.env.ok(&[ix], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]);
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
    w.env.advance(3 * DAY + 1); // the lifeboat opens a loosen delay after the seal (finding 88)
    w.refresh_prices();
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
                AccountMeta::new_readonly(dest_owner, true),
            ],
        )
    };
    let early = exit(dest);
    assert_eq!(w.env.fails(&[early], &[&w.m.destination]), verr::CHANGE_NOT_EXECUTABLE);
    w.env.advance(3 * DAY);
    let wrong = exit(thief);
    assert!(w.env.send(&[wrong], &[&w.m.destination]).is_err(), "only the committed destination");
    // The destination signs (finding 85): nobody else can make the exit land.
    let mut unsigned = exit(dest);
    unsigned.accounts[6].is_signer = false;
    assert_eq!(w.env.fails(&[unsigned], &[]), verr::MISSING_SIGNATURE);
    let right = exit(dest);
    w.env.ok(&[right], &[&w.m.destination]);
    assert_eq!(w.env.balance(&dest), 4_000_000 * USDC);
}

#[test]
fn a_release_cannot_pay_the_lifeboat() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    w.env.advance(3 * DAY + 1); // the lifeboat opens a loosen delay after the seal (finding 88)
    w.refresh_prices();
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let mv = w.m.vault_ix(24, &USDC.to_le_bytes(), vec![
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
    assert_eq!(w.env.balance(&lifeboat), USDC);
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
    // The vault token account is one of them: a payout to it would debit the
    // ledger while the tokens stay. Its address check (custody.rs) refuses it
    // first, and the owner check behind it would too, so this case cannot tell
    // the two apart; the stray account above is what pins the owner check.
    let own = w.usdc.vault_tokens;
    let pay = w.m.admin_payout_ix(&w.env, &w.usdc, &own, &vault, 1_000 * USDC, &w.usdc_prices(true));
    assert_eq!(w.env.fails(&[pay], &[&w.m.admin]), verr::DUPLICATE_ACCOUNT, "the vault's own account");
}

#[test]
fn a_quote_cannot_promise_more_than_the_vault_holds() {
    let mut w = World::new();
    let whale = w.user();
    let to = w.deposit("usdc", &whale, 1_000_000 * USDC);
    w.seal();
    w.env.advance(3 * DAY + 1); // the lifeboat opens a loosen delay after the seal (finding 88)
    w.refresh_prices();
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
    // The lifeboat is shut before the seal (finding 86): the 900 cannot be
    // moved where a fee would shrink them to 810 behind the seal's back.
    assert_eq!(w.env.fails(&[mv], &[&w.m.admin]), verr::NOT_SEALED);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 900 * USDC);
    // The deposit's backing is what arrived (900), so the seal holds.
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    w.refresh_prices();
    let seal = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    w.env.ok(&[seal], &[]);
}

/// Finding 97: Token-2022 withholds a transfer fee even between two accounts
/// the vault PDA owns, so a stolen admin key pairing `lifeboat_move` and
/// `lifeboat_return` many times in one transaction burned depositors' value
/// (30 round trips at 10% withheld almost all of it). The lifeboat now
/// refuses a mint that charges a fee, or whose fee can be raised.
#[test]
fn the_lifeboat_refuses_a_mint_that_charges_or_can_charge_a_transfer_fee() {
    let mut w = World::with_transfer_fee_mint();
    let depositor = w.user();
    w.deposit("usdc", &depositor, 1_000 * USDC);
    w.seal();
    w.env.advance(3 * DAY + 1);
    w.refresh_prices();
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let mv = |w: &World, amount: u64| {
        w.m.vault_ix(24, &amount.to_le_bytes(), vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(w.usdc.vault_tokens, false),
            AccountMeta::new(lifeboat, false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
            AccountMeta::new(w.env.payer.pubkey(), true),
            AccountMeta::new_readonly(SYSTEM, false),
        ])
    };
    let before = w.env.balance(&w.usdc.vault_tokens);
    assert_eq!(w.env.fails(&[mv(&w, before)], &[&w.m.admin]), verr::FEE_BEARING_MINT);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), before);

    // The same mint with both fees at zero and no fee authority can't burn
    // anything, so it may use the lifeboat.
    let mut mint = w.env.svm.get_account(&w.usdc.mint).unwrap();
    for at in [242usize, 260] {
        mint.data[at + 16..at + 18].copy_from_slice(&0u16.to_le_bytes());
    }
    w.env.svm.set_account(w.usdc.mint, mint.clone()).unwrap();
    w.env.ok(&[mv(&w, 10 * USDC)], &[&w.m.admin]);
    assert_eq!(w.env.balance(&lifeboat), 10 * USDC);

    // A fee authority could raise the fee at any time: refused again.
    mint.data[170..202].copy_from_slice(Keypair::new().pubkey().as_ref()); // TransferFeeConfig: fee config authority
    w.env.svm.set_account(w.usdc.mint, mint).unwrap();
    w.env.advance(1);
    assert_eq!(w.env.fails(&[mv(&w, 10 * USDC)], &[&w.m.admin]), verr::FEE_BEARING_MINT);
}

#[test]
fn a_guardian_quorum_can_return_funds_from_the_lifeboat() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    w.env.advance(3 * DAY + 1); // the lifeboat opens a loosen delay after the seal (finding 88)
    w.refresh_prices();
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
        let ix = w.m.cancel_ix(&w.usdc, &t, ticket_id(&w.env, &t), &g0, &w.env.payer.pubkey());
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

    let puppets = [Keypair::new(), Keypair::new(), Keypair::new()];
    let mut guardians = vec![3u8];
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
    assert_eq!(w.env.fails(std::slice::from_ref(&seal), &[]), verr::SEAL_NOT_EXECUTABLE);
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
fn after_the_seal_the_admin_cannot_import_backing() {
    // Imported backing is an owner's own money, released without the limiter
    // (G2). After the seal nothing checks it against a balance, so an admin
    // key that could import would credit itself and take it unthrottled.
    let mut w = World::new();
    let owner = Keypair::new().pubkey();
    let ix = import_ix(&w, &owner, 1);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &w.usdc.vault_tokens, 1, &w.usdc.token_program);
    w.seal();
    let ix = import_ix(&w, &Keypair::new().pubkey(), 1_000_000 * USDC);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::GENESIS_ONLY, "a new backing");
    let ix = import_ix(&w, &owner, 1_000_000 * USDC);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::GENESIS_ONLY, "an existing backing");
}

#[test]
fn after_the_seal_the_admin_cannot_upsert_an_asset() {
    // After the seal an asset changes only through `propose_change`, so a
    // looser haircut waits 72h and guardians can veto it (G4). Before the
    // seal the same upsert goes through.
    let mut w = World::new();
    let no_haircut = asset_bytes(true, 10_000, 10_500, 20_000, 60, 100, SOL_FEED);
    let ix = w.m.upsert_asset_ix(&w.env, &w.sol, &no_haircut);
    w.env.ok(&[ix], &[&w.m.admin]);
    let ix = w.m.upsert_asset_ix(&w.env, &w.sol, &sol_cfg());
    w.env.ok(&[ix], &[&w.m.admin]);
    w.seal();
    let ix = w.m.upsert_asset_ix(&w.env, &w.sol, &no_haircut);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::GENESIS_ONLY, "a loosening");
    let tighter = asset_bytes(true, 8_000, 10_500, 20_000, 60, 100, SOL_FEED);
    let ix = w.m.upsert_asset_ix(&w.env, &w.sol, &tighter);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::GENESIS_ONLY, "a tightening");
    // A vault made after the seal (lane closed) has no asset yet: listing it
    // is a change too.
    let mut closed = Limits::default_limits();
    closed.long_bps = 0;
    let late = w.m.create_vault(&mut w.env, 6, closed, [3; 32], None);
    let ix = w.m.upsert_asset_ix(&w.env, &late, &asset_bytes(true, 10_000, 10_000, 20_000, 60, 100, [3; 32]));
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::GENESIS_ONLY, "a new listing");
}

#[test]
fn the_seal_checks_each_vault_once() {
    // The seal checks every vault's claims against its balance. Naming one
    // vault twice in place of another would skip the other's check, wherever
    // the two names are: the first named, next to each other, or neither.
    let mut w = World::new();
    let third = w.m.create_vault(&mut w.env, 6, Limits::default_limits(), [3; 32], None);
    let fourth = w.m.create_vault(&mut w.env, 6, Limits::default_limits(), [4; 32], None);
    let ix = import_ix(&w, &Keypair::new().pubkey(), 1_000 * USDC);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    let ix = w.m.execute_seal_ix(&[&w.sol, &third, &fourth, &w.sol]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::DUPLICATE_ACCOUNT, "the first named");
    let ix = w.m.execute_seal_ix(&[&w.sol, &third, &third, &fourth]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::DUPLICATE_ACCOUNT, "adjacent");
    let ix = w.m.execute_seal_ix(&[&w.sol, &third, &fourth, &third]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::DUPLICATE_ACCOUNT, "neither");
    let ix = w.m.execute_seal_ix(&[&w.usdc, &w.sol, &third, &fourth]);
    assert_eq!(w.env.fails(std::slice::from_ref(&ix), &[]), verr::IMPORT_EXCEEDS_BALANCE, "the skipped vault");
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &w.usdc.vault_tokens, 1_000 * USDC, &w.usdc.token_program);
    w.env.ok(&[ix], &[]);
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
    let by_admin = w.m.cancel_ix(&w.usdc, &ticket, ticket_id(&w.env, &ticket), &admin, &w.env.payer.pubkey());
    assert_eq!(w.env.fails(&[by_admin], &[&w.m.admin]), verr::NOT_GUARDIAN);
    let g0 = w.m.g[0].pubkey();
    let by_guardian = w.m.cancel_ix(&w.usdc, &ticket, ticket_id(&w.env, &ticket), &g0, &w.env.payer.pubkey());
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
    assert_eq!(read_protocol(&w.env, &protocol).admin, new_admin.to_bytes(), "the admin changed");
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
    Address::from(read_protocol(&w.env, &w.m.protocol).admin)
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
    // It may replace itself; once one exists the admin may not alone (only
    // with a live quorum, `replace_recovery`).
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
    // The owner's signature after the price pair: read only for a loan, so an
    // own-deposit withdrawal takes any key there (finding 74).
    ok.push(any(H + 12, "owner's signature: consulted only for a loan"));
    s.run(&mut w.env, "withdraw (backed)", ix, &[&whale], &ok);
    // The same withdrawal with the user's signature only at the free slot:
    // signing is per key, so Harbor still sees account 2 signed, and the
    // sweep must pick the key from there.
    w.env.mint_to(
        &w.usdc.mint,
        &w.usdc.mint_authority,
        &whale_acc,
        1_000 * USDC,
        &w.usdc.token_program,
    );
    let ix =
        w.m.deposit_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 1_000 * USDC);
    w.env.ok(&[ix], &[&whale]);
    let mut ix = w.m.withdraw_ix(
        &w.env,
        &w.usdc,
        &whale.pubkey(),
        &whale_acc,
        1_000 * USDC,
        &w.usdc_prices(true),
    );
    ix.accounts[2].is_signer = false;
    assert!(ix.accounts[H + 12].pubkey == whale.pubkey() && ix.accounts[H + 12].is_signer);
    s.run(&mut w.env, "withdraw (signed at the free slot only)", ix, &[&whale], &ok);
    // Harbor is right, so no swap succeeds here: check the try was made.
    assert!(
        s.unsigned.contains(&("withdraw (signed at the free slot only)".into(), whale.pubkey())),
        "the sweep must try a key that signs only at a free slot unsigned"
    );

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
    let mut extend = 3_600i64.to_le_bytes().to_vec();
    extend.extend_from_slice(&ticket_id(&w.env, &t1).to_le_bytes());
    let ix = w.m.vault_ix(
        11,
        &extend,
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

    // --- views: attest, quote ------------------------------------------------
    let ix = w.m.vault_ix(
        22,
        &[],
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new_readonly(w.usdc.vault, false),
            AccountMeta::new_readonly(w.usdc.vault_tokens, false),
        ],
    );
    s.run(&mut w.env, "attest", ix, &[], &[]);
    let mut quote = vec![AccountMeta::new_readonly(w.m.caller, false)];
    quote.extend(w.m.release_accounts(&w.env, &w.usdc, &whale_acc, &whale.pubkey(), &w.usdc_prices(true)));
    let ix = w.m.vault_ix(23, &(1_000 * USDC).to_le_bytes(), quote);
    // A quote is the release's slots after the caller, minus Harbor's.
    s.run(
        &mut w.env,
        "quote release",
        ix,
        &[],
        &[
            any(0, "caller: a quote is anyone's, so it does not check the caller"),
            any(8, "payer: a quote returns before it would create a ticket"),
            any(9, "ticket PDA: a quote returns before it would create a ticket"),
            any(10, "system program: a quote returns before it would create a ticket"),
            any(12, "price account: an owner taking back a deposit needs no price (G2)"),
        ],
    );

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
    let ix = w.m.cancel_ix(&w.usdc, &t1, ticket_id(&w.env, &t1), &g0, &w.env.payer.pubkey());
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
    let ix = w.m.unfreeze_ix(Some(&w.usdc), &[g1, g2]);
    s.run(
        &mut w.env,
        "unfreeze (vault)",
        ix,
        &[],
        &[
            role(1, protocol_vaults.clone(), "any vault of this protocol"),
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
            AccountMeta::new_readonly(dest_owner, true),
        ],
    );
    let destination = w.m.destination.insecure_clone();
    s.run(&mut w.env, "execute lifeboat exit", ix, &[&destination], &[]);

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

/// Finding 65: capital deposited and taken back (backed) in the same
/// transaction cannot lift the base back to a reference still lagging above
/// what is left. Before the fix the payout below was instant (the deposit
/// raised the live balance to the 10M reference: a 200,000 burst).
#[test]
fn a_flash_deposit_cannot_restore_the_burst_after_a_large_exit() {
    let mut w = World::new();
    let small = w.user();
    let whale = w.user();
    w.deposit("usdc", &small, 1_000_000 * USDC);
    let whale_acc = w.deposit("usdc", &whale, 9_000_000 * USDC);
    w.seal();
    w.env.advance(2 * DAY);
    let ix = w.m.withdraw_ix(
        &w.env,
        &w.usdc,
        &whale.pubkey(),
        &whale_acc,
        9_000_000 * USDC,
        &w.usdc_prices(false),
    );
    w.env.ok(&[ix], &[&whale]);
    w.env.advance(60);
    // One transaction: put the 9M back, pay 25,000 unbacked, take the 9M back.
    let attacker = Keypair::new();
    let loot = w.account("usdc", &attacker.pubkey());
    let back_in = w.m.deposit_ix(
        &w.env,
        &w.usdc,
        &whale.pubkey(),
        &whale_acc,
        9_000_000 * USDC,
    );
    let payout = w.m.admin_payout_ix(
        &w.env,
        &w.usdc,
        &loot,
        &attacker.pubkey(),
        25_000 * USDC,
        &w.usdc_prices(true),
    );
    let back_out = w.m.withdraw_ix(
        &w.env,
        &w.usdc,
        &whale.pubkey(),
        &whale_acc,
        9_000_000 * USDC,
        &w.usdc_prices(false),
    );
    w.env
        .ok(&[back_in, payout, back_out], &[&whale, &w.m.admin]);
    assert_eq!(
        w.env.balance(&loot),
        0,
        "above the 20,000 burst of the 1M left: queued, not paid"
    );
    assert_eq!(
        w.env.balance(&whale_acc),
        9_000_000 * USDC,
        "the whale's own money is still backed and instant"
    );
    assert_eq!(
        w.m.attest(&mut w.env, &w.usdc).available_now,
        0,
        "the 25,000 reservation used the 20,000 burst"
    );
}

/// Finding 63: a loosening of one mint's asset record must name that record;
/// another record's version would let it survive a later tightening.
#[test]
fn an_asset_loosening_must_name_its_own_asset_record() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let (mint, program) = (w.usdc.mint, w.usdc.token_program);
    let mut ix = w.m.propose_change_ix(
        &w.env,
        1,
        &mint,
        &asset_bytes(true, 9_990, 10_100, 20_000, 60, 100, USDC_FEED),
        Some(&w.sol.asset),
    );
    ix.accounts.push(AccountMeta::new_readonly(mint, false));
    ix.accounts.push(AccountMeta::new_readonly(program, false));
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::WRONG_ADDRESS);
}

/// Finding 67: a closed ticket's address is reused by its payer's next ticket,
/// so a cancel names the ticket the guardian decided on.
#[test]
fn a_cancel_or_extension_names_its_ticket() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let payee = w.user();
    let to = w.account("usdc", &payee.pubkey());
    let ix = w.m.admin_payout_ix(
        &w.env,
        &w.usdc,
        &to,
        &payee.pubkey(),
        2_000_000 * USDC,
        &w.usdc_prices(true),
    );
    let (_, ticket) = w.m.next_ticket(&w.env);
    w.env.ok(&[ix], &[&w.m.admin]);
    let id = ticket_id(&w.env, &ticket);
    let g0 = w.m.g[0].pubkey();
    let wrong =
        w.m.cancel_ix(&w.usdc, &ticket, id + 1, &g0, &w.env.payer.pubkey());
    assert_eq!(w.env.fails(&[wrong], &[&w.m.g[0]]), verr::WRONG_TICKET);
    let mut args = 3_600i64.to_le_bytes().to_vec();
    args.extend_from_slice(&(id + 1).to_le_bytes());
    let extend = w.m.vault_ix(
        11,
        &args,
        vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(ticket, false),
            AccountMeta::new_readonly(g0, true),
        ],
    );
    assert_eq!(w.env.fails(&[extend], &[&w.m.g[0]]), verr::WRONG_TICKET);
    let right =
        w.m.cancel_ix(&w.usdc, &ticket, id, &g0, &w.env.payer.pubkey());
    w.env.ok(&[right], &[&w.m.g[0]]);
}

/// Finding 64: every Vault event ends with the protocol it concerns, so a
/// reader can tell one protocol's events from another's in one transaction.
#[test]
fn every_vault_event_names_its_protocol() {
    let mut w = World::new();
    w.seal();
    let g0 = w.m.g[0].pubkey();
    let freeze = w.m.freeze_ix(&g0, None, 3_600);
    let m = w.env.ok(&[freeze], &[&w.m.g[0]]);
    let data: Vec<&String> = m
        .logs
        .iter()
        .filter(|l| l.starts_with("Program data: "))
        .collect();
    assert!(!data.is_empty());
    fn b64(s: &str) -> Vec<u8> {
        let val = |c: u8| match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            _ => 63,
        };
        let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
        for c in s.bytes().filter(|c| *c != b'=') {
            acc = acc << 6 | val(c) as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }
    for line in data {
        let fields: Vec<Vec<u8>> = line["Program data: ".len()..].split(' ').map(b64).collect();
        assert_eq!(
            fields.last().unwrap().as_slice(),
            w.m.protocol.as_ref(),
            "{line}"
        );
    }
}

/// Finding 68: an InterestBearing (or ScaledUiAmount) mint's UI amount is its
/// raw amount times a factor the issuer moves at will. Pyth prices UI units,
/// the ledger raw units, so such a mint is never priced. Custody is fine.
#[test]
fn a_mint_whose_ui_amount_rescales_is_held_but_never_priced() {
    let mut env = Env::new();
    let m = Market::new(&mut env);
    let mint = Keypair::new();
    let authority = Keypair::new();
    let size = 165 + 1 + 4 + 52; // InterestBearingConfig (type 10)
    let lamports = env.svm.minimum_balance_for_rent_exemption(size);
    let t22 = token_2022();
    let create = solana_system_interface::instruction::create_account(
        &env.payer.pubkey(),
        &mint.pubkey(),
        lamports,
        size as u64,
        &t22,
    );
    let mut d = vec![33u8, 0]; // InterestBearingMintExtension::Initialize
    d.extend_from_slice(authority.pubkey().as_ref());
    d.extend_from_slice(&500i16.to_le_bytes());
    let init_interest = solana_instruction::Instruction {
        program_id: t22,
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data: d,
    };
    let mut d = vec![20u8, 6]; // InitializeMint2
    d.extend_from_slice(authority.pubkey().as_ref());
    d.push(0);
    let init_mint = solana_instruction::Instruction {
        program_id: t22,
        accounts: vec![AccountMeta::new(mint.pubkey(), false)],
        data: d,
    };
    env.ok(&[create, init_interest, init_mint], &[&mint]);
    let vault = pda(
        &[b"vault", m.protocol.as_ref(), mint.pubkey().as_ref()],
        &m.vault_program,
    );
    let vault_tokens = pda(
        &[b"vault-tokens", m.protocol.as_ref(), mint.pubkey().as_ref()],
        &m.vault_program,
    );
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
    let asset = pda(
        &[b"asset", m.protocol.as_ref(), mint.pubkey().as_ref()],
        &m.vault_program,
    );
    let upsert = |env: &Env, listed: bool| {
        let mut ix = m.propose_change_ix(
            env,
            1,
            &mint.pubkey(),
            &asset_bytes(listed, 8_500, 10_500, 20_000, 60, 100, USDC_FEED),
            Some(&asset),
        );
        ix.accounts
            .push(AccountMeta::new_readonly(mint.pubkey(), false));
        ix.accounts.push(AccountMeta::new_readonly(t22, false));
        ix
    };
    let ix = upsert(&env, true);
    assert_eq!(env.fails(&[ix], &[&m.admin]), verr::EXTENSION_NOT_ALLOWED);
    let ix = upsert(&env, false);
    env.ok(&[ix], &[&m.admin]);
}

#[test]
fn replace_recovery_respects_the_seal_review_abdication_and_never_picks_a_guardian() {
    // replace_recovery is a loosening at once, so it obeys what every other
    // loosening obeys: nothing changes while the seal is under review (T19),
    // and an abdicated SetRecovery is fixed for good. And no key holds two
    // roles: a guardian that is also the recovery key would never veto its
    // own new admin.
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    let (g0, g1, g2) = (w.m.g[0].pubkey(), w.m.g[1].pubkey(), w.m.g[2].pubkey());
    let admin = w.m.admin.pubkey();
    let zero = Address::default();
    let quorum: [&Keypair; 3] = [&w.m.admin, &w.m.g[0], &w.m.g[1]];
    let set = |keys: &[Address]| {
        let mut d = vec![keys.len() as u8];
        keys.iter().for_each(|k| d.extend_from_slice(k.as_ref()));
        d.push(2);
        d.extend_from_slice(&(7 * DAY).to_le_bytes());
        d
    };

    // Under seal review: refused; once a guardian vetoes the seal: allowed.
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    let ix = w.m.replace_recovery_ix(&admin, &Keypair::new().pubkey(), &[g0, g1]);
    assert_eq!(w.env.fails(&[ix], &quorum), verr::SEAL_UNDER_REVIEW);
    let veto = w.m.vault_ix(6, &[], vec![AccountMeta::new(w.m.protocol, false), AccountMeta::new_readonly(g0, true)]);
    w.env.ok(&[veto], &[&w.m.g[0]]);
    let ix = w.m.replace_recovery_ix(&admin, &Keypair::new().pubkey(), &[g0, g1]);
    w.env.ok(&[ix], &quorum);
    // ... and back to none, so the admin may propose one again below.
    w.env.next_slot();
    let ix = w.m.replace_recovery_ix(&admin, &zero, &[g0, g1]);
    w.env.ok(&[ix], &quorum);
    w.seal();
    let quorum: [&Keypair; 3] = [&w.m.admin, &w.m.g[0], &w.m.g[1]];

    // A guardian, through replace_recovery or SetRecovery.
    let ix = w.m.replace_recovery_ix(&admin, &g2, &[g0, g1]);
    assert_eq!(w.env.fails(&[ix], &quorum), verr::INVALID_INSTRUCTION);
    let ix = w.m.propose_change_ix(&w.env, 6, &g2, &[], None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::INVALID_INSTRUCTION);

    // A SetRecovery (change 0) whose key becomes a guardian (change 1) while
    // it waits is refused when executed.
    let protocol = w.m.protocol;
    let k = Keypair::new().pubkey();
    let ix = w.m.propose_change_ix(&w.env, 6, &k, &[], None);
    w.env.ok(&[ix], &[&w.m.admin]);
    let ix = w.m.propose_change_ix(&w.env, 2, &zero, &set(&[g0, g1, k]), None);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    w.env.ok(&[execute_change_ix(&w, 1, &protocol)], &[]);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 0, &protocol)], &[]), verr::INVALID_INSTRUCTION);

    // A guardian set (change 2) whose new key becomes the recovery key while
    // it waits is refused when executed, and can't be proposed again.
    let r = Keypair::new().pubkey();
    let ix = w.m.propose_change_ix(&w.env, 2, &zero, &set(&[g0, g1, r]), None);
    w.env.ok(&[ix], &[&w.m.admin]);
    let ix = w.m.replace_recovery_ix(&admin, &r, &[g0, g1]);
    w.env.ok(&[ix], &quorum);
    w.env.advance(3 * DAY);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, 2, &protocol)], &[]), verr::INVALID_GUARDIANS);
    let ix = w.m.propose_change_ix(&w.env, 2, &zero, &set(&[g0, g1, r]), None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::INVALID_GUARDIANS);

    // Abdicated: fixed for good, even for the admin with a quorum; only
    // removing it stays possible (finding 72: it only takes power away).
    let ab = w.m.vault_ix(17, &[6], vec![
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new_readonly(admin, true),
        AccountMeta::new_readonly(g0, true),
        AccountMeta::new_readonly(g1, true),
    ]);
    w.env.ok(&[ab], &quorum);
    let ix = w.m.replace_recovery_ix(&admin, &Keypair::new().pubkey(), &[g0, g1]);
    assert_eq!(w.env.fails(&[ix], &quorum), verr::ABDICATED);
    w.env.next_slot();
    let ix = w.m.replace_recovery_ix(&admin, &zero, &[g0, g1]);
    w.env.ok(&[ix], &quorum);

    // Registration naming a guardian as the recovery key; a fresh key is fine.
    let harbor = Address::new_unique();
    w.env.svm.add_program(harbor, &so("bulkhead_harbor")).unwrap();
    let mut ix = w.m.register_ix(&w.env, harbor, 3 * DAY);
    ix.data.extend_from_slice(g1.as_ref());
    assert_eq!(w.env.fails(&[ix], &[]), verr::INVALID_GUARDIANS);
    let mut ix = w.m.register_ix(&w.env, harbor, 3 * DAY);
    ix.data.extend_from_slice(Keypair::new().pubkey().as_ref());
    w.env.ok(&[ix], &[]);
}

/// A recovery key cut short at registration is an error, not "no recovery key".
#[test]
fn registration_refuses_a_cut_off_recovery_key() {
    let mut w = World::new();
    let harbor = Address::new_unique();
    w.env.svm.add_program(harbor, &so("bulkhead_harbor")).unwrap();
    let mut ix = w.m.register_ix(&w.env, harbor, 3 * DAY);
    ix.data.extend_from_slice(&Keypair::new().pubkey().as_ref()[..31]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::INVALID_INSTRUCTION);
    let ix = w.m.register_ix(&w.env, harbor, 3 * DAY);
    w.env.ok(&[ix], &[]);
}

/// Finding 65, the other side: a withdrawal taken straight back (or capital
/// parked for under a window) lowers the base only until the low-water window
/// has passed, not for a day as when the reference itself dropped. Capital
/// parked for under a window still does not count.
#[test]
fn a_round_trip_lowers_the_burst_for_at_most_two_windows() {
    use bulkhead_core::consts::LOW_WINDOW_S;
    let mut w = World::new();
    let small = w.user();
    let whale = w.user();
    w.deposit("usdc", &small, 1_000_000 * USDC);
    let whale_acc = w.deposit("usdc", &whale, 9_000_000 * USDC);
    w.seal();
    w.env.advance(2 * DAY);
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 200_000 * USDC);
    // One transaction: out and straight back in.
    let out = w.m.withdraw_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 9_000_000 * USDC, &w.usdc_prices(false));
    let back = w.m.deposit_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 9_000_000 * USDC);
    w.env.ok(&[out, back], &[&whale]);
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!((a.balance, a.available_now), (10_000_000 * USDC, 20_000 * USDC), "the 1M low counts within the window");
    // Capital parked for under a window: still the 1M low.
    w.env.advance(LOW_WINDOW_S / 2);
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 20_000 * USDC);
    // After two windows the low has rolled off; the 24h reference never moved.
    w.env.advance(2 * LOW_WINDOW_S);
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 200_000 * USDC, "back in full, not a day later");
}

fn r2_lifeboat(w: &World) -> Address {
    pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program)
}

fn r2_move_in(w: &World, amount: u64) -> Instruction {
    w.m.vault_ix(24, &amount.to_le_bytes(), vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(w.usdc.vault_tokens, false),
        AccountMeta::new(r2_lifeboat(w), false),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        AccountMeta::new(w.env.payer.pubkey(), true),
        AccountMeta::new_readonly(SYSTEM, false),
    ])
}

fn r2_propose_exit(w: &World, amount: u64) -> Instruction {
    w.m.vault_ix(26, &amount.to_le_bytes(), vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
    ])
}

/// Finding 72: a freeze stops the admin parking the vault in the lifeboat, so
/// a stolen admin key cannot re-park it after every quorum return while own-
/// deposit exits wait for recovery.
#[test]
fn the_admin_cannot_park_the_vault_while_it_is_frozen() {
    let mut w = World::new();
    let alice = w.user();
    let acc = w.deposit("usdc", &alice, 1_000_000 * USDC);
    w.seal();
    w.env.advance(3 * DAY + 1); // the lifeboat opens a loosen delay after the seal (finding 88)
    w.refresh_prices();
    let g0 = w.m.g[0].pubkey();
    let freeze = w.m.freeze_ix(&g0, None, 86_400);
    w.env.ok(&[freeze], &[&w.m.g[0]]);
    let all = w.env.balance(&w.usdc.vault_tokens);
    assert_eq!(w.env.fails(&[r2_move_in(&w, all)], &[&w.m.admin]), verr::FROZEN);
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &alice.pubkey(), &acc, 1_000_000 * USDC, &w.usdc_prices(false));
    w.env.ok(&[ix], &[&alice]);
    assert_eq!(w.env.balance(&acc), 1_000_000 * USDC, "own deposit out during the freeze");
}

/// Finding 72: the admin is never the lifeboat destination, from either side.
#[test]
fn the_admin_never_becomes_the_lifeboat_destination() {
    let mut w = World::new();
    w.seal();
    let dest = w.m.destination.pubkey();
    let ix = w.m.propose_change_ix(&w.env, 3, &dest, &[], None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::INVALID_INSTRUCTION);
}

/// Finding 86: the lifeboat is shut before the seal. Then every change is
/// instant and depositors cannot withdraw at all, so a stolen admin key could
/// swap in its own guardians, park the deposits, and take them out through an
/// exit about 6 days later. Neither a move nor an exit is possible until the
/// seal; after it, a depositor's own deposit leaves instantly, and an exit
/// still waits 72h. (Finding 72's case, the seal counting tokens a pending
/// exit takes, can no longer arise; the seal still subtracts a live exit.)
#[test]
fn the_lifeboat_stays_shut_until_the_seal() {
    let mut w = World::new();
    let alice = w.user();
    let alice_acc = w.deposit("usdc", &alice, 1_000_000 * USDC);
    w.env.advance(3 * DAY + 1); // the registration destination is now 72h old
    assert_eq!(w.env.fails(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]), verr::NOT_SEALED);
    assert_eq!(w.env.fails(&[r2_propose_exit(&w, 1)], &[&w.m.admin]), verr::NOT_SEALED);
    w.seal();
    // Not with the seal either: a thief holding the admin key could execute
    // the seal and park the vault in one transaction (finding 88). For a
    // loosen delay after the seal, every depositor can leave first.
    assert_eq!(w.env.fails(&[r2_move_in(&w, 1_000 * USDC)], &[&w.m.admin]), verr::NOT_SEALED);
    w.refresh_prices();
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &alice.pubkey(), &alice_acc, 1_000 * USDC, &w.usdc_prices(false));
    w.env.ok(&[ix], &[&alice]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[r2_move_in(&w, 1_000 * USDC)], &[&w.m.admin]);
    w.env.ok(&[r2_propose_exit(&w, 1_000 * USDC)], &[&w.m.admin]);
}

/// Issue #38: a lifeboat destination this program owns (here the SOL vault,
/// which can own a USDC token account) could never send the tokens on. The
/// exit is refused, and the tokens stay in the lifeboat.
#[test]
fn a_lifeboat_exit_never_strands_tokens_with_a_vault() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let stranded = w.sol.vault;
    w.env.ok(&[w.m.propose_change_ix(&w.env, 4, &stranded, &[], None)], &[&w.m.admin]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[execute_change_ix(&w, 0, &stranded)], &[]);
    w.env.advance(3 * DAY + 1); // the new destination is now 72h old
    w.env.ok(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.advance(3 * DAY + 1);
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let dest = w.account("usdc", &stranded);
    let exit = |owner: Address| {
        w.m.vault_ix(27, &[], vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(lifeboat, false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
            AccountMeta::new_readonly(owner, false),
        ])
    };
    // Account 6 must be the destination itself, so the check cannot be dodged.
    assert_eq!(w.env.fails(&[exit(Keypair::new().pubkey())], &[]), verr::RECIPIENT_OWNER_MISMATCH);
    assert_eq!(w.env.fails(&[exit(stranded)], &[]), verr::STRANDED_DESTINATION);
    assert_eq!(w.env.balance(&lifeboat), 1_000_000 * USDC, "still in the lifeboat");
}

/// Finding 85: the issue #38 check refused only accounts this program owns. A
/// token PDA of the Vault (owned by the token program) or a Vault PDA not yet
/// created (owned by the system program) passed it, and the exit stranded the
/// tokens. The destination now signs the exit: none of these ever can.
#[test]
fn a_lifeboat_exit_needs_the_destination_to_sign() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    // The SOL vault's token account PDA, owned by the token program.
    let stranded = w.sol.vault_tokens;
    w.env.ok(&[w.m.propose_change_ix(&w.env, 4, &stranded, &[], None)], &[&w.m.admin]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[execute_change_ix(&w, 0, &stranded)], &[]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.advance(3 * DAY + 1);
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let dest = w.account("usdc", &stranded);
    let ix = w.m.vault_ix(27, &[], vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(lifeboat, false),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(stranded, false),
    ]);
    assert_eq!(w.env.fails(&[ix], &[]), verr::MISSING_SIGNATURE);
    assert_eq!(w.env.balance(&lifeboat), 1_000_000 * USDC, "still in the lifeboat");
    assert_eq!(w.env.balance(&dest), 0);
    assert_eq!(w.env.balance(&dest), 0);
}

/// Issue #66: an exit executes only while its proposer is still the admin,
/// like a change (finding 87). A thief who saw the recovery key's rotation
/// coming used to queue an exit behind it, and the exit outlived the rotation.
#[test]
fn a_lifeboat_exit_proposed_by_a_replaced_admin_does_not_execute() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let recovery = w.user();
    let protocol = w.m.protocol;
    w.env.ok(&[w.m.propose_change_ix(&w.env, 6, &recovery.pubkey(), &[], None)], &[&w.m.admin]);
    w.env.advance(3 * DAY + 1); // also opens the lifeboat (finding 88)
    w.env.ok(&[execute_change_ix(&w, 0, &protocol)], &[]);
    w.env.ok(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    // The recovery key proposes a new admin; the thief queues an exit behind it.
    let fresh = w.user();
    let mut ix = w.m.propose_change_ix(&w.env, 3, &fresh.pubkey(), &[], None);
    ix.accounts[1].pubkey = recovery.pubkey();
    w.env.ok(&[ix], &[&recovery]);
    w.env.advance(3_600);
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.advance(3 * DAY);
    w.env.ok(&[execute_change_ix(&w, 1, &protocol)], &[]);
    assert_eq!(protocol_admin(&w), fresh.pubkey());
    w.env.advance(3_600); // the thief's exit is now due
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let destination = w.m.destination.pubkey();
    let dest = w.account("usdc", &destination);
    let exit = w.m.vault_ix(27, &[], vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(lifeboat, false),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(destination, true),
    ]);
    assert_eq!(w.env.fails(std::slice::from_ref(&exit), &[&w.m.destination]), verr::CHANGE_STALE);
    assert_eq!(w.env.balance(&lifeboat), 1_000_000 * USDC, "still in the lifeboat");
    // The new admin's own exit executes: the rule refuses only a replaced proposer.
    let propose = w.m.vault_ix(26, &(1_000_000 * USDC).to_le_bytes(), vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new_readonly(fresh.pubkey(), true),
    ]);
    w.env.ok(&[propose], &[&fresh]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[exit], &[&w.m.destination]);
    assert_eq!(w.env.balance(&dest), 1_000_000 * USDC);
    assert_eq!(w.env.balance(&lifeboat), 0);
}

fn r2_execute_exit(w: &World, owner: &Address, to: &Address) -> Instruction {
    w.m.vault_ix(27, &[], vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(r2_lifeboat(w), false),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new(*to, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(*owner, true),
    ])
}

fn r2_veto_exit(w: &World, guardian: &Address) -> Instruction {
    w.m.vault_ix(28, &[], vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new_readonly(*guardian, true),
    ])
}

fn r2_heartbeat(w: &World, guardian: &Address) -> Instruction {
    w.m.vault_ix(14, &[], vec![
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new_readonly(*guardian, true),
    ])
}

/// G6: a guardian's veto stops a lifeboat exit for good. From the end of its
/// delay to the last second before it expires, the vetoed exit does not
/// execute. A new proposal clears the veto, and it waits the full delay again.
#[test]
fn a_vetoed_lifeboat_exit_never_executes() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    w.env.advance(3 * DAY + 1); // the lifeboat opens a loosen delay after the seal (finding 88)
    w.refresh_prices();
    w.env.ok(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    let g0 = w.m.g[0].pubkey();
    w.env.ok(&[r2_heartbeat(&w, &g0), r2_veto_exit(&w, &g0)], &[&w.m.g[0]]);
    w.env.advance(3 * DAY); // the exit's delay ends
    let owner = w.m.destination.pubkey();
    let dest = w.account("usdc", &owner);
    let exit = r2_execute_exit(&w, &owner, &dest);
    assert_eq!(w.env.fails(std::slice::from_ref(&exit), &[&w.m.destination]), verr::CHANGE_NOT_EXECUTABLE);
    w.env.advance(7 * DAY - 1); // the exit expires 7 days after its delay
    assert_eq!(w.env.fails(std::slice::from_ref(&exit), &[&w.m.destination]), verr::CHANGE_NOT_EXECUTABLE);
    assert_eq!(w.env.balance(&r2_lifeboat(&w)), 1_000_000 * USDC, "still in the lifeboat");
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.advance(3 * DAY - 1);
    assert_eq!(w.env.fails(std::slice::from_ref(&exit), &[&w.m.destination]), verr::CHANGE_NOT_EXECUTABLE);
    w.env.advance(1);
    w.env.ok(&[exit], &[&w.m.destination]);
    assert_eq!(w.env.balance(&dest), 1_000_000 * USDC);
}

/// G6: an exit goes only to a destination committed 72h before the exit was
/// proposed. An exit queued behind a destination change does not follow the
/// change, though the new destination signs. A new exit waits until the new
/// destination is 72h old, to the second, then its own delay.
#[test]
fn a_lifeboat_exit_goes_only_to_a_destination_committed_72h_before_it() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    w.env.advance(3 * DAY + 1); // the lifeboat opens a loosen delay after the seal (finding 88)
    w.refresh_prices();
    w.env.ok(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    let next = w.user();
    w.env.ok(&[w.m.propose_change_ix(&w.env, 4, &next.pubkey(), &[], None)], &[&w.m.admin]);
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[execute_change_ix(&w, 0, &next.pubkey())], &[]);
    // The exit is due; the destination it would pay was set after it was proposed.
    let to = w.account("usdc", &next.pubkey());
    let exit = r2_execute_exit(&w, &next.pubkey(), &to);
    assert_eq!(w.env.fails(std::slice::from_ref(&exit), &[&next]), verr::DESTINATION_NOT_SETTLED);
    // Nor to the destination it was proposed for, now replaced: the age check
    // runs before the recipient check, so any recipient is refused here.
    let old = w.m.destination.pubkey();
    let old_acc = w.account("usdc", &old);
    let to_old = r2_execute_exit(&w, &old, &old_acc);
    assert_eq!(w.env.fails(std::slice::from_ref(&to_old), &[&w.m.destination]), verr::DESTINATION_NOT_SETTLED);
    assert_eq!(w.env.fails(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]), verr::DESTINATION_NOT_SETTLED);
    w.env.advance(3 * DAY - 1);
    assert_eq!(w.env.fails(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]), verr::DESTINATION_NOT_SETTLED);
    w.env.advance(1);
    // The new destination is 72h old now; the old exit still does not pay it:
    // the age counts at the proposal, not at the execution.
    assert_eq!(w.env.fails(std::slice::from_ref(&exit), &[&next]), verr::DESTINATION_NOT_SETTLED);
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.advance(3 * DAY - 1);
    assert_eq!(w.env.fails(std::slice::from_ref(&exit), &[&next]), verr::CHANGE_NOT_EXECUTABLE);
    w.env.advance(1);
    assert_eq!(w.env.fails(&[to_old], &[&w.m.destination]), verr::RECIPIENT_OWNER_MISMATCH);
    w.env.ok(&[exit], &[&next]);
    assert_eq!(w.env.balance(&to), 1_000_000 * USDC);
}

/// G5: only live guardians act. A guardian silent for longer than its
/// heartbeat interval (7 days here) can no longer heartbeat, veto, reset the
/// backlog, extend or cancel a ticket, or freeze. One that heartbeat on time still does each; a
/// heartbeat at exactly the interval still counts.
#[test]
fn a_guardian_silent_past_its_interval_can_no_longer_act() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let (g0, g1) = (w.m.g[0].pubkey(), w.m.g[1].pubkey());
    w.env.ok(&[r2_heartbeat(&w, &g0)], &[&w.m.g[0]]);
    w.env.ok(&[r2_heartbeat(&w, &g1)], &[&w.m.g[1]]);
    w.env.advance(7 * DAY);
    w.env.ok(&[r2_heartbeat(&w, &g1)], &[&w.m.g[1]]);
    w.env.advance(1); // g0 is one second past its interval, g1 is not
    w.refresh_prices();
    w.env.ok(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    let mut looser = Limits::default_limits();
    looser.short_bps = 300;
    let vault = w.usdc.vault;
    w.env.ok(&[w.m.propose_change_ix(&w.env, 0, &vault, &looser.bytes(), Some(&vault))], &[&w.m.admin]);
    let veto_change = |g: &Address| {
        w.m.vault_ix(19, &[], vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.m.change_address(0), false),
            AccountMeta::new_readonly(*g, true),
        ])
    };
    let (vc0, vc1) = (veto_change(&g0), veto_change(&g1));
    let reset = |g: &Address| {
        w.m.vault_ix(16, &[], vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new_readonly(*g, true),
        ])
    };
    assert_eq!(w.env.fails(&[reset(&g0)], &[&w.m.g[0]]), verr::NOT_GUARDIAN, "reset backlog");
    w.env.ok(&[reset(&g1)], &[&w.m.g[1]]);
    let payee = w.user();
    let payee_acc = w.account("usdc", &payee.pubkey());
    let (_, ticket) = w.m.next_ticket(&w.env);
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &payee_acc, &payee.pubkey(), 1_000_000 * USDC, &w.usdc_prices(true));
    w.env.ok(&[ix], &[&w.m.admin]);
    let id = ticket_id(&w.env, &ticket);
    let extend = |g: &Address| {
        let mut d = 3_600i64.to_le_bytes().to_vec();
        d.extend_from_slice(&id.to_le_bytes());
        w.m.vault_ix(11, &d, vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(ticket, false),
            AccountMeta::new_readonly(*g, true),
        ])
    };
    let (ex0, ex1) = (extend(&g0), extend(&g1));
    let payer = w.env.payer.pubkey();
    for (what, ix) in [
        ("heartbeat", r2_heartbeat(&w, &g0)),
        ("veto exit", r2_veto_exit(&w, &g0)),
        ("veto change", vc0),
        ("extend ticket", ex0),
        ("cancel ticket", w.m.cancel_ix(&w.usdc, &ticket, id, &g0, &payer)),
        ("freeze", w.m.freeze_ix(&g0, None, 86_400)),
    ] {
        assert_eq!(w.env.fails(&[ix], &[&w.m.g[0]]), verr::NOT_GUARDIAN, "{what}");
    }
    for ix in [
        r2_heartbeat(&w, &g1),
        r2_veto_exit(&w, &g1),
        vc1,
        ex1,
        w.m.cancel_ix(&w.usdc, &ticket, id, &g1, &payer),
        w.m.freeze_ix(&g1, None, 86_400),
    ] {
        w.env.ok(&[ix], &[&w.m.g[1]]);
    }
}

/// G5, before the seal: a guardian silent past its interval cannot veto the
/// seal either. One that heartbeat on time can.
#[test]
fn a_guardian_silent_past_its_interval_cannot_veto_the_seal() {
    let mut w = World::new();
    let (g0, g1) = (w.m.g[0].pubkey(), w.m.g[1].pubkey());
    w.env.ok(&[r2_heartbeat(&w, &g0)], &[&w.m.g[0]]);
    w.env.ok(&[r2_heartbeat(&w, &g1)], &[&w.m.g[1]]);
    w.env.advance(7 * DAY);
    w.env.ok(&[r2_heartbeat(&w, &g1)], &[&w.m.g[1]]);
    w.env.advance(1); // g0 is one second past its interval, g1 is not
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    let veto = |g: &Address| {
        w.m.vault_ix(6, &[], vec![
            AccountMeta::new(w.m.protocol, false),
            AccountMeta::new_readonly(*g, true),
        ])
    };
    let (v0, v1) = (veto(&g0), veto(&g1));
    assert_eq!(w.env.fails(&[v0], &[&w.m.g[0]]), verr::NOT_GUARDIAN);
    w.env.ok(&[v1], &[&w.m.g[1]]);
}

/// G5: a quorum counts live guardians only. With g0 silent past its interval,
/// g0 and g1 (two signatures, threshold 2) are no quorum for any action that
/// needs one: unfreeze, a lifeboat return, abdicate, tightening an abdicated
/// kind, replace_recovery, eject. g1 and g2, both live, are. For tightening an
/// abdicated kind, listed but unsigned, they are not (the admin signs).
#[test]
fn a_silent_guardian_does_not_count_toward_a_quorum() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let (g0, g1, g2) = (w.m.g[0].pubkey(), w.m.g[1].pubkey(), w.m.g[2].pubkey());
    for k in [&w.m.g[0], &w.m.g[1], &w.m.g[2]] {
        w.env.ok(&[r2_heartbeat(&w, &k.pubkey())], &[k]);
    }
    w.env.advance(7 * DAY);
    w.env.ok(&[r2_heartbeat(&w, &g1)], &[&w.m.g[1]]);
    w.env.ok(&[r2_heartbeat(&w, &g2)], &[&w.m.g[2]]);
    w.env.advance(1); // g0 is one second past its interval
    w.refresh_prices();
    let admin = w.m.admin.pubkey();
    let dead = [g0, g1];
    let live = [g1, g2];
    let signed = |mut ix: Instruction, by: &[Address]| {
        ix.accounts.extend(by.iter().map(|g| AccountMeta::new_readonly(*g, true)));
        ix
    };

    // Lifeboat return.
    w.env.ok(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    let ret = |w: &World| {
        w.m.vault_ix(25, &(1_000_000 * USDC).to_le_bytes(), vec![
            AccountMeta::new_readonly(w.m.protocol, false),
            AccountMeta::new(w.usdc.vault, false),
            AccountMeta::new(w.usdc.vault_tokens, false),
            AccountMeta::new(r2_lifeboat(w), false),
            AccountMeta::new_readonly(w.usdc.mint, false),
            AccountMeta::new_readonly(w.usdc.token_program, false),
        ])
    };
    assert_eq!(w.env.fails(&[signed(ret(&w), &dead)], &[&w.m.g[0], &w.m.g[1]]), verr::NO_QUORUM, "lifeboat return");
    w.env.ok(&[signed(ret(&w), &live)], &[&w.m.g[1], &w.m.g[2]]);

    // Abdicate SetLimits, then tighten it.
    let abdicate = |w: &World| {
        w.m.vault_ix(17, &[0], vec![
            AccountMeta::new(w.m.protocol, false),
            AccountMeta::new_readonly(w.m.admin.pubkey(), true),
        ])
    };
    assert_eq!(w.env.fails(&[signed(abdicate(&w), &dead)], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]), verr::NO_QUORUM, "abdicate");
    w.env.ok(&[signed(abdicate(&w), &live)], &[&w.m.admin, &w.m.g[1], &w.m.g[2]]);
    let vault = w.usdc.vault;
    let mut tighter = Limits::default_limits();
    tighter.short_bps = 100;
    let tighten = |w: &World| w.m.propose_change_ix(&w.env, 0, &vault, &tighter.bytes(), Some(&vault));
    assert_eq!(w.env.fails(&[signed(tighten(&w), &dead)], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]), verr::NO_QUORUM, "tighten abdicated");
    // The admin's signature alone does not make listed guardians count.
    let mut unsigned = tighten(&w);
    unsigned.accounts.extend(live.iter().map(|g| AccountMeta::new_readonly(*g, false)));
    assert_eq!(w.env.fails(&[unsigned], &[&w.m.admin]), verr::NO_QUORUM, "tighten abdicated, guardians unsigned");
    w.env.ok(&[signed(tighten(&w), &live)], &[&w.m.admin, &w.m.g[1], &w.m.g[2]]);

    // Replace the recovery key.
    let recovery = Address::new_unique();
    let ix = w.m.replace_recovery_ix(&admin, &recovery, &dead);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]), verr::NO_QUORUM, "replace recovery");
    w.env.ok(&[w.m.replace_recovery_ix(&admin, &recovery, &live)], &[&w.m.admin, &w.m.g[1], &w.m.g[2]]);

    // Unfreeze.
    w.env.ok(&[w.m.freeze_ix(&g1, None, 86_400)], &[&w.m.g[1]]);
    assert_eq!(w.env.fails(&[w.m.unfreeze_ix(None, &dead)], &[&w.m.g[0], &w.m.g[1]]), verr::NO_QUORUM, "unfreeze");
    w.env.ok(&[w.m.unfreeze_ix(None, &live)], &[&w.m.g[1], &w.m.g[2]]);

    // Eject g2 (g0 and g1 sign) is refused; eject g0 (g1 and g2 sign) is not.
    let eject = |w: &World, target: u8| w.m.vault_ix(15, &[target], vec![AccountMeta::new(w.m.protocol, false)]);
    assert_eq!(w.env.fails(&[signed(eject(&w, 2), &dead)], &[&w.m.g[0], &w.m.g[1]]), verr::CANNOT_EJECT, "eject");
    w.env.ok(&[signed(eject(&w, 0), &live)], &[&w.m.g[1], &w.m.g[2]]);
}

/// Finding 72: an abdicated recovery key can still be removed (it only takes
/// power away), or a stolen one would stale every admin rotation for good.
#[test]
fn an_abdicated_recovery_key_can_still_be_removed() {
    let mut w = World::new();
    w.seal();
    let (g0, g1) = (w.m.g[0].pubkey(), w.m.g[1].pubkey());
    let admin = w.m.admin.pubkey();
    let rec = Keypair::new().pubkey();
    let signers: [&Keypair; 3] = [&w.m.admin, &w.m.g[0], &w.m.g[1]];
    w.env.ok(&[w.m.replace_recovery_ix(&admin, &rec, &[g0, g1])], &signers);
    let ab = w.m.vault_ix(17, &[6], vec![
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new_readonly(admin, true),
        AccountMeta::new_readonly(g0, true),
        AccountMeta::new_readonly(g1, true),
    ]);
    w.env.ok(&[ab], &signers);
    let ix = w.m.replace_recovery_ix(&admin, &Keypair::new().pubkey(), &[g0, g1]);
    assert_eq!(w.env.fails(&[ix], &signers), verr::ABDICATED);
    w.env.ok(&[w.m.replace_recovery_ix(&admin, &Address::default(), &[g0, g1])], &signers);
}

/// Finding 74: a backed loan needs the borrower's signature. A compromised
/// caller paying USDC to a SOL holder used to create that loan in the
/// holder's name, through the backed lane, during a freeze: the USDC vault
/// drained to holders who never asked, and their own SOL lost its instant
/// exit. Now the payout is unbacked (queued behind the freeze), the lender's
/// own exit and the holder's own SOL are untouched, and a borrow the holder
/// signs is still backed.
#[test]
fn a_backed_loan_needs_the_borrowers_signature() {
    let mut w = World::new();
    let lender = w.user();
    let lender_acc = w.deposit("usdc", &lender, 1_000_000 * USDC);
    let holder = w.user();
    let holder_sol = w.deposit("sol", &holder, 700 * SOL);
    w.seal();
    let both = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
    // The admin pays the holder 50,000 USDC: no signature, so not a loan,
    // although the SOL would back one. Unfrozen, so only the signature rule
    // can refuse it (a freeze refuses any loan too, finding 90).
    let holder_usdc = w.account("usdc", &holder.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &holder_usdc, &holder.pubkey(), 50_000 * USDC, &both);
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!(o.backed, 0, "unsigned: not a loan");
    assert_eq!(o.instant + o.queued, 50_000 * USDC, "all of it unbacked");
    // Nor is the holder's key listed without a signature: consent is the
    // signature, not the account.
    let mut ix = w.m.admin_payout_ix(&w.env, &w.usdc, &holder_usdc, &holder.pubkey(), 50_000 * USDC, &both);
    ix.accounts.push(AccountMeta::new_readonly(holder.pubkey(), false));
    let o2 = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!(o2.backed, 0, "listed, unsigned: not a loan");
    assert_eq!(o2.instant + o2.queued, 50_000 * USDC, "all of it unbacked");
    let paid = w.env.balance(&holder_usdc);
    assert_eq!(paid, o.instant + o2.instant);
    let g0 = w.m.g[0].pubkey();
    let freeze = w.m.freeze_ix(&g0, None, 86_400);
    w.env.ok(&[freeze], &[&w.m.g[0]]);
    // Frozen: the same payout waits behind the freeze.
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &holder_usdc, &holder.pubkey(), 50_000 * USDC, &both);
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!((o.backed, o.instant, o.queued), (0, 0, 50_000 * USDC), "unbacked: queued behind the freeze");
    assert_eq!(w.env.balance(&holder_usdc), paid);
    // The lender's own exit and the holder's own SOL, during the freeze.
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &lender.pubkey(), &lender_acc, 1_000_000 * USDC, &w.usdc_prices(false));
    w.env.ok(&[ix], &[&lender]);
    assert_eq!(w.env.balance(&lender_acc), 1_000_000 * USDC);
    let sol_only = vec![(w.sol.asset, SYSTEM)];
    let ix = w.m.withdraw_ix(&w.env, &w.sol, &holder.pubkey(), &holder_sol, 100 * SOL, &sol_only);
    let o = outcome(&w.env.ok(&[ix], &[&holder]));
    assert_eq!(o.backed, 100 * SOL, "own SOL: backed, no prices, frozen");
    // A borrow the holder signs is backed, once the freeze is over (while
    // frozen, no loan is backed: finding 90).
    w.env.advance(86_400 + 1);
    w.refresh_prices();
    let lender2 = w.user();
    w.deposit("usdc", &lender2, 1_000_000 * USDC);
    let ix = w.m.withdraw_ix(&w.env, &w.usdc, &holder.pubkey(), &holder_usdc, 10_000 * USDC, &both);
    let o = outcome(&w.env.ok(&[ix], &[&holder]));
    assert_eq!(o.backed, 10_000 * USDC, "signed: a backed loan against the SOL");
}

/// Finding 98: the caller PDA signs every release, so its signature counted
/// as consent when it owned the ledger itself (an integrator that deposits
/// through its caller PDA, a pooled design). A compromised protocol program
/// then borrowed USDC against the pool's SOL through the backed lane, with no
/// user's signature. Now that excess is unbacked; the pool's own balance of
/// the paid mint would still be backed.
#[test]
fn the_callers_own_signature_is_not_consent_to_a_loan() {
    let mut w = World::new();
    let lender = w.user();
    w.deposit("usdc", &lender, 1_000_000 * USDC);
    // A pooled ledger: 700 SOL deposited, then held under the caller PDA.
    let pooler = w.user();
    w.deposit("sol", &pooler, 700 * SOL);
    let caller = w.m.caller;
    let (from, (to, bump)) = (
        w.m.backing(&pooler.pubkey()),
        Address::find_program_address(&[b"backing", w.m.protocol.as_ref(), caller.as_ref()], &w.m.vault_program),
    );
    let mut acct = w.env.svm.get_account(&from).unwrap();
    let mut b = read_backing(&w.env, &from);
    (b.owner, b.bump) = (caller.to_bytes(), bump);
    b.store(&mut acct.data).unwrap();
    w.env.svm.set_account(to, acct).unwrap();
    let mut gone = w.env.svm.get_account(&from).unwrap();
    gone.data.fill(0);
    gone.lamports = 0;
    w.env.svm.set_account(from, gone).unwrap();
    w.seal();
    let both = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
    let pool_usdc = w.account("usdc", &caller);
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &pool_usdc, &caller, 50_000 * USDC, &both);
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!(o.backed, 0, "the caller's signature is not a borrower's consent");
    assert_eq!(o.instant + o.queued, 50_000 * USDC, "all of it limited and freezable");
}

/// `propose_change` signed by `proposer` (the admin or the recovery key).
fn propose_as(w: &World, proposer: &Address, kind: u8, target: &Address) -> (Instruction, u64) {
    let id = read_protocol(&w.env, &w.m.protocol).next_change_id;
    let mut args = vec![kind];
    args.extend_from_slice(target.as_ref());
    let ix = w.m.vault_ix(18, &args, vec![
        AccountMeta::new(w.env.payer.pubkey(), true),
        AccountMeta::new_readonly(*proposer, true),
        AccountMeta::new(w.m.protocol, false),
        AccountMeta::new(w.m.change_address(id), false),
        AccountMeta::new_readonly(SYSTEM, false),
    ]);
    (ix, id)
}

/// Finding 87: a thief holding the admin key queues a loosening (here its own
/// lifeboat destination). The recovery key replaces the admin; the thief's
/// change used to execute anyway after the delay, and nobody could cancel it.
/// Now only the keys that hold the roles can have changes executed.
#[test]
fn a_replaced_admin_s_queued_loosening_never_executes() {
    let mut w = World::new();
    w.seal();
    let (g0, g1) = (w.m.g[0].pubkey(), w.m.g[1].pubkey());
    let admin = w.m.admin.pubkey();
    let recovery = Keypair::new();
    w.env.fund(&recovery);
    w.env.ok(&[w.m.replace_recovery_ix(&admin, &recovery.pubkey(), &[g0, g1])], &[&w.m.admin, &w.m.g[0], &w.m.g[1]]);
    // The thief (the admin key) queues its own destination.
    let thief = Keypair::new().pubkey();
    let (ix, theirs) = propose_as(&w, &admin, 4, &thief);
    w.env.ok(&[ix], &[&w.m.admin]);
    // Recovery: a new admin.
    let new_admin = Keypair::new();
    w.env.fund(&new_admin);
    let (ix, rotation) = propose_as(&w, &recovery.pubkey(), 3, &new_admin.pubkey());
    w.env.ok(&[ix], &[&recovery]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[execute_change_ix(&w, rotation, &new_admin.pubkey())], &[]);
    assert_eq!(w.env.fails(&[execute_change_ix(&w, theirs, &thief)], &[]), verr::CHANGE_STALE);
    // The new admin's own changes still execute.
    let mine = Keypair::new().pubkey();
    let (ix, id) = propose_as(&w, &new_admin.pubkey(), 4, &mine);
    w.env.ok(&[ix], &[&new_admin]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[execute_change_ix(&w, id, &mine)], &[]);
}

/// Finding 87: the seal names every vault in one transaction, so more than 10
/// vaults before the seal could never seal, and the pre-seal deposits stayed
/// locked for good. The eleventh vault before the seal is refused.
#[test]
fn no_more_vaults_before_the_seal_than_the_seal_can_name() {
    let mut env = Env::new();
    let m = Market::new(&mut env);
    for _ in 0..10 {
        m.create_vault(&mut env, 6, Limits::default_limits(), USDC_FEED, None);
    }
    let (mint, _) = env.create_mint(6, &token_program());
    let vault = pda(&[b"vault", m.protocol.as_ref(), mint.as_ref()], &m.vault_program);
    let vault_tokens = pda(&[b"vault-tokens", m.protocol.as_ref(), mint.as_ref()], &m.vault_program);
    let ix = m.vault_ix(1, &Limits::default_limits().bytes(), vec![
        AccountMeta::new(env.payer.pubkey(), true),
        AccountMeta::new_readonly(m.admin.pubkey(), true),
        AccountMeta::new(m.protocol, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(vault_tokens, false),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(SYSTEM, false),
    ]);
    assert_eq!(env.fails(&[ix], &[&m.admin]), verr::TOO_MANY_VAULTS);
}

/// Finding 96: in an n-of-n set nobody can be ejected (the others never reach
/// a quorum without the rogue), so one guardian renewed freezes and vetoed
/// every loosening for good. A set must have more keys than its threshold;
/// a 3-of-4 is fine.
#[test]
fn an_n_of_n_guardian_set_is_refused() {
    let mut w = World::new();
    w.seal();
    let keys: Vec<Address> = (0..4).map(|_| Keypair::new().pubkey()).collect();
    let zero = Address::default();
    for (set, th) in [(&keys[..2], 2u8), (&keys[..3], 3), (&keys[..4], 4)] {
        let ix = w.m.propose_change_ix(&w.env, 2, &zero, &guardian_set(set, th), None);
        assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::INVALID_GUARDIANS);
    }
    let ix = w.m.propose_change_ix(&w.env, 2, &zero, &guardian_set(&keys, 3), None);
    w.env.ok(&[ix], &[&w.m.admin]);
}

/// The guardian-set payload for `SetGuardians`.
fn guardian_set(keys: &[Address], threshold: u8) -> Vec<u8> {
    let mut d = vec![keys.len() as u8];
    for k in keys {
        d.extend_from_slice(k.as_ref());
    }
    d.push(threshold);
    d.extend_from_slice(&(7 * DAY).to_le_bytes());
    d
}

/// Finding 88: before the seal, a stolen admin key swaps in its own guardians,
/// sets its own destination and proposes the seal. That review used to lock
/// the recovery key out (`SealUnderReview`), and the thief then executed the
/// seal and parked the vault in one transaction. Now (1) the recovery key
/// replaces the admin during the review, which ends it, and (2) even without
/// one, the lifeboat stays shut for a loosen delay after the seal, while every
/// depositor can withdraw.
#[test]
fn a_pre_seal_thief_cannot_seal_and_park_the_vault() {
    let zero = Address::default();
    // (1) With a recovery key.
    let mut w = World::new();
    let alice = w.user();
    w.deposit("usdc", &alice, 1_000_000 * USDC);
    let recovery = Keypair::new();
    w.env.fund(&recovery);
    let (ix, _) = propose_as(&w, &w.m.admin.pubkey(), 6, &recovery.pubkey());
    w.env.ok(&[ix], &[&w.m.admin]); // genesis: at once
    let admin = w.m.admin.pubkey();
    let puppets = [Keypair::new().pubkey(), Keypair::new().pubkey(), Keypair::new().pubkey()];
    let thief = Keypair::new().pubkey();
    w.env.ok(&[
        w.m.propose_change_ix(&w.env, 2, &zero, &guardian_set(&puppets, 2), None),
    ], &[&w.m.admin]);
    let (ix, _) = propose_as(&w, &admin, 4, &thief);
    w.env.ok(&[ix], &[&w.m.admin]);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    // The recovery key's new admin applies during the review and ends it.
    let new_admin = Keypair::new();
    let (ix, _) = propose_as(&w, &recovery.pubkey(), 3, &new_admin.pubkey());
    w.env.ok(&[ix], &[&recovery]);
    w.env.advance(3 * DAY + 1);
    w.refresh_prices();
    assert!(w.env.send(&[w.m.execute_seal_ix(&[&w.usdc, &w.sol])], &[]).is_err(), "the thief's seal is gone");

    // (2) Without one: the seal executes, but the vault cannot be parked in
    // the same transaction, and the depositor leaves during the window.
    let mut w = World::new();
    let alice = w.user();
    let alice_acc = w.deposit("usdc", &alice, 1_000_000 * USDC);
    w.env.ok(&[w.m.propose_change_ix(&w.env, 2, &zero, &guardian_set(&puppets, 2), None)], &[&w.m.admin]);
    w.env.ok(&[w.m.propose_seal_ix()], &[&w.m.admin]);
    w.env.advance(3 * DAY + 1);
    w.refresh_prices();
    let seal = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    assert_eq!(w.env.fails(&[seal, r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]), verr::NOT_SEALED);
    w.env.ok(&[w.m.execute_seal_ix(&[&w.usdc, &w.sol])], &[]);
    let out = w.m.withdraw_ix(&w.env, &w.usdc, &alice.pubkey(), &alice_acc, 1_000_000 * USDC, &w.usdc_prices(false));
    w.env.ok(&[out], &[&alice]);
    assert_eq!(w.env.balance(&alice_acc), 1_000_000 * USDC, "out before the lifeboat opens");
}

/// Finding 88: an allowlisted asset's oracle settings are bounded: a price at
/// most an hour old, a margin of at least one sigma, a confidence at most 10%
/// of the price, and a real feed. A delisted asset is not priced, so its
/// settings are not checked.
#[test]
fn oracle_settings_of_a_priced_asset_are_bounded() {
    let mut w = World::new();
    for (cfg, what) in [
        (asset_bytes(true, 8_500, 10_500, 20_000, 7_200, 100, SOL_FEED), "two-hour-old prices"),
        (asset_bytes(true, 8_500, 10_500, 5_000, 60, 100, SOL_FEED), "half a sigma"),
        (asset_bytes(true, 8_500, 10_500, 20_000, 60, 5_000, SOL_FEED), "confidence of half the price"),
        (asset_bytes(true, 8_500, 10_500, 20_000, 60, 100, [0; 32]), "no feed"),
    ] {
        let ix = w.m.upsert_asset_ix(&w.env, &w.sol, &cfg);
        assert!(w.env.send(&[ix], &[&w.m.admin]).is_err(), "{what} must be refused");
    }
    let ix = w.m.upsert_asset_ix(&w.env, &w.sol, &asset_bytes(false, 8_500, 10_500, 20_000, 60, 100, [0; 32]));
    w.env.ok(&[ix], &[&w.m.admin]);
}

/// Finding 89: a payout to a token account the protocol PDA owns is refused,
/// like one the vault PDA owns: no instruction can move tokens out of it.
#[test]
fn a_release_cannot_pay_an_account_the_protocol_owns() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let (mint, protocol, program) = (w.usdc.mint, w.m.protocol, w.usdc.token_program);
    let stray = w.env.token_account(&mint, &protocol, &program);
    let pay = w.m.admin_payout_ix(&w.env, &w.usdc, &stray, &protocol, 1_000 * USDC, &w.usdc_prices(true));
    assert_eq!(w.env.fails(&[pay], &[&w.m.admin]), verr::DUPLICATE_ACCOUNT);
}

/// Finding 91, stated: an exit records its proposer's key, not the admin
/// version, so an admin rotated away and back (A -> B -> A) revives an exit
/// that was stale in between, as `execute_change` does a change whose
/// target version the rotations left alone. Both
/// rotations wait the loosen delay under veto, and the key that regains the
/// role could propose the exit again anyway; the guardian vetoes every exit.
#[test]
fn an_exit_stale_after_a_rotation_revives_only_if_the_same_admin_returns() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    let protocol = w.m.protocol;
    w.env.advance(3 * DAY + 1); // the lifeboat opens
    w.env.ok(&[r2_move_in(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    let a = w.m.admin.pubkey();
    // A proposes an exit, and a rotation to B.
    w.env.ok(&[r2_propose_exit(&w, 1_000_000 * USDC)], &[&w.m.admin]);
    let b = w.user();
    w.env.ok(&[w.m.propose_change_ix(&w.env, 3, &b.pubkey(), &[], None)], &[&w.m.admin]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[execute_change_ix(&w, 0, &protocol)], &[]);
    assert_eq!(protocol_admin(&w), b.pubkey());
    let lifeboat = pda(&[b"lifeboat-tokens", w.m.protocol.as_ref(), w.usdc.mint.as_ref()], &w.m.vault_program);
    let destination = w.m.destination.pubkey();
    let dest = w.account("usdc", &destination);
    let exit = w.m.vault_ix(27, &[], vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new(lifeboat, false),
        AccountMeta::new_readonly(w.usdc.mint, false),
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(w.usdc.token_program, false),
        AccountMeta::new_readonly(destination, true),
    ]);
    assert_eq!(w.env.fails(std::slice::from_ref(&exit), &[&w.m.destination]), verr::CHANGE_STALE);
    // B rotates back to A; A's old exit, never re-proposed, executes.
    let mut ix = w.m.propose_change_ix(&w.env, 3, &a, &[], None);
    ix.accounts[1].pubkey = b.pubkey();
    w.env.ok(&[ix], &[&b]);
    w.env.advance(3 * DAY + 1);
    w.env.ok(&[execute_change_ix(&w, 1, &protocol)], &[]);
    assert_eq!(protocol_admin(&w), a);
    w.env.ok(&[exit], &[&w.m.destination]);
    assert_eq!(w.env.balance(&dest), 1_000_000 * USDC);
}

/// Finding 100 (stated, not fixed): one withdraw-and-redeposit by a holder of
/// most of the vault lowers the low-water base for two windows, but a payout
/// made inside them is charged at the lowered capacity, and that reservation
/// outlives the dip: an ordinary 100,000 payout, instant without the round
/// trip, queues for 24h and leaves no instant room for a day. Availability
/// only; G1 is unaffected. This pins today's behaviour so that any fix has
/// to change it on purpose.
#[test]
fn a_round_trip_dip_charges_payouts_at_the_dipped_capacity() {
    use bulkhead_core::consts::LOW_WINDOW_S;
    let run = |round_trip: bool| -> (Outcome, i64, u64, u64) {
        let mut w = World::new();
        let small = w.user();
        let whale = w.user();
        w.deposit("usdc", &small, 1_000_000 * USDC);
        let whale_acc = w.deposit("usdc", &whale, 9_000_000 * USDC);
        w.seal();
        w.env.advance(2 * DAY);
        assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 200_000 * USDC);
        if round_trip {
            let out = w.m.withdraw_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 9_000_000 * USDC, &w.usdc_prices(false));
            let back = w.m.deposit_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 9_000_000 * USDC);
            w.env.ok(&[out, back], &[&whale]);
        }
        w.env.advance(60);
        let paid_at = w.env.time;
        let user = Keypair::new();
        let to = w.account("usdc", &user.pubkey());
        let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &user.pubkey(), 100_000 * USDC, &w.usdc_prices(false));
        let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
        w.env.advance(2 * LOW_WINDOW_S + 60);
        let after_dip = w.m.attest(&mut w.env, &w.usdc).available_now;
        w.env.advance(20 * 3_600);
        let after_21h = w.m.attest(&mut w.env, &w.usdc).available_now;
        (o, paid_at, after_dip, after_21h)
    };
    let (o, _, after_dip, after_21h) = run(false);
    assert_eq!((o.instant, o.queued), (100_000 * USDC, 0), "without the round trip: instant");
    assert_eq!(after_dip, 198_000 * USDC, "2% of the 9.9M left");
    assert_eq!(after_21h, 198_000 * USDC);
    let (o, paid_at, after_dip, after_21h) = run(true);
    assert_eq!((o.instant, o.queued), (0, 100_000 * USDC), "charged at a tenth of the capacity: queued");
    assert_eq!(o.eta_s - paid_at, 86_400, "the payout waits a day, not 6h");
    assert_eq!(after_dip, 0, "the base is back to 10M, yet no instant room");
    assert_eq!(after_21h, 0, "and still none 21 hours after one round trip");
}

/// Finding 100 needs no position in the vault. In one transaction a borrower
/// with nothing deposited puts in SOL collateral (it could be flash-borrowed),
/// borrows 9M USDC backed by it, pays the 9M straight back and takes the SOL
/// out again. The four instructions fit in one packet. The same honest
/// 100,000 payout then waits a day, and the lane has no instant room after
/// the dip, nor 21 hours later. During the dip `attest` reports a worst hour
/// of 40,000 instead of 400,000. This pins today's behaviour so that any
/// fix has to change it on purpose.
#[test]
fn a_loan_round_trip_with_no_position_dips_the_lane() {
    use bulkhead_core::consts::LOW_WINDOW_S;
    for round_trip in [false, true] {
        let mut w = World::new();
        let lender = w.user();
        w.deposit("usdc", &lender, 10_000_000 * USDC);
        let borrower = w.user();
        let sol_acc = w.account("sol", &borrower.pubkey());
        let usdc_acc = w.account("usdc", &borrower.pubkey());
        w.seal();
        w.env.advance(2 * DAY);
        w.refresh_prices();
        assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 200_000 * USDC);
        if round_trip {
            let flash = 72_000 * SOL;
            w.env.mint_to(&w.sol.mint, &w.sol.mint_authority, &sol_acc, flash, &w.sol.token_program);
            let put = w.m.deposit_ix(&w.env, &w.sol, &borrower.pubkey(), &sol_acc, flash);
            let usdc_first = vec![(w.usdc.asset, w.usdc.price), (w.sol.asset, w.sol.price)];
            let borrow = w.m.withdraw_ix(&w.env, &w.usdc, &borrower.pubkey(), &usdc_acc, 9_000_000 * USDC, &usdc_first);
            let repay = w.m.deposit_ix(&w.env, &w.usdc, &borrower.pubkey(), &usdc_acc, 9_000_000 * USDC);
            let sol_first = vec![(w.sol.asset, w.sol.price), (w.usdc.asset, w.usdc.price)];
            let take = w.m.withdraw_ix(&w.env, &w.sol, &borrower.pubkey(), &sol_acc, flash, &sol_first);
            let ixs = [put, borrow, repay, take];
            let msg = solana_message::Message::new(&ixs, Some(&w.env.payer.pubkey()));
            assert!(legacy_tx_size(&msg) <= PACKET, "one transaction");
            assert_eq!(PACKET - legacy_tx_size(&msg), 236, "the room left for a flash venue's own instructions");
            w.env.ok(&ixs, &[&borrower]);
            assert_eq!(w.env.balance(&sol_acc), flash, "the collateral is back");
            assert_eq!(w.env.balance(&usdc_acc), 0, "and no USDC was kept");
            // A borrow that was partly unbacked would leave the repaid surplus
            // as a deposit; an empty ledger means all 9M was backed.
            assert_eq!(ledger_of(&w.env, &w.m.backing(&borrower.pubkey())), vec![], "the loan was fully backed");
        }
        w.env.advance(60);
        // What a guardian reads from `attest` for its freeze threshold.
        let worst_1h = w.m.attest(&mut w.env, &w.usdc).worst_1h;
        let paid_at = w.env.time;
        let user = Keypair::new();
        let to = w.account("usdc", &user.pubkey());
        let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &user.pubkey(), 100_000 * USDC, &w.usdc_prices(false));
        let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
        w.env.advance(2 * LOW_WINDOW_S + 60);
        let after_dip = w.m.attest(&mut w.env, &w.usdc).available_now;
        w.env.advance(20 * 3_600);
        let after_21h = w.m.attest(&mut w.env, &w.usdc).available_now;
        if round_trip {
            assert_eq!((o.instant, o.queued), (0, 100_000 * USDC), "queued after the loan round trip");
            assert_eq!(o.eta_s - paid_at, DAY, "for a day");
            assert_eq!((after_dip, after_21h), (0, 0), "no instant room after the dip, nor 21 hours later");
            assert_eq!(worst_1h, 40_000 * USDC, "attest's worst hour is a tenth during the dip");
        } else {
            assert_eq!((o.instant, o.queued), (100_000 * USDC, 0), "without it: instant");
            assert_eq!((after_dip, after_21h), (198_000 * USDC, 198_000 * USDC), "2% of the 9.9M left");
            assert_eq!(worst_1h, 400_000 * USDC);
        }
    }
}

/// Finding 100 at 99%: after a holder of 99% of the vault withdraws and
/// re-deposits in one transaction, an honest 50,000 payout a minute later is
/// refused (after a 90% round trip, a 100,000 payout is queued instead). At
/// the dipped capacity its ETA would lie past the queue's horizon
/// (`QueueFull`), though the queue is empty.
/// A failed transaction reserves nothing, so a retry two windows later is
/// instant, unless the round trip is repeated. Without the round trip it is
/// instant too.
#[test]
fn a_99_percent_round_trip_refuses_an_honest_payout() {
    use bulkhead_core::consts::LOW_WINDOW_S;
    for round_trip in [false, true] {
        let mut w = World::new();
        let small = w.user();
        let whale = w.user();
        w.deposit("usdc", &small, 100_000 * USDC);
        let whale_acc = w.deposit("usdc", &whale, 9_900_000 * USDC);
        w.seal();
        w.env.advance(2 * DAY);
        if round_trip {
            let out = w.m.withdraw_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 9_900_000 * USDC, &w.usdc_prices(false));
            let back = w.m.deposit_ix(&w.env, &w.usdc, &whale.pubkey(), &whale_acc, 9_900_000 * USDC);
            w.env.ok(&[out, back], &[&whale]);
        }
        w.env.advance(60);
        let user = Keypair::new();
        let to = w.account("usdc", &user.pubkey());
        let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &user.pubkey(), 50_000 * USDC, &w.usdc_prices(false));
        if !round_trip {
            let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
            assert_eq!((o.instant, o.queued), (50_000 * USDC, 0), "without the round trip: instant");
            continue;
        }
        assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::QUEUE_FULL);
        w.env.advance(2 * LOW_WINDOW_S + 60);
        let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &user.pubkey(), 50_000 * USDC, &w.usdc_prices(false));
        let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
        assert_eq!((o.instant, o.queued), (50_000 * USDC, 0), "two windows later: instant");
    }
}

/// Finding 101: a reset clamps each bucket to "just emptied", and it used the
/// raw clock. If the cluster clock stepped back by δ right after a drain, the
/// admin alone (or one guardian) reset to `now − δ + W` and paid `C·δ/W`
/// more than G1 allows. The reset now uses the latest time the vault has seen.
#[test]
fn a_reset_on_a_clock_that_stepped_back_grants_nothing_extra() {
    let mut w = World::new();
    let whale = w.user();
    w.deposit("usdc", &whale, 10_000_000 * USDC);
    w.seal();
    w.env.advance(2 * DAY);
    let burst = w.m.attest(&mut w.env, &w.usdc).available_now;
    assert_eq!(burst, 200_000 * USDC);
    let user = Keypair::new();
    let to = w.account("usdc", &user.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.usdc, &to, &user.pubkey(), burst, &w.usdc_prices(false));
    assert_eq!(outcome(&w.env.ok(&[ix], &[&w.m.admin])).instant, burst);
    w.env.advance(-3_600); // the clock steps back an hour
    let reset = w.m.vault_ix(16, &[], vec![
        AccountMeta::new_readonly(w.m.protocol, false),
        AccountMeta::new(w.usdc.vault, false),
        AccountMeta::new_readonly(w.m.admin.pubkey(), true),
    ]);
    w.env.ok(&[reset], &[&w.m.admin]);
    w.env.advance(3_600); // back where the drain happened
    assert_eq!(w.m.attest(&mut w.env, &w.usdc).available_now, 0, "no room beyond an empty bucket");
}

/// The Vault's account layouts are a contract with off-chain readers that
/// decode them by position (`decodeProtocol`, `decodeVault`, `decodeTicket` in
/// `cloud/lib/solana.mjs`: the guardian and the status page). Tests decode
/// through the Vault's own types, so this test pins both directions to those
/// offsets, field by field: `load` reads each field where the readers do (on a
/// pattern where any misread shows), and `store` writes it there. A layout
/// change must change both sides. Booleans: `store` must write exactly 1 or
/// 0, the only bytes on which `load` (`!= 0`) and the readers (`=== 1`)
/// agree; the program is the only writer of these accounts. (`decodeChange` and `assetVersion`
/// are pinned too; the backing account has no off-chain reader yet, and its
/// layout is the one `05` documents.)
#[test]
fn account_layouts_match_what_off_chain_readers_decode() {
    use bulkhead_vault::{Asset, Backing, Change, Protocol, Ticket, Vault};
    fn k(d: &[u8], o: usize) -> [u8; 32] {
        d[o..o + 32].try_into().unwrap()
    }
    fn n<const N: usize>(d: &[u8], o: usize) -> [u8; N] {
        d[o..o + N].try_into().unwrap()
    }

    // Each struct's two booleans are set to (1, 0), then (0, 1): every field
    // takes both values, and a swap of the two fields shows. A store that
    // wrote anything but 1 for true, or a constant, fails.
    for (a, b) in [(1u8, 0u8), (0, 1)] {
        let mut d = patterned(Protocol::LEN, &Protocol::DISC);
        d[424] = 8; // guardian count: load refuses more than 8
        (d[426], d[532]) = (a, b);
        let p = Protocol::load(&d).unwrap();
        assert_eq!((p.sealed, p.seal_vetoed), (a == 1, b == 1));
        let mut stored = vec![0u8; Protocol::LEN];
        p.store(&mut stored).unwrap();
        for d in [&d, &stored] {
            assert_eq!((k(d, 8), k(d, 40), k(d, 72)), (p.protocol_program, p.caller, p.admin));
            for i in 0..8 {
                assert_eq!(k(d, 104 + 32 * i), p.guardians[i], "guardian {i}");
                assert_eq!(i64::from_le_bytes(n(d, 360 + 8 * i)), p.last_heartbeat[i], "heartbeat {i}");
            }
            assert_eq!((d[424], d[425], d[426], d[427]), (p.guardian_count, p.threshold, p.sealed as u8, p.bump));
            assert_eq!(i64::from_le_bytes(n(d, 428)), p.heartbeat_interval_s);
            assert_eq!(i64::from_le_bytes(n(d, 436)), p.loosen_delay_s);
            assert_eq!(i64::from_le_bytes(n(d, 444)), p.frozen_until);
            assert_eq!((u32::from_le_bytes(n(d, 452)), u32::from_le_bytes(n(d, 456))), (p.abdications, p.vault_count));
            assert_eq!((u64::from_le_bytes(n(d, 460)), u64::from_le_bytes(n(d, 468))), (p.next_ticket_id, p.next_change_id));
            assert_eq!(k(d, 476), p.lifeboat_destination);
            assert_eq!(i64::from_le_bytes(n(d, 508)), p.destination_set_s);
            assert_eq!((i64::from_le_bytes(n(d, 516)), i64::from_le_bytes(n(d, 524))), (p.seal_executable_s, p.seal_expires_s));
            assert_eq!(d[532], p.seal_vetoed as u8);
            for (i, v) in p.versions.iter().enumerate() {
                assert_eq!(u32::from_le_bytes(n(d, 533 + 4 * i)), *v, "version {i}");
            }
            assert_eq!(k(d, 553), p.recovery);
        }
        assert_eq!(&stored[0..8], &Protocol::DISC[..]);
    }

    for (a, b) in [(1u8, 0u8), (0, 1)] {
        let mut d = patterned(Vault::LEN, &Vault::DISC);
        (d[216], d[368]) = (a, b);
        let v = Vault::load(&d).unwrap();
        assert_eq!((v.ref_initialized, v.exit_vetoed), (a == 1, b == 1));
        let mut stored = vec![0u8; Vault::LEN];
        v.store(&mut stored).unwrap();
        let l = &v.limits;
        for d in [&d, &stored] {
            assert_eq!((k(d, 8), k(d, 40), k(d, 72), k(d, 104)), (v.protocol, v.mint, v.token_program, v.token_account));
            assert_eq!((u16::from_le_bytes(n(d, 136)), u32::from_le_bytes(n(d, 138))), (l.short_bps, l.short_window_s));
            assert_eq!((u16::from_le_bytes(n(d, 142)), u32::from_le_bytes(n(d, 144))), (l.long_bps, l.long_window_s));
            assert_eq!(u32::from_le_bytes(n(d, 148)), l.min_queue_delay_s);
            assert_eq!((u64::from_le_bytes(n(d, 152)), u64::from_le_bytes(n(d, 160))), (l.short_floor, l.long_floor));
            assert_eq!((u64::from_le_bytes(n(d, 168)), u64::from_le_bytes(n(d, 176))), (l.short_cap, l.long_cap));
            assert_eq!((i64::from_le_bytes(n(d, 184)), i64::from_le_bytes(n(d, 192))), (v.tat_short_ms, v.tat_long_ms));
            assert_eq!((u64::from_le_bytes(n(d, 200)), i64::from_le_bytes(n(d, 208))), (v.ref_balance, v.ref_updated_s));
            assert_eq!((d[216], d[217], d[218], d[219]), (v.ref_initialized as u8, v.decimals, v.bump, v.token_bump));
            assert_eq!((u32::from_le_bytes(n(d, 220)), u64::from_le_bytes(n(d, 224))), (v.pending_tickets, v.queued_amount));
            assert_eq!((i64::from_le_bytes(n(d, 232)), u64::from_le_bytes(n(d, 240))), (v.frozen_until, v.imported));
            assert_eq!((u128::from_le_bytes(n(d, 248)), u128::from_le_bytes(n(d, 264))), (v.total_in, v.backed_out));
            assert_eq!((u128::from_le_bytes(n(d, 280)), u128::from_le_bytes(n(d, 296))), (v.unbacked_out, v.settled));
            assert_eq!(u128::from_le_bytes(n(d, 312)), v.cancelled);
            assert_eq!((u64::from_le_bytes(n(d, 328)), u64::from_le_bytes(n(d, 336))), (v.lifeboat_amount, v.exit_amount));
            assert_eq!((i64::from_le_bytes(n(d, 344)), i64::from_le_bytes(n(d, 352))), (v.exit_proposed_s, v.exit_executable_s));
            assert_eq!((i64::from_le_bytes(n(d, 360)), d[368]), (v.exit_expires_s, v.exit_vetoed as u8));
            assert_eq!(u32::from_le_bytes(n(d, 369)), v.limits_version);
            assert_eq!((u64::from_le_bytes(n(d, 373)), u64::from_le_bytes(n(d, 381))), (v.low.prev, v.low.cur));
            assert_eq!(i64::from_le_bytes(n(d, 389)), v.low.window);
            assert_eq!(k(d, 397), v.exit_proposer);
        }
        assert_eq!(&stored[0..8], &Vault::DISC[..]);
    }

    let d = patterned(Ticket::LEN, &Ticket::DISC);
    let t = Ticket::load(&d).unwrap();
    let mut stored = vec![0u8; Ticket::LEN];
    t.store(&mut stored).unwrap();
    for d in [&d, &stored] {
        assert_eq!((k(d, 8), k(d, 40), k(d, 72)), (t.protocol, t.vault, t.recipient));
        assert_eq!((k(d, 104), k(d, 136)), (t.recipient_owner, t.payer));
        assert_eq!((u64::from_le_bytes(n(d, 168)), u64::from_le_bytes(n(d, 176))), (t.id, t.amount));
        assert_eq!((i64::from_le_bytes(n(d, 184)), i64::from_le_bytes(n(d, 192))), (t.created_s, t.eta_s));
    }
    assert_eq!(&stored[0..8], &Ticket::DISC[..]);

    for (a, b) in [(1u8, 0u8), (0, 1)] {
        let mut d = patterned(Change::LEN, &Change::DISC);
        d[140..142].copy_from_slice(&200u16.to_le_bytes()); // payload length: at most 300
        (d[49], d[50]) = (a, b);
        let c = Change::load(&d).unwrap();
        assert_eq!((c.vetoed, c.executed), (a == 1, b == 1));
        let mut stored = vec![0u8; Change::LEN];
        c.store(&mut stored).unwrap();
        for d in [&d, &stored] {
            assert_eq!((k(d, 8), u64::from_le_bytes(n(d, 40)), d[48]), (c.protocol, c.id, c.kind));
            assert_eq!((d[49], d[50], d[51]), (c.vetoed as u8, c.executed as u8, c.bump));
            assert_eq!((k(d, 52), k(d, 84)), (c.target, c.proposer));
            assert_eq!((i64::from_le_bytes(n(d, 116)), i64::from_le_bytes(n(d, 124))), (c.created_s, c.executable_s));
            assert_eq!(i64::from_le_bytes(n(d, 132)), c.expires_s);
            assert_eq!(u16::from_le_bytes(n(d, 140)), c.payload_len);
            assert_eq!(&d[142..342], &c.payload[..200]);
            assert_eq!(u32::from_le_bytes(n(d, 442)), c.base_version);
        }
        assert_eq!(&stored[0..8], &Change::DISC[..]);
    }

    let d = patterned(Asset::LEN, &Asset::DISC);
    let a = Asset::load(&d).unwrap();
    let mut stored = vec![0u8; Asset::LEN];
    a.store(&mut stored).unwrap();
    for d in [&d, &stored] {
        assert_eq!((k(d, 8), k(d, 40)), (a.protocol, a.mint));
        assert_eq!((d[125], d[126], u32::from_le_bytes(n(d, 127))), (a.decimals, a.bump, a.version));
    }
    assert_eq!(&stored[0..8], &Asset::DISC[..]);

    let d = patterned(Backing::LEN, &Backing::DISC);
    let b = Backing::load(&d).unwrap();
    let mut stored = vec![0u8; Backing::LEN];
    b.store(&mut stored).unwrap();
    for d in [&d, &stored] {
        assert_eq!((k(d, 8), k(d, 40), d[72]), (b.protocol, b.owner, b.bump));
        for (i, (mint, net)) in b.positions.iter().enumerate() {
            assert_eq!((k(d, 73 + 48 * i), i128::from_le_bytes(n(d, 105 + 48 * i))), (*mint, *net), "slot {i}");
        }
    }
    assert_eq!(&stored[0..8], &Backing::DISC[..]);
}

// ---------------------------------------------------------------------------
// Measurement: the cost of a release for an owner whose ledger is full
// (MAX_SLOTS = 8). `release` needs (asset PDA, price account) for the paid
// mint and every other mint in the recipient owner's ledger, so the account
// list, the transaction size and the compute grow with the ledger. Reports
// CU (Harbor CPI path, the Vault's own share, and a direct quote_release),
// unique keys, and the legacy transaction size against the 1,232-byte limit.
// LiteSVM here has no explicit compute budget: the limit comes from the
// transaction (200,000 per instruction by default, at most 1,400,000).
// ---------------------------------------------------------------------------

const PACKET: usize = 1_232;
const MAX_SLOTS_T: usize = bulkhead_core::consts::MAX_SLOTS;

fn compact_len(n: usize) -> usize {
    if n < 0x80 {
        1
    } else if n < 0x4000 {
        2
    } else {
        3
    }
}

/// Wire size of a legacy transaction carrying `msg`: signatures, then the
/// message (header, keys, blockhash, compiled instructions).
fn legacy_tx_size(msg: &solana_message::Message) -> usize {
    let sigs = msg.header.num_required_signatures as usize;
    let mut s = compact_len(sigs) + 64 * sigs;
    s += 3 + compact_len(msg.account_keys.len()) + 32 * msg.account_keys.len() + 32;
    s += compact_len(msg.instructions.len());
    for ci in &msg.instructions {
        s += 1 + compact_len(ci.accounts.len()) + ci.accounts.len() + compact_len(ci.data.len()) + ci.data.len();
    }
    s
}

fn compute_budget_program() -> Address {
    Address::from_str_const("ComputeBudget111111111111111111111111111111")
}
fn cu_limit_ix(units: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program_id: compute_budget_program(), accounts: vec![], data }
}
fn cu_price_ix(micro_lamports: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction { program_id: compute_budget_program(), accounts: vec![], data }
}

/// `ix` with every `from` key replaced by `to` (the user paying their own fees).
fn rekey(ix: &Instruction, from: &Address, to: &Address) -> Instruction {
    let mut ix = ix.clone();
    for a in ix.accounts.iter_mut() {
        if &a.pubkey == from {
            a.pubkey = *to;
        }
    }
    ix
}

struct Ledgered {
    env: Env,
    m: Market,
    vs: Vec<VaultRef>,
    borrower: Keypair,
    slots: usize,
    placeholder_prices: bool,
}

impl Ledgered {
    /// `slots - 1` collateral mints and one borrowed mint in the borrower's
    /// ledger, plus one more priced mint the borrower never touched.
    fn new(slots: usize) -> Ledgered {
        let mut env = Env::new();
        let m = Market::new(&mut env);
        let vs: Vec<VaultRef> = (0..=slots)
            .map(|i| m.create_vault(&mut env, 6, Limits::default_limits(), [0x40 + i as u8; 32], None))
            .collect();
        for v in &vs {
            let ix = m.upsert_asset_ix(&env, v, &asset_bytes(true, 9_000, 10_100, 20_000, 60, 100, v.feed));
            env.ok(&[ix], &[&m.admin]);
        }
        let lender = Keypair::new();
        env.fund(&lender);
        let borrower = Keypair::new();
        env.fund(&borrower);
        let mut l = Ledgered { env, m, vs, borrower, slots, placeholder_prices: false };
        // Liquidity in the loan mint and in the untouched mint.
        l.deposit(slots - 1, &lender, 1_000_000 * USDC);
        l.deposit(slots, &lender, 1_000_000 * USDC);
        let b = l.borrower.insecure_clone();
        for i in 0..slots - 1 {
            l.deposit(i, &b, 10_000 * USDC);
        }
        l.env.ok(&[l.m.propose_seal_ix()], &[&l.m.admin]);
        l.env.advance(3 * DAY);
        let refs: Vec<&VaultRef> = l.vs.iter().collect();
        let ix = l.m.execute_seal_ix(&refs);
        l.env.ok(&[ix], &[]);
        l.refresh_prices();
        // Open the loan: the ledger now holds `slots` positions.
        let ix = l.withdraw(slots - 1, 100 * USDC);
        let o = outcome(&l.env.ok(&[ix], &[&b]));
        assert_eq!(o.backed, 100 * USDC, "a signed, collateralised loan is backed");
        l
    }

    fn deposit(&mut self, i: usize, user: &Keypair, amount: u64) {
        let v = &self.vs[i];
        let acc = self.env.token_account(&v.mint, &user.pubkey(), &v.token_program);
        self.env.mint_to(&v.mint, &v.mint_authority, &acc, amount, &v.token_program);
        let ix = self.m.deposit_ix(&self.env, v, &user.pubkey(), &acc, amount);
        self.env.ok(&[ix], &[user]);
    }

    fn refresh_prices(&mut self) {
        let t = self.env.time;
        for v in &self.vs {
            self.env.set_price(&v.price, v.feed, 100_000_000, 20_000, -8, 100_000_000, t);
        }
    }

    /// Pairs for mint `i`, then every other ledger mint in ledger order.
    fn pairs(&self, i: usize) -> Vec<(Address, Address)> {
        // Placeholder prices: every price account is the system program.
        let price = |j: usize| if self.placeholder_prices { SYSTEM } else { self.vs[j].price };
        let mut p = vec![(self.vs[i].asset, price(i))];
        for j in 0..self.slots {
            if j != i {
                p.push((self.vs[j].asset, price(j)));
            }
        }
        p
    }

    fn withdraw(&mut self, i: usize, amount: u64) -> Instruction {
        let to = self.env.token_account(&self.vs[i].mint, &self.borrower.pubkey(), &self.vs[i].token_program);
        let pairs = self.pairs(i);
        self.m.withdraw_ix(&self.env, &self.vs[i], &self.borrower.pubkey(), &to, amount, &pairs)
    }

    /// Measures one release (built as `withdraw(i, amount)`): sizes, a direct
    /// quote_release, then the real release under the default budget (200,000
    /// per instruction; LiteSVM sets no other limit), which it must fit.
    fn measure(&mut self, label: &str, i: usize, amount: u64) -> Cost {
        let ix = self.withdraw(i, amount);
        let b = self.borrower.insecure_clone();
        let payer = self.env.payer.pubkey();
        // Harbor: vault program, caller, user; Vault: 10 fixed; pairs; user [s].
        let pair_accounts = ix.accounts.len() - 3 - 10 - 1;

        // Sizes: as sent (relayer pays, two signatures) and user-pays (one).
        let msg2 = solana_message::Message::new(std::slice::from_ref(&ix), Some(&payer));
        let own = rekey(&ix, &payer, &b.pubkey());
        let msg1 = solana_message::Message::new(std::slice::from_ref(&own), Some(&b.pubkey()));
        let msg1cb = solana_message::Message::new(&[cu_limit_ix(400_000), cu_price_ix(1), own], Some(&b.pubkey()));
        let (k2, s2) = (msg2.account_keys.len(), legacy_tx_size(&msg2));
        let (k1, s1) = (msg1.account_keys.len(), legacy_tx_size(&msg1));
        let (k1cb, s1cb) = (msg1cb.account_keys.len(), legacy_tx_size(&msg1cb));
        // Cross-check the hand count against the SDK's own serialization.
        for msg in [&msg2, &msg1, &msg1cb] {
            let sigs = msg.header.num_required_signatures as usize;
            assert_eq!(legacy_tx_size(msg), compact_len(sigs) + 64 * sigs + msg.serialize().len());
        }

        // Direct Vault call: quote_release runs the same computation, no writes.
        let mut qacc = vec![AccountMeta::new_readonly(self.m.caller, false)];
        qacc.extend(ix.accounts[3..].iter().cloned());
        let nonce = u64::from_le_bytes(ix.data[9..17].try_into().unwrap());
        // The ticket PDA's bump: `release` derives it on chain only when part
        // of the payout queues, and each step below 255 costs extra compute.
        let (_, ticket_bump) = Address::find_program_address(
            &[b"ticket", self.m.protocol.as_ref(), payer.as_ref(), &nonce.to_le_bytes()],
            &self.m.vault_program,
        );
        // Harbor derives its caller PDA on every call, at the same cost per
        // step. Harbor's program id differs between machines, and with it
        // this bump and the protocol PDA in the ticket's seeds.
        let (_, caller_bump) = Address::find_program_address(&[b"bulkhead-caller"], &self.m.harbor);
        let quote = self.m.vault_ix(23, &release_args(amount, nonce), qacc);
        let q = self.env.ok(&[quote], &[&b]);
        let quote_cu = q.compute_units_consumed;
        let quoted = outcome(&q);

        // The release itself, under the default budget.
        let prefix = format!("Program {} consumed ", self.m.vault_program);
        let m = self.env.ok(std::slice::from_ref(&ix), &[&b]);
        let (cu, o) = (m.compute_units_consumed, outcome(&m));
        let vault_cu: u64 = m
            .logs
            .iter()
            .rev()
            .find_map(|l| l.strip_prefix(&prefix)?.split(' ').next()?.parse().ok())
            .unwrap_or(0);
        assert_eq!((o.backed, o.instant, o.queued), (quoted.backed, quoted.instant, quoted.queued), "quote and release agree");
        println!(
            "[{label}] slots={} (asset, price) accounts={pair_accounts} | CU: harbor tx {cu}, vault inside CPI {vault_cu}, \
             direct quote_release {quote_cu} | backed={} instant={} queued={} | ticket bump {ticket_bump}, caller bump {caller_bump}",
            self.slots,
            o.backed / USDC,
            o.instant / USDC,
            o.queued / USDC,
        );
        println!(
            "    relayer+user (2 sigs): {k2} keys, {s2} B, margin {} B | user pays (1 sig): {k1} keys, {s1} B, margin {} B | \
             user pays + CU limit/price ixs: {k1cb} keys, {s1cb} B, margin {} B",
            PACKET as i64 - s2 as i64,
            PACKET as i64 - s1 as i64,
            PACKET as i64 - s1cb as i64,
        );
        // Harbor's caller search runs on every call; the ticket's only when a
        // ticket is created.
        let ticket_steps = if o.queued > 0 { 255 - ticket_bump as u64 } else { 0 };
        let bump_steps = 255 - caller_bump as u64 + ticket_steps;
        Cost { o, cu, bump_steps, pair_accounts, keys2: k2, size2: s2, size1: s1 }
    }
}

/// What one release cost: the outcome, the transaction's compute and the
/// PDA bump-search steps in it (Harbor's caller, and the ticket's), the (asset, price) accounts it named,
/// and the legacy transaction's keys and size with a relayer paying (two
/// signatures) and the user paying (one).
struct Cost {
    o: Outcome,
    cu: u64,
    bump_steps: u64,
    pair_accounts: usize,
    keys2: usize,
    size2: usize,
    size1: usize,
}

/// Every case: under 80,000 CU (about 77k in the worst case measured) apart from two PDA bump
/// searches, each 1,500 CU per step the bump sits below 255: Harbor's caller
/// PDA (its program id decides it) and, when a ticket is created, the ticket's
/// (the protocol, payer and nonce decide it; half of all tickets need none); and, through Harbor,
/// 14 fixed keys plus `mints` (asset, price) pairs, all distinct.
fn assert_cheap(c: &Cost, mints: usize) {
    let net = c.cu - 1_500 * c.bump_steps;
    assert!(net < 80_000, "{} CU, {} of them bump searches", c.cu, c.cu - net);
    assert_eq!(c.pair_accounts, 2 * mints, "one (asset, price) pair per mint");
    assert_eq!(c.keys2, 14 + 2 * mints);
}

/// The cost of `release` for an owner whose ledger holds `slots` positions;
/// returns the size, with a relayer paying, of paying a mint outside the
/// ledger (one more pair than the ledger holds).
fn release_cost_report(slots: usize) -> (usize, usize) {
    let mut l = Ledgered::new(slots);
    let loan = slots - 1;
    println!("== ledger with {slots} positions ({} collateral mints, 1 borrowed) ==", slots - 1);
    // A further backed loan of the borrowed mint: `valid(amount)` holds at once.
    let c = l.measure("borrow more, fully backed", loan, 100 * USDC);
    assert_eq!(c.o.backed, 100 * USDC);
    assert_cheap(&c, slots);
    assert!(c.size2 <= PACKET, "a borrow fits a legacy transaction: {} B", c.size2);
    // Withdrawing collateral while a loan is open: priced, not G2.
    let c = l.measure("withdraw collateral (priced)", 0, 100 * USDC);
    assert_eq!(c.o.backed, 100 * USDC);
    assert_cheap(&c, slots);
    // Over-asking: the binary search runs and the rest queues as a ticket.
    let c = l.measure("over-ask: search + queued ticket", loan, 200_000 * USDC);
    assert!(c.o.backed > 0 && c.o.backed < 200_000 * USDC && c.o.queued > 0);
    assert_cheap(&c, slots);

    // A mint not in the ledger, on a fresh ledger with borrowing room: one
    // more pair than the ledger holds. Below a full ledger the payout is a
    // new, backed position; at a full ledger there is no slot for it, so
    // nothing can be backed, prices or not.
    let mut l = Ledgered::new(slots);
    // A borrow with placeholder price accounts is not a backed loan: nothing
    // can be priced, so it is all unbacked (`07` §2).
    l.placeholder_prices = true;
    let c = l.measure("borrow with placeholder prices", loan, 100 * USDC);
    assert_eq!((c.o.backed, c.o.instant + c.o.queued), (0, 100 * USDC), "placeholders back nothing");
    l.placeholder_prices = false;
    let c = l.measure("withdraw a mint outside the ledger", slots, 10 * USDC);
    assert_cheap(&c, slots + 1);
    let outside = (c.size2, c.size1);
    if slots < MAX_SLOTS_T {
        assert_eq!(c.o.backed, 10 * USDC, "a new position, backed");
    } else {
        assert_eq!((c.o.backed, c.o.instant + c.o.queued), (0, 10 * USDC), "no slot: nothing backed");
        // So no price can change the outcome: the price accounts may all be one placeholder
        // (`07` §2), and the payout then fits a legacy transaction.
        l.placeholder_prices = true;
        let c = l.measure("the same, placeholder prices", slots, 10 * USDC);
        assert_eq!((c.o.backed, c.o.instant + c.o.queued), (0, 10 * USDC));
        assert!(c.size2 <= PACKET, "placeholders: {} B", c.size2);
    }
    outside
}

/// Finding 104: in these cases compute is not the limit (about 77k CU net of PDA
/// bump searches; it grows with the search, so integrators simulate), the size is.
/// With a full ledger (8 mints), a borrow still fits a legacy transaction (1,176
/// of 1,232 bytes with a relayer paying), but paying a ninth mint does not
/// (1,242 bytes) unless the user pays the fees; an integrator's own accounts
/// make it worse. Such borrowers need a v0 transaction with an address lookup
/// table (`07` §2). If this changes, update `07` and `09`.
#[test]
fn a_full_ledger_release_is_cheap_but_a_ninth_mint_needs_v0() {
    assert_eq!(MAX_SLOTS_T, 8);
    let (relayer, user) = release_cost_report(MAX_SLOTS_T);
    assert!(relayer > PACKET, "a ninth mint no longer overflows a legacy transaction: {relayer} B");
    assert!(user <= PACKET, "user pays: {user} B");
}

#[test]
fn a_four_mint_ledger_release_fits_with_room() {
    let (relayer, _) = release_cost_report(4);
    assert!(relayer + 200 <= PACKET, "{relayer} B");
}
