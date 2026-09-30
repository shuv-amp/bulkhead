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
use solana_instruction::AccountMeta;
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

/// A10: at the seal, every backing claim (imports plus what deposits
/// credited) must be covered by the tokens the vault holds.
#[test]
fn the_seal_requires_imports_and_deposits_to_be_covered_together() {
    let mut w = World::new();
    let depositor = w.user();
    w.deposit("usdc", &depositor, 1_000 * USDC);
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
    // The migration moves the imported tokens in; then every claim is covered.
    w.env.mint_to(&w.usdc.mint, &w.usdc.mint_authority, &w.usdc.vault_tokens, 1_000 * USDC, &w.usdc.token_program);
    let ix = w.m.execute_seal_ix(&[&w.usdc, &w.sol]);
    w.env.ok(&[ix], &[]);
}

/// A8: a mint that can be closed (and then created again with other
/// extensions) can't become a vault; the same extension with no close
/// authority can.
#[test]
fn a_mint_with_a_close_authority_cannot_become_a_vault() {
    let mut env = Env::new();
    let m = Market::new(&mut env);
    let t22 = token_2022();
    for (close_authority, allowed) in [(Some(Keypair::new().pubkey()), false), (None, true)] {
        let mint = Keypair::new();
        let size = 165 + 1 + 4 + 32; // base padded to 165, account type, one TLV entry
        let lamports = env.svm.minimum_balance_for_rent_exemption(size);
        let create = solana_system_interface::instruction::create_account(&env.payer.pubkey(), &mint.pubkey(), lamports, size as u64, &t22);
        let mut d = vec![25u8]; // InitializeMintCloseAuthority
        match close_authority {
            Some(k) => {
                d.push(1);
                d.extend_from_slice(k.as_ref());
            }
            None => d.push(0),
        }
        let init_close = solana_instruction::Instruction { program_id: t22, accounts: vec![AccountMeta::new(mint.pubkey(), false)], data: d };
        let mut d = vec![20u8, 6]; // InitializeMint2
        d.extend_from_slice(Keypair::new().pubkey().as_ref());
        d.push(0);
        let init_mint = solana_instruction::Instruction { program_id: t22, accounts: vec![AccountMeta::new(mint.pubkey(), false)], data: d };
        env.ok(&[create, init_close, init_mint], &[&mint]);
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
        if allowed {
            env.ok(&[ix], &[&m.admin]);
        } else {
            assert_eq!(env.fails(&[ix], &[&m.admin]), verr::EXTENSION_NOT_ALLOWED);
        }
    }
}

/// attest never reports more than the vault holds, even with a floor far
/// above the balance.
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
    w.env.ok(&[ix], &[&w.m.admin]); // before the seal a change applies at once
    w.seal();
    let a = w.m.attest(&mut w.env, &w.usdc);
    assert_eq!(a.balance, 1_000 * USDC);
    assert_eq!(a.available_now, 1_000 * USDC, "the balance, not the 1,000,000 floor");
}

/// A11: Harbor forwards only to the Vault it was built for, even to a copy of
/// the Vault program deployed at another address.
#[test]
fn harbor_forwards_only_to_its_own_vault() {
    let mut w = World::new();
    let depositor = w.user();
    let from = w.account("usdc", &depositor.pubkey());
    let (mint, auth, program) = (w.usdc.mint, &w.usdc.mint_authority, w.usdc.token_program);
    w.env.mint_to(&mint, auth, &from, 1_000 * USDC, &program);
    let copy = Address::new_unique();
    w.env.svm.add_program(copy, &so("bulkhead_vault")).unwrap();
    let mut ix = w.m.deposit_ix(&w.env, &w.usdc, &depositor.pubkey(), &from, 1_000 * USDC);
    ix.accounts[0].pubkey = copy;
    assert_eq!(
        w.env.fails_err(&[ix], &[&depositor]),
        solana_transaction_error::TransactionError::InstructionError(0, solana_instruction_error::InstructionError::IncorrectProgramId)
    );
    let ix = w.m.deposit_ix(&w.env, &w.usdc, &depositor.pubkey(), &from, 1_000 * USDC);
    w.env.ok(&[ix], &[&depositor]);
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

/// A7: raising the loosen delay is a tightening and applies at once, so it is
/// capped (30 days); above the cap a single key could stall governance.
#[test]
fn the_loosen_delay_is_capped_at_30_days() {
    let mut w = World::new();
    w.seal();
    let zero = Address::default();
    let ix = w.m.propose_change_ix(&w.env, 5, &zero, &(30 * DAY + 1).to_le_bytes(), None);
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::DELAY_ABOVE_MAXIMUM);
    let ix = w.m.propose_change_ix(&w.env, 5, &zero, &(30 * DAY).to_le_bytes(), None);
    w.env.ok(&[ix], &[&w.m.admin]);
    let d = w.env.account(&w.m.protocol).data;
    assert_eq!(i64::from_le_bytes(d[436..444].try_into().unwrap()), 30 * DAY, "raised at once, to the cap");
    // A new protocol can't register above the cap either.
    let harbor = Address::new_unique();
    w.env.svm.add_program(harbor, &so("bulkhead_harbor")).unwrap();
    let ix = w.m.register_ix(&w.env, harbor, 30 * DAY + 1);
    assert_eq!(w.env.fails(&[ix], &[]), verr::DELAY_ABOVE_MAXIMUM);
    let ix = w.m.register_ix(&w.env, harbor, 30 * DAY);
    w.env.ok(&[ix], &[]);
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
    let (base, _) = w.m.next_ticket(&w.env);
    let mut ixs = Vec::new();
    for k in 0..10u64 {
        let amount = if k == 1 { 99_000 } else { 100_000 } * USDC;
        let mut ix = w.m.admin_payout_ix(&w.env, &w.usdc, &loot, &attacker.pubkey(), amount, &w.usdc_prices(true));
        // The first two fit the burst; each later one becomes ticket base + (k - 2).
        let id = base + k.saturating_sub(2);
        let ticket = pda(&[b"ticket", w.m.protocol.as_ref(), &id.to_le_bytes()], &w.m.vault_program);
        ix.accounts[3 + 9 - 1].pubkey = ticket; // Harbor: 3 own accounts, then Vault release index 9 at 3 + (9 - 1)
        ixs.push(ix);
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
    for id in base..base + 8 {
        let t = pda(&[b"ticket", w.m.protocol.as_ref(), &id.to_le_bytes()], &w.m.vault_program);
        let ix = w.m.cancel_ix(&w.usdc, &t, &g0, &w.env.payer.pubkey());
        w.env.ok(&[ix], &[&w.m.g[0]]);
    }
    assert_eq!(w.env.balance(&loot), 199_000 * USDC);
    assert_eq!(w.env.balance(&w.usdc.vault_tokens), 9_801_000 * USDC, "98% stays");
}
