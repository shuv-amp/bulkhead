//! The Vault with wrapped SOL: the classic SPL Token native mint
//! `So11111111111111111111111111111111111111112`, on the real runtime.
//!
//! A native token account differs from any other in three ways, and each one
//! is a way custody could go wrong: its token amount is its lamports minus a
//! rent-exempt reserve it records at initialization (`is_native`); anyone can
//! raise the amount by sending lamports to it and calling `SyncNative`, with no
//! signature and without the Vault seeing it; and its owner may close it while
//! it still holds tokens (a non-native account must be empty first). The tests
//! below drive the same Harbor paths as `vault.rs` (S1 compromised admin, S4
//! own-deposit exit) through a native vault and check each of the three.
//!
//! LiteSVM 0.16 with mainnet features loads p-token (pinocchio_token_program)
//! as `Tokenkeg…`, the program mainnet now runs, but creates no native mint
//! account, so `native_mint` writes one as mainnet holds it.

mod common;

use bulkhead_core::ema::ema_update;
use bulkhead_core::limiter::{available_now, capacity_base, params_from_config};
use common::vault::*;
use common::*;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

const SOL: u64 = 1_000_000_000; // 9 decimals: one token unit is one lamport
const SOL_FEED: [u8; 32] = [2; 32];
const NATIVE_MINT: Address = Address::from_str_const("So11111111111111111111111111111111111111112");

/// p-token's `TokenError::OwnerMismatch`: the signer is not the account's owner.
const TOKEN_OWNER_MISMATCH: u32 = 4;
/// p-token's `TokenError::NativeNotSupported`: the instruction refuses native accounts.
const TOKEN_NATIVE_NOT_SUPPORTED: u32 = 10;

/// Classic SPL Token instruction tags used here.
mod tok {
    pub const TRANSFER: u8 = 3;
    pub const CLOSE_ACCOUNT: u8 = 9;
    pub const SYNC_NATIVE: u8 = 17;
    pub const WITHDRAW_EXCESS_LAMPORTS: u8 = 38;
}

/// The native mint as mainnet holds it: no mint or freeze authority, nine
/// decimals, initialized, owned by the classic token program. Its supply field
/// is not maintained for wrapped SOL, so zero is as good as any value.
fn native_mint(env: &mut Env) {
    let mut data = vec![0u8; 82];
    data[44] = 9; // decimals
    data[45] = 1; // is_initialized
    let lamports = env.svm.minimum_balance_for_rent_exemption(82);
    env.svm
        .set_account(NATIVE_MINT, Account { lamports, data, owner: token_program(), executable: false, rent_epoch: 0 })
        .unwrap();
}

fn sync_native_ix(account: &Address) -> Instruction {
    Instruction { program_id: token_program(), accounts: vec![AccountMeta::new(*account, false)], data: vec![tok::SYNC_NATIVE] }
}

/// The `is_native` field of a classic token account (bytes 109..121: a u32
/// option tag, then the rent-exempt reserve).
fn is_native(env: &Env, account: &Address) -> Option<u64> {
    let d = env.account(account).data;
    (u32::from_le_bytes(d[109..113].try_into().unwrap()) == 1).then(|| u64::from_le_bytes(d[113..121].try_into().unwrap()))
}

/// The error of a transaction expected to fail, custom or not: some refusals
/// below come from the token program as plain `InstructionError`s.
fn fails_with(env: &mut Env, ixs: &[Instruction], signers: &[&Keypair]) -> InstructionError {
    match env.send(ixs, signers) {
        Ok(m) => panic!("expected failure, got success:\n{}", m.logs.join("\n")),
        Err(e) => match e.err {
            TransactionError::InstructionError(_, ie) => ie,
            other => panic!("not an instruction error: {other:?}\n{}", e.meta.logs.join("\n")),
        },
    }
}

/// A market with one vault, for wrapped SOL, allowlisted and priced like the
/// SOL vault in `vault.rs`.
struct Wsol {
    env: Env,
    m: Market,
    sol: VaultRef,
    /// What a 165-byte token account must hold to be rent exempt: the reserve
    /// every native account records, the vault's own included.
    reserve: u64,
}

impl Wsol {
    fn new() -> Wsol {
        let mut env = Env::new();
        native_mint(&mut env);
        let m = Market::new(&mut env);
        // The native mint has no authority: the key the helper keeps is unused.
        let sol = m.create_vault_for(&mut env, NATIVE_MINT, Keypair::new(), 9, Limits::default_limits(), SOL_FEED, token_program());
        let ix = m.upsert_asset_ix(&env, &sol, &asset_bytes(true, 8_500, 10_500, 20_000, 60, 100, SOL_FEED));
        env.ok(&[ix], &[&m.admin]);
        let reserve = env.svm.minimum_balance_for_rent_exemption(165);
        let mut w = Wsol { env, m, sol, reserve };
        w.refresh_prices();
        w
    }

    /// SOL $150.00 ± 0.075 with EMA $151.00, as in `vault.rs`.
    fn refresh_prices(&mut self) {
        let (t, p) = (self.env.time, self.sol.price);
        self.env.set_price(&p, SOL_FEED, 15_000_000_000, 7_500_000, -8, 15_100_000_000, t);
    }

    fn prices(&self) -> Vec<(Address, Address)> {
        vec![(self.sol.asset, self.sol.price)]
    }

    /// A key with `sol` SOL to wrap, plus fees.
    fn user(&mut self, sol: u64) -> Keypair {
        let k = Keypair::new();
        self.env.svm.airdrop(&k.pubkey(), sol * SOL + SOL).unwrap();
        k
    }

    /// An empty native token account for `owner`: rent-exempt, amount zero.
    fn account(&mut self, owner: &Address) -> Address {
        self.env.token_account(&NATIVE_MINT, owner, &token_program())
    }

    /// How a wallet wraps SOL: a system transfer into its native token account,
    /// then `SyncNative`, which sets the amount to lamports minus the reserve.
    fn wrap(&mut self, user: &Keypair, lamports: u64) -> Address {
        let acc = self.account(&user.pubkey());
        let send = solana_system_interface::instruction::transfer(&user.pubkey(), &acc, lamports);
        self.env.ok(&[send, sync_native_ix(&acc)], &[user]);
        acc
    }

    /// `user` wraps `lamports` and deposits all of it through Harbor.
    fn deposit(&mut self, user: &Keypair, lamports: u64) -> Address {
        let acc = self.wrap(user, lamports);
        let ix = self.m.deposit_ix(&self.env, &self.sol, &user.pubkey(), &acc, lamports);
        self.env.ok(&[ix], &[user]);
        acc
    }

    fn seal(&mut self) {
        self.env.ok(&[self.m.propose_seal_ix()], &[&self.m.admin]);
        self.env.advance(3 * DAY);
        let ix = self.m.execute_seal_ix(&[&self.sol]);
        self.env.ok(&[ix], &[]);
        self.refresh_prices();
    }

    fn balance(&self) -> u64 {
        self.env.balance(&self.sol.vault_tokens)
    }

    /// The vault token account's lamports.
    fn lamports(&self) -> u64 {
        self.env.account(&self.sol.vault_tokens).lamports
    }

    /// The instant unbacked room as the program computes it (views.rs,
    /// attest), recomputed from the vault record: touch the reference and the
    /// low-water balance with the live balance, size the buckets from
    /// min(reference, live, low), then the limiter's available room.
    fn model_available_now(&self) -> u64 {
        let v = read_vault(&self.env, &self.sol.vault);
        let (balance, t) = (self.balance(), self.env.time);
        let low = v.low.touch(balance, t, v.ref_initialized);
        let reference = ema_update(v.ref_balance, v.ref_updated_s, balance, t, v.ref_initialized);
        let params = params_from_config(&v.limits, capacity_base(reference, balance.min(low.low())));
        available_now(&v.limiter_state(), &params, t * 1_000).min(balance)
    }
}

// ---------------------------------------------------------------------------
// 1. The native mint is accepted, and the vault holds a native account.
// ---------------------------------------------------------------------------

/// create_vault takes the native mint like any classic mint (no extensions,
/// nine decimals), and the token account it creates is a native one: the
/// token program records the rent-exempt reserve at initialization, and the
/// owner is the vault PDA, so only the Vault's own signature can move it.
#[test]
fn create_vault_accepts_the_native_mint_and_holds_a_native_account_owned_by_the_vault_pda() {
    let w = Wsol::new();
    let v = read_vault(&w.env, &w.sol.vault);
    assert_eq!(v.mint, NATIVE_MINT.to_bytes());
    assert_eq!(v.token_program, token_program().to_bytes(), "classic SPL Token, not Token-2022");
    assert_eq!(v.token_account, w.sol.vault_tokens.to_bytes());
    assert_eq!(v.decimals, 9);

    let a = w.env.account(&w.sol.vault_tokens);
    assert_eq!(a.owner, token_program());
    assert_eq!(a.data.len(), 165, "GetAccountDataSize: a plain classic account");
    assert_eq!(&a.data[0..32], NATIVE_MINT.as_ref(), "mint");
    assert_eq!(&a.data[32..64], w.sol.vault.as_ref(), "owner: the vault PDA");
    assert_eq!(a.data[108], 1, "initialized, not frozen");
    assert_eq!(&a.data[72..76], &[0; 4], "no delegate");
    assert_eq!(&a.data[129..133], &[0; 4], "no close authority");
    // create_pda funds exactly the reserve, so the vault starts empty.
    assert_eq!(is_native(&w.env, &w.sol.vault_tokens), Some(w.reserve), "a native (wrapped SOL) account");
    assert_eq!((w.balance(), a.lamports), (0, w.reserve));
}

// ---------------------------------------------------------------------------
// 2. Wrap, deposit, and G2: the own deposit comes back at once, in full.
// ---------------------------------------------------------------------------

/// A user wraps 250 SOL and deposits it through Harbor. The ledger credits
/// what arrived in the vault's token amount, which for a native transfer is
/// also exactly the lamports that moved. After the seal, during a guardian
/// freeze and with no price passed, the whole deposit comes back backed and
/// instant (G2, as S4 asserts for USDC), and the user unwraps it all by
/// closing their own account.
#[test]
fn wrapped_sol_deposits_are_credited_exactly_and_come_back_instantly_in_full() {
    let mut w = Wsol::new();
    let user = w.user(300);
    let amount = 250 * SOL;
    let acc = w.wrap(&user, amount);
    assert_eq!(w.env.balance(&acc), amount, "SyncNative: amount = lamports - reserve");
    assert_eq!(w.env.account(&acc).lamports, w.reserve + amount);

    // Asking for one lamport more than was wrapped is the token program's
    // InsufficientFunds (1): lamports sent without SyncNative are not tokens.
    let ix = w.m.deposit_ix(&w.env, &w.sol, &user.pubkey(), &acc, amount + 1);
    assert_eq!(w.env.fails(&[ix], &[&user]), 1, "TokenError::InsufficientFunds");

    let ix = w.m.deposit_ix(&w.env, &w.sol, &user.pubkey(), &acc, amount);
    let m = w.env.ok(&[ix], &[&user]);
    assert_eq!(m.return_data.data, amount.to_le_bytes(), "deposit returns what was received");
    assert_eq!(ledger_of(&w.env, &w.m.backing(&user.pubkey())), vec![(NATIVE_MINT.to_bytes(), amount as i128)]);
    assert_eq!(read_vault(&w.env, &w.sol.vault).total_in, amount as u128);
    assert_eq!(w.balance(), amount);
    assert_eq!(w.lamports(), w.reserve + amount, "the lamports moved with the tokens");
    assert_eq!((w.env.balance(&acc), w.env.account(&acc).lamports), (0, w.reserve));

    w.seal();
    let g0 = w.m.g[0].pubkey();
    let fz = w.m.freeze_ix(&g0, None, DAY);
    w.env.ok(&[fz], &[&w.m.g[0]]);
    let no_price = vec![(w.sol.asset, SYSTEM)];
    let ix = w.m.withdraw_ix(&w.env, &w.sol, &user.pubkey(), &acc, amount, &no_price);
    let m = w.env.ok(&[ix], &[&user]);
    let o = outcome(&m);
    assert_eq!((o.backed, o.instant, o.queued, o.eta_s), (amount, 0, 0, 0), "own deposit: backed, instant, frozen or not");
    assert_eq!(w.env.balance(&acc), amount);
    assert_eq!(w.env.account(&acc).lamports, w.reserve + amount);
    assert!(ledger_of(&w.env, &w.m.backing(&user.pubkey())).is_empty());

    // Unwrapping is the user's own CloseAccount: amount and reserve both go
    // to their wallet.
    let wallet = w.env.account(&user.pubkey()).lamports;
    let close = Instruction {
        program_id: token_program(),
        accounts: vec![AccountMeta::new(acc, false), AccountMeta::new(user.pubkey(), false), AccountMeta::new_readonly(user.pubkey(), true)],
        data: vec![tok::CLOSE_ACCOUNT],
    };
    w.env.ok(&[close], &[&user]);
    assert_eq!(w.env.account(&user.pubkey()).lamports, wallet + amount + w.reserve);
}

// ---------------------------------------------------------------------------
// 3. The stolen admin key, in SOL.
// ---------------------------------------------------------------------------

/// S1 with a 10,000 SOL vault: Harbor's AdminPayout to a fresh account. The
/// limiter never splits a request: it is paid in full, queued in full, or
/// refused. So the whole vault in one request is refused outright (beyond the
/// 7-day horizon: at most 40% fits one request), the 2% burst, 200 SOL, is
/// paid at once (as S1 and the attestation test find 200,000 of 10M USDC),
/// and the next request is a public ticket. A guardian's freeze then makes
/// every unbacked payout wait until after it, and cancelling the tickets
/// leaves the attacker with the burst alone.
#[test]
fn a_stolen_admin_key_takes_at_most_the_burst_of_a_sol_vault_and_a_freeze_stops_the_rest() {
    let mut w = Wsol::new();
    let whale = w.user(10_000);
    w.deposit(&whale, 10_000 * SOL);
    w.seal();
    let a = w.m.attest(&mut w.env, &w.sol);
    assert_eq!((a.balance, a.available_now), (10_000 * SOL, 200 * SOL), "2% burst");
    assert_eq!((a.worst_1h, a.worst_24h), (400 * SOL, 1_000 * SOL), "golden G-6 in SOL");

    let attacker = Keypair::new();
    let loot = w.account(&attacker.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.sol, &loot, &attacker.pubkey(), 10_000 * SOL, &w.prices());
    assert_eq!(w.env.fails(&[ix], &[&w.m.admin]), verr::QUEUE_FULL, "the whole vault: refused, state unchanged");
    assert_eq!(w.balance(), 10_000 * SOL);

    let ix = w.m.admin_payout_ix(&w.env, &w.sol, &loot, &attacker.pubkey(), 200 * SOL, &w.prices());
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!((o.backed, o.instant, o.queued), (0, 200 * SOL, 0), "the burst, unbacked and instant");

    w.env.advance(60);
    w.refresh_prices();
    let ix = w.m.admin_payout_ix(&w.env, &w.sol, &loot, &attacker.pubkey(), 3_000 * SOL, &w.prices());
    let (id, ticket) = w.m.next_ticket(&w.env);
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!((o.backed, o.instant, o.queued, o.ticket_id), (0, 0, 3_000 * SOL, id), "the rest: a ticket");
    assert!(o.eta_s >= w.env.time + 21_600, "no earlier than the 6h minimum delay");
    assert_eq!(w.env.balance(&loot), 200 * SOL);
    assert_eq!(w.env.account(&loot).lamports, w.reserve + 200 * SOL);

    // A guardian freezes. An hour later the short bucket has refilled, yet
    // even a 1 SOL payout is not instant: it waits until after the freeze.
    let fz = w.m.freeze_ix(&w.m.g[0].pubkey(), None, DAY);
    w.env.ok(&[fz], &[&w.m.g[0]]);
    let frozen_until = read_protocol(&w.env, &w.m.protocol).frozen_until;
    w.env.advance(3_600);
    w.refresh_prices();
    assert_eq!(w.m.attest(&mut w.env, &w.sol).available_now, 0, "frozen: nothing unbacked is instant");
    let ix = w.m.admin_payout_ix(&w.env, &w.sol, &loot, &attacker.pubkey(), SOL, &w.prices());
    let (id2, ticket2) = w.m.next_ticket(&w.env);
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!((o.instant, o.queued), (0, SOL));
    assert!(o.eta_s >= frozen_until, "queued behind the freeze");
    assert_eq!(w.env.balance(&loot), 200 * SOL);

    // The guardian cancels both tickets: the attacker keeps the burst only.
    let g0 = w.m.g[0].pubkey();
    for (t, i) in [(ticket, id), (ticket2, id2)] {
        let ix = w.m.cancel_ix(&w.sol, &t, i, &g0, &w.env.payer.pubkey());
        w.env.ok(&[ix], &[&w.m.g[0]]);
    }
    let a = w.m.attest(&mut w.env, &w.sol);
    assert_eq!((a.pending, a.queued, a.balance), (0, 0, 9_800 * SOL));
    assert_eq!(w.env.balance(&loot), 200 * SOL);
}

// ---------------------------------------------------------------------------
// 4. Lamports sent straight into the vault.
// ---------------------------------------------------------------------------

/// Anyone can raise the vault's amount without the Vault: send lamports to
/// its token account (crediting lamports needs no owner signature), then call
/// SyncNative (which needs no signature at all). That is a donation: the live
/// balance rises, but nobody's ledger and not `total_in`.
///
/// It does not raise the instant unbacked room above what the existing base
/// allows. The base is min(reference, live balance, low-water balance)
/// (lib.rs, unbacked_base), and the next touch sees the donation as balance
/// that was there since the previous touch: the reference steps toward it by
/// dt/24h, and the low-water keeps the lowest balance a touch saw in the
/// current and previous 30-minute window. A minute after a touch both are
/// still the pre-donation balance, so the burst is unchanged, in the view and
/// on the payout path.
///
/// After a quiet day (no touch for 24h and two windows) the next touch takes
/// the whole balance as the reference, donation included: the burst becomes
/// 2% of it. This is the same for any mint when tokens are transferred
/// straight to a vault's token account, and it is not a loss to depositors:
/// the donor leaves the whole amount in the vault to raise the instant room
/// by 2% of it. In between, a donation `dt` after the last touch (and more
/// than a window after it) lifts the base by `donation * dt / 24h`.
#[test]
fn lamports_sent_straight_into_the_vault_credit_nobody_and_do_not_raise_the_burst_at_once() {
    let mut w = Wsol::new();
    let whale = w.user(10_000);
    w.deposit(&whale, 10_000 * SOL);
    w.seal();
    // A small deposit touches the reference: three quiet days, so it starts
    // at the 10,000 SOL the deposit saw before its own transfer.
    let small = w.user(2);
    w.deposit(&small, SOL);
    let v = read_vault(&w.env, &w.sol.vault);
    assert_eq!((v.ref_balance, v.low.low(), v.total_in), (10_000 * SOL, 10_000 * SOL, 10_001 * SOL as u128));
    let burst = w.m.attest(&mut w.env, &w.sol).available_now;
    assert_eq!(burst, 200 * SOL, "2% of min(10,000 reference, 10,001 live, 10,000 low)");

    w.env.advance(60);
    w.refresh_prices();
    let donor = w.user(5_000);
    let send = solana_system_interface::instruction::transfer(&donor.pubkey(), &w.sol.vault_tokens, 5_000 * SOL);
    w.env.ok(&[send], &[&donor]);
    assert_eq!(w.lamports(), w.reserve + 15_001 * SOL);
    assert_eq!(w.balance(), 10_001 * SOL, "lamports are not tokens until SyncNative");
    // Anyone syncs it: SyncNative lists no signer, so a key that owns
    // nothing here sends it, paying the fee and signing nothing else.
    let stranger = w.user(0);
    let msg = Message::new(&[sync_native_ix(&w.sol.vault_tokens)], Some(&stranger.pubkey()));
    let tx = Transaction::new(&[&stranger], msg, w.env.svm.latest_blockhash());
    w.env.svm.send_transaction(tx).expect("SyncNative from a stranger");
    w.env.svm.expire_blockhash();
    assert_eq!(w.balance(), 15_001 * SOL, "the live balance rose");
    assert_eq!(is_native(&w.env, &w.sol.vault_tokens), Some(w.reserve), "the reserve did not move");

    // Credited to nobody: both ledgers as they were, no backing record for the
    // donor (nor the stranger), total_in unchanged.
    assert_eq!(ledger_of(&w.env, &w.m.backing(&whale.pubkey())), vec![(NATIVE_MINT.to_bytes(), 10_000 * SOL as i128)]);
    assert_eq!(ledger_of(&w.env, &w.m.backing(&small.pubkey())), vec![(NATIVE_MINT.to_bytes(), SOL as i128)]);
    assert!(w.env.svm.get_account(&w.m.backing(&donor.pubkey())).is_none());
    assert!(w.env.svm.get_account(&w.m.backing(&stranger.pubkey())).is_none());
    assert_eq!(read_vault(&w.env, &w.sol.vault).total_in, 10_001 * SOL as u128);

    // The instant room: unchanged in the view, and the model agrees.
    assert_eq!(w.m.attest(&mut w.env, &w.sol).available_now, burst, "the donation did not raise the burst");
    assert_eq!(w.model_available_now(), burst);
    // And on the payout path: the old burst is paid at once, one lamport more
    // queues. Sized from the 15,001 SOL live balance the burst would be 300 SOL.
    let attacker = Keypair::new();
    let loot = w.account(&attacker.pubkey());
    let ix = w.m.admin_payout_ix(&w.env, &w.sol, &loot, &attacker.pubkey(), burst, &w.prices());
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!((o.instant, o.queued), (burst, 0));
    let ix = w.m.admin_payout_ix(&w.env, &w.sol, &loot, &attacker.pubkey(), 1, &w.prices());
    let o = outcome(&w.env.ok(&[ix], &[&w.m.admin]));
    assert_eq!((o.instant, o.queued), (0, 1), "nothing beyond the pre-donation burst is instant");
    assert_eq!(w.env.balance(&loot), burst);

    // After a quiet day the donation counts like any balance held for a day.
    w.env.advance(DAY + 3_600);
    w.refresh_prices();
    let live = w.balance();
    assert_eq!(live, 14_801 * SOL);
    let a = w.m.attest(&mut w.env, &w.sol);
    assert_eq!(a.available_now, live / 50, "2% of the live balance, donation included");
    assert_eq!(w.model_available_now(), a.available_now);
}

// ---------------------------------------------------------------------------
// 5. The rent-exempt reserve never leaves.
// ---------------------------------------------------------------------------

/// A release moves token amount, and for a native account the token program
/// moves exactly that many lamports: the reserve is not part of the amount,
/// so no release can reach it. Asking for one lamport more than the balance
/// is refused by the Vault itself (InsufficientBalance: the backed part is the
/// whole deposit and the unbacked lamport would exceed the balance). The full
/// exit leaves the account initialized, rent exempt and empty, and the next
/// deposit and exit work as the first did.
#[test]
fn a_full_exit_never_pays_the_rent_reserve_and_leaves_the_vault_account_usable() {
    let mut w = Wsol::new();
    let user = w.user(100);
    let amount = 40 * SOL;
    let acc = w.deposit(&user, amount);
    w.seal();
    assert_eq!(w.lamports(), w.reserve + amount);

    let ix = w.m.withdraw_ix(&w.env, &w.sol, &user.pubkey(), &acc, amount + 1, &w.prices());
    assert_eq!(w.env.fails(&[ix], &[&user]), verr::INSUFFICIENT_BALANCE, "never into the reserve");

    let ix = w.m.withdraw_ix(&w.env, &w.sol, &user.pubkey(), &acc, amount, &w.prices());
    let o = outcome(&w.env.ok(&[ix], &[&user]));
    assert_eq!((o.backed, o.instant, o.queued), (amount, 0, 0));
    assert_eq!(w.env.account(&acc).lamports, w.reserve + amount, "the user got the amount and no more");
    let a = w.env.account(&w.sol.vault_tokens);
    assert_eq!((w.balance(), a.lamports), (0, w.reserve), "empty, and exactly rent exempt");
    assert_eq!(a.lamports, w.env.svm.minimum_balance_for_rent_exemption(a.data.len()));
    assert_eq!((a.owner, a.data[108]), (token_program(), 1), "still an initialized token account");
    assert_eq!(is_native(&w.env, &w.sol.vault_tokens), Some(w.reserve));

    // Usable: the same wrapped SOL goes back in, and out again.
    w.env.advance(60);
    w.refresh_prices();
    let ix = w.m.deposit_ix(&w.env, &w.sol, &user.pubkey(), &acc, amount);
    w.env.ok(&[ix], &[&user]);
    assert_eq!(w.lamports(), w.reserve + amount);
    let ix = w.m.withdraw_ix(&w.env, &w.sol, &user.pubkey(), &acc, amount, &w.prices());
    assert_eq!(outcome(&w.env.ok(&[ix], &[&user])).backed, amount);
    assert_eq!((w.balance(), w.lamports()), (0, w.reserve));
}

// ---------------------------------------------------------------------------
// 6. Nobody closes the vault's account or takes its lamports.
// ---------------------------------------------------------------------------

/// The token program lets a native account's owner close it with tokens in
/// it (amount and reserve go to the destination), so who the owner is decides
/// everything: it is the vault PDA, which signs only inside Vault
/// instructions, and the Vault issues no CloseAccount, Transfer,
/// SetAuthority or WithdrawExcessLamports (token.rs makes only
/// TransferChecked, InitializeAccount3 and GetAccountDataSize CPIs). The
/// admin and a depositor each try to close it and transfer out of it (the
/// token program's OwnerMismatch) and to withdraw its lamports (refused for
/// every native account, NativeNotSupported), and the account is left
/// exactly as it was.
#[test]
fn nobody_can_close_the_vault_account_or_withdraw_its_lamports_outside_the_vault() {
    let mut w = Wsol::new();
    let user = w.user(100);
    let acc = w.deposit(&user, 50 * SOL);
    w.seal();
    let before = w.env.account(&w.sol.vault_tokens);
    for (who, k) in [("admin", &w.m.admin), ("depositor", &user)] {
        let me = k.pubkey();
        let close = Instruction {
            program_id: token_program(),
            accounts: vec![AccountMeta::new(w.sol.vault_tokens, false), AccountMeta::new(me, false), AccountMeta::new_readonly(me, true)],
            data: vec![tok::CLOSE_ACCOUNT],
        };
        assert_eq!(fails_with(&mut w.env, &[close], &[k]), InstructionError::Custom(TOKEN_OWNER_MISMATCH), "{who}: CloseAccount");
        let mut d = vec![tok::TRANSFER];
        d.extend_from_slice(&(50 * SOL).to_le_bytes());
        let transfer = Instruction {
            program_id: token_program(),
            accounts: vec![AccountMeta::new(w.sol.vault_tokens, false), AccountMeta::new(acc, false), AccountMeta::new_readonly(me, true)],
            data: d,
        };
        assert_eq!(fails_with(&mut w.env, &[transfer], &[k]), InstructionError::Custom(TOKEN_OWNER_MISMATCH), "{who}: Transfer");
        let withdraw = Instruction {
            program_id: token_program(),
            accounts: vec![AccountMeta::new(w.sol.vault_tokens, false), AccountMeta::new(me, false), AccountMeta::new_readonly(me, true)],
            data: vec![tok::WITHDRAW_EXCESS_LAMPORTS],
        };
        // Refused before any authority check: a native account's lamports
        // above the reserve are its amount, so none of them are "excess".
        let e = fails_with(&mut w.env, &[withdraw], &[k]);
        assert_eq!(e, InstructionError::Custom(TOKEN_NATIVE_NOT_SUPPORTED), "{who}: WithdrawExcessLamports");
        w.env.next_slot();
    }
    let after = w.env.account(&w.sol.vault_tokens);
    assert_eq!((after.lamports, after.data, after.owner), (before.lamports, before.data, before.owner));
    // The depositor's way out is still the Vault's, in full.
    let ix = w.m.withdraw_ix(&w.env, &w.sol, &user.pubkey(), &acc, 50 * SOL, &w.prices());
    assert_eq!(outcome(&w.env.ok(&[ix], &[&user])).backed, 50 * SOL);
}

// ---------------------------------------------------------------------------
// 7. Lamports at the vault's token address before the vault exists.
// ---------------------------------------------------------------------------

/// The vault's token account is a PDA, so its address is known before
/// create_vault runs, and anyone can send lamports there first. create_pda
/// allocates and assigns an address that already holds lamports (lib.rs,
/// create_pda), so the vault is still created; and InitializeAccount3 on the
/// native mint sets the amount to lamports minus the reserve, so the vault
/// starts with a balance nobody deposited. That is the donation of test 4,
/// made before genesis: no ledger and not `total_in` count it, the reserve is
/// the same, and deposits after it are credited exactly as usual. (A
/// non-native mint ignores the lamports: its amount starts at zero.)
#[test]
fn lamports_sent_to_the_vault_token_address_before_create_vault_become_an_uncredited_balance() {
    let mut env = Env::new();
    native_mint(&mut env);
    let m = Market::new(&mut env);
    let vault_tokens = pda(&[b"vault-tokens", m.protocol.as_ref(), NATIVE_MINT.as_ref()], &m.vault_program);
    let send = solana_system_interface::instruction::transfer(&env.payer.pubkey(), &vault_tokens, 7 * SOL);
    env.ok(&[send], &[]);
    let sol = m.create_vault_for(&mut env, NATIVE_MINT, Keypair::new(), 9, Limits::default_limits(), SOL_FEED, token_program());
    assert_eq!(sol.vault_tokens, vault_tokens);
    let reserve = env.svm.minimum_balance_for_rent_exemption(165);
    assert_eq!(env.account(&vault_tokens).lamports, 7 * SOL, "create_pda added nothing: it already held more than rent");
    assert_eq!(is_native(&env, &vault_tokens), Some(reserve));
    assert_eq!(env.balance(&vault_tokens), 7 * SOL - reserve, "the excess became token amount");
    assert_eq!(&env.account(&vault_tokens).data[32..64], sol.vault.as_ref(), "still owned by the vault PDA");
    let v = read_vault(&env, &sol.vault);
    assert_eq!((v.total_in, v.ref_initialized), (0, false), "credited to nobody, and not yet seen");

    // A deposit after it is credited exactly what it moved.
    let user = Keypair::new();
    env.svm.airdrop(&user.pubkey(), 11 * SOL).unwrap();
    let acc = env.token_account(&NATIVE_MINT, &user.pubkey(), &token_program());
    let send = solana_system_interface::instruction::transfer(&user.pubkey(), &acc, 10 * SOL);
    env.ok(&[send, sync_native_ix(&acc)], &[&user]);
    let ix = m.deposit_ix(&env, &sol, &user.pubkey(), &acc, 10 * SOL);
    env.ok(&[ix], &[&user]);
    assert_eq!(ledger_of(&env, &m.backing(&user.pubkey())), vec![(NATIVE_MINT.to_bytes(), 10 * SOL as i128)]);
    assert_eq!(read_vault(&env, &sol.vault).total_in, 10 * SOL as u128);
    assert_eq!(env.balance(&vault_tokens), 17 * SOL - reserve);
}
