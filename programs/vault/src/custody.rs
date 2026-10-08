//! Custody: deposit, release (and its dry-run twin, quote), settle.

use crate::state::{Asset, Backing, Protocol, Ticket, Vault};

use crate::*;
use bulkhead_core::consts::MAX_SLOTS;
use bulkhead_core::ledger::{Ledger, Pricing};
use bulkhead_core::limiter::{params_from_config, request, Decision, LimiterError};

/// Loads the backing ledger of `owner`, creating it if it does not exist.
pub(crate) fn load_or_create_backing(
    program_id: &Address,
    accounts: &[AccountView],
    payer_i: usize,
    protocol_i: usize,
    backing_i: usize,
    owner: &[u8; 32],
) -> Result<Backing, ProgramError> {
    let pk = key(acc(accounts, protocol_i)?);
    let backing = acc(accounts, backing_i)?;
    if backing.is_data_empty() {
        let bump = expect_pda(&[seeds::BACKING, &pk, owner], program_id, backing)?;
        let b = [bump];
        create_pda(
            acc(accounts, payer_i)?,
            backing,
            &[
                Seed::from(seeds::BACKING),
                Seed::from(&pk),
                Seed::from(owner),
                Seed::from(&b),
            ],
            Backing::LEN,
            program_id,
        )?;
        return Ok(Backing {
            protocol: pk,
            owner: *owner,
            bump,
            positions: [([0; 32], 0); MAX_SLOTS],
        });
    }
    read_backing(program_id, &pk, backing, owner)
}

/// An existing backing account for `owner`, or an empty ledger if the
/// canonical address holds nothing yet. Never trusts a mismatched account.
pub(crate) fn read_backing(
    program_id: &Address,
    protocol: &[u8; 32],
    backing: &AccountView,
    owner: &[u8; 32],
) -> Result<Backing, ProgramError> {
    if backing.is_data_empty() {
        let bump = expect_pda(&[seeds::BACKING, protocol, owner], program_id, backing)?;
        return Ok(Backing {
            protocol: *protocol,
            owner: *owner,
            bump,
            positions: [([0; 32], 0); MAX_SLOTS],
        });
    }
    let b = load(program_id, backing, Backing::load)?;
    if &b.protocol != protocol
        || &b.owner != owner
        || backing.address() != &derive(&[seeds::BACKING, protocol, owner], b.bump, program_id)
    {
        return Err(VaultError::WrongAddress.into());
    }
    Ok(b)
}

// ---------------------------------------------------------------------------
// 7. deposit
// ---------------------------------------------------------------------------
// Accounts: 0 caller [s], 1 protocol, 2 vault [w], 3 vault token account [w],
//           4 mint, 5 source token account [w], 6 source authority [s],
//           7 backing PDA of the source authority [w], 8 payer [s,w],
//           9 token program, 10 system program.
// Data: amount u64. Returns (return data) the amount actually received.
pub fn deposit(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let amount = state::R::args(args).u64()?;
    if amount == 0 {
        return Err(VaultError::ZeroAmount.into());
    }
    let protocol = acc(accounts, 1)?;
    let p = load_protocol(program_id, protocol)?;
    check_caller(&p, acc(accounts, 0)?)?;
    let mut v = load_vault(program_id, protocol, acc(accounts, 2)?)?;
    let (vault_tokens, mint, source, authority, token_program) = (
        acc(accounts, 3)?,
        acc(accounts, 4)?,
        acc(accounts, 5)?,
        acc(accounts, 6)?,
        acc(accounts, 9)?,
    );
    check_vault_accounts(&v, vault_tokens, mint, token_program)?;
    if source.address() == vault_tokens.address() {
        return Err(VaultError::DuplicateAccount.into());
    }
    require_signer(authority)?;
    check_system(acc(accounts, 10)?)?;

    let t = now()?;
    let before = token::balance(vault_tokens)?;
    touch_reference(&mut v, before, t);
    token::transfer_checked(
        token_program,
        source,
        mint,
        vault_tokens,
        authority,
        amount,
        v.decimals,
        &[],
    )?;
    let received = token::balance(vault_tokens)?
        .checked_sub(before)
        .ok_or(VaultError::Overflow)?;
    v.total_in = v
        .total_in
        .checked_add(received as u128)
        .ok_or(VaultError::Overflow)?;

    let owner = key(authority);
    let mut b = load_or_create_backing(program_id, accounts, 8, 1, 7, &owner)?;
    let mut ledger = b.ledger()?;
    let backed = ledger.credit(v.mint, received);
    b.set_ledger(&ledger);
    save(&mut accounts[7], |d| b.store(d))?;
    save(&mut accounts[2], |d| v.store(d))?;
    pinocchio::cpi::set_return_data(&received.to_le_bytes());
    sys::event(
        &key(&accounts[1]),
        &[
            b"vault:deposited",
            &v.mint,
            &owner,
            &received.to_le_bytes(),
            &[backed as u8],
        ],
    );
    Ok(())
}

fn check_caller(p: &Protocol, caller: &AccountView) -> ProgramResult {
    if !caller.is_signer() || key(caller) != p.caller {
        return Err(VaultError::WrongCaller.into());
    }
    Ok(())
}

fn check_vault_accounts(
    v: &Vault,
    vault_tokens: &AccountView,
    mint: &AccountView,
    token_program: &AccountView,
) -> ProgramResult {
    if key(vault_tokens) != v.token_account {
        return Err(VaultError::WrongVault.into());
    }
    if key(mint) != v.mint {
        return Err(VaultError::WrongMint.into());
    }
    if key(token_program) != v.token_program {
        return Err(VaultError::WrongTokenProgram.into());
    }
    Ok(())
}

/// Pricing table for one release: an entry for the released mint and for every
/// mint in the owner's ledger, built from (asset PDA, price account) pairs the
/// client must pass in that order. Allowlisted status comes from the asset
/// account at the derived address (the client can't make an allowlisted mint
/// look unlisted by omitting it); only prices may be omitted, and an omitted
/// price makes the result fail closed.
struct PriceTable {
    entries: [([u8; 32], Pricing); MAX_SLOTS + 1],
    n: usize,
}

impl PriceTable {
    fn lookup(&self, mint: &[u8; 32]) -> Pricing {
        self.entries[..self.n]
            .iter()
            .find(|(m, _)| m == mint)
            .map(|(_, p)| *p)
            .unwrap_or(Pricing::Unpriced)
    }
}

fn price_table(
    program_id: &Address,
    protocol: &[u8; 32],
    release_mint: &[u8; 32],
    ledger: &Ledger,
    pairs: &[AccountView],
    now_s: i64,
) -> Result<PriceTable, ProgramError> {
    let mut mints = [[0u8; 32]; MAX_SLOTS + 1];
    let mut n = 1;
    mints[0] = *release_mint;
    for pos in ledger.positions() {
        if &pos.mint != release_mint {
            mints[n] = pos.mint;
            n += 1;
        }
    }
    if pairs.len() < 2 * n {
        return Err(VaultError::BadPriceAccount.into());
    }
    let mut t = PriceTable {
        entries: [([0u8; 32], Pricing::NotAllowlisted); MAX_SLOTS + 1],
        n,
    };
    for i in 0..n {
        let (asset_acc, price_acc) = (&pairs[2 * i], &pairs[2 * i + 1]);
        let pricing = if asset_acc.is_data_empty() {
            // No asset record exists at the canonical address: truly not listed.
            expect_pda(&[seeds::ASSET, protocol, &mints[i]], program_id, asset_acc)?;
            Pricing::NotAllowlisted
        } else {
            let a = load(program_id, asset_acc, Asset::load)?;
            if &a.protocol != protocol
                || a.mint != mints[i]
                || asset_acc.address()
                    != &derive(&[seeds::ASSET, protocol, &mints[i]], a.bump, program_id)
            {
                return Err(VaultError::BadPriceAccount.into());
            }
            pyth::pricing(&a, Some(price_acc), now_s)?
        };
        t.entries[i] = (mints[i], pricing);
    }
    Ok(t)
}

fn limiter_error(e: LimiterError) -> ProgramError {
    match e {
        LimiterError::LaneClosed => VaultError::LaneClosed,
        LimiterError::QueueFull => VaultError::QueueFull,
        LimiterError::ZeroAmount => VaultError::ZeroAmount,
        LimiterError::TicketsPending => VaultError::TicketsPending,
    }
    .into()
}

// ---------------------------------------------------------------------------
// 8. release  (and 23. quote_release: same computation, no writes, no signer)
// ---------------------------------------------------------------------------
// Accounts: 0 caller [s], 1 protocol [w], 2 vault [w], 3 vault token account [w],
//           4 mint, 5 recipient token account [w], 6 backing PDA of the
//           recipient's owner [w], 7 token program, 8 payer [s,w],
//           9 ticket PDA ["ticket", protocol, payer, nonce] [w], 10 system,
//           11.. (asset PDA, price account) for the released mint, then for
//           each other mint in the recipient owner's ledger, in ledger order.
// Data: amount u64, then nonce u64 (needed only when part is queued). The
// payer names its own ticket, so queued releases built from the same state
// never race for one address; the ticket's id is still the protocol counter.
// Returns `ReleaseOutcome` as return data: backed, instant, queued (u64),
// ticket_id (u64, meaningful when queued > 0), eta_s (i64).
pub fn release(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
    dry_run: bool,
) -> ProgramResult {
    let mut data = state::R::args(args);
    let amount = data.u64()?;
    let nonce = data.u64().ok();
    if amount == 0 {
        return Err(VaultError::ZeroAmount.into());
    }
    let protocol = acc(accounts, 1)?;
    let mut p = load_protocol(program_id, protocol)?;
    if !dry_run {
        check_caller(&p, acc(accounts, 0)?)?;
    }
    if !p.sealed {
        return Err(VaultError::NotSealed.into());
    }
    let pk = key(protocol);
    let mut v = load_vault(program_id, protocol, acc(accounts, 2)?)?;
    let (vault_tokens, mint, recipient, token_program) = (
        acc(accounts, 3)?,
        acc(accounts, 4)?,
        acc(accounts, 5)?,
        acc(accounts, 7)?,
    );
    check_vault_accounts(&v, vault_tokens, mint, token_program)?;
    if recipient.address() == vault_tokens.address() {
        return Err(VaultError::DuplicateAccount.into());
    }
    let (rmint, owner, _) = token::account_info(recipient)?;
    if owner == key(acc(accounts, 2)?) {
        // A token account the vault PDA owns: the lifeboat (entered only by
        // lifeboat_move, which records the balance), or any other account
        // someone opened for the vault PDA, which no instruction can move
        // tokens out of. Either way a payout there is lost to the ledger.
        return Err(VaultError::DuplicateAccount.into());
    }
    if rmint != v.mint {
        return Err(VaultError::WrongMint.into());
    }
    let mut b = read_backing(program_id, &pk, acc(accounts, 6)?, &owner)?;
    let mut ledger = b.ledger()?;

    let t = now()?;
    let prices = price_table(
        program_id,
        &pk,
        &v.mint,
        &ledger,
        accounts.get(11..).unwrap_or(&[]),
        t,
    )?;
    let lookup = |m: &[u8; 32]| prices.lookup(m);

    // Backed lane: the largest amount the owner's ledger can pay soundly.
    let backed = ledger.backed_amount(&v.mint, amount, &lookup);
    let unbacked = amount - backed;

    // Unbacked lane: the dual-bucket limiter.
    let balance = token::balance(vault_tokens)?;
    touch_reference(&mut v, balance, t);
    // Capacities from min(reference, live balance, low-water balance): money
    // that has left stops counting at once (docs/15, A1), and money that
    // arrived within the window does not count yet (finding 65).
    let params = params_from_config(&v.limits, unbacked_base(&v, balance));
    let frozen_until_ms = p.frozen_until.max(v.frozen_until).saturating_mul(1_000);
    let mut state = v.limiter_state();
    let (mut instant, mut queued, mut eta_s) = (0u64, 0u64, 0i64);
    if unbacked > 0 {
        match request(
            &mut state,
            &params,
            t.saturating_mul(1_000),
            unbacked,
            frozen_until_ms,
        )
        .map_err(limiter_error)?
        {
            Decision::Instant => instant = unbacked,
            Decision::Queued { eta_ms } => {
                queued = unbacked;
                eta_s = eta_ms.div_euclid(1_000) + (eta_ms.rem_euclid(1_000) > 0) as i64;
                // never early
            }
        }
    }
    let ticket_id = p.next_ticket_id;
    let mut outcome = [0u8; 40];
    outcome[0..8].copy_from_slice(&backed.to_le_bytes());
    outcome[8..16].copy_from_slice(&instant.to_le_bytes());
    outcome[16..24].copy_from_slice(&queued.to_le_bytes());
    outcome[24..32].copy_from_slice(&ticket_id.to_le_bytes());
    outcome[32..40].copy_from_slice(&eta_s.to_le_bytes());
    // The lifeboat, or a floor above the live balance, can make the ledger and
    // the limiter promise more than this token account holds. Quote and release
    // must agree: the token program would reject the transfer.
    if backed + instant > balance {
        return Err(VaultError::InsufficientBalance.into());
    }
    if dry_run {
        pinocchio::cpi::set_return_data(&outcome);
        return Ok(());
    }

    ledger
        .debit_backed(v.mint, backed, &lookup)
        .map_err(|_| VaultError::LedgerUnsound)?;
    v.set_limiter_state(state);
    let signer = VaultSigner::new(&v);
    let seeds = signer.seeds();
    token::transfer_checked(
        token_program,
        vault_tokens,
        mint,
        recipient,
        acc(accounts, 2)?,
        backed + instant,
        v.decimals,
        &[Signer::from(&seeds)],
    )?;
    v.backed_out = v.backed_out.saturating_add(backed as u128);
    v.unbacked_out = v.unbacked_out.saturating_add(instant as u128);

    // The ticket's address, for the event (all zero when nothing is queued):
    // it can no longer be derived from the id alone.
    let mut ticket_key = [0u8; 32];
    if queued > 0 {
        let payer = acc(accounts, 8)?;
        require_signer(payer)?;
        check_system(acc(accounts, 10)?)?;
        let nb = nonce.ok_or(VaultError::InvalidInstruction)?.to_le_bytes();
        let pb = key(payer);
        let ticket = acc(accounts, 9)?;
        let bump = expect_pda(&[seeds::TICKET, &pk, &pb, &nb], program_id, ticket)?;
        ticket_key = key(ticket);
        let tb = [bump];
        create_pda(
            payer,
            ticket,
            &[
                Seed::from(seeds::TICKET),
                Seed::from(&pk),
                Seed::from(&pb),
                Seed::from(&nb),
                Seed::from(&tb),
            ],
            Ticket::LEN,
            program_id,
        )?;
        let tk = Ticket {
            protocol: pk,
            vault: key(acc(accounts, 2)?),
            recipient: key(recipient),
            recipient_owner: owner,
            payer: key(payer),
            id: ticket_id,
            amount: queued,
            created_s: t,
            eta_s,
            extended_s: 0,
            bump,
        };
        save(&mut accounts[9], |d| tk.store(d))?;
        p.next_ticket_id += 1;
        v.pending_tickets += 1;
        v.queued_amount = v
            .queued_amount
            .checked_add(queued)
            .ok_or(VaultError::Overflow)?;
        save(&mut accounts[1], |d| p.store(d))?;
    }
    if backed > 0 {
        b.set_ledger(&ledger);
        if !accounts[6].is_data_empty() {
            save(&mut accounts[6], |d| b.store(d))?;
        }
    }
    save(&mut accounts[2], |d| v.store(d))?;
    // Set last: every CPI (the token transfer, the ticket's account) clears
    // return data when it starts.
    pinocchio::cpi::set_return_data(&outcome);
    sys::event(
        &key(&accounts[1]),
        &[b"vault:released", &v.mint, &owner, &outcome, &ticket_key],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 9. settle_ticket (anyone, once due and not frozen)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault [w], 2 vault token account [w], 3 mint,
//           4 ticket [w], 5 recipient token account [w], 6 rent receiver
//           (the ticket's payer) [w], 7 token program.
pub fn settle_ticket(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    let (vault_tokens, mint, ticket, recipient, token_program) = (
        acc(accounts, 2)?,
        acc(accounts, 3)?,
        acc(accounts, 4)?,
        acc(accounts, 5)?,
        acc(accounts, 7)?,
    );
    check_vault_accounts(&v, vault_tokens, mint, token_program)?;
    let tk = load(program_id, ticket, Ticket::load)?;
    if tk.vault != key(acc(accounts, 1)?) || tk.protocol != key(protocol) {
        return Err(VaultError::WrongVault.into());
    }
    if key(recipient) != tk.recipient || key(acc(accounts, 6)?) != tk.payer {
        return Err(VaultError::RecipientOwnerMismatch.into());
    }
    // The owner as it is now: a token account's owner can be changed after the
    // ticket was created. Same rule as `release`.
    if token::account_info(recipient)?.1 == key(acc(accounts, 1)?) {
        return Err(VaultError::DuplicateAccount.into());
    }
    let t = now()?;
    if t < tk.eta_s {
        return Err(VaultError::TicketNotDue.into());
    }
    if t < p.frozen_until.max(v.frozen_until) {
        return Err(VaultError::Frozen.into());
    }
    touch_reference(&mut v, token::balance(vault_tokens)?, t);
    let signer = VaultSigner::new(&v);
    let seeds = signer.seeds();
    token::transfer_checked(
        token_program,
        vault_tokens,
        mint,
        recipient,
        acc(accounts, 1)?,
        tk.amount,
        v.decimals,
        &[Signer::from(&seeds)],
    )?;
    v.pending_tickets = v
        .pending_tickets
        .checked_sub(1)
        .ok_or(VaultError::TicketNotPending)?;
    v.queued_amount = v.queued_amount.saturating_sub(tk.amount);
    v.settled = v.settled.saturating_add(tk.amount as u128);
    v.unbacked_out = v.unbacked_out.saturating_add(tk.amount as u128);
    save(&mut accounts[1], |d| v.store(d))?;
    close(accounts, 4, 6)?;
    sys::event(
        &key(&accounts[0]),
        &[
            b"vault:settled",
            &tk.id.to_le_bytes(),
            &tk.amount.to_le_bytes(),
        ],
    );
    Ok(())
}
