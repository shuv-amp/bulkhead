//! Lifeboat (D7): the admin can move funds instantly, but only *into* a
//! Bulkhead-held lifeboat. Leaving it waits at least 72 hours, is vetoable,
//! and goes only to the destination that was committed at least 72 hours
//! before the exit was proposed. A live guardian quorum (or the admin) can
//! return funds to the vault, so a compromised admin can't use the lifeboat to
//! lock depositors out for long.

use crate::state::R;
use crate::*;
use bulkhead_core::classify::Class;
use bulkhead_core::consts::MIN_LOOSEN_DELAY_S;
use bulkhead_core::governance::{can_execute, quorum, schedule, Schedule};

/// The lifeboat opens a loosen delay after the seal (findings 86 and 88).
/// Opening it with the seal let a stolen pre-seal admin key execute the seal
/// and park the vault in one transaction: no slot in which depositors, now
/// able to withdraw, could. A full delay after the seal, every depositor's own
/// deposit can leave first.
fn require_sealed(p: &crate::state::Protocol, now_s: i64) -> ProgramResult {
    if !p.sealed || now_s < p.sealed_at.saturating_add(p.loosen_delay_s) {
        return Err(VaultError::NotSealed.into());
    }
    Ok(())
}

fn check_lifeboat(
    program_id: &Address,
    protocol: &[u8; 32],
    mint: &[u8; 32],
    a: &AccountView,
) -> Result<u8, ProgramError> {
    expect_pda(&[seeds::LIFEBOAT_TOKENS, protocol, mint], program_id, a)
}

// ---------------------------------------------------------------------------
// 24. lifeboat_move (admin, instant)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault [w], 2 vault token account [w],
//           3 lifeboat token PDA [w], 4 mint, 5 token program, 6 admin [s],
//           7 payer [s,w], 8 system. Data: amount u64.
pub fn move_in(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let amount = R::args(args).u64()?;
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    require_admin(&p, acc(accounts, 6)?)?;
    // Not before the seal. Then every change is instant and nothing can be
    // paid out, the depositors' own withdrawals included: a stolen admin key
    // swapped in its own guardians, parked the deposits and took them out
    // through an exit about 6 days later, with nobody to veto and no way out
    // for depositors (docs/09, finding 86). From the seal, a depositor's own
    // deposit leaves instantly, and an exit still waits 72h in public.
    let t = now()?;
    require_sealed(&p, t)?;
    let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    // A freeze stops the admin parking the vault: otherwise a stolen admin key
    // moves it back in after every quorum return, and own-deposit exits fail
    // for as long as recovery takes (docs/09, finding 72).
    if t < p.frozen_until.max(v.frozen_until) {
        return Err(VaultError::Frozen.into());
    }
    let (vault_tokens, lifeboat, mint, token_program) = (
        acc(accounts, 2)?,
        acc(accounts, 3)?,
        acc(accounts, 4)?,
        acc(accounts, 5)?,
    );
    if key(vault_tokens) != v.token_account
        || key(mint) != v.mint
        || key(token_program) != v.token_program
    {
        return Err(VaultError::WrongVault.into());
    }
    if token::may_charge_transfer_fee(mint)? {
        return Err(VaultError::FeeBearingMint.into());
    }
    let bump = check_lifeboat(program_id, &v.protocol, &v.mint, lifeboat)?;
    if lifeboat.is_data_empty() {
        check_system(acc(accounts, 8)?)?;
        let size = token::account_size(token_program, mint)? as usize;
        let b = [bump];
        create_pda(
            acc(accounts, 7)?,
            lifeboat,
            &[
                Seed::from(seeds::LIFEBOAT_TOKENS),
                Seed::from(&v.protocol),
                Seed::from(&v.mint),
                Seed::from(&b),
            ],
            size,
            token_program.address(),
        )?;
        token::initialize_account(token_program, lifeboat, mint, acc(accounts, 1)?.address())?;
    }
    touch_reference(&mut v, token::balance(vault_tokens)?, t);
    let signer = VaultSigner::new(&v);
    let seeds = signer.seeds();
    token::transfer_checked(
        token_program,
        vault_tokens,
        mint,
        lifeboat,
        acc(accounts, 1)?,
        amount,
        v.decimals,
        &[Signer::from(&seeds)],
    )?;
    // Token-2022 transfer fees reduce the spendable amount credited to the
    // lifeboat. Track its actual balance, not the gross source debit.
    v.lifeboat_amount = token::balance(lifeboat)?;
    save(&mut accounts[1], |d| v.store(d))?;
    sys::event(
        &key(&accounts[0]),
        &[b"vault:lifeboat_in", &v.mint, &amount.to_le_bytes()],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 25. lifeboat_return (admin, or a live guardian quorum)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault [w], 2 vault token account [w],
//           3 lifeboat token PDA [w], 4 mint, 5 token program, 6.. signers
//           (the admin alone, or guardians forming a live quorum).
// Data: amount u64.
pub fn move_back(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let amount = R::args(args).u64()?;
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    let t = now()?;
    let signers = accounts.get(6..).unwrap_or(&[]);
    let by_admin = signers.len() == 1 && signers[0].is_signer() && key(&signers[0]) == p.admin;
    if !by_admin {
        let alive = p.alive_mask(t);
        let bits = guardian_signers(&p, signers)?;
        if !quorum(bits & alive, alive, p.threshold) {
            return Err(VaultError::NoQuorum.into());
        }
    }
    let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    let (vault_tokens, lifeboat, mint, token_program) = (
        acc(accounts, 2)?,
        acc(accounts, 3)?,
        acc(accounts, 4)?,
        acc(accounts, 5)?,
    );
    if key(vault_tokens) != v.token_account
        || key(mint) != v.mint
        || key(token_program) != v.token_program
    {
        return Err(VaultError::WrongVault.into());
    }
    check_lifeboat(program_id, &v.protocol, &v.mint, lifeboat)?;
    touch_reference(&mut v, token::balance(vault_tokens)?, t);
    let signer = VaultSigner::new(&v);
    let seeds = signer.seeds();
    token::transfer_checked(
        token_program,
        lifeboat,
        mint,
        vault_tokens,
        acc(accounts, 1)?,
        amount,
        v.decimals,
        &[Signer::from(&seeds)],
    )?;
    // Reading the source account also repairs any stale gross-transfer value
    // left by an older build.
    v.lifeboat_amount = token::balance(lifeboat)?;
    v.exit_amount = v.exit_amount.min(v.lifeboat_amount);
    save(&mut accounts[1], |d| v.store(d))?;
    sys::event(
        &key(&accounts[0]),
        &[b"vault:lifeboat_out", &v.mint, &amount.to_le_bytes()],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 26. propose_lifeboat_exit (admin; the destination must be ≥ 72h old)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault [w], 2 admin [s]. Data: amount u64.
pub fn propose_exit(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let amount = R::args(args).u64()?;
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    require_admin(&p, acc(accounts, 2)?)?;
    let t = now()?;
    require_sealed(&p, t)?; // findings 86 and 88, as `move_in`
    let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    if t - p.destination_set_s < MIN_LOOSEN_DELAY_S {
        return Err(VaultError::DestinationNotSettled.into());
    }
    if amount == 0 || amount > v.lifeboat_amount {
        return Err(VaultError::NothingToExit.into());
    }
    let s = schedule(t, Class::Loosen, p.loosen_delay_s);
    v.exit_amount = amount;
    v.exit_proposed_s = t;
    v.exit_executable_s = s.executable_s;
    v.exit_expires_s = s.expires_s;
    v.exit_vetoed = false;
    v.exit_proposer = key(acc(accounts, 2)?);
    save(&mut accounts[1], |d| v.store(d))?;
    sys::event(
        &key(&accounts[0]),
        &[
            b"vault:exit_proposed",
            &v.mint,
            &amount.to_le_bytes(),
            &s.executable_s.to_le_bytes(),
        ],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 27. execute_lifeboat_exit (once executable; the destination signs)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault [w], 2 lifeboat token PDA [w], 3 mint,
//           4 destination token account [w], 5 token program,
//           6 the destination (the token account's owner) [s].
//
// The destination signs: an address nobody can sign for (any PDA of this
// program, created or not, or one owning a token account) would hold the
// tokens for good. Refusing only accounts this program owns missed its token
// PDAs and its PDAs not yet created (docs/09, finding 85); no list of
// addresses can be complete, a signature is. A multisig vault, a PDA of
// another program, still signs through that program. Unsigned, the exit is
// refused and the tokens stay in the lifeboat, from which the admin or a
// guardian quorum can move them back (issue #38).
pub fn execute_exit(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    let (lifeboat, mint, dest, token_program) = (
        acc(accounts, 2)?,
        acc(accounts, 3)?,
        acc(accounts, 4)?,
        acc(accounts, 5)?,
    );
    if key(mint) != v.mint || key(token_program) != v.token_program {
        return Err(VaultError::WrongVault.into());
    }
    check_lifeboat(program_id, &v.protocol, &v.mint, lifeboat)?;
    let t = now()?;
    let s = Schedule {
        executable_s: v.exit_executable_s,
        expires_s: v.exit_expires_s,
    };
    if v.exit_amount == 0 {
        return Err(VaultError::NothingToExit.into());
    }
    can_execute(&s, t, v.exit_vetoed, false, false).map_err(|_| VaultError::ChangeNotExecutable)?;
    // A freeze is the incident signal: while the protocol or the vault is
    // frozen nothing leaves Bulkhead's custody, the lifeboat included. A
    // guardian who froze but had no time to veto is still covered, and no key
    // gains a power it lacked: a guardian who can freeze can veto the exit
    // outright (docs/09, finding 134).
    if t < p.frozen_until.max(v.frozen_until) {
        return Err(VaultError::Frozen.into());
    }
    // Only an exit the current admin proposed executes. A recovery rotation
    // replaced a stolen admin, yet an exit it queued while the rotation waited
    // still executed: finding 87's rule for changes, missed here (issue #66).
    if v.exit_proposer != p.admin {
        return Err(VaultError::ChangeStale.into());
    }
    // The destination must have been committed ≥ 72h before this exit was proposed.
    if v.exit_proposed_s - p.destination_set_s < MIN_LOOSEN_DELAY_S {
        return Err(VaultError::DestinationNotSettled.into());
    }
    let (dmint, downer, _) = token::account_info(dest)?;
    if dmint != v.mint || downer != p.lifeboat_destination {
        return Err(VaultError::RecipientOwnerMismatch.into());
    }
    let destination = acc(accounts, 6)?;
    if key(destination) != downer {
        return Err(VaultError::RecipientOwnerMismatch.into());
    }
    if destination.owned_by(program_id) {
        return Err(VaultError::StrandedDestination.into());
    }
    if !destination.is_signer() {
        return Err(VaultError::MissingSignature.into());
    }
    let amount = v.exit_amount;
    let signer = VaultSigner::new(&v);
    let seeds = signer.seeds();
    token::transfer_checked(
        token_program,
        lifeboat,
        mint,
        dest,
        acc(accounts, 1)?,
        amount,
        v.decimals,
        &[Signer::from(&seeds)],
    )?;
    v.lifeboat_amount = token::balance(lifeboat)?;
    v.exit_amount = 0;
    save(&mut accounts[1], |d| v.store(d))?;
    sys::event(
        &key(&accounts[0]),
        &[b"vault:exit_executed", &v.mint, &amount.to_le_bytes()],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 28. veto_lifeboat_exit (any live guardian)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault [w], 2 guardian [s].
pub fn veto_exit(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    live_guardian(&p, acc(accounts, 2)?, now()?)?;
    let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    v.exit_vetoed = true;
    save(&mut accounts[1], |d| v.store(d))?;
    sys::event(&key(&accounts[0]), &[b"vault:exit_vetoed", &v.mint]);
    Ok(())
}
