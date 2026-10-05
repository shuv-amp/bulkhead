//! Brakes: guardians and the admin can stop, delay and cancel. None of these
//! instructions can move tokens or choose a recipient (G5).

use crate::state::{Protocol, Ticket};
use crate::*;
use bulkhead_core::consts::{MAX_TICKET_EXTENSION_S, MAX_TICKET_TOTAL_EXTENSION_S};
use bulkhead_core::governance::{can_eject, freeze_until, quorum, Abdications};
use bulkhead_core::limiter::{params_from_config, reset_backlog as core_reset};

fn guardian_or_admin(p: &Protocol, a: &AccountView, now_s: i64) -> ProgramResult {
    require_signer(a)?;
    if key(a) == p.admin {
        return Ok(());
    }
    live_guardian(p, a, now_s).map(|_| ())
}

// ---------------------------------------------------------------------------
// 10. cancel_ticket: a live guardian. The reservation is NOT refunded (G1
//     depends on it). The tokens stay in the vault. Not the admin: a stolen
//     admin key could otherwise cancel every honest queued withdrawal with no
//     counter, and each cancel keeps its reservation, so the lane stays full
//     (docs/15, A4). The admin's brake is `freeze`.
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault [w], 2 ticket [w], 3 guardian [s], 4 rent receiver [w].
pub fn cancel_ticket(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    live_guardian(&p, acc(accounts, 3)?, now()?)?;
    let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    let tk = load(program_id, acc(accounts, 2)?, Ticket::load)?;
    if tk.vault != key(acc(accounts, 1)?) || tk.protocol != key(protocol) {
        return Err(VaultError::WrongVault.into());
    }
    if key(acc(accounts, 4)?) != tk.payer {
        return Err(VaultError::RecipientOwnerMismatch.into());
    }
    v.pending_tickets = v
        .pending_tickets
        .checked_sub(1)
        .ok_or(VaultError::TicketNotPending)?;
    v.queued_amount = v.queued_amount.saturating_sub(tk.amount);
    v.cancelled = v.cancelled.saturating_add(tk.amount as u128);
    save(&mut accounts[1], |d| v.store(d))?;
    close(accounts, 2, 4)?;
    let who = key(&accounts[3]);
    sys::event(&[b"vault:ticket_cancelled", &tk.id.to_le_bytes(), &who]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 11. extend_ticket: live guardian; ≤ 24h per call, ≤ 7 days in total.
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 ticket [w], 2 guardian [s]. Data: secs i64.
pub fn extend_ticket(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let secs = state::R::args(args).i64()?;
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    live_guardian(&p, acc(accounts, 2)?, now()?)?;
    let mut tk = load(program_id, acc(accounts, 1)?, Ticket::load)?;
    if tk.protocol != key(protocol) {
        return Err(VaultError::WrongVault.into());
    }
    if secs <= 0
        || secs > MAX_TICKET_EXTENSION_S
        || tk.extended_s + secs > MAX_TICKET_TOTAL_EXTENSION_S
    {
        return Err(VaultError::ExtensionTooLong.into());
    }
    tk.eta_s += secs;
    tk.extended_s += secs;
    save(&mut accounts[1], |d| tk.store(d))?;
    sys::event(&[
        b"vault:ticket_extended",
        &tk.id.to_le_bytes(),
        &tk.eta_s.to_le_bytes(),
    ]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 12. freeze: live guardian or admin; ≤ 24h per call, re-freezable, never
//     shortens an existing freeze. Scope 0 = whole protocol, 1 = one vault.
// ---------------------------------------------------------------------------
// Accounts: 0 protocol [w], 1 signer [s], 2 vault [w] (scope 1).
// Data: scope u8, secs i64.
pub fn freeze(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let mut r = state::R::args(args);
    let (scope, secs) = (r.u8()?, r.i64()?);
    let protocol = acc(accounts, 0)?;
    let mut p = load_protocol(program_id, protocol)?;
    let t = now()?;
    guardian_or_admin(&p, acc(accounts, 1)?, t)?;
    let who = key(&accounts[1]);
    match scope {
        0 => {
            p.frozen_until =
                freeze_until(p.frozen_until, t, secs).map_err(|_| VaultError::FreezeTooLong)?;
            save(&mut accounts[0], |d| p.store(d))?;
            sys::event(&[b"vault:frozen", &[0], &who, &p.frozen_until.to_le_bytes()]);
        }
        1 => {
            let mut v = load_vault(program_id, protocol, acc(accounts, 2)?)?;
            v.frozen_until =
                freeze_until(v.frozen_until, t, secs).map_err(|_| VaultError::FreezeTooLong)?;
            save(&mut accounts[2], |d| v.store(d))?;
            sys::event(&[b"vault:frozen", &[1], &who, &v.frozen_until.to_le_bytes()]);
        }
        _ => return Err(VaultError::InvalidInstruction.into()),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 13. unfreeze: a live guardian quorum only (the admin can't: Aave's
//     "freeze markets, not unfreeze them").
// ---------------------------------------------------------------------------
// Accounts: 0 protocol [w], 1 vault [w] (scope 1; any account for scope 0),
//           2.. guardians [s]. Data: scope u8.
pub fn unfreeze(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let scope = state::R::args(args).u8()?;
    let protocol = acc(accounts, 0)?;
    let mut p = load_protocol(program_id, protocol)?;
    let t = now()?;
    let alive = p.alive_mask(t);
    let signers = guardian_signers(&p, accounts.get(2..).unwrap_or(&[]))?;
    if !quorum(signers & alive, alive, p.threshold) {
        return Err(VaultError::NoQuorum.into());
    }
    match scope {
        0 => {
            p.frozen_until = p.frozen_until.min(t);
            save(&mut accounts[0], |d| p.store(d))?;
        }
        1 => {
            let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
            v.frozen_until = v.frozen_until.min(t);
            save(&mut accounts[1], |d| v.store(d))?;
        }
        _ => return Err(VaultError::InvalidInstruction.into()),
    }
    sys::event(&[b"vault:unfrozen", &[scope], &[signers & alive]]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 14. heartbeat: a live guardian proves it is awake. A dead guardian can't
//     revive itself; only a new guardian set (a delayed change) does.
// ---------------------------------------------------------------------------
// Accounts: 0 protocol [w], 1 guardian [s].
pub fn heartbeat(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut p = load_protocol(program_id, acc(accounts, 0)?)?;
    let t = now()?;
    let i = live_guardian(&p, acc(accounts, 1)?, t)?;
    p.last_heartbeat[i] = t;
    save(&mut accounts[0], |d| p.store(d))?;
    sys::event(&[b"vault:heartbeat", &[i as u8], &t.to_le_bytes()]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 15. eject: a live quorum of the *other* guardians removes one, at once.
// ---------------------------------------------------------------------------
// Accounts: 0 protocol [w], 1.. guardians [s]. Data: target index u8.
pub fn eject(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let target = state::R::args(args).u8()?;
    let mut p = load_protocol(program_id, acc(accounts, 0)?)?;
    let t = now()?;
    let approvals = guardian_signers(&p, accounts.get(1..).unwrap_or(&[]))?;
    if !can_eject(
        approvals,
        p.alive_mask(t),
        p.threshold,
        target,
        p.guardian_count,
    ) {
        return Err(VaultError::CannotEject.into());
    }
    let (i, n) = (target as usize, p.guardian_count as usize);
    let removed = p.guardians[i];
    for j in i..n - 1 {
        p.guardians[j] = p.guardians[j + 1];
        p.last_heartbeat[j] = p.last_heartbeat[j + 1];
    }
    p.guardians[n - 1] = [0; 32];
    p.last_heartbeat[n - 1] = 0;
    p.guardian_count -= 1;
    save(&mut accounts[0], |d| p.store(d))?;
    sys::event(&[b"vault:ejected", &removed]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 16. reset_backlog: admin or live guardian, only with zero pending tickets;
//     clamps each bucket to "just emptied" (never more than an empty bucket).
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 vault [w], 2 signer [s].
pub fn reset_backlog(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    let t = now()?;
    guardian_or_admin(&p, acc(accounts, 2)?, t)?;
    let mut v = load_vault(program_id, protocol, acc(accounts, 1)?)?;
    // A reset only clamps each bucket to "just emptied" (now + window); it
    // never reads a capacity, so the reference alone is enough here.
    let params = params_from_config(&v.limits, v.ref_balance);
    let mut state = v.limiter_state();
    core_reset(
        &mut state,
        &params,
        t.saturating_mul(1_000),
        v.pending_tickets,
    )
    .map_err(|_| VaultError::TicketsPending)?;
    v.set_limiter_state(state);
    save(&mut accounts[1], |d| v.store(d))?;
    sys::event(&[b"vault:backlog_reset", &v.mint]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 17. abdicate: the admin, with a live guardian quorum, permanently gives up
//     loosening a change kind (Morpho V2). Tightening that kind stays possible.
// ---------------------------------------------------------------------------
// Accounts: 0 protocol [w], 1 admin [s], 2.. guardians [s] forming a live quorum.
// Data: kind u8.
// The quorum is required because abdication can't be undone: an admin key
// alone (possibly stolen) must not be able to give up SetAdmin or
// SetGuardians and keep the protocol locked to it forever (docs/15, A3).
pub fn abdicate(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
    let kind = state::R::args(args).u8()?;
    if kind >= state::change::COUNT {
        return Err(VaultError::InvalidInstruction.into());
    }
    let mut p = load_protocol(program_id, acc(accounts, 0)?)?;
    require_admin(&p, acc(accounts, 1)?)?;
    let alive = p.alive_mask(now()?);
    let signers = guardian_signers(&p, accounts.get(2..).unwrap_or(&[]))?;
    if !quorum(signers & alive, alive, p.threshold) {
        return Err(VaultError::NoQuorum.into());
    }
    p.abdications = Abdications(p.abdications).abdicate(kind).0;
    save(&mut accounts[0], |d| p.store(d))?;
    sys::event(&[b"vault:abdicated", &[kind]]);
    Ok(())
}
