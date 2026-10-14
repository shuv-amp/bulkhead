//! Guardians: who is a live guardian, which guardians signed, the guardian-set
//! payload, and the instructions that act on the set (heartbeat, eject, and
//! the owner replacing the recovery key with a live quorum).

use crate::*;

/// Index of a signing, live guardian.
pub(crate) fn live_guardian(
    c: &Config,
    a: &AccountView,
    now_s: i64,
) -> Result<usize, ProgramError> {
    require_signer(a)?;
    let i = c
        .guardian_index(&key(a))
        .ok_or(FloorError::NotLiveGuardian)?;
    if c.alive_mask(now_s) & (1 << i) == 0 {
        return Err(FloorError::NotLiveGuardian.into());
    }
    Ok(i)
}

/// Bitmap of guardians among `signers`. Each must sign and be a current
/// guardian; bits are only ever set for occupied slots.
pub(crate) fn guardian_signers(c: &Config, signers: &[AccountView]) -> Result<u8, ProgramError> {
    let pairs = signers.iter().map(|s| (key(s), s.is_signer()));
    signer_bits(&c.guardians, c.guardian_count, pairs).map_err(|e| {
        match e {
            SignerError::NotSigner => FloorError::MissingSignature,
            SignerError::NotGuardian => FloorError::NotLiveGuardian,
        }
        .into()
    })
}

/// Parses `[count u8][count × 32][threshold u8][interval i64]` with the
/// core's `GuardianSet::parse` (the Vault parses with the same function), and
/// returns the set and the number of argument bytes it used.
pub(crate) fn parse_guardian_set(
    args: &[u8],
    owner: &[u8; 32],
    recovery: &[u8; 32],
) -> Result<(GuardianSet, usize), ProgramError> {
    GuardianSet::parse(args, [owner, recovery]).map_err(|e| {
        match e {
            GuardianSetError::Truncated => FloorError::InvalidInstruction,
            GuardianSetError::BadCount | GuardianSetError::BadKey => FloorError::InvalidGuardians,
            GuardianSetError::BadThreshold => FloorError::InvalidThreshold,
            GuardianSetError::BadInterval => FloorError::InvalidInterval,
        }
        .into()
    })
}

// ---------------------------------------------------------------------------
// 9. Heartbeat               Accounts: 0 config [w], 1 guardian [s].
// ---------------------------------------------------------------------------
// A dead guardian cannot revive itself; only a new guardian set (a delayed,
// vetoable proposal) brings it back.
pub(crate) fn heartbeat(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let t = now()?;
    let i = live_guardian(&c, acc(accounts, 1)?, t)?;
    c.last_heartbeat[i] = t;
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::HEARTBEAT, &c.program, &[i as u8], &t.to_le_bytes()]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 10. Eject a guardian (live quorum of the others, instant)
// ---------------------------------------------------------------------------
// Accounts: 0 config [w], 1.. guardians [s]. Data: target index u8.
pub(crate) fn eject(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let target = *args.first().ok_or(FloorError::InvalidInstruction)?;
    let t = now()?;
    let approvals = guardian_signers(&c, accounts.get(1..).unwrap_or(&[]))?;
    if !can_eject(
        approvals,
        c.alive_mask(t),
        c.threshold,
        target,
        c.guardian_count,
    ) {
        return Err(FloorError::CannotEject.into());
    }
    let (i, n) = (target as usize, c.guardian_count as usize);
    let removed = c.guardians[i];
    for j in i..n - 1 {
        c.guardians[j] = c.guardians[j + 1];
        c.last_heartbeat[j] = c.last_heartbeat[j + 1];
    }
    c.guardians[n - 1] = [0; 32];
    c.last_heartbeat[n - 1] = 0;
    c.guardian_count -= 1;
    c.pending_approvals = 0; // indices shifted; approvals must be given again

    // A pending guardian set was written before this ejection and may still
    // name the ejected key: withdraw it, so it cannot bring that key back.
    // The owner may propose again; it waits again.
    if c.pending_kind == kind::SET_GUARDIANS {
        c.clear_pending();
    }
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::EJECTED, &c.program, &removed]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 12. Replace the recovery key (the owner with a live guardian quorum, at once)
// ---------------------------------------------------------------------------
// Accounts: 0 config [w], 1 owner [s], 2.. guardians [s] forming a live quorum.
// Data: the new recovery key[32] (all zero: none).
//
// A stolen recovery key can only propose, but it can do that forever: each
// proposal takes the slot from the owner's, and nothing else could replace
// it. The owner and a live quorum together can, at once (a delayed proposal
// would sit in the slot the stolen key takes). Together they already decide
// more than this (a guardian's stop and a quorum-approved restore install
// code at once); neither can alone.
pub(crate) fn replace_recovery(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let owner = acc(accounts, 1)?;
    require_signer(owner)?;
    if key(owner) != c.owner {
        return Err(FloorError::NotOwner.into());
    }
    let recovery = k32_arg(args, 0)?;
    if recovery == c.owner || c.guardian_index(&recovery).is_some() {
        return Err(FloorError::InvalidInstruction.into());
    }
    let alive = c.alive_mask(now()?);
    let signers = guardian_signers(&c, accounts.get(2..).unwrap_or(&[]))?;
    if !quorum(signers & alive, alive, c.threshold) {
        return Err(FloorError::NoQuorum.into());
    }
    c.recovery = recovery;
    // What the replaced key proposed, or a pending new recovery key, is void.
    if c.pending_by_recovery == 1 || c.pending_kind == kind::SET_RECOVERY {
        c.clear_pending();
    }
    save_config(&mut accounts[0], &c)?;
    sys::event(&[
        ev::RECOVERY_REPLACED,
        &c.program,
        &recovery,
        &[signers & alive],
    ]);
    Ok(())
}
