//! Proposals: one pending change at a time (an upgrade, a restore, a release
//! of the authority, or a setting), vetoed or approved by guardians, executed
//! after its delay, or cancelled by its proposer.

use crate::*;

// ---------------------------------------------------------------------------
// 4. Propose (owner; the recovery key only a new owner or recovery key)
// ---------------------------------------------------------------------------
//
// Accounts: 0 config [w], 1 owner or recovery key [s], 2 target buffer
// (Upgrade/Restore only). Data: kind u8, target[32], payload.
//
// The recovery key replaces a stolen owner key (docs/15, A4): its proposal
// waits the delay and any guardian can veto it, but the owner can neither
// cancel it nor block it, since it takes the place of a pending owner proposal.
pub(crate) fn propose(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let signer = acc(accounts, 1)?;
    require_signer(signer)?;
    let k = *args.first().ok_or(FloorError::InvalidInstruction)?;
    let by_recovery = c.recovery != [0; 32] && key(signer) == c.recovery;
    if by_recovery {
        if k != kind::SET_OWNER && k != kind::SET_RECOVERY {
            return Err(FloorError::NotOwner.into());
        }
    } else if key(signer) != c.owner || (k == kind::SET_RECOVERY && c.recovery != [0; 32]) {
        return Err(FloorError::NotOwner.into());
    }
    let t = now()?;
    // Raising the delay is a tightening: instant. A recovery-key proposal in
    // the slot, which the owner cannot cancel, must not keep the owner from
    // it (docs/09, finding 62); it stays in the slot.
    if k == kind::SET_DELAY && !by_recovery && c.pending_by_recovery == 1 {
        let d = i64_arg(args.get(33..).unwrap_or(&[]), 0)?;
        check_delay(d)?;
        if d >= c.upgrade_delay_s {
            c.upgrade_delay_s = d;
            save_config(&mut accounts[0], &c)?;
            sys::event(&[ev::DELAY_RAISED, &c.program, &d.to_le_bytes()]);
            return Ok(());
        }
    }
    if c.pending_kind != kind::NONE {
        // A recovery proposal that can never execute (vetoed or expired) no
        // longer holds the slot: only the recovery key may cancel it, so it
        // would otherwise block every owner proposal for good.
        let dead_recovery =
            c.pending_by_recovery == 1 && (c.pending_vetoed != 0 || t >= c.pending_expires);
        if (by_recovery && c.pending_by_recovery == 0) || dead_recovery {
            c.clear_pending();
        } else {
            return Err(FloorError::ProposalPending.into());
        }
    }
    let target = k32_arg(args, 1)?;
    let payload = &args[33..];
    if payload.len() > MAX_PAYLOAD {
        return Err(FloorError::InvalidInstruction.into());
    }
    match k {
        kind::UPGRADE => {
            if c.status != STATUS_LIVE {
                return Err(FloorError::NotLive.into());
            }
        }
        kind::RESTORE => {
            if c.status != STATUS_ABORTED {
                return Err(FloorError::NotAborted.into());
            }
        }
        kind::RELEASE_AUTHORITY => {}
        // The owner and the recovery key stay distinct, or recovery means nothing.
        // The owner is never a guardian (as `parse_guardian_set` keeps it
        // from the other side), or the owner's limits fall away (finding 57).
        kind::SET_OWNER => {
            if target == [0; 32] || target == c.recovery || c.guardian_index(&target).is_some() {
                return Err(FloorError::InvalidInstruction.into());
            }
        }
        kind::SET_RECOVERY => {
            if target == c.owner || c.guardian_index(&target).is_some() {
                return Err(FloorError::InvalidInstruction.into());
            }
        }
        kind::SET_GUARDIANS => {
            parse_guardian_set(payload, &c.owner, &c.recovery)?;
        }
        kind::SET_DELAY => {
            let d = i64_arg(payload, 0)?;
            check_delay(d)?;
            if d >= c.upgrade_delay_s {
                // Raising the delay is a tightening: instant.
                c.upgrade_delay_s = d;
                save_config(&mut accounts[0], &c)?;
                sys::event(&[ev::DELAY_RAISED, &c.program, &d.to_le_bytes()]);
                return Ok(());
            }
        }
        _ => return Err(FloorError::WrongProposalKind.into()),
    }
    if k == kind::UPGRADE || k == kind::RESTORE {
        let buffer = acc(accounts, 2)?;
        // Upgrading from the staged abort buffer would use it up and leave
        // Floor pointing at a closed account: no stop, and no way to stage
        // another (docs/09, finding 58). The pinned snapshot is the quorum's.
        if key(buffer) != target || target == c.abort_buffer || target == c.snapshot_buffer {
            return Err(FloorError::WrongBuffer.into());
        }
        check_frozen_buffer(program_id, &c, buffer)?;
    }
    c.pending_kind = k;
    c.pending_by_recovery = by_recovery as u8;
    c.pending_vetoed = 0;
    c.pending_approvals = 0;
    c.pending_id = c.pending_id.checked_add(1).ok_or(FloorError::Overflow)?;
    c.pending_target = target;
    c.pending_eta = upgrade_eta(t, c.upgrade_delay_s);
    c.pending_expires = c.pending_eta + CHANGE_EXPIRY_S;
    c.pending_payload = [0; MAX_PAYLOAD];
    c.pending_payload[..payload.len()].copy_from_slice(payload);
    c.pending_payload_len = payload.len() as u16;
    save_config(&mut accounts[0], &c)?;
    sys::event(&[
        ev::PROPOSED,
        &c.program,
        &[k],
        &c.pending_id.to_le_bytes(),
        &target,
        &c.pending_eta.to_le_bytes(),
    ]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Veto (any live guardian)       Accounts: 0 config [w], 1 guardian [s].
//    Data: empty, or the pending proposal id (u64). An id that is no longer
//    pending is refused, so a retry cannot veto a proposal that replaced it.
// ---------------------------------------------------------------------------
pub(crate) fn veto(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let guardian = acc(accounts, 1)?;
    live_guardian(&c, guardian, now()?)?;
    if c.pending_kind == kind::NONE {
        return Err(FloorError::NoProposal.into());
    }
    if !args.is_empty() {
        let id: [u8; 8] = args
            .try_into()
            .map_err(|_| FloorError::InvalidInstruction)?;
        if u64::from_le_bytes(id) != c.pending_id {
            return Err(FloorError::NoProposal.into());
        }
    }
    c.pending_vetoed = 1;
    let who = key(guardian);
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::VETOED, &c.program, &c.pending_id.to_le_bytes(), &who]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Approve a restore (guardians)  Accounts: 0 config [w], 1.. guardians [s].
//    Data: the pending proposal's id (u64).
// ---------------------------------------------------------------------------
pub(crate) fn approve(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    if c.pending_kind != kind::RESTORE {
        return Err(FloorError::WrongProposalKind.into());
    }
    // The approval names the proposal it is for: guardians review a buffer,
    // and an owner who cancels it and proposes another before their signatures
    // land must not collect them for that one (docs/09, finding 58).
    let id: [u8; 8] = args
        .try_into()
        .map_err(|_| FloorError::InvalidInstruction)?;
    if u64::from_le_bytes(id) != c.pending_id {
        return Err(FloorError::NoProposal.into());
    }
    let bits = guardian_signers(&c, accounts.get(1..).unwrap_or(&[]))?;
    if bits == 0 || bits & c.alive_mask(now()?) != bits {
        return Err(FloorError::NotLiveGuardian.into());
    }
    c.pending_approvals |= bits;
    save_config(&mut accounts[0], &c)?;
    sys::event(&[
        ev::APPROVED,
        &c.program,
        &c.pending_id.to_le_bytes(),
        &[c.pending_approvals],
    ]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Execute the pending proposal (anyone, once allowed; a release to a key:
//    that key signs; a release to none: the owner signs)
// ---------------------------------------------------------------------------
//
// Upgrade / Restore accounts: 0 config [w], 1 programdata [w], 2 program [w],
//   3 buffer [w], 4 spill [w] (the owner: the buffer's rent returns to it),
//   5 rent, 6 clock, 7 authority PDA, 8 loader-v3.
// ReleaseAuthority: 0 config [w], 1 programdata [w], 2 authority PDA,
//   3 loader-v3, 4 owner [w] (receives the config's and the buffers' rent;
//   signs a release to none, finding 95),
//   5 new authority [s] (omitted when the target is zero: program becomes
//   immutable), then the staged abort buffer [w] and the pinned snapshot [w],
//   each required while set: nothing could close them once the config is gone.
//   Then, optionally, any other frozen buffer Floor holds [w], such as a spare
//   pin identical to the live code that `close_buffer` refuses while live; each
//   is closed to the owner, anything else is skipped (finding 93).
//   The new authority signs (`SetAuthorityChecked`): a mistyped key nobody
//   holds fails here, while the config still exists, instead of leaving the
//   program with no one able to upgrade it (issue #39).
// SetGuardians / SetOwner / SetDelay: 0 config [w].
pub(crate) fn execute(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let c = load_config(program_id, acc(accounts, 0)?)?;
    let t = now()?;
    let schedule = Schedule {
        executable_s: c.pending_eta,
        expires_s: c.pending_expires,
    };
    let vetoed = c.pending_vetoed != 0;
    match c.pending_kind {
        kind::NONE => Err(FloorError::NoProposal.into()),
        kind::UPGRADE | kind::RESTORE => {
            execute_code(program_id, accounts, c, t, &schedule, vetoed)
        }
        kind::RELEASE_AUTHORITY => execute_release(program_id, accounts, c, t, &schedule, vetoed),
        kind::SET_GUARDIANS | kind::SET_OWNER | kind::SET_DELAY | kind::SET_RECOVERY => {
            execute_config(accounts, c, t, &schedule, vetoed)
        }
        _ => Err(FloorError::WrongProposalKind.into()),
    }
}

/// Installs the pending buffer: an upgrade once its delay is over, or a
/// restore (after a stop) with a live quorum's approval of that buffer or its
/// delay. The buffer's rent goes to the owner.
fn execute_code(
    program_id: &Address,
    accounts: &mut [AccountView],
    mut c: Config,
    t: i64,
    schedule: &Schedule,
    vetoed: bool,
) -> ProgramResult {
    let (programdata, program, buffer) = (acc(accounts, 1)?, acc(accounts, 2)?, acc(accounts, 3)?);
    check_program_accounts(&c, programdata, program)?;
    // Staged or pinned since the proposal: still never consumed here.
    if key(buffer) != c.pending_target
        || c.pending_target == c.abort_buffer
        || c.pending_target == c.snapshot_buffer
    {
        return Err(FloorError::WrongBuffer.into());
    }
    let authority = acc(accounts, 7)?;
    check_authority(program_id, &c, authority)?;
    if c.pending_kind == kind::UPGRADE {
        if c.status != STATUS_LIVE {
            return Err(FloorError::NotLive.into());
        }
        can_execute(schedule, t, vetoed, false, false).map_err(gov_error)?;
    } else {
        if c.status != STATUS_ABORTED {
            return Err(FloorError::NotAborted.into());
        }
        let alive = c.alive_mask(t);
        let quorum_ok = quorum(c.pending_approvals & alive, alive, c.threshold);
        // Approvals are only ever recorded for the pending buffer.
        let ok = can_restore(
            RestoreSource::Proposed,
            &c.pending_target,
            &c.pending_target,
            quorum_ok,
            vetoed,
            t,
            c.pending_eta,
            c.pending_expires,
        );
        if !ok {
            return Err(FloorError::NotExecutable.into());
        }
    }
    // The buffer's rent goes back to the owner who funded it, not to
    // whoever executes first (docs/09, finding 58).
    if key(acc(accounts, 4)?) != c.owner {
        return Err(FloorError::NotOwner.into());
    }
    cpi_upgrade(
        &c,
        programdata,
        program,
        buffer,
        acc(accounts, 4)?,
        acc(accounts, 5)?,
        acc(accounts, 6)?,
        authority,
    )?;
    c.status = STATUS_LIVE;
    c.elf_is_v3 = live_code_is_v3(programdata)?;
    c.snapshot_buffer = [0; 32]; // the live code changed
    c.snapshot_valid = 0;
    let (k, id) = (c.pending_kind, c.pending_id);
    c.clear_pending();
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::EXECUTED, &c.program, &[k], &id.to_le_bytes()]);
    Ok(())
}

/// Releases the upgrade authority (to a key that signs, or to none with the
/// owner's signature), closes every buffer Floor still holds, then the config.
fn execute_release(
    program_id: &Address,
    accounts: &mut [AccountView],
    c: Config,
    t: i64,
    schedule: &Schedule,
    vetoed: bool,
) -> ProgramResult {
    can_execute(schedule, t, vetoed, false, false).map_err(gov_error)?;
    let programdata = acc(accounts, 1)?;
    let authority = acc(accounts, 2)?;
    if key(programdata) != c.programdata {
        return Err(FloorError::ProgramMismatch.into());
    }
    check_authority(program_id, &c, authority)?;
    if key(acc(accounts, 4)?) != c.owner {
        return Err(FloorError::NotOwner.into());
    }
    // A release to none: the owner signs. Unsigned, a stranger who
    // executed first could leave out the spares the owner meant to
    // close, and nothing could close them afterwards (finding 95). A
    // release to a key is signed by that key below.
    if c.pending_target == [0; 32] {
        require_signer(&accounts[4])?;
    }
    // Close what Floor still holds: after this nothing can (issue #37).
    let rest = accounts.get(5..).unwrap_or(&[]);
    // Anyone may re-pin while the program is live, so a release naming
    // the pin it read must not fail: a passed frozen copy of the live
    // code stands in for the pin and is closed with the spares below,
    // as in `abort` (finding 66). A stranger's re-pin keeps its rent.
    let mut live_copy = false;
    if c.status == STATUS_LIVE {
        for a in rest {
            if key(a) != c.abort_buffer
                && check_frozen_buffer(program_id, &c, a).is_ok()
                && snapshot_identical(a, programdata)?
            {
                live_copy = true;
                break;
            }
        }
    }
    for held in [c.abort_buffer, c.snapshot_buffer] {
        if held == [0; 32] {
            continue;
        }
        let Some(buffer) = rest.iter().find(|a| key(a) == held) else {
            if held == c.snapshot_buffer && live_copy {
                continue;
            }
            return Err(FloorError::WrongBuffer.into());
        };
        check_frozen_buffer(program_id, &c, buffer)?;
        cpi_close_buffer(&c, buffer, &accounts[4], authority)?;
    }
    // And any other buffer Floor holds that the caller passes. A spare
    // identical to the live code cannot be closed while the program is
    // live (`BufferInUse`), so this is its last chance (issue #68).
    // Anything else (the new authority, a closed or foreign account)
    // is skipped.
    for (i, buffer) in rest.iter().enumerate() {
        let k = key(buffer);
        if k == c.abort_buffer
            || k == c.snapshot_buffer
            || rest[..i].iter().any(|a| key(a) == k)
            || check_frozen_buffer(program_id, &c, buffer).is_err()
        {
            continue;
        }
        cpi_close_buffer(&c, buffer, &accounts[4], authority)?;
    }
    let bump = [c.authority_bump];
    let seeds = [
        Seed::from(AUTHORITY_SEED),
        Seed::from(&c.program),
        Seed::from(&bump),
    ];
    if c.pending_target == [0; 32] {
        let data = 4u32.to_le_bytes(); // SetAuthority, to none
        let metas = [
            InstructionAccount::writable(programdata.address()),
            InstructionAccount::readonly_signer(authority.address()),
        ];
        let ix = InstructionView {
            program_id: &LOADER_V3,
            data: &data,
            accounts: &metas,
        };
        invoke_signed(&ix, &[programdata, authority], &[Signer::from(&seeds)])?;
    } else {
        let new_authority = acc(accounts, 5)?;
        if key(new_authority) != c.pending_target {
            return Err(FloorError::WrongBuffer.into());
        }
        require_signer(new_authority)?;
        let data = 7u32.to_le_bytes(); // SetAuthorityChecked
        let metas = [
            InstructionAccount::writable(programdata.address()),
            InstructionAccount::readonly_signer(authority.address()),
            InstructionAccount::readonly_signer(new_authority.address()),
        ];
        let ix = InstructionView {
            program_id: &LOADER_V3,
            data: &data,
            accounts: &metas,
        };
        invoke_signed(
            &ix,
            &[programdata, authority, new_authority],
            &[Signer::from(&seeds)],
        )?;
    }
    // Close the config; its rent goes to the owner.
    let lamports = accounts[0].lamports();
    let credit = accounts[4]
        .lamports()
        .checked_add(lamports)
        .ok_or(FloorError::Overflow)?;
    accounts[4].set_lamports(credit);
    accounts[0].set_lamports(0);
    accounts[0].close()?;
    sys::event(&[
        ev::EXECUTED,
        &c.program,
        &[kind::RELEASE_AUTHORITY],
        &c.pending_target,
    ]);
    Ok(())
}

/// Applies a pending setting: a guardian set, an owner, a delay or a recovery
/// key, each checked again against the roles as they are now.
fn execute_config(
    accounts: &mut [AccountView],
    mut c: Config,
    t: i64,
    schedule: &Schedule,
    vetoed: bool,
) -> ProgramResult {
    can_execute(schedule, t, vetoed, false, false).map_err(gov_error)?;
    let len = c.pending_payload_len as usize;
    let mut payload = [0u8; MAX_PAYLOAD];
    payload[..len].copy_from_slice(&c.pending_payload[..len]);
    match c.pending_kind {
        kind::SET_GUARDIANS => {
            let (set, _) = parse_guardian_set(&payload[..len], &c.owner, &c.recovery)?;
            c.guardians = set.keys;
            c.guardian_count = set.count;
            c.threshold = set.threshold;
            c.heartbeat_interval_s = set.interval_s;
            c.last_heartbeat = [t; MAX_GUARDIANS]; // the new set starts alive
        }
        kind::SET_OWNER => {
            if c.pending_target == c.recovery || c.guardian_index(&c.pending_target).is_some() {
                return Err(FloorError::InvalidInstruction.into());
            }
            c.owner = c.pending_target;
        }
        kind::SET_RECOVERY => {
            if c.pending_target == c.owner || c.guardian_index(&c.pending_target).is_some() {
                return Err(FloorError::InvalidInstruction.into());
            }
            c.recovery = c.pending_target;
        }
        _ => {
            let d = i64_arg(&payload[..len], 0)?;
            check_delay(d)?;
            c.upgrade_delay_s = d;
        }
    }
    let (k, id) = (c.pending_kind, c.pending_id);
    c.clear_pending();
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::EXECUTED, &c.program, &[k], &id.to_le_bytes()]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 11. Cancel the pending proposal (its proposer)  Accounts: 0 config [w], 1 owner or recovery key [s].
// ---------------------------------------------------------------------------
pub(crate) fn cancel(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let signer = acc(accounts, 1)?;
    require_signer(signer)?;
    if c.pending_kind == kind::NONE {
        return Err(FloorError::NoProposal.into());
    }
    // Each key withdraws only its own proposal: a stolen owner key cannot
    // cancel the recovery key's.
    let by_recovery = c.recovery != [0; 32] && key(signer) == c.recovery;
    let allowed = if c.pending_by_recovery == 1 {
        by_recovery
    } else {
        key(signer) == c.owner
    };
    if !allowed {
        return Err(FloorError::NotOwner.into());
    }
    let id = c.pending_id;
    c.clear_pending();
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::CANCELLED, &c.program, &id.to_le_bytes()]);
    Ok(())
}
