//! The stop path: stage the abort binary, pin a snapshot, stop the program,
//! restore the snapshot with a live quorum, and close buffers nothing refers to.

use crate::*;

// ---------------------------------------------------------------------------
// 1. Stage the abort buffer
// ---------------------------------------------------------------------------
// Accounts: 0 config [w], 1 buffer, 2 programdata, 3.. guardians [s] (only
// to replace a staged one). Anyone stages the first.
// The buffer must hold exactly a canonical abort binary, be frozen (Floor is
// its authority), and fit in the programdata account; a staged abort that the
// loader would reject is worse than none.
//
// A staged abort buffer is replaced only by a live guardian quorum: if a
// runtime change ever made the staged binary undeployable, every stop would
// fail, and the minimal fallback could not be swapped in (docs/09, finding
// 88). One key alone may not, or it could swap the buffer under every stop in
// flight. The replaced buffer is then an orphan the owner may close.
pub(crate) fn stage_abort(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let buffer = acc(accounts, 1)?;
    let programdata = acc(accounts, 2)?;
    if c.abort_buffer != [0; 32] {
        let bits = guardian_signers(&c, accounts.get(3..).unwrap_or(&[]))?;
        let alive = c.alive_mask(now()?);
        if bits == 0 || !quorum(bits & alive, alive, c.threshold) {
            return Err(FloorError::AbortAlreadyStaged.into());
        }
        if key(buffer) == c.abort_buffer {
            return Err(FloorError::WrongBuffer.into());
        }
    }
    if key(programdata) != c.programdata {
        return Err(FloorError::ProgramMismatch.into());
    }
    check_frozen_buffer(program_id, &c, buffer)?;
    {
        let d = buffer.try_borrow()?;
        let abort_elf = &d[BUFFER_DATA_OFFSET..];
        if !is_canonical_abort(abort_elf) {
            return Err(FloorError::NotCanonicalAbort.into());
        }
        let capacity = programdata
            .data_len()
            .saturating_sub(PROGRAMDATA_DATA_OFFSET);
        if abort_elf.len() > capacity {
            return Err(FloorError::AbortDoesNotFit.into());
        }
    }
    c.abort_buffer = key(buffer);
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::ABORT_STAGED, &c.program, &c.abort_buffer]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Pin a snapshot    Accounts: 0 config [w], 1 programdata, 2 buffer. Anyone.
// ---------------------------------------------------------------------------
pub(crate) fn pin_snapshot(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let programdata = acc(accounts, 1)?;
    let buffer = acc(accounts, 2)?;
    if c.status != STATUS_LIVE {
        return Err(FloorError::NotLive.into());
    }
    if key(programdata) != c.programdata {
        return Err(FloorError::ProgramMismatch.into());
    }
    check_frozen_buffer(program_id, &c, buffer)?;
    if !snapshot_identical(buffer, programdata)? {
        return Err(FloorError::SnapshotMismatch.into());
    }
    c.snapshot_buffer = key(buffer);
    c.snapshot_valid = 0; // decided again at the moment of an abort
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::SNAPSHOT_PINNED, &c.program, &c.snapshot_buffer]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Abort
// ---------------------------------------------------------------------------
//
// Accounts: 0 config [w], 1 guardian or owner [s], 2 programdata [w],
//           3 program [w], 4 abort buffer [w], 5 spill [w] (the config itself:
//           finding 88), 6 rent, 7 clock,
//           8 authority PDA, 9 loader-v3, 10 snapshot buffer (required while
//           one is pinned).
//
// A pinned snapshot must be named: otherwise whoever stops the program would
// decide, by leaving it out, that the quorum may not restore it (docs/09,
// finding 53). It always exists while pinned (Floor holds its authority; a
// restore that consumes it clears the pin), and comparing it costs about one
// unit per 250 bytes. An honest stop that names the pin it read cannot fail
// because of the snapshot, even after someone re-pins: any frozen buffer
// byte-identical to the live code is accepted and becomes the pin (docs/09,
// finding 66). A stop that omits account 10, or names the abort buffer or a
// buffer not byte-identical to the live code (other than the current pin),
// is refused (`SnapshotMismatch`). If the current pin's contents ever
// differed from the live code, the stop still lands; only the quorum's fast
// restore would be unavailable.
pub(crate) fn abort(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let t = now()?;
    let signer = acc(accounts, 1)?;
    require_signer(signer)?;
    if key(signer) != c.owner {
        live_guardian(&c, signer, t)?;
    } else if c.alive_mask(t).count_ones() >= c.threshold as u32 {
        // The owner stops the program only while the guardians cannot (fewer
        // than a quorum live). Otherwise a stolen owner key could stop it
        // after every quorum restore, until recovery (docs/15, A4).
        return Err(FloorError::NotLiveGuardian.into());
    }
    if c.status != STATUS_LIVE {
        return Err(FloorError::NotLive.into());
    }
    let (programdata, program, buffer) = (acc(accounts, 2)?, acc(accounts, 3)?, acc(accounts, 4)?);
    check_program_accounts(&c, programdata, program)?;
    if c.abort_buffer == [0; 32] {
        return Err(FloorError::NoAbortBuffer.into());
    }
    if key(buffer) != c.abort_buffer {
        return Err(FloorError::WrongBuffer.into());
    }
    let authority = acc(accounts, 8)?;
    check_authority(program_id, &c, authority)?;
    // The spill (what the loader refunds when it installs the abort binary)
    // is Floor's config, not whoever stops: with SIMD-0433, an `Upgrade`
    // shrinks programdata to the binary and refunds the rest to the spill,
    // ~73 SOL for a program pre-extended to 10 MiB, a reward for a single
    // guardian's stop (docs/09, finding 88). The owner receives it at release.
    if key(acc(accounts, 5)?) != key(acc(accounts, 0)?) {
        return Err(FloorError::WrongAccount.into());
    }

    // Decide, against the exact live bytes, whether the snapshot restores them.
    c.snapshot_valid = 0;
    if c.snapshot_buffer != [0; 32] {
        let snap = accounts.get(10).ok_or(FloorError::SnapshotMismatch)?;
        // The abort buffer is used up by this stop: never a snapshot.
        let restores = key(snap) != c.abort_buffer
            && check_frozen_buffer(program_id, &c, snap).is_ok()
            && snapshot_identical(snap, programdata)?;
        // Anyone may re-pin, so a stop naming an earlier pin must not fail: a
        // buffer that restores the live code is as good as the pin, and
        // becomes it (docs/09, finding 66). Anything else must be the pin.
        if key(snap) != c.snapshot_buffer && !restores {
            return Err(FloorError::SnapshotMismatch.into());
        }
        if restores {
            c.snapshot_buffer = key(snap);
            c.snapshot_valid = 1;
        }
    }

    cpi_upgrade(
        &c,
        programdata,
        program,
        buffer,
        acc(accounts, 5)?,
        acc(accounts, 6)?,
        acc(accounts, 7)?,
        authority,
    )?;

    c.status = STATUS_ABORTED;
    c.aborted_at = t;
    c.abort_buffer = [0; 32];
    // Nothing the owner proposed before the stop may execute after it. A
    // recovery proposal stays: otherwise a stolen owner key could erase it by
    // stopping the program.
    if c.pending_by_recovery == 0 {
        c.clear_pending();
    }
    let who = key(signer);
    save_config(&mut accounts[0], &c)?;
    sys::event(&[
        ev::ABORTED,
        &c.program,
        &who,
        &[c.snapshot_valid],
        &t.to_le_bytes(),
    ]);
    sys::log("Floor: program stopped.");
    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Restore the snapshot (live quorum, instant)
// ---------------------------------------------------------------------------
//
// Accounts: 0 config [w], 1 programdata [w], 2 program [w], 3 snapshot buffer
// [w], 4 spill [w], 5 rent, 6 clock, 7 authority PDA, 8 loader-v3,
// 9.. guardians [s].
pub(crate) fn restore_snapshot(
    program_id: &Address,
    accounts: &mut [AccountView],
) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let t = now()?;
    if c.status != STATUS_ABORTED {
        return Err(FloorError::NotAborted.into());
    }
    if c.snapshot_valid != 1 || c.snapshot_buffer == [0; 32] {
        return Err(FloorError::NoValidSnapshot.into());
    }
    let (programdata, program, buffer) = (acc(accounts, 1)?, acc(accounts, 2)?, acc(accounts, 3)?);
    check_program_accounts(&c, programdata, program)?;
    if key(buffer) != c.snapshot_buffer {
        return Err(FloorError::WrongBuffer.into());
    }
    let authority = acc(accounts, 7)?;
    check_authority(program_id, &c, authority)?;
    let alive = c.alive_mask(t);
    let signers = guardian_signers(&c, accounts.get(9..).unwrap_or(&[]))?;
    let quorum_ok = quorum(signers & alive, alive, c.threshold);
    let snap = c.snapshot_buffer;
    if !can_restore(
        RestoreSource::Snapshot,
        &snap,
        &snap,
        quorum_ok,
        false,
        t,
        0,
        0,
    ) {
        return Err(FloorError::NoQuorum.into());
    }
    // As in `execute`: the snapshot buffer's rent returns to the owner.
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
    c.snapshot_buffer = [0; 32]; // consumed by the upgrade
    c.snapshot_valid = 0;
    if c.pending_by_recovery == 0 {
        c.clear_pending();
    }
    save_config(&mut accounts[0], &c)?;
    sys::event(&[ev::RESTORED, &c.program, &[signers & alive]]);
    sys::log("Floor: restored the exact code that ran before the stop.");
    Ok(())
}

// ---------------------------------------------------------------------------
// 13. Close a buffer Floor holds that nothing refers to (owner)
// ---------------------------------------------------------------------------
//
// Accounts: 0 config, 1 owner [s][w] (receives the rent), 2 buffer [w],
//           3 authority PDA, 4 loader-v3, 5 programdata.
//
// A pin that is replaced (`pin_snapshot`, the re-pin in `abort`) or cleared by
// an upgrade, and a proposal's buffer orphaned by a cancel or a stop, are
// still buffers whose authority is Floor's PDA; without this their rent was
// locked for good (issue #37). Closing them is left to the owner, rather than
// done where they are orphaned, so that a stop never depends on it (finding
// 66). The abort buffer, the pin and the pending proposal's buffer are never
// closed (`buffer_closable`). Only the owner may, so nobody can close a buffer
// someone has just frozen to propose or pin in their next transaction.
//
// While the program is live, a buffer byte-identical to the live code is never
// closed either: a stop accepts any such buffer as the snapshot (finding 66),
// so a guardian's stop in flight may name a pin that was just replaced.
// Closing it ahead of the stop made the stop fail; with a stolen owner key,
// re-pin and close in one transaction held every stop off, slot by slot
// (docs/09, finding 85). The two sets, what a stop accepts and what may be
// closed, are now disjoint. Such a spare pin can be closed once the code
// changes (an upgrade), or after a stop.
pub(crate) fn close_buffer(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let c = load_config(program_id, acc(accounts, 0)?)?;
    let owner = acc(accounts, 1)?;
    require_signer(owner)?;
    if key(owner) != c.owner {
        return Err(FloorError::NotOwner.into());
    }
    let (buffer, authority, programdata) =
        (acc(accounts, 2)?, acc(accounts, 3)?, acc(accounts, 5)?);
    check_authority(program_id, &c, authority)?;
    check_frozen_buffer(program_id, &c, buffer)?;
    if key(programdata) != c.programdata {
        return Err(FloorError::ProgramMismatch.into());
    }
    if c.status == STATUS_LIVE && snapshot_identical(buffer, programdata)? {
        return Err(FloorError::BufferInUse.into());
    }
    let pending_buffer = match c.pending_kind {
        kind::UPGRADE | kind::RESTORE => c.pending_target,
        _ => [0; 32],
    };
    if !buffer_closable(
        &key(buffer),
        &c.abort_buffer,
        &c.snapshot_buffer,
        &pending_buffer,
    ) {
        return Err(FloorError::BufferInUse.into());
    }
    let closed = key(buffer);
    cpi_close_buffer(&c, buffer, owner, authority)?;
    sys::event(&[ev::BUFFER_CLOSED, &c.program, &closed]);
    Ok(())
}
