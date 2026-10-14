//! Loader-v3: the program and buffer accounts Floor checks, the snapshot
//! comparison, and the `Upgrade` and `Close` CPIs it signs as the authority PDA.

use crate::*;

/// A buffer whose authority is Floor's authority PDA: nobody can write to it
/// again, so its bytes are frozen.
pub(crate) fn check_frozen_buffer(
    program_id: &Address,
    c: &Config,
    buffer: &AccountView,
) -> ProgramResult {
    if !buffer.owned_by(&LOADER_V3) {
        return Err(FloorError::NotLoaderV3.into());
    }
    let data = buffer.try_borrow()?;
    let auth = buffer_authority(&data).ok_or(FloorError::WrongBuffer)?;
    if auth != Some(authority_address(program_id, c).to_bytes()) {
        return Err(FloorError::BufferNotFrozen.into());
    }
    Ok(())
}

/// A buffer that restores the live code, exactly as
/// `bulkhead_core::floor::snapshot_restorable` defines it (byte identity, and
/// at least the ELF's declared length), using `sol_memcmp_`.
pub(crate) fn snapshot_identical(
    buffer: &AccountView,
    programdata: &AccountView,
) -> Result<bool, ProgramError> {
    let b = buffer.try_borrow()?;
    let p = programdata.try_borrow()?;
    let (bp, pp) = match (
        b.get(BUFFER_DATA_OFFSET..),
        p.get(PROGRAMDATA_DATA_OFFSET..),
    ) {
        (Some(bp), Some(pp)) => (bp, pp),
        _ => return Ok(false),
    };
    let n = bp.len();
    // At least as long as the live ELF says it is: a copy cut before its
    // trailing zeros matched, but the loader cannot redeploy it (finding 88).
    let Some(extent) = elf_extent(pp) else {
        return Ok(false);
    };
    Ok(n > 0
        && n >= extent
        && n <= pp.len()
        && sys::bytes_equal(bp, &pp[..n])
        && sys::all_zero(&pp[n..]))
}

pub(crate) fn live_code_is_v3(programdata: &AccountView) -> Result<u8, ProgramError> {
    let p = programdata.try_borrow()?;
    let elf = p.get(PROGRAMDATA_DATA_OFFSET..).unwrap_or(&[]);
    Ok(deployable_after_simd0500(elf_info(elf)) as u8)
}

/// Loader-v3 `Upgrade`, signed by Floor's authority PDA.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cpi_upgrade(
    c: &Config,
    programdata: &AccountView,
    program: &AccountView,
    buffer: &AccountView,
    spill: &AccountView,
    rent: &AccountView,
    clock: &AccountView,
    authority: &AccountView,
) -> ProgramResult {
    if rent.address() != &SYSVAR_RENT || clock.address() != &SYSVAR_CLOCK {
        return Err(FloorError::WrongSysvar.into());
    }
    let metas = [
        InstructionAccount::writable(programdata.address()),
        InstructionAccount::writable(program.address()),
        InstructionAccount::writable(buffer.address()),
        InstructionAccount::writable(spill.address()),
        InstructionAccount::readonly(rent.address()),
        InstructionAccount::readonly(clock.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];
    let data = 3u32.to_le_bytes(); // UpgradeableLoaderInstruction::Upgrade
    let ix = InstructionView {
        program_id: &LOADER_V3,
        data: &data,
        accounts: &metas,
    };
    let bump = [c.authority_bump];
    let seeds = [
        Seed::from(AUTHORITY_SEED),
        Seed::from(&c.program),
        Seed::from(&bump),
    ];
    invoke_signed(
        &ix,
        &[programdata, program, buffer, spill, rent, clock, authority],
        &[Signer::from(&seeds)],
    )
}

/// Loader-v3 `Close` of a buffer Floor holds, signed by Floor's authority PDA;
/// its rent goes to `recipient`. Only ever a buffer: `check_frozen_buffer`
/// accepts nothing else, and a buffer's `Close` takes no program account.
pub(crate) fn cpi_close_buffer(
    c: &Config,
    buffer: &AccountView,
    recipient: &AccountView,
    authority: &AccountView,
) -> ProgramResult {
    let metas = [
        InstructionAccount::writable(buffer.address()),
        InstructionAccount::writable(recipient.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];
    let data = 5u32.to_le_bytes(); // UpgradeableLoaderInstruction::Close
    let ix = InstructionView {
        program_id: &LOADER_V3,
        data: &data,
        accounts: &metas,
    };
    let bump = [c.authority_bump];
    let seeds = [
        Seed::from(AUTHORITY_SEED),
        Seed::from(&c.program),
        Seed::from(&bump),
    ];
    invoke_signed(
        &ix,
        &[buffer, recipient, authority],
        &[Signer::from(&seeds)],
    )
}

pub(crate) fn check_program_accounts(
    c: &Config,
    programdata: &AccountView,
    program: &AccountView,
) -> ProgramResult {
    if key(programdata) != c.programdata || key(program) != c.program {
        return Err(FloorError::ProgramMismatch.into());
    }
    Ok(())
}
