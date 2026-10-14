//! Registration: take a program's upgrade authority, with its guardians and
//! delay chosen in the same instruction.

use crate::*;

// ---------------------------------------------------------------------------
// 0. Register
// ---------------------------------------------------------------------------
//
// Accounts: 0 payer [s,w], 1 config [w], 2 authority PDA, 3 program,
//           4 programdata [w], 5 current upgrade authority [s],
//           6 system program, 7 loader-v3.
// Data: owner[32], guardian set, upgrade_delay i64.
//
// The current authority signs, and Floor itself performs the handover
// (`SetAuthority` by CPI) in the same instruction, so there is never a moment
// when Floor holds the authority but someone else chose the guardians.
pub(crate) fn register(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let owner = k32_arg(args, 0)?;
    if owner == [0; 32] {
        return Err(FloorError::InvalidGuardians.into());
    }
    let (set, used) = parse_guardian_set(args.get(32..).unwrap_or(&[]), &owner, &[0; 32])?;
    let delay = i64_arg(args, 32 + used)?;
    // Optional recovery key after the delay (absent or all zero: none).
    // Absent: none. Present, all 32 bytes: a cut-off key is an error, not none.
    let recovery = if args.len() <= 32 + used + 8 {
        [0; 32]
    } else {
        k32_arg(args, 32 + used + 8)?
    };
    // No key holds two roles: a guardian that is also the recovery key would
    // never veto its own new owner (docs/09, finding 62).
    if recovery == owner || (recovery != [0; 32] && set.contains(&recovery)) {
        return Err(FloorError::InvalidGuardians.into());
    }
    check_delay(delay)?;

    let payer = acc(accounts, 0)?;
    let config = acc(accounts, 1)?;
    let authority = acc(accounts, 2)?;
    let program = acc(accounts, 3)?;
    let programdata = acc(accounts, 4)?;
    let current = acc(accounts, 5)?;
    let system = acc(accounts, 6)?;
    require_signer(payer)?;
    require_signer(current)?;
    if system.address() != &SYSTEM_PROGRAM {
        return Err(FloorError::WrongProgram.into());
    }

    // The protected program and its programdata.
    if !program.owned_by(&LOADER_V3) || !programdata.owned_by(&LOADER_V3) {
        return Err(FloorError::NotLoaderV3.into());
    }
    {
        let pdata = program.try_borrow()?;
        if program_programdata(&pdata) != Some(key(programdata)) {
            return Err(FloorError::ProgramMismatch.into());
        }
    }
    let elf_is_v3;
    {
        let d = programdata.try_borrow()?;
        let h = programdata_header(&d).ok_or(FloorError::ProgramMismatch)?;
        if h.upgrade_authority != Some(key(current)) {
            return Err(FloorError::NotCurrentAuthority.into());
        }
        elf_is_v3 = deployable_after_simd0500(elf_info(&d[PROGRAMDATA_DATA_OFFSET..])) as u8;
    }

    // PDAs, with canonical bumps.
    let (config_addr, config_bump) =
        Address::find_program_address(&[CONFIG_SEED, program.address().as_ref()], program_id);
    let (auth_addr, authority_bump) =
        Address::find_program_address(&[AUTHORITY_SEED, program.address().as_ref()], program_id);
    if config.address() != &config_addr {
        return Err(FloorError::WrongConfigAddress.into());
    }
    if authority.address() != &auth_addr {
        return Err(FloorError::WrongAuthorityAddress.into());
    }
    if !config.owned_by(&SYSTEM_PROGRAM) || !config.is_data_empty() {
        return Err(FloorError::AlreadyRegistered.into());
    }

    // Create the config account. If someone pre-funded the address (a known way
    // to block `CreateAccount`), top it up, then allocate and assign instead.
    let space = state::LEN as u64;
    let rent_needed = Rent::get()?.try_minimum_balance(state::LEN)?;
    let bump = [config_bump];
    let program_key = key(program);
    let seeds = [
        Seed::from(CONFIG_SEED),
        Seed::from(&program_key),
        Seed::from(&bump),
    ];
    let signer = [Signer::from(&seeds)];
    let have = config.lamports();
    if have == 0 {
        let mut d = [0u8; 52]; // CreateAccount: tag 0, lamports, space, owner
        d[4..12].copy_from_slice(&rent_needed.to_le_bytes());
        d[12..20].copy_from_slice(&space.to_le_bytes());
        d[20..52].copy_from_slice(program_id.as_ref());
        let metas = [
            InstructionAccount::writable_signer(payer.address()),
            InstructionAccount::writable_signer(config.address()),
        ];
        let ix = InstructionView {
            program_id: &SYSTEM_PROGRAM,
            data: &d,
            accounts: &metas,
        };
        invoke_signed(&ix, &[payer, config], &signer)?;
    } else {
        if have < rent_needed {
            let mut d = [0u8; 12]; // Transfer: tag 2, lamports
            d[0..4].copy_from_slice(&2u32.to_le_bytes());
            d[4..12].copy_from_slice(&(rent_needed - have).to_le_bytes());
            let metas = [
                InstructionAccount::writable_signer(payer.address()),
                InstructionAccount::writable(config.address()),
            ];
            let ix = InstructionView {
                program_id: &SYSTEM_PROGRAM,
                data: &d,
                accounts: &metas,
            };
            invoke(&ix, &[payer, config])?;
        }
        let metas = [InstructionAccount::writable_signer(config.address())];
        let mut d = [0u8; 12]; // Allocate: tag 8, space
        d[0..4].copy_from_slice(&8u32.to_le_bytes());
        d[4..12].copy_from_slice(&space.to_le_bytes());
        let ix = InstructionView {
            program_id: &SYSTEM_PROGRAM,
            data: &d,
            accounts: &metas,
        };
        invoke_signed(&ix, &[config], &signer)?;
        let mut d = [0u8; 36]; // Assign: tag 1, owner
        d[0..4].copy_from_slice(&1u32.to_le_bytes());
        d[4..36].copy_from_slice(program_id.as_ref());
        let ix = InstructionView {
            program_id: &SYSTEM_PROGRAM,
            data: &d,
            accounts: &metas,
        };
        invoke_signed(&ix, &[config], &signer)?;
    }

    // Hand the upgrade authority to Floor (the current authority signed this).
    let metas = [
        InstructionAccount::writable(programdata.address()),
        InstructionAccount::readonly_signer(current.address()),
        InstructionAccount::readonly(authority.address()),
    ];
    let data = 4u32.to_le_bytes(); // SetAuthority
    let ix = InstructionView {
        program_id: &LOADER_V3,
        data: &data,
        accounts: &metas,
    };
    invoke(&ix, &[programdata, current, authority])?;

    let t = now()?;
    let c = Config {
        program: program_key,
        programdata: key(programdata),
        owner,
        guardians: set.keys,
        last_heartbeat: [t; MAX_GUARDIANS],
        guardian_count: set.count,
        threshold: set.threshold,
        status: STATUS_LIVE,
        elf_is_v3,
        config_bump,
        authority_bump,
        snapshot_valid: 0,
        heartbeat_interval_s: set.interval_s,
        upgrade_delay_s: delay,
        abort_buffer: [0; 32],
        snapshot_buffer: [0; 32],
        aborted_at: 0,
        pending_kind: kind::NONE,
        pending_vetoed: 0,
        pending_approvals: 0,
        pending_id: 0,
        pending_target: [0; 32],
        pending_eta: 0,
        pending_expires: 0,
        pending_payload_len: 0,
        pending_payload: [0; MAX_PAYLOAD],
        recovery,
        pending_by_recovery: 0,
    };
    save_config(&mut accounts[1], &c)?;
    sys::event(&[
        ev::REGISTERED,
        &c.program,
        &[elf_is_v3],
        &delay.to_le_bytes(),
    ]);
    sys::log("Floor: registered. Upgrades now wait for the delay; guardians can stop the program.");
    Ok(())
}
