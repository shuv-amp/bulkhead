//! # Bulkhead Floor
//!
//! Floor holds a program's loader-v3 upgrade authority and enforces rules its
//! owner cannot lower:
//!
//! 1. **Change is slow.** New code waits at least 72 hours (constant), in
//!    public, and any live guardian can veto it.
//! 2. **Stopping is fast.** Any single live guardian (or the owner) can stop the
//!    program in one instruction by swapping in a pre-staged, verified abort
//!    binary that logs why it fails and returns `Custom(0x464C4F52)` ("FLOR").
//! 3. **Undoing a stop is cheap and can't smuggle in code.** A live guardian
//!    quorum restores the *snapshot*: a buffer verified on-chain, at the moment
//!    of the abort, to be byte-identical to the code that was running. A new
//!    fix instead needs quorum approval of that exact buffer, or the full delay.
//! 4. **The only fast path to new code goes through a visible stop.**
//! 5. `Close` of the program (which destroys it) is never reachable. Floor
//!    closes only buffers it holds that nothing refers to any more, to return
//!    their rent (`close_buffer`).
//!
//! All rules live in `bulkhead-core` (proved with Kani, tested three ways);
//! this program loads accounts, checks them, calls the core and performs the
//! loader CPIs. See `docs/06-FLOOR.md`.

#![cfg_attr(target_os = "solana", no_std)]
#![deny(unsafe_code)]

mod error;
mod state;
mod sys;

pub use error::FloorError;
pub use state::{
    kind, Config, LEN as CONFIG_LEN, MAX_GUARDIANS, MAX_PAYLOAD, STATUS_ABORTED, STATUS_LIVE,
};

use bulkhead_core::floor::{
    buffer_authority, buffer_closable, can_restore, deployable_after_simd0500, elf_extent,
    elf_info, is_canonical_abort, program_programdata, programdata_header, upgrade_eta,
    RestoreSource, BUFFER_DATA_OFFSET, PROGRAMDATA_DATA_OFFSET,
};
use bulkhead_core::governance::{
    can_eject, can_execute, quorum, signer_bits, GovError, GuardianSet, GuardianSetError, Schedule,
    SignerError, CHANGE_EXPIRY_S,
};
use pinocchio::cpi::{invoke, invoke_signed, Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::sysvars::{clock::Clock, rent::Rent, Sysvar};
use pinocchio::{AccountView, Address, ProgramResult};

// The entrypoint, allocator and panic handler are at the end of this file,
// behind `no-entrypoint`: tests and fuzz link this crate as a library, and
// two crates' `entrypoint` symbols cannot share one binary.

/// `BPFLoaderUpgradeab1e11111111111111111111111`
pub const LOADER_V3: Address = Address::new_from_array([
    2, 168, 246, 145, 78, 136, 161, 176, 226, 16, 21, 62, 247, 99, 174, 43, 0, 194, 185, 61, 22,
    193, 36, 210, 192, 83, 122, 16, 4, 128, 0, 0,
]);
/// `11111111111111111111111111111111`
pub const SYSTEM_PROGRAM: Address = Address::new_from_array([0; 32]);
/// `SysvarRent111111111111111111111111111111111`
pub const SYSVAR_RENT: Address = Address::new_from_array([
    6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 155, 161,
    253, 68, 227, 219, 217, 138, 0, 0, 0, 0,
]);
/// `SysvarC1ock11111111111111111111111111111111`
pub const SYSVAR_CLOCK: Address = Address::new_from_array([
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182, 139, 94, 184, 163, 155,
    75, 109, 92, 115, 85, 91, 33, 0, 0, 0, 0,
]);

pub const CONFIG_SEED: &[u8] = b"floor";
pub const AUTHORITY_SEED: &[u8] = b"authority";
/// Upper bound on the configurable upgrade delay (a longer one is a self-lock).
/// Same 30 days as the Vault's loosen delay.
pub use bulkhead_core::consts::MAX_UPGRADE_DELAY_S;

/// Instruction tags (first byte of instruction data).
pub mod ix {
    pub const REGISTER: u8 = 0;
    pub const STAGE_ABORT: u8 = 1;
    pub const PIN_SNAPSHOT: u8 = 2;
    pub const ABORT: u8 = 3;
    pub const PROPOSE: u8 = 4;
    pub const VETO: u8 = 5;
    pub const APPROVE: u8 = 6;
    pub const EXECUTE: u8 = 7;
    pub const RESTORE_SNAPSHOT: u8 = 8;
    pub const HEARTBEAT: u8 = 9;
    pub const EJECT: u8 = 10;
    pub const CANCEL: u8 = 11;
    pub const REPLACE_RECOVERY: u8 = 12;
    pub const CLOSE_BUFFER: u8 = 13;
}

/// Event tags (first field of every `Program data:` event).
pub mod ev {
    pub const REGISTERED: &[u8] = b"floor:registered";
    pub const ABORT_STAGED: &[u8] = b"floor:abort_staged";
    pub const SNAPSHOT_PINNED: &[u8] = b"floor:snapshot_pinned";
    pub const ABORTED: &[u8] = b"floor:aborted";
    pub const PROPOSED: &[u8] = b"floor:proposed";
    pub const VETOED: &[u8] = b"floor:vetoed";
    pub const APPROVED: &[u8] = b"floor:approved";
    pub const EXECUTED: &[u8] = b"floor:executed";
    pub const RESTORED: &[u8] = b"floor:restored";
    pub const HEARTBEAT: &[u8] = b"floor:heartbeat";
    pub const EJECTED: &[u8] = b"floor:ejected";
    pub const CANCELLED: &[u8] = b"floor:cancelled";
    pub const DELAY_RAISED: &[u8] = b"floor:delay_raised";
    pub const RECOVERY_REPLACED: &[u8] = b"floor:recovery_replaced";
    pub const BUFFER_CLOSED: &[u8] = b"floor:buffer_closed";
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&tag, args) = data.split_first().ok_or(FloorError::InvalidInstruction)?;
    match tag {
        ix::REGISTER => register(program_id, accounts, args),
        ix::STAGE_ABORT => stage_abort(program_id, accounts),
        ix::PIN_SNAPSHOT => pin_snapshot(program_id, accounts),
        ix::ABORT => abort(program_id, accounts),
        ix::PROPOSE => propose(program_id, accounts, args),
        ix::VETO => veto(program_id, accounts, args),
        ix::APPROVE => approve(program_id, accounts, args),
        ix::EXECUTE => execute(program_id, accounts),
        ix::RESTORE_SNAPSHOT => restore_snapshot(program_id, accounts),
        ix::HEARTBEAT => heartbeat(program_id, accounts),
        ix::EJECT => eject(program_id, accounts, args),
        ix::CANCEL => cancel(program_id, accounts),
        ix::REPLACE_RECOVERY => replace_recovery(program_id, accounts, args),
        ix::CLOSE_BUFFER => close_buffer(program_id, accounts),
        _ => Err(FloorError::InvalidInstruction.into()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn acc(accounts: &[AccountView], i: usize) -> Result<&AccountView, ProgramError> {
    accounts.get(i).ok_or(ProgramError::NotEnoughAccountKeys)
}

fn key(a: &AccountView) -> [u8; 32] {
    a.address().to_bytes()
}

fn now() -> Result<i64, ProgramError> {
    Ok(Clock::get()?.unix_timestamp)
}

/// Loads the config after checking Floor owns it.
fn load_config(program_id: &Address, config: &AccountView) -> Result<Config, ProgramError> {
    if !config.owned_by(program_id) {
        return Err(FloorError::NotAFloorConfig.into());
    }
    let data = config.try_borrow()?;
    Config::load(&data)
}

fn save_config(config: &mut AccountView, c: &Config) -> ProgramResult {
    let mut data = config.try_borrow_mut()?;
    c.store(&mut data)
}

fn authority_address(program_id: &Address, c: &Config) -> Address {
    Address::derive_address(
        &[AUTHORITY_SEED, c.program.as_ref()],
        Some(c.authority_bump),
        program_id,
    )
}

fn check_authority(program_id: &Address, c: &Config, a: &AccountView) -> ProgramResult {
    if a.address() != &authority_address(program_id, c) {
        return Err(FloorError::WrongAuthorityAddress.into());
    }
    Ok(())
}

fn require_signer(a: &AccountView) -> ProgramResult {
    if !a.is_signer() {
        return Err(FloorError::MissingSignature.into());
    }
    Ok(())
}

/// Index of a signing, live guardian.
fn live_guardian(c: &Config, a: &AccountView, now_s: i64) -> Result<usize, ProgramError> {
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
fn guardian_signers(c: &Config, signers: &[AccountView]) -> Result<u8, ProgramError> {
    let pairs = signers.iter().map(|s| (key(s), s.is_signer()));
    signer_bits(&c.guardians, c.guardian_count, pairs).map_err(|e| {
        match e {
            SignerError::NotSigner => FloorError::MissingSignature,
            SignerError::NotGuardian => FloorError::NotLiveGuardian,
        }
        .into()
    })
}

/// A buffer whose authority is Floor's authority PDA: nobody can write to it
/// again, so its bytes are frozen.
fn check_frozen_buffer(program_id: &Address, c: &Config, buffer: &AccountView) -> ProgramResult {
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
fn snapshot_identical(
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

fn live_code_is_v3(programdata: &AccountView) -> Result<u8, ProgramError> {
    let p = programdata.try_borrow()?;
    let elf = p.get(PROGRAMDATA_DATA_OFFSET..).unwrap_or(&[]);
    Ok(deployable_after_simd0500(elf_info(elf)) as u8)
}

/// Loader-v3 `Upgrade`, signed by Floor's authority PDA.
#[allow(clippy::too_many_arguments)]
fn cpi_upgrade(
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
fn cpi_close_buffer(
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

fn check_program_accounts(
    c: &Config,
    programdata: &AccountView,
    program: &AccountView,
) -> ProgramResult {
    if key(programdata) != c.programdata || key(program) != c.program {
        return Err(FloorError::ProgramMismatch.into());
    }
    Ok(())
}

/// Parses `[count u8][count × 32][threshold u8][interval i64]` with the
/// core's `GuardianSet::parse` (the Vault parses with the same function), and
/// returns the set and the number of argument bytes it used.
fn parse_guardian_set(
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

fn i64_arg(args: &[u8], at: usize) -> Result<i64, ProgramError> {
    let b = args.get(at..at + 8).ok_or(FloorError::InvalidInstruction)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(i64::from_le_bytes(a))
}

fn k32_arg(args: &[u8], at: usize) -> Result<[u8; 32], ProgramError> {
    let b = args
        .get(at..at + 32)
        .ok_or(FloorError::InvalidInstruction)?;
    let mut k = [0u8; 32];
    k.copy_from_slice(b);
    Ok(k)
}

fn check_delay(delay: i64) -> ProgramResult {
    if !(bulkhead_core::consts::MIN_UPGRADE_DELAY_S..=MAX_UPGRADE_DELAY_S).contains(&delay) {
        return Err(FloorError::InvalidDelay.into());
    }
    Ok(())
}

fn gov_error(e: GovError) -> ProgramError {
    match e {
        GovError::Vetoed => FloorError::Vetoed,
        GovError::Expired => FloorError::Expired,
        _ => FloorError::NotExecutable,
    }
    .into()
}

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
fn register(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
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
fn stage_abort(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
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
fn pin_snapshot(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
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
fn abort(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
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
// 4. Propose (owner; the recovery key only a new owner or recovery key)
// ---------------------------------------------------------------------------
//
// Accounts: 0 config [w], 1 owner or recovery key [s], 2 target buffer
// (Upgrade/Restore only). Data: kind u8, target[32], payload.
//
// The recovery key replaces a stolen owner key (docs/15, A4): its proposal
// waits the delay and any guardian can veto it, but the owner can neither
// cancel it nor block it, since it takes the place of a pending owner proposal.
fn propose(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
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
            if target == [0; 32]
                || target == c.recovery
                || c.guardians[..c.guardian_count as usize].contains(&target)
            {
                return Err(FloorError::InvalidInstruction.into());
            }
        }
        kind::SET_RECOVERY => {
            if target == c.owner || c.guardians[..c.guardian_count as usize].contains(&target) {
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
fn veto(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
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
fn approve(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
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
fn execute(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let t = now()?;
    let schedule = Schedule {
        executable_s: c.pending_eta,
        expires_s: c.pending_expires,
    };
    let vetoed = c.pending_vetoed != 0;
    match c.pending_kind {
        kind::NONE => Err(FloorError::NoProposal.into()),
        kind::UPGRADE | kind::RESTORE => {
            let (programdata, program, buffer) =
                (acc(accounts, 1)?, acc(accounts, 2)?, acc(accounts, 3)?);
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
                can_execute(&schedule, t, vetoed, false, false).map_err(gov_error)?;
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
        kind::RELEASE_AUTHORITY => {
            can_execute(&schedule, t, vetoed, false, false).map_err(gov_error)?;
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
        kind::SET_GUARDIANS | kind::SET_OWNER | kind::SET_DELAY | kind::SET_RECOVERY => {
            can_execute(&schedule, t, vetoed, false, false).map_err(gov_error)?;
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
                    if c.pending_target == c.recovery
                        || c.guardians[..c.guardian_count as usize].contains(&c.pending_target)
                    {
                        return Err(FloorError::InvalidInstruction.into());
                    }
                    c.owner = c.pending_target;
                }
                kind::SET_RECOVERY => {
                    if c.pending_target == c.owner
                        || c.guardians[..c.guardian_count as usize].contains(&c.pending_target)
                    {
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
        _ => Err(FloorError::WrongProposalKind.into()),
    }
}

// ---------------------------------------------------------------------------
// 8. Restore the snapshot (live quorum, instant)
// ---------------------------------------------------------------------------
//
// Accounts: 0 config [w], 1 programdata [w], 2 program [w], 3 snapshot buffer
// [w], 4 spill [w], 5 rent, 6 clock, 7 authority PDA, 8 loader-v3,
// 9.. guardians [s].
fn restore_snapshot(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
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
// 9. Heartbeat               Accounts: 0 config [w], 1 guardian [s].
// ---------------------------------------------------------------------------
// A dead guardian cannot revive itself; only a new guardian set (a delayed,
// vetoable proposal) brings it back.
fn heartbeat(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
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
fn eject(program_id: &Address, accounts: &mut [AccountView], args: &[u8]) -> ProgramResult {
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
// 11. Cancel the pending proposal (its proposer)  Accounts: 0 config [w], 1 owner or recovery key [s].
// ---------------------------------------------------------------------------
fn cancel(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
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
fn replace_recovery(
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
    if recovery == c.owner || c.guardians[..c.guardian_count as usize].contains(&recovery) {
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
fn close_buffer(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
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

#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process_instruction);
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::no_allocator!();
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();
