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
//! 5. `Close` (which destroys a program) is never reachable.
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
    buffer_authority, can_restore, deployable_after_simd0500, elf_info, is_canonical_abort,
    program_programdata, programdata_header, upgrade_eta, RestoreSource, BUFFER_DATA_OFFSET,
    PROGRAMDATA_DATA_OFFSET,
};
use bulkhead_core::governance::{
    can_eject, can_execute, quorum, GovError, Schedule, CHANGE_EXPIRY_S, MAX_HEARTBEAT_INTERVAL_S,
    MIN_GUARDIAN_THRESHOLD, MIN_HEARTBEAT_INTERVAL_S,
};
use pinocchio::cpi::{invoke, invoke_signed, Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::sysvars::{clock::Clock, rent::Rent, Sysvar};
use pinocchio::{AccountView, Address, ProgramResult};

pinocchio::program_entrypoint!(process_instruction);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

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
        ix::APPROVE => approve(program_id, accounts),
        ix::EXECUTE => execute(program_id, accounts),
        ix::RESTORE_SNAPSHOT => restore_snapshot(program_id, accounts),
        ix::HEARTBEAT => heartbeat(program_id, accounts),
        ix::EJECT => eject(program_id, accounts, args),
        ix::CANCEL => cancel(program_id, accounts),
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
    let mut bits = 0u8;
    for s in signers {
        require_signer(s)?;
        let i = c
            .guardian_index(&key(s))
            .ok_or(FloorError::NotLiveGuardian)?;
        bits |= 1 << i;
    }
    Ok(bits)
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

/// Byte identity of a buffer with the live programdata, exactly as
/// `bulkhead_core::floor::snapshot_matches` defines it, using `sol_memcmp_`.
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
    Ok(n > 0 && n <= pp.len() && sys::bytes_equal(bp, &pp[..n]) && sys::all_zero(&pp[n..]))
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

/// A validated guardian set: list, count, threshold, heartbeat interval, and
/// the number of argument bytes it used.
type GuardianSet = ([[u8; 32]; MAX_GUARDIANS], u8, u8, i64, usize);

/// Parses `[count u8][count × 32][threshold u8][interval i64]`.
fn parse_guardian_set(args: &[u8], owner: &[u8; 32]) -> Result<GuardianSet, ProgramError> {
    let count = *args.first().ok_or(FloorError::InvalidInstruction)? as usize;
    if !(MIN_GUARDIAN_THRESHOLD as usize..=MAX_GUARDIANS).contains(&count) {
        return Err(FloorError::InvalidGuardians.into());
    }
    let need = 1 + 32 * count + 1 + 8;
    if args.len() < need {
        return Err(FloorError::InvalidInstruction.into());
    }
    let mut g = [[0u8; 32]; MAX_GUARDIANS];
    for i in 0..count {
        let mut k = [0u8; 32];
        k.copy_from_slice(&args[1 + 32 * i..1 + 32 * i + 32]);
        if k == [0; 32] || &k == owner || g[..i].contains(&k) {
            return Err(FloorError::InvalidGuardians.into());
        }
        g[i] = k;
    }
    let threshold = args[1 + 32 * count];
    if threshold < MIN_GUARDIAN_THRESHOLD || threshold as usize > count {
        return Err(FloorError::InvalidThreshold.into());
    }
    let interval = i64_arg(args, 2 + 32 * count)?;
    if !(MIN_HEARTBEAT_INTERVAL_S..=MAX_HEARTBEAT_INTERVAL_S).contains(&interval) {
        return Err(FloorError::InvalidInterval.into());
    }
    Ok((g, count as u8, threshold, interval, need))
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
    let (guardians, count, threshold, interval, used) =
        parse_guardian_set(args.get(32..).unwrap_or(&[]), &owner)?;
    let delay = i64_arg(args, 32 + used)?;
    // Optional recovery key after the delay (absent or all zero: none).
    let recovery = k32_arg(args, 32 + used + 8).unwrap_or([0; 32]);
    if recovery == owner {
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
        guardians,
        last_heartbeat: [t; MAX_GUARDIANS],
        guardian_count: count,
        threshold,
        status: STATUS_LIVE,
        elf_is_v3,
        config_bump,
        authority_bump,
        snapshot_valid: 0,
        heartbeat_interval_s: interval,
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
// Accounts: 0 config [w], 1 buffer, 2 programdata. Anyone.
// The buffer must hold exactly a canonical abort binary, be frozen (Floor is
// its authority), and fit in the programdata account; a staged abort that the
// loader would reject is worse than none.
fn stage_abort(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    let buffer = acc(accounts, 1)?;
    let programdata = acc(accounts, 2)?;
    if c.abort_buffer != [0; 32] {
        return Err(FloorError::AbortAlreadyStaged.into());
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
//           3 program [w], 4 abort buffer [w], 5 spill [w], 6 rent, 7 clock,
//           8 authority PDA, 9 loader-v3, 10 snapshot buffer (required while
//           one is pinned).
//
// A pinned snapshot must be named: otherwise whoever stops the program would
// decide, by leaving it out, that the quorum may not restore it (docs/09,
// finding 53). It always exists while pinned (Floor holds its authority; a
// restore that consumes it clears the pin), and comparing it costs about one
// unit per 250 bytes, so naming it cannot keep an honest stop from landing. Its
// contents never stop the abort: if they ever differed from the live code,
// only the quorum's fast restore would be unavailable.
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

    // Decide, against the exact live bytes, whether the snapshot restores them.
    c.snapshot_valid = 0;
    if c.snapshot_buffer != [0; 32] {
        let snap = accounts.get(10).ok_or(FloorError::SnapshotMismatch)?;
        if key(snap) != c.snapshot_buffer {
            return Err(FloorError::SnapshotMismatch.into());
        }
        if check_frozen_buffer(program_id, &c, snap).is_ok()
            && snapshot_identical(snap, programdata)?
        {
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
    if c.pending_kind != kind::NONE {
        if by_recovery && c.pending_by_recovery == 0 {
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
    let t = now()?;
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
        kind::SET_OWNER => {
            if target == [0; 32] || target == c.recovery {
                return Err(FloorError::InvalidInstruction.into());
            }
        }
        kind::SET_RECOVERY => {
            if target == c.owner {
                return Err(FloorError::InvalidInstruction.into());
            }
        }
        kind::SET_GUARDIANS => {
            parse_guardian_set(payload, &c.owner)?;
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
        if key(buffer) != target {
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
// ---------------------------------------------------------------------------
fn approve(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut c = load_config(program_id, acc(accounts, 0)?)?;
    if c.pending_kind != kind::RESTORE {
        return Err(FloorError::WrongProposalKind.into());
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
// 7. Execute the pending proposal (anyone, once allowed)
// ---------------------------------------------------------------------------
//
// Upgrade / Restore accounts: 0 config [w], 1 programdata [w], 2 program [w],
//   3 buffer [w], 4 spill [w], 5 rent, 6 clock, 7 authority PDA, 8 loader-v3.
// ReleaseAuthority: 0 config [w], 1 programdata [w], 2 authority PDA,
//   3 loader-v3, 4 owner [w] (receives the config's rent),
//   5 new authority (omitted when the target is zero: program becomes immutable).
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
            if key(buffer) != c.pending_target {
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
            let bump = [c.authority_bump];
            let seeds = [
                Seed::from(AUTHORITY_SEED),
                Seed::from(&c.program),
                Seed::from(&bump),
            ];
            let data = 4u32.to_le_bytes(); // SetAuthority
            if c.pending_target == [0; 32] {
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
                let metas = [
                    InstructionAccount::writable(programdata.address()),
                    InstructionAccount::readonly_signer(authority.address()),
                    InstructionAccount::readonly(new_authority.address()),
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
                    let (g, n, th, interval, _) = parse_guardian_set(&payload[..len], &c.owner)?;
                    c.guardians = g;
                    c.guardian_count = n;
                    c.threshold = th;
                    c.heartbeat_interval_s = interval;
                    c.last_heartbeat = [t; MAX_GUARDIANS]; // the new set starts alive
                }
                kind::SET_OWNER => {
                    if c.pending_target == c.recovery {
                        return Err(FloorError::InvalidInstruction.into());
                    }
                    c.owner = c.pending_target;
                }
                kind::SET_RECOVERY => {
                    if c.pending_target == c.owner {
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
