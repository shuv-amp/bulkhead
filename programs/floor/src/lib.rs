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
mod guardians;
mod loader;
mod proposals;
mod register;
mod state;
mod stop;
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

use guardians::{
    eject, guardian_signers, heartbeat, live_guardian, parse_guardian_set, replace_recovery,
};
use loader::{
    check_frozen_buffer, check_program_accounts, cpi_close_buffer, cpi_upgrade, live_code_is_v3,
    snapshot_identical,
};
use proposals::{approve, cancel, execute, propose, veto};
use register::register;
use stop::{abort, close_buffer, pin_snapshot, restore_snapshot, stage_abort};

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

pub(crate) fn acc(accounts: &[AccountView], i: usize) -> Result<&AccountView, ProgramError> {
    accounts.get(i).ok_or(ProgramError::NotEnoughAccountKeys)
}

pub(crate) fn key(a: &AccountView) -> [u8; 32] {
    a.address().to_bytes()
}

pub(crate) fn now() -> Result<i64, ProgramError> {
    Ok(Clock::get()?.unix_timestamp)
}

/// Loads the config after checking Floor owns it.
pub(crate) fn load_config(
    program_id: &Address,
    config: &AccountView,
) -> Result<Config, ProgramError> {
    if !config.owned_by(program_id) {
        return Err(FloorError::NotAFloorConfig.into());
    }
    let data = config.try_borrow()?;
    Config::load(&data)
}

pub(crate) fn save_config(config: &mut AccountView, c: &Config) -> ProgramResult {
    let mut data = config.try_borrow_mut()?;
    c.store(&mut data)
}

pub(crate) fn authority_address(program_id: &Address, c: &Config) -> Address {
    Address::derive_address(
        &[AUTHORITY_SEED, c.program.as_ref()],
        Some(c.authority_bump),
        program_id,
    )
}

pub(crate) fn check_authority(program_id: &Address, c: &Config, a: &AccountView) -> ProgramResult {
    if a.address() != &authority_address(program_id, c) {
        return Err(FloorError::WrongAuthorityAddress.into());
    }
    Ok(())
}

pub(crate) fn require_signer(a: &AccountView) -> ProgramResult {
    if !a.is_signer() {
        return Err(FloorError::MissingSignature.into());
    }
    Ok(())
}

pub(crate) fn i64_arg(args: &[u8], at: usize) -> Result<i64, ProgramError> {
    let b = args.get(at..at + 8).ok_or(FloorError::InvalidInstruction)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(i64::from_le_bytes(a))
}

pub(crate) fn k32_arg(args: &[u8], at: usize) -> Result<[u8; 32], ProgramError> {
    let b = args
        .get(at..at + 32)
        .ok_or(FloorError::InvalidInstruction)?;
    let mut k = [0u8; 32];
    k.copy_from_slice(b);
    Ok(k)
}

pub(crate) fn check_delay(delay: i64) -> ProgramResult {
    if !(bulkhead_core::consts::MIN_UPGRADE_DELAY_S..=MAX_UPGRADE_DELAY_S).contains(&delay) {
        return Err(FloorError::InvalidDelay.into());
    }
    Ok(())
}

pub(crate) fn gov_error(e: GovError) -> ProgramError {
    match e {
        GovError::Vetoed => FloorError::Vetoed,
        GovError::Expired => FloorError::Expired,
        _ => FloorError::NotExecutable,
    }
    .into()
}

#[cfg(not(feature = "no-entrypoint"))]
pinocchio::program_entrypoint!(process_instruction);
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::no_allocator!();
#[cfg(not(feature = "no-entrypoint"))]
pinocchio::nostd_panic_handler!();
