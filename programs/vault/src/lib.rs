//! # Bulkhead Vault
//!
//! Custody that a protocol's own admin can't turn off. The vault token accounts
//! belong to this program; the protocol decides *who* gets paid (it calls
//! `release` through its signer PDA), Bulkhead decides *how fast*:
//!
//! - **Backed lane.** An owner's own deposits, and borrows against real
//!   collateral at conservative Pyth prices, pay out instantly. Returning an
//!   owner's own deposit needs no prices and ignores freezes (G2).
//! - **Unbacked lane.** Everything else goes through two GCRA buckets
//!   (default 2%/hour burst, 5%/day cap). Excess becomes a public ticket with a
//!   minimum delay; guardians can freeze, cancel or extend (G1).
//! - **Slow loosening.** Tightening applies at once; anything that loosens
//!   waits at least 72 hours (a constant), in public, vetoable (G4).
//!
//! All rules are computed by `bulkhead-core` (Kani proofs, exhaustive tests,
//! differential tests against an independent Python reference). This program
//! loads and checks accounts, calls the core, moves tokens and emits events.
//! Specification: `docs/05-PROGRAM-SPEC.md`.

#![cfg_attr(target_os = "solana", no_std)]
#![deny(unsafe_code)]

mod brakes;
mod custody;
mod error;
mod genesis;
mod governance;
mod lifeboat;
mod pyth;
mod state;
mod sys;
mod token;
mod views;

pub use error::VaultError;
pub use state::{change, Asset, Backing, Change, Protocol, Ticket, Vault, MAX_GUARDIANS};
// Pure byte parsers, exported for the fuzz targets (`fuzz/`).
pub use pyth::{parse as parse_price_update, PriceUpdate};
pub use token::{mint_policy_decimals, token_account_fields};

use bulkhead_core::ema::ema_update;
use bulkhead_core::governance::{
    MAX_HEARTBEAT_INTERVAL_S, MIN_GUARDIAN_THRESHOLD, MIN_HEARTBEAT_INTERVAL_S,
};
use pinocchio::cpi::{invoke, invoke_signed, Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::sysvars::{clock::Clock, rent::Rent, Sysvar};
use pinocchio::{AccountView, Address, ProgramResult};

pinocchio::program_entrypoint!(process_instruction);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

pub const SYSTEM_PROGRAM: Address = Address::new_from_array([0; 32]);

/// PDA seeds.
pub mod seeds {
    pub const PROTOCOL: &[u8] = b"protocol";
    pub const VAULT: &[u8] = b"vault";
    pub const VAULT_TOKENS: &[u8] = b"vault-tokens";
    pub const LIFEBOAT_TOKENS: &[u8] = b"lifeboat-tokens";
    pub const ASSET: &[u8] = b"asset";
    pub const BACKING: &[u8] = b"backing";
    pub const TICKET: &[u8] = b"ticket";
    pub const CHANGE: &[u8] = b"change";
    /// Under the *protocol's* program id: the signer that proves a CPI came from it.
    pub const CALLER: &[u8] = b"bulkhead-caller";
}

/// Instruction tags.
pub mod ix {
    pub const REGISTER_PROTOCOL: u8 = 0;
    pub const CREATE_VAULT: u8 = 1;
    pub const UPSERT_ASSET: u8 = 2;
    pub const IMPORT_BACKING: u8 = 3;
    pub const PROPOSE_SEAL: u8 = 4;
    pub const EXECUTE_SEAL: u8 = 5;
    pub const VETO_SEAL: u8 = 6;
    pub const DEPOSIT: u8 = 7;
    pub const RELEASE: u8 = 8;
    pub const SETTLE_TICKET: u8 = 9;
    pub const CANCEL_TICKET: u8 = 10;
    pub const EXTEND_TICKET: u8 = 11;
    pub const FREEZE: u8 = 12;
    pub const UNFREEZE: u8 = 13;
    pub const HEARTBEAT: u8 = 14;
    pub const EJECT: u8 = 15;
    pub const RESET_BACKLOG: u8 = 16;
    pub const ABDICATE: u8 = 17;
    pub const PROPOSE_CHANGE: u8 = 18;
    pub const VETO_CHANGE: u8 = 19;
    pub const EXECUTE_CHANGE: u8 = 20;
    pub const CANCEL_CHANGE: u8 = 21;
    pub const ATTEST: u8 = 22;
    pub const QUOTE_RELEASE: u8 = 23;
    pub const LIFEBOAT_MOVE: u8 = 24;
    pub const LIFEBOAT_RETURN: u8 = 25;
    pub const PROPOSE_LIFEBOAT_EXIT: u8 = 26;
    pub const EXECUTE_LIFEBOAT_EXIT: u8 = 27;
    pub const VETO_LIFEBOAT_EXIT: u8 = 28;
    pub const REPLACE_RECOVERY: u8 = 29;
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&tag, args) = data.split_first().ok_or(VaultError::InvalidInstruction)?;
    match tag {
        ix::REGISTER_PROTOCOL => genesis::register_protocol(program_id, accounts, args),
        ix::CREATE_VAULT => genesis::create_vault(program_id, accounts, args),
        ix::UPSERT_ASSET => genesis::upsert_asset(program_id, accounts, args),
        ix::IMPORT_BACKING => genesis::import_backing(program_id, accounts, args),
        ix::PROPOSE_SEAL => genesis::propose_seal(program_id, accounts),
        ix::EXECUTE_SEAL => genesis::execute_seal(program_id, accounts),
        ix::VETO_SEAL => genesis::veto_seal(program_id, accounts),
        ix::DEPOSIT => custody::deposit(program_id, accounts, args),
        ix::RELEASE => custody::release(program_id, accounts, args, false),
        ix::SETTLE_TICKET => custody::settle_ticket(program_id, accounts),
        ix::CANCEL_TICKET => brakes::cancel_ticket(program_id, accounts),
        ix::EXTEND_TICKET => brakes::extend_ticket(program_id, accounts, args),
        ix::FREEZE => brakes::freeze(program_id, accounts, args),
        ix::UNFREEZE => brakes::unfreeze(program_id, accounts, args),
        ix::HEARTBEAT => brakes::heartbeat(program_id, accounts),
        ix::EJECT => brakes::eject(program_id, accounts, args),
        ix::RESET_BACKLOG => brakes::reset_backlog(program_id, accounts),
        ix::ABDICATE => brakes::abdicate(program_id, accounts, args),
        ix::PROPOSE_CHANGE => governance::propose_change(program_id, accounts, args),
        ix::VETO_CHANGE => governance::veto_change(program_id, accounts),
        ix::EXECUTE_CHANGE => governance::execute_change(program_id, accounts),
        ix::CANCEL_CHANGE => governance::cancel_change(program_id, accounts),
        ix::ATTEST => views::attest(program_id, accounts),
        ix::QUOTE_RELEASE => custody::release(program_id, accounts, args, true),
        ix::LIFEBOAT_MOVE => lifeboat::move_in(program_id, accounts, args),
        ix::LIFEBOAT_RETURN => lifeboat::move_back(program_id, accounts, args),
        ix::PROPOSE_LIFEBOAT_EXIT => lifeboat::propose_exit(program_id, accounts, args),
        ix::EXECUTE_LIFEBOAT_EXIT => lifeboat::execute_exit(program_id, accounts),
        ix::VETO_LIFEBOAT_EXIT => lifeboat::veto_exit(program_id, accounts),
        ix::REPLACE_RECOVERY => governance::replace_recovery(program_id, accounts, args),
        _ => Err(VaultError::InvalidInstruction.into()),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
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

pub(crate) fn require_signer(a: &AccountView) -> ProgramResult {
    if !a.is_signer() {
        return Err(VaultError::MissingSignature.into());
    }
    Ok(())
}

pub(crate) fn check_system(a: &AccountView) -> ProgramResult {
    if a.address() != &SYSTEM_PROGRAM {
        return Err(VaultError::WrongAddress.into());
    }
    Ok(())
}

/// Loads a program-owned account of type `T` via `load`.
pub(crate) fn load<T>(
    program_id: &Address,
    a: &AccountView,
    load: fn(&[u8]) -> Result<T, ProgramError>,
) -> Result<T, ProgramError> {
    if !a.owned_by(program_id) {
        return Err(VaultError::WrongAccountType.into());
    }
    let d = a.try_borrow()?;
    load(&d)
}

pub(crate) fn save(
    a: &mut AccountView,
    store: impl FnOnce(&mut [u8]) -> ProgramResult,
) -> ProgramResult {
    let mut d = a.try_borrow_mut()?;
    store(&mut d)
}

/// The address derived from `seeds` + `bump` under `program_id` (no curve check;
/// used only with bumps this program found canonically and stored).
pub(crate) fn derive<const N: usize>(
    seeds: &[&[u8]; N],
    bump: u8,
    program_id: &Address,
) -> Address {
    Address::derive_address(seeds, Some(bump), program_id)
}

/// Canonical PDA, checked against the account passed.
pub(crate) fn expect_pda(
    seeds: &[&[u8]],
    program_id: &Address,
    a: &AccountView,
) -> Result<u8, ProgramError> {
    let (addr, bump) = Address::find_program_address(seeds, program_id);
    if a.address() != &addr {
        return Err(VaultError::WrongAddress.into());
    }
    Ok(bump)
}

/// Creates a program-owned PDA account. Survives a griefer who pre-funds the
/// address (which makes `CreateAccount` fail): tops it up, allocates, assigns.
pub(crate) fn create_pda(
    payer: &AccountView,
    target: &AccountView,
    signer_seeds: &[Seed],
    space: usize,
    owner: &Address,
) -> ProgramResult {
    if !target.is_data_empty() || !target.owned_by(&SYSTEM_PROGRAM) {
        return Err(VaultError::AlreadyInitialized.into());
    }
    let rent = Rent::get()?.try_minimum_balance(space)?;
    let signer = [Signer::from(signer_seeds)];
    let have = target.lamports();
    if have == 0 {
        let mut d = [0u8; 52];
        d[4..12].copy_from_slice(&rent.to_le_bytes());
        d[12..20].copy_from_slice(&(space as u64).to_le_bytes());
        d[20..52].copy_from_slice(owner.as_ref());
        let metas = [
            InstructionAccount::writable_signer(payer.address()),
            InstructionAccount::writable_signer(target.address()),
        ];
        let ix = InstructionView {
            program_id: &SYSTEM_PROGRAM,
            data: &d,
            accounts: &metas,
        };
        return invoke_signed(&ix, &[payer, target], &signer);
    }
    if have < rent {
        let mut d = [0u8; 12];
        d[0..4].copy_from_slice(&2u32.to_le_bytes());
        d[4..12].copy_from_slice(&(rent - have).to_le_bytes());
        let metas = [
            InstructionAccount::writable_signer(payer.address()),
            InstructionAccount::writable(target.address()),
        ];
        let ix = InstructionView {
            program_id: &SYSTEM_PROGRAM,
            data: &d,
            accounts: &metas,
        };
        invoke(&ix, &[payer, target])?;
    }
    let metas = [InstructionAccount::writable_signer(target.address())];
    let mut d = [0u8; 12];
    d[0..4].copy_from_slice(&8u32.to_le_bytes());
    d[4..12].copy_from_slice(&(space as u64).to_le_bytes());
    let ix = InstructionView {
        program_id: &SYSTEM_PROGRAM,
        data: &d,
        accounts: &metas,
    };
    invoke_signed(&ix, &[target], &signer)?;
    let mut d = [0u8; 36];
    d[0..4].copy_from_slice(&1u32.to_le_bytes());
    d[4..36].copy_from_slice(owner.as_ref());
    let ix = InstructionView {
        program_id: &SYSTEM_PROGRAM,
        data: &d,
        accounts: &metas,
    };
    invoke_signed(&ix, &[target], &signer)
}

/// Closes a program-owned account, sending its lamports to `to`.
pub(crate) fn close(accounts: &mut [AccountView], i: usize, to: usize) -> ProgramResult {
    let lamports = accounts[i].lamports();
    let credit = accounts[to]
        .lamports()
        .checked_add(lamports)
        .ok_or(VaultError::Overflow)?;
    accounts[to].set_lamports(credit);
    accounts[i].set_lamports(0);
    accounts[i].close()
}

/// Loads the protocol account and checks it is this protocol's PDA.
pub(crate) fn load_protocol(
    program_id: &Address,
    a: &AccountView,
) -> Result<Protocol, ProgramError> {
    let p = load(program_id, a, Protocol::load)?;
    let expected = derive(&[seeds::PROTOCOL, &p.protocol_program], p.bump, program_id);
    if a.address() != &expected {
        return Err(VaultError::WrongAddress.into());
    }
    Ok(p)
}

/// Loads a vault and checks it belongs to `protocol` (its PDA re-derived).
pub(crate) fn load_vault(
    program_id: &Address,
    protocol: &AccountView,
    a: &AccountView,
) -> Result<Vault, ProgramError> {
    let v = load(program_id, a, Vault::load)?;
    if v.protocol != key(protocol) {
        return Err(VaultError::WrongVault.into());
    }
    let expected = derive(&[seeds::VAULT, &v.protocol, &v.mint], v.bump, program_id);
    if a.address() != &expected {
        return Err(VaultError::WrongVault.into());
    }
    Ok(v)
}

/// Signer seeds of a vault PDA (it owns the vault and lifeboat token accounts).
pub(crate) struct VaultSigner {
    protocol: [u8; 32],
    mint: [u8; 32],
    bump: [u8; 1],
}

impl VaultSigner {
    pub fn new(v: &Vault) -> VaultSigner {
        VaultSigner {
            protocol: v.protocol,
            mint: v.mint,
            bump: [v.bump],
        }
    }
    pub fn seeds(&self) -> [Seed<'_>; 4] {
        [
            Seed::from(seeds::VAULT),
            Seed::from(&self.protocol),
            Seed::from(&self.mint),
            Seed::from(&self.bump),
        ]
    }
}

/// Updates the reference balance (EMA) with the balance *before* an operation.
pub(crate) fn touch_reference(v: &mut Vault, balance: u64, now_s: i64) {
    v.ref_balance = ema_update(
        v.ref_balance,
        v.ref_updated_s,
        balance,
        now_s,
        v.ref_initialized,
    );
    v.ref_updated_s = now_s;
    v.ref_initialized = true;
}

/// Guardian bitmap of `signers`: each must sign and be a current guardian.
pub(crate) fn guardian_signers(p: &Protocol, signers: &[AccountView]) -> Result<u8, ProgramError> {
    let mut bits = 0u8;
    for s in signers {
        require_signer(s)?;
        let i = p.guardian_index(&key(s)).ok_or(VaultError::NotGuardian)?;
        bits |= 1 << i;
    }
    Ok(bits)
}

/// Index of a signing, live guardian.
pub(crate) fn live_guardian(
    p: &Protocol,
    a: &AccountView,
    now_s: i64,
) -> Result<usize, ProgramError> {
    require_signer(a)?;
    let i = p.guardian_index(&key(a)).ok_or(VaultError::NotGuardian)?;
    if p.alive_mask(now_s) & (1 << i) == 0 {
        return Err(VaultError::NotGuardian.into());
    }
    Ok(i)
}

pub(crate) fn require_admin(p: &Protocol, a: &AccountView) -> ProgramResult {
    require_signer(a)?;
    if key(a) != p.admin {
        return Err(VaultError::NotAdmin.into());
    }
    Ok(())
}

/// Parses and validates a guardian set: `[count][count × 32][threshold][interval i64]`.
pub(crate) type GuardianSet = ([[u8; 32]; MAX_GUARDIANS], u8, u8, i64);

pub(crate) fn parse_guardian_set(
    r: &mut state::R,
    admin: &[u8; 32],
) -> Result<GuardianSet, ProgramError> {
    let count = r.u8()? as usize;
    if !(MIN_GUARDIAN_THRESHOLD as usize..=MAX_GUARDIANS).contains(&count) {
        return Err(VaultError::InvalidGuardians.into());
    }
    let mut g = [[0u8; 32]; MAX_GUARDIANS];
    for i in 0..count {
        let k = r.key()?;
        if k == [0; 32] || &k == admin || g[..i].contains(&k) {
            return Err(VaultError::InvalidGuardians.into());
        }
        g[i] = k;
    }
    let threshold = r.u8()?;
    let interval = r.i64()?;
    if threshold < MIN_GUARDIAN_THRESHOLD
        || threshold as usize > count
        || !(MIN_HEARTBEAT_INTERVAL_S..=MAX_HEARTBEAT_INTERVAL_S).contains(&interval)
    {
        return Err(VaultError::InvalidGuardians.into());
    }
    Ok((g, count as u8, threshold, interval))
}
