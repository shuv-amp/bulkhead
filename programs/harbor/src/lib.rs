//! # Harbor: a demo protocol whose custody is a Bulkhead Vault
//!
//! Deliberately naive, like a protocol whose logic or admin key has been
//! compromised: it lets any user withdraw any amount to themselves, and lets
//! its admin pay anyone anything. Harbor decides *who* gets paid; Bulkhead
//! decides *how fast*. This is how the scenarios in `docs/08-SCENARIOS.md`
//! exercise the Vault program through real CPIs.
//!
//! Every instruction forwards to Bulkhead, signing as Harbor's caller PDA
//! `["bulkhead-caller"]`, and only to the Vault program it was built for
//! (`build.rs`; docs/07 §3). Accounts: `0` = the Bulkhead Vault program, `1` =
//! Harbor's caller PDA, then instruction-specific accounts, then the Vault
//! instruction's accounts from its index 1 on (index 0 is the caller).

#![cfg_attr(target_os = "solana", no_std)]
#![deny(unsafe_code)]

use pinocchio::cpi::{invoke_signed_with_bounds, Seed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::{AccountView, Address, ProgramResult};

pinocchio::program_entrypoint!(process_instruction);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

pub const CALLER_SEED: &[u8] = b"bulkhead-caller";

// `VAULT_PROGRAM`: the Vault this Harbor forwards to, fixed at build time (build.rs).
include!(concat!(env!("OUT_DIR"), "/vault_id.rs"));
const VAULT: Address = Address::new_from_array(VAULT_PROGRAM);

pub mod ix {
    /// Register with Bulkhead (the caller PDA is the registrar). Data: Vault args.
    pub const REGISTER: u8 = 0;
    /// A user deposits. Data: amount. Harbor account 2: the user [s].
    pub const DEPOSIT: u8 = 1;
    /// A user withdraws to their own token account. Data: amount.
    /// Harbor account 2: the user [s], who must own the recipient account.
    pub const WITHDRAW: u8 = 2;
    /// The admin pays anyone anything. Data: amount. Harbor account 2: admin [s].
    pub const ADMIN_PAYOUT: u8 = 3;
}

const VAULT_REGISTER: u8 = 0;
const VAULT_DEPOSIT: u8 = 7;
const VAULT_RELEASE: u8 = 8;
const MAX_CPI_ACCOUNTS: usize = 40;

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&tag, args) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let vault_program = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    // Every forwarded call carries the caller PDA's signature, which the Vault
    // trusts as Harbor itself: forward to that one Vault and nothing else.
    if vault_program.address() != &VAULT {
        return Err(ProgramError::IncorrectProgramId);
    }
    let caller = accounts.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (caller_addr, bump) = Address::find_program_address(&[CALLER_SEED], program_id);
    if caller.address() != &caller_addr {
        return Err(ProgramError::InvalidSeeds);
    }
    let (vault_tag, first_vault_account) = match tag {
        ix::REGISTER => (VAULT_REGISTER, 2),
        ix::DEPOSIT => (VAULT_DEPOSIT, 3),
        ix::WITHDRAW => {
            // The user must own the recipient token account (Vault release index 5).
            let user = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
            let recipient = accounts
                .get(3 + 4)
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            let d = recipient.try_borrow()?;
            if !user.is_signer() || d.len() < 64 || d[32..64] != *user.address().as_ref() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            (VAULT_RELEASE, 3)
        }
        ix::ADMIN_PAYOUT => {
            // Harbor's admin is the admin recorded in its Bulkhead protocol
            // account (Vault release account 1; bytes 72..104). Whoever holds
            // that key can order any payout: the Drift situation.
            let admin = accounts.get(2).ok_or(ProgramError::NotEnoughAccountKeys)?;
            let protocol = accounts.get(3).ok_or(ProgramError::NotEnoughAccountKeys)?;
            let d = protocol.try_borrow()?;
            if !admin.is_signer() || d.len() < 104 || d[72..104] != *admin.address().as_ref() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            (VAULT_RELEASE, 3)
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    };

    // Forward: caller PDA as Vault account 0 (or 4, the registrar, for REGISTER).
    let rest = accounts.get(first_vault_account..).unwrap_or(&[]);
    let mut metas: [InstructionAccount; MAX_CPI_ACCOUNTS] =
        core::array::from_fn(|_| InstructionAccount::readonly(caller.address()));
    let mut views: [&AccountView; MAX_CPI_ACCOUNTS] = [caller; MAX_CPI_ACCOUNTS];
    let mut n = 0;
    if vault_tag != VAULT_REGISTER {
        metas[0] = InstructionAccount::readonly_signer(caller.address());
        views[0] = caller;
        n = 1;
    }
    for a in rest {
        if n >= MAX_CPI_ACCOUNTS {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let signer = a.is_signer() || a.address() == caller.address();
        metas[n] = InstructionAccount::new(a.address(), a.is_writable(), signer);
        views[n] = a;
        n += 1;
    }
    let mut buf = [0u8; 1 + 512];
    if args.len() > 512 {
        return Err(ProgramError::InvalidInstructionData);
    }
    buf[0] = vault_tag;
    buf[1..1 + args.len()].copy_from_slice(args);
    let ix = InstructionView {
        program_id: vault_program.address(),
        data: &buf[..1 + args.len()],
        accounts: &metas[..n],
    };
    let b = [bump];
    let seeds = [Seed::from(CALLER_SEED), Seed::from(&b)];
    invoke_signed_with_bounds::<MAX_CPI_ACCOUNTS, &AccountView>(
        &ix,
        &views[..n],
        &[Signer::from(&seeds)],
    )
}
