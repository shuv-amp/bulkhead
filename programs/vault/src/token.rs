//! SPL Token / Token-2022: reading accounts, the extension policy
//! (`docs/05-PROGRAM-SPEC.md §7`), and the three token CPIs custody needs.

use crate::error::VaultError;
use pinocchio::cpi::{invoke, invoke_signed, Signer};
use pinocchio::error::ProgramError;
use pinocchio::instruction::{InstructionAccount, InstructionView};
use pinocchio::{AccountView, Address, ProgramResult};

/// `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
pub const TOKEN_PROGRAM: Address = Address::new_from_array([
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
]);
/// `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
pub const TOKEN_2022: Address = Address::new_from_array([
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
]);

pub fn is_token_program(a: &Address) -> bool {
    a == &TOKEN_PROGRAM || a == &TOKEN_2022
}

const MINT_BASE_LEN: usize = 82;
const ACCOUNT_BASE_LEN: usize = 165;
/// Classic and Token-2022 multisig. Byte 165 is a signer pubkey byte, not an
/// account-type tag, so a length check alone can accept one as an account.
const MULTISIG_LEN: usize = 355;
const ACCOUNT_TYPE_MINT: u8 = 1;
const ACCOUNT_TYPE_ACCOUNT: u8 = 2;

/// A token account's (mint, owner, amount). Requires an initialized account
/// owned by one of the two token programs.
pub fn account_info(a: &AccountView) -> Result<([u8; 32], [u8; 32], u64), ProgramError> {
    if !is_token_program(a.owner()) {
        return Err(VaultError::WrongTokenProgram.into());
    }
    let d = a.try_borrow()?;
    token_account_fields(&d, a.owner() == &TOKEN_2022)
}

/// `account_info` over the raw bytes of an account a token program owns
/// (`token_2022`: owned by Token-2022). Pure, so it is fuzzed (`fuzz/`).
pub fn token_account_fields(
    d: &[u8],
    token_2022: bool,
) -> Result<([u8; 32], [u8; 32], u64), ProgramError> {
    if d.len() < ACCOUNT_BASE_LEN || d.len() == MULTISIG_LEN || d[108] == 0 {
        return Err(VaultError::WrongAccountType.into());
    }
    // A classic token account is exactly 165 bytes. Anything longer is
    // Token-2022 and must be an Account (type 2), not a mint or a multisig:
    // those pass a length check and then fail, or worse, get misread.
    if d.len() > ACCOUNT_BASE_LEN && (!token_2022 || d[ACCOUNT_BASE_LEN] != ACCOUNT_TYPE_ACCOUNT) {
        return Err(VaultError::WrongAccountType.into());
    }
    let mint: [u8; 32] = d[0..32].try_into().unwrap();
    let owner: [u8; 32] = d[32..64].try_into().unwrap();
    let amount = u64::from_le_bytes(d[64..72].try_into().unwrap());
    Ok((mint, owner, amount))
}

pub fn balance(a: &AccountView) -> Result<u64, ProgramError> {
    Ok(account_info(a)?.2)
}

/// Mint decimals, after checking the mint passes the custody policy.
///
/// Allowed Token-2022 extensions (by `ExtensionType` number): TransferFeeConfig
/// (1), MintCloseAuthority (3) only with no close authority, DefaultAccountState (6) only if not Frozen,
/// InterestBearingConfig (10), MetadataPointer (18), TokenMetadata (19), group
/// pointers and members (20–23), ScaledUiAmount (25), PermissionedBurn (28).
/// Everything else is refused, including every type not known today:
/// PermanentDelegate (12) could move vault tokens, TransferHook (14) runs
/// arbitrary code in the custody path, confidential transfers (4, 16, 24) hide
/// balances, NonTransferable (9) and Pausable (26) would trap custody.
pub fn checked_mint_decimals(
    mint: &AccountView,
    token_program: &Address,
) -> Result<u8, ProgramError> {
    if !is_token_program(token_program) || mint.owner() != token_program {
        return Err(VaultError::WrongTokenProgram.into());
    }
    let d = mint.try_borrow()?;
    mint_policy_decimals(&d, token_program == &TOKEN_2022)
}

/// `checked_mint_decimals` over the raw bytes of a mint a token program owns
/// (`token_2022`: owned by Token-2022). Pure, so the extension walk is fuzzed
/// against an independent statement of the policy (`fuzz/`).
pub fn mint_policy_decimals(d: &[u8], token_2022: bool) -> Result<u8, ProgramError> {
    if d.len() < MINT_BASE_LEN || d.len() == MULTISIG_LEN || d[45] != 1 {
        return Err(VaultError::WrongMint.into());
    }
    let decimals = d[44];
    if d.len() > MINT_BASE_LEN {
        // Token-2022 mint with extensions: padding to 165, account type, TLV.
        if !token_2022 || d.len() <= ACCOUNT_BASE_LEN || d[ACCOUNT_BASE_LEN] != ACCOUNT_TYPE_MINT {
            return Err(VaultError::WrongMint.into());
        }
        let mut o = ACCOUNT_BASE_LEN + 1;
        while o + 4 <= d.len() {
            let ty = u16::from_le_bytes([d[o], d[o + 1]]);
            let len = u16::from_le_bytes([d[o + 2], d[o + 3]]) as usize;
            let value = d.get(o + 4..o + 4 + len).ok_or(VaultError::WrongMint)?;
            let allowed = match ty {
                0 => break, // Uninitialized: end of the extensions
                1 | 10 | 18..=23 | 25 | 28 => true,
                // A set close authority can close the mint at supply 0 and
                // recreate the address with extensions this policy refuses.
                3 => value.len() == 32 && value.iter().all(|b| *b == 0),
                6 => value.first() != Some(&2), // DefaultAccountState: not Frozen
                _ => false,
            };
            if !allowed {
                return Err(VaultError::ExtensionNotAllowed.into());
            }
            o += 4 + len;
        }
    }
    Ok(decimals)
}

/// `TransferChecked` (instruction 12) from `from` to `to`, authorized by
/// `authority` (a signer, or the vault PDA through `signer`).
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked(
    token_program: &AccountView,
    from: &AccountView,
    mint: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    amount: u64,
    decimals: u8,
    signer: &[Signer],
) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }
    let mut data = [0u8; 10];
    data[0] = 12;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    data[9] = decimals;
    let metas = [
        InstructionAccount::writable(from.address()),
        InstructionAccount::readonly(mint.address()),
        InstructionAccount::writable(to.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];
    let ix = InstructionView {
        program_id: token_program.address(),
        data: &data,
        accounts: &metas,
    };
    invoke_signed(&ix, &[from, mint, to, authority], signer)
}

/// Size a token account for `mint` needs (`GetAccountDataSize`, instruction 21),
/// read from return data; covers Token-2022 extension space.
pub fn account_size(token_program: &AccountView, mint: &AccountView) -> Result<u64, ProgramError> {
    let metas = [InstructionAccount::readonly(mint.address())];
    let data = [21u8];
    let ix = InstructionView {
        program_id: token_program.address(),
        data: &data,
        accounts: &metas,
    };
    invoke(&ix, &[mint])?;
    let rd = pinocchio::cpi::get_return_data().ok_or(VaultError::WrongTokenProgram)?;
    if rd.program_id() != token_program.address() || rd.as_slice().len() != 8 {
        return Err(VaultError::WrongTokenProgram.into());
    }
    Ok(u64::from_le_bytes(rd.as_slice().try_into().unwrap()))
}

/// `InitializeAccount3` (instruction 18): `account` for `mint`, owned by `owner`.
pub fn initialize_account(
    token_program: &AccountView,
    account: &AccountView,
    mint: &AccountView,
    owner: &Address,
) -> ProgramResult {
    let mut data = [0u8; 33];
    data[0] = 18;
    data[1..33].copy_from_slice(owner.as_ref());
    let metas = [
        InstructionAccount::writable(account.address()),
        InstructionAccount::readonly(mint.address()),
    ];
    let ix = InstructionView {
        program_id: token_program.address(),
        data: &data,
        accounts: &metas,
    };
    invoke(&ix, &[account, mint])
}
