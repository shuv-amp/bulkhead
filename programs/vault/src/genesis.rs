//! Genesis: register, create vaults, list assets, import existing backing,
//! then seal (72h, vetoable). Before the seal, releases are disabled.

use crate::state::{Asset, Protocol, Vault, R};
use crate::*;
use bulkhead_core::classify::{AssetConfig, LimitConfig};
use bulkhead_core::consts::{MAX_LOOSEN_DELAY_S, MIN_LOOSEN_DELAY_S};
use bulkhead_core::floor::{program_programdata, programdata_header};
use bulkhead_core::governance::{can_execute, schedule, Schedule};
use bulkhead_core::limiter::config_is_valid;

/// `BPFLoaderUpgradeab1e11111111111111111111111`
const LOADER_V3: Address = Address::new_from_array([
    2, 168, 246, 145, 78, 136, 161, 176, 226, 16, 21, 62, 247, 99, 174, 43, 0, 194, 185, 61, 22,
    193, 36, 210, 192, 83, 122, 16, 4, 128, 0, 0,
]);

pub(crate) fn valid_asset(c: &AssetConfig) -> bool {
    c.haircut_bps <= 10_000
        && c.liability_bps >= 10_000
        && c.max_conf_bps <= 10_000
        && c.max_age_s > 0
}

// ---------------------------------------------------------------------------
// 0. register_protocol
// ---------------------------------------------------------------------------
// Accounts: 0 payer [s,w], 1 protocol PDA [w], 2 protocol program,
//           3 its programdata, 4 registrar [s], 5 system program.
// Data: admin[32], guardian set, loosen_delay i64, lifeboat_destination[32].
//
// The registrar is the protocol program's upgrade authority, or the
// protocol's own caller PDA signing through a CPI (for programs whose upgrade
// authority is Floor, or that are immutable).
pub fn register_protocol(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let mut r = R::args(args);
    let admin = r.key()?;
    if admin == [0; 32] {
        return Err(VaultError::InvalidGuardians.into());
    }
    let (guardians, count, threshold, interval) = parse_guardian_set(&mut r, &admin)?;
    let loosen_delay = r.i64()?;
    let destination = r.key()?;
    if loosen_delay < MIN_LOOSEN_DELAY_S {
        return Err(VaultError::DelayBelowMinimum.into());
    }
    if loosen_delay > MAX_LOOSEN_DELAY_S {
        return Err(VaultError::DelayAboveMaximum.into());
    }
    if destination == admin || destination == [0; 32] {
        return Err(VaultError::InvalidGuardians.into());
    }

    let payer = acc(accounts, 0)?;
    let protocol = acc(accounts, 1)?;
    let program = acc(accounts, 2)?;
    let programdata = acc(accounts, 3)?;
    let registrar = acc(accounts, 4)?;
    check_system(acc(accounts, 5)?)?;
    require_signer(payer)?;
    require_signer(registrar)?;

    let (caller, _) = Address::find_program_address(&[seeds::CALLER], program.address());
    let mut authorized = registrar.address() == &caller;
    if !authorized && program.owned_by(&LOADER_V3) && programdata.owned_by(&LOADER_V3) {
        let p = program.try_borrow()?;
        let d = programdata.try_borrow()?;
        authorized = program_programdata(&p) == Some(key(programdata))
            && programdata_header(&d).and_then(|h| h.upgrade_authority) == Some(key(registrar));
    }
    if !authorized {
        return Err(VaultError::NotRegistrar.into());
    }

    let bump = expect_pda(
        &[seeds::PROTOCOL, program.address().as_ref()],
        program_id,
        protocol,
    )?;
    let pk = key(program);
    let b = [bump];
    create_pda(
        payer,
        protocol,
        &[Seed::from(seeds::PROTOCOL), Seed::from(&pk), Seed::from(&b)],
        Protocol::LEN,
        program_id,
    )?;

    let t = now()?;
    let p = Protocol {
        protocol_program: pk,
        caller: caller.to_bytes(),
        admin,
        guardians,
        last_heartbeat: [t; MAX_GUARDIANS],
        guardian_count: count,
        threshold,
        sealed: false,
        bump,
        heartbeat_interval_s: interval,
        loosen_delay_s: loosen_delay,
        frozen_until: 0,
        abdications: 0,
        vault_count: 0,
        next_ticket_id: 0,
        next_change_id: 0,
        lifeboat_destination: destination,
        destination_set_s: t,
        seal_executable_s: 0,
        seal_expires_s: 0,
        seal_vetoed: false,
    };
    save(&mut accounts[1], |d| p.store(d))?;
    sys::event(&[b"vault:registered", &pk, &p.admin]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. create_vault
// ---------------------------------------------------------------------------
// Accounts: 0 payer [s,w], 1 admin [s], 2 protocol [w], 3 vault PDA [w],
//           4 vault token account PDA [w], 5 mint, 6 token program, 7 system.
// Data: LimitConfig.
pub fn create_vault(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let limits: LimitConfig = R::args(args).limits()?;
    if !config_is_valid(&limits) {
        return Err(VaultError::InvalidLimits.into());
    }
    let payer = acc(accounts, 0)?;
    let protocol = acc(accounts, 2)?;
    let vault = acc(accounts, 3)?;
    let vault_tokens = acc(accounts, 4)?;
    let mint = acc(accounts, 5)?;
    let token_program = acc(accounts, 6)?;
    check_system(acc(accounts, 7)?)?;
    require_signer(payer)?;
    let mut p = load_protocol(program_id, protocol)?;
    require_admin(&p, acc(accounts, 1)?)?;
    let decimals = token::checked_mint_decimals(mint, token_program.address())?;

    let (pk, mk) = (key(protocol), key(mint));
    let vbump = expect_pda(&[seeds::VAULT, &pk, &mk], program_id, vault)?;
    let tbump = expect_pda(&[seeds::VAULT_TOKENS, &pk, &mk], program_id, vault_tokens)?;
    let vb = [vbump];
    create_pda(
        payer,
        vault,
        &[
            Seed::from(seeds::VAULT),
            Seed::from(&pk),
            Seed::from(&mk),
            Seed::from(&vb),
        ],
        Vault::LEN,
        program_id,
    )?;

    // The vault's token account: a PDA owned by the token program, whose
    // authority is the vault PDA. The protocol can't transfer, close or
    // delegate it.
    let size = token::account_size(token_program, mint)? as usize;
    let tb = [tbump];
    create_pda(
        payer,
        vault_tokens,
        &[
            Seed::from(seeds::VAULT_TOKENS),
            Seed::from(&pk),
            Seed::from(&mk),
            Seed::from(&tb),
        ],
        size,
        token_program.address(),
    )?;
    token::initialize_account(token_program, vault_tokens, mint, vault.address())?;

    let v = Vault {
        protocol: pk,
        mint: mk,
        token_program: key(token_program),
        token_account: key(vault_tokens),
        limits,
        tat_short_ms: 0,
        tat_long_ms: 0,
        ref_balance: 0,
        ref_updated_s: 0,
        ref_initialized: false,
        decimals,
        bump: vbump,
        token_bump: tbump,
        pending_tickets: 0,
        queued_amount: 0,
        frozen_until: 0,
        imported: 0,
        total_in: 0,
        backed_out: 0,
        unbacked_out: 0,
        settled: 0,
        cancelled: 0,
        lifeboat_amount: 0,
        exit_amount: 0,
        exit_proposed_s: 0,
        exit_executable_s: 0,
        exit_expires_s: 0,
        exit_vetoed: false,
    };
    save(&mut accounts[3], |d| v.store(d))?;
    p.vault_count = p.vault_count.checked_add(1).ok_or(VaultError::Overflow)?;
    save(&mut accounts[2], |d| p.store(d))?;
    sys::event(&[b"vault:vault_created", &pk, &mk]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. upsert_asset (genesis only; after the seal it is a proposed change)
// ---------------------------------------------------------------------------
// Accounts: 0 payer [s,w], 1 admin [s], 2 protocol, 3 asset PDA [w], 4 mint,
//           5 token program, 6 system. Data: AssetConfig.
pub fn upsert_asset(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let config: AssetConfig = R::args(args).asset_config()?;
    if !valid_asset(&config) {
        return Err(VaultError::InvalidAsset.into());
    }
    let p = load_protocol(program_id, acc(accounts, 2)?)?;
    require_admin(&p, acc(accounts, 1)?)?;
    if p.sealed {
        return Err(VaultError::GenesisOnly.into());
    }
    write_asset(program_id, accounts, 0, 2, 3, 4, 5, &config)
}

/// Creates or overwrites an asset record (shared with `execute_change`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_asset(
    program_id: &Address,
    accounts: &mut [AccountView],
    payer_i: usize,
    protocol_i: usize,
    asset_i: usize,
    mint_i: usize,
    token_program_i: usize,
    config: &AssetConfig,
) -> ProgramResult {
    let (pk, mk) = (key(&accounts[protocol_i]), key(acc(accounts, mint_i)?));
    let decimals = token::checked_mint_decimals(
        acc(accounts, mint_i)?,
        acc(accounts, token_program_i)?.address(),
    )?;
    let asset = acc(accounts, asset_i)?;
    let bump = expect_pda(&[seeds::ASSET, &pk, &mk], program_id, asset)?;
    if asset.is_data_empty() {
        let b = [bump];
        create_pda(
            acc(accounts, payer_i)?,
            asset,
            &[
                Seed::from(seeds::ASSET),
                Seed::from(&pk),
                Seed::from(&mk),
                Seed::from(&b),
            ],
            Asset::LEN,
            program_id,
        )?;
    }
    let a = Asset {
        protocol: pk,
        mint: mk,
        config: *config,
        decimals,
        bump,
    };
    save(&mut accounts[asset_i], |d| a.store(d))?;
    sys::event(&[b"vault:asset", &pk, &mk, &[config.allowlisted as u8]]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. import_backing (genesis only)
// ---------------------------------------------------------------------------
// Accounts: 0 payer [s,w], 1 admin [s], 2 protocol, 3 vault [w],
//           4 backing PDA [w], 5 owner, 6 system. Data: amount u64.
//
// Imports are public events and, at seal, must be covered together with what
// deposits credited; the seal waits 72h so anyone can compare them with the
// protocol's own books (T19).
pub fn import_backing(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let amount = R::args(args).u64()?;
    let protocol = acc(accounts, 2)?;
    let p = load_protocol(program_id, protocol)?;
    require_admin(&p, acc(accounts, 1)?)?;
    if p.sealed {
        return Err(VaultError::GenesisOnly.into());
    }
    let mut v = load_vault(program_id, protocol, acc(accounts, 3)?)?;
    let owner = key(acc(accounts, 5)?);
    let mut b = custody::load_or_create_backing(program_id, accounts, 0, 2, 4, &owner)?;
    let mut ledger = b.ledger()?;
    if !ledger.credit(v.mint, amount) {
        return Err(VaultError::NoSlot.into());
    }
    b.set_ledger(&ledger);
    save(&mut accounts[4], |d| b.store(d))?;
    v.imported = v.imported.checked_add(amount).ok_or(VaultError::Overflow)?;
    save(&mut accounts[3], |d| v.store(d))?;
    sys::event(&[b"vault:imported", &v.mint, &owner, &amount.to_le_bytes()]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 4–6. Seal: propose (admin), veto (live guardian), execute (anyone)
// ---------------------------------------------------------------------------
// propose: 0 protocol [w], 1 admin [s].
pub fn propose_seal(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut p = load_protocol(program_id, acc(accounts, 0)?)?;
    require_admin(&p, acc(accounts, 1)?)?;
    if p.sealed {
        return Err(VaultError::AlreadySealed.into());
    }
    let s = schedule(
        now()?,
        bulkhead_core::classify::Class::Loosen,
        p.loosen_delay_s,
    );
    p.seal_executable_s = s.executable_s;
    p.seal_expires_s = s.expires_s;
    p.seal_vetoed = false;
    save(&mut accounts[0], |d| p.store(d))?;
    sys::event(&[
        b"vault:seal_proposed",
        &p.protocol_program,
        &s.executable_s.to_le_bytes(),
    ]);
    Ok(())
}

// veto: 0 protocol [w], 1 guardian [s].
pub fn veto_seal(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let mut p = load_protocol(program_id, acc(accounts, 0)?)?;
    live_guardian(&p, acc(accounts, 1)?, now()?)?;
    if p.sealed || p.seal_executable_s == 0 {
        return Err(VaultError::SealNotExecutable.into());
    }
    p.seal_vetoed = true;
    save(&mut accounts[0], |d| p.store(d))?;
    sys::event(&[b"vault:seal_vetoed", &p.protocol_program]);
    Ok(())
}

// execute: 0 protocol [w], then (vault, vault token account) for every vault.
pub fn execute_seal(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let mut p = load_protocol(program_id, protocol)?;
    if p.seal_executable_s == 0 {
        return Err(VaultError::SealNotExecutable.into());
    }
    let s = Schedule {
        executable_s: p.seal_executable_s,
        expires_s: p.seal_expires_s,
    };
    can_execute(&s, now()?, p.seal_vetoed, p.sealed, false)
        .map_err(|_| VaultError::SealNotExecutable)?;
    let pairs = &accounts[1..];
    if pairs.len() != 2 * p.vault_count as usize {
        return Err(VaultError::VaultCountMismatch.into());
    }
    let mut seen = [[0u8; 32]; 64];
    for (i, pair) in pairs.chunks(2).enumerate() {
        let v = load_vault(program_id, protocol, &pair[0])?;
        if key(&pair[1]) != v.token_account {
            return Err(VaultError::WrongVault.into());
        }
        let k = key(&pair[0]);
        if i >= seen.len() || seen[..i].contains(&k) {
            return Err(VaultError::DuplicateAccount.into());
        }
        seen[i] = k;
        // Every backing claim must be covered: imports plus what deposits
        // credited, against the tokens in the vault and its lifeboat. Checking
        // imports alone let total claims exceed the tokens held (docs/15, A10).
        let claims = v.imported as u128 + v.total_in;
        let held = token::balance(&pair[1])? as u128 + v.lifeboat_amount as u128;
        if claims > held {
            return Err(VaultError::ImportExceedsBalance.into());
        }
    }
    p.sealed = true;
    save(&mut accounts[0], |d| p.store(d))?;
    sys::event(&[b"vault:sealed", &p.protocol_program]);
    Ok(())
}
