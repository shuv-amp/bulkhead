//! Governance: tighten now, loosen later (G4).
//!
//! `bulkhead-core::classify` decides. A tightening applies at proposal time;
//! everything else becomes a `Change` that waits at least 72 hours (a
//! constant), can be vetoed by any live guardian, and expires 7 days after it
//! becomes executable. Before the seal nothing can be released, so changes
//! apply at once (genesis configuration).

use crate::genesis::{valid_asset, write_asset};
use crate::state::{change, Asset, Change, Protocol, MAX_PAYLOAD, R};
use crate::*;
use bulkhead_core::classify::{
    classify_asset, classify_delay, classify_limits, AssetConfig, Class, LimitConfig,
};
use bulkhead_core::consts::MIN_LOOSEN_DELAY_S;
use bulkhead_core::governance::{can_execute, schedule, Abdications, Schedule};
use bulkhead_core::limiter::{config_is_valid, params_from_config, rescale_windows};

// A short-lived value on the stack; no allocator exists to box the guardian set.
#[allow(clippy::large_enum_variant)]
enum Parsed {
    Limits(LimitConfig),
    Asset(AssetConfig),
    Guardians(GuardianSet),
    Key([u8; 32]),
    Delay(i64),
}

fn parse(
    p: &Protocol,
    kind: u8,
    target: &[u8; 32],
    payload: &[u8],
) -> Result<Parsed, ProgramError> {
    let mut r = R::args(payload);
    Ok(match kind {
        change::SET_LIMITS => {
            let l = r.limits()?;
            if !config_is_valid(&l) {
                return Err(VaultError::InvalidLimits.into());
            }
            Parsed::Limits(l)
        }
        change::UPSERT_ASSET => {
            let a = r.asset_config()?;
            if !valid_asset(&a) {
                return Err(VaultError::InvalidAsset.into());
            }
            Parsed::Asset(a)
        }
        change::SET_GUARDIANS => Parsed::Guardians(parse_guardian_set(&mut r, &p.admin)?),
        change::SET_ADMIN | change::SET_LIFEBOAT_DESTINATION => {
            if *target == [0; 32]
                || (kind == change::SET_LIFEBOAT_DESTINATION && *target == p.admin)
            {
                return Err(VaultError::InvalidInstruction.into());
            }
            Parsed::Key(*target)
        }
        change::SET_LOOSEN_DELAY => Parsed::Delay(r.i64()?),
        _ => return Err(VaultError::InvalidInstruction.into()),
    })
}

/// Applies a parsed change. Accounts by index: `target_i` is the vault
/// (SetLimits) or the asset PDA (UpsertAsset); `payer_i`, `mint_i`,
/// `token_i` are used when an asset record must be created.
#[allow(clippy::too_many_arguments)]
fn apply(
    program_id: &Address,
    accounts: &mut [AccountView],
    p: &mut Protocol,
    kind: u8,
    target: &[u8; 32],
    parsed: Parsed,
    t: i64,
    (protocol_i, target_i, payer_i, mint_i, token_i): (usize, usize, usize, usize, usize),
) -> ProgramResult {
    match parsed {
        Parsed::Limits(l) => {
            if key(acc(accounts, target_i)?) != *target {
                return Err(VaultError::WrongVault.into());
            }
            let mut v = load_vault(program_id, &accounts[protocol_i], &accounts[target_i])?;
            // Keep each bucket's used fraction across a window change, or a
            // longer window (a tightening, applied at once) refills a drained
            // bucket. Capacities don't enter: only the windows are read.
            let mut state = v.limiter_state();
            rescale_windows(
                &mut state,
                &params_from_config(&v.limits, 0),
                &params_from_config(&l, 0),
                t.saturating_mul(1_000),
            );
            v.set_limiter_state(state);
            v.limits = l;
            save(&mut accounts[target_i], |d| v.store(d))
        }
        Parsed::Asset(a) => {
            if key(acc(accounts, mint_i)?) != *target {
                return Err(VaultError::WrongMint.into());
            }
            write_asset(
                program_id, accounts, payer_i, protocol_i, target_i, mint_i, token_i, &a,
            )
        }
        Parsed::Guardians((g, n, th, interval)) => {
            p.guardians = g;
            p.guardian_count = n;
            p.threshold = th;
            p.heartbeat_interval_s = interval;
            p.last_heartbeat = [t; MAX_GUARDIANS];
            Ok(())
        }
        Parsed::Key(k) => {
            if kind == change::SET_ADMIN {
                p.admin = k;
            } else {
                p.lifeboat_destination = k;
                p.destination_set_s = t;
            }
            Ok(())
        }
        Parsed::Delay(d) => {
            p.loosen_delay_s = d;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// 18. propose_change (admin)
// ---------------------------------------------------------------------------
// Accounts: 0 payer [s,w], 1 admin [s], 2 protocol [w],
//           3 change PDA for id = protocol.next_change_id [w], 4 system,
//           5 target: vault [w] (SetLimits) or asset PDA [w] (UpsertAsset),
//           6 mint (UpsertAsset), 7 token program (UpsertAsset).
// Data: kind u8, target[32], payload.
pub fn propose_change(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let mut r = R::args(args);
    let kind = r.u8()?;
    let target = r.key()?;
    let payload = r.rest();
    if payload.len() > MAX_PAYLOAD {
        return Err(VaultError::InvalidInstruction.into());
    }
    let protocol = acc(accounts, 2)?;
    let mut p = load_protocol(program_id, protocol)?;
    require_admin(&p, acc(accounts, 1)?)?;
    let abdicated = Abdications(p.abdications).is_abdicated(kind);
    let parsed = parse(&p, kind, &target, payload)?;
    let class = match &parsed {
        Parsed::Limits(l) => {
            let v = load_vault(program_id, protocol, acc(accounts, 5)?)?;
            if key(&accounts[5]) != target {
                return Err(VaultError::WrongVault.into());
            }
            classify_limits(&v.limits, l)
        }
        Parsed::Asset(a) => {
            let asset = acc(accounts, 5)?;
            let old = if asset.is_data_empty() {
                None
            } else {
                Some(load(program_id, asset, Asset::load)?.config)
            };
            classify_asset(old.as_ref(), a)
        }
        // Outside [72h, 30 days] is never accepted, even before the seal.
        Parsed::Delay(d) => {
            classify_delay(p.loosen_delay_s, *d).ok_or(if *d < MIN_LOOSEN_DELAY_S {
                VaultError::DelayBelowMinimum
            } else {
                VaultError::DelayAboveMaximum
            })?
        }
        Parsed::Guardians(_) | Parsed::Key(_) => Class::Loosen,
    };
    // Abdication gives up loosening a kind forever; tightening it must stay
    // possible (making things safer never waits, docs/15, A3).
    if abdicated && class == Class::Loosen {
        return Err(VaultError::Abdicated.into());
    }
    let t = now()?;
    if class == Class::Loosen {
        crate::genesis::require_no_seal_review(&p, t)?;
    }

    if class == Class::Tighten || !p.sealed {
        // Tightening (or genesis): apply now.
        apply(
            program_id,
            accounts,
            &mut p,
            kind,
            &target,
            parsed,
            t,
            (2, 5, 0, 6, 7),
        )?;
        save(&mut accounts[2], |d| p.store(d))?;
        sys::event(&[b"vault:change_applied", &[kind], &target]);
        return Ok(());
    }

    // Loosening: a public, delayed, vetoable, expiring proposal.
    let payer = acc(accounts, 0)?;
    require_signer(payer)?;
    check_system(acc(accounts, 4)?)?;
    let id = p.next_change_id;
    let idb = id.to_le_bytes();
    let pk = key(protocol);
    let change_acc = acc(accounts, 3)?;
    let bump = expect_pda(&[seeds::CHANGE, &pk, &idb], program_id, change_acc)?;
    let b = [bump];
    create_pda(
        payer,
        change_acc,
        &[
            Seed::from(seeds::CHANGE),
            Seed::from(&pk),
            Seed::from(&idb),
            Seed::from(&b),
        ],
        Change::LEN,
        program_id,
    )?;
    let s = schedule(t, Class::Loosen, p.loosen_delay_s);
    let mut buf = [0u8; MAX_PAYLOAD];
    buf[..payload.len()].copy_from_slice(payload);
    let c = Change {
        protocol: pk,
        id,
        kind,
        vetoed: false,
        executed: false,
        bump,
        target,
        proposer: key(acc(accounts, 1)?),
        created_s: t,
        executable_s: s.executable_s,
        expires_s: s.expires_s,
        payload_len: payload.len() as u16,
        payload: buf,
    };
    save(&mut accounts[3], |d| c.store(d))?;
    p.next_change_id += 1;
    save(&mut accounts[2], |d| p.store(d))?;
    sys::event(&[
        b"vault:change_proposed",
        &idb,
        &[kind],
        &target,
        &s.executable_s.to_le_bytes(),
    ]);
    Ok(())
}

fn load_change(
    program_id: &Address,
    protocol: &AccountView,
    a: &AccountView,
) -> Result<Change, ProgramError> {
    let c = load(program_id, a, Change::load)?;
    if c.protocol != key(protocol) {
        return Err(VaultError::WrongAddress.into());
    }
    Ok(c)
}

// ---------------------------------------------------------------------------
// 19. veto_change (any live guardian)   Accounts: 0 protocol, 1 change [w], 2 guardian [s].
// ---------------------------------------------------------------------------
pub fn veto_change(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    live_guardian(&p, acc(accounts, 2)?, now()?)?;
    let mut c = load_change(program_id, protocol, acc(accounts, 1)?)?;
    if c.executed {
        return Err(VaultError::ChangeExecuted.into());
    }
    c.vetoed = true;
    save(&mut accounts[1], |d| c.store(d))?;
    let who = key(&accounts[2]);
    sys::event(&[b"vault:change_vetoed", &c.id.to_le_bytes(), &who]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 20. execute_change (anyone, once executable)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol [w], 1 change [w], 2 target (vault or asset PDA) [w],
//           3 payer [s,w], 4 mint, 5 token program, 6 system.
pub fn execute_change(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let mut p = load_protocol(program_id, protocol)?;
    let mut c = load_change(program_id, protocol, acc(accounts, 1)?)?;
    let t = now()?;
    let s = Schedule {
        executable_s: c.executable_s,
        expires_s: c.expires_s,
    };
    let abdicated = Abdications(p.abdications).is_abdicated(c.kind);
    can_execute(&s, t, c.vetoed, c.executed, abdicated).map_err(|e| {
        ProgramError::from(match e {
            bulkhead_core::governance::GovError::Vetoed => VaultError::ChangeVetoed,
            bulkhead_core::governance::GovError::Expired => VaultError::ChangeExpired,
            bulkhead_core::governance::GovError::AlreadyExecuted => VaultError::ChangeExecuted,
            bulkhead_core::governance::GovError::Abdicated => VaultError::Abdicated,
            _ => VaultError::ChangeNotExecutable,
        })
    })?;
    let payload = &c.payload[..c.payload_len as usize];
    let parsed = parse(&p, c.kind, &c.target, payload)?; // re-validated at execution
    apply(
        program_id,
        accounts,
        &mut p,
        c.kind,
        &c.target,
        parsed,
        t,
        (0, 2, 3, 4, 5),
    )?;
    c.executed = true;
    save(&mut accounts[1], |d| c.store(d))?;
    save(&mut accounts[0], |d| p.store(d))?;
    sys::event(&[b"vault:change_executed", &c.id.to_le_bytes(), &[c.kind]]);
    Ok(())
}

// ---------------------------------------------------------------------------
// 21. cancel_change (admin withdraws a pending change)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 change [w], 2 admin [s].
pub fn cancel_change(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    require_admin(&p, acc(accounts, 2)?)?;
    let mut c = load_change(program_id, protocol, acc(accounts, 1)?)?;
    if c.executed {
        return Err(VaultError::ChangeExecuted.into());
    }
    c.vetoed = true; // a withdrawn change can never execute
    save(&mut accounts[1], |d| c.store(d))?;
    sys::event(&[b"vault:change_cancelled", &c.id.to_le_bytes()]);
    Ok(())
}
