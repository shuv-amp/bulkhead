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
use bulkhead_core::governance::{can_execute, quorum, schedule, Abdications, Schedule};
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
        change::SET_GUARDIANS => {
            Parsed::Guardians(parse_guardian_set(&mut r, &p.admin, &p.recovery)?)
        }
        change::SET_ADMIN | change::SET_LIFEBOAT_DESTINATION => {
            // The admin is never a guardian (as `parse_guardian_set` keeps it
            // from the other side): an admin who is also a guardian would get
            // back the powers kept from the admin, cancelling honest tickets
            // first (docs/09, finding 57). Checked again at execution, so a
            // guardian set changed in between cannot slip one in.
            if *target == [0; 32]
                || (kind == change::SET_LIFEBOAT_DESTINATION && *target == p.admin)
                // The admin parks the vault; the destination receives its
                // exit. One key must never be both (docs/09, finding 72).
                || (kind == change::SET_ADMIN && *target == p.lifeboat_destination)
                || (kind == change::SET_ADMIN
                    && (*target == p.recovery
                        || p.guardian_index(target).is_some()))
            {
                return Err(VaultError::InvalidInstruction.into());
            }
            Parsed::Key(*target)
        }
        // The admin and the recovery key stay distinct, or recovery means nothing.
        change::SET_RECOVERY => {
            if *target == p.admin || p.guardian_index(target).is_some() {
                return Err(VaultError::InvalidInstruction.into());
            }
            Parsed::Key(*target)
        }
        change::SET_LOOSEN_DELAY => Parsed::Delay(r.i64()?),
        _ => return Err(VaultError::InvalidInstruction.into()),
    })
}

/// Who may propose a change of `kind`: the admin, for every kind but a new
/// recovery key once one exists; the recovery key, only a new admin or a new
/// recovery key. A stolen admin key therefore cannot stop or pre-empt the
/// protocol's way of replacing it (docs/15, A4).
fn require_proposer(p: &Protocol, signer: &AccountView, kind: u8) -> ProgramResult {
    require_signer(signer)?;
    let k = key(signer);
    if p.recovery != [0; 32] && k == p.recovery {
        if kind == change::SET_ADMIN || kind == change::SET_RECOVERY {
            return Ok(());
        }
        return Err(VaultError::NotAdmin.into());
    }
    require_admin(p, signer)?;
    if kind == change::SET_RECOVERY && p.recovery != [0; 32] {
        return Err(VaultError::NotAdmin.into());
    }
    Ok(())
}

/// Which `Protocol::versions` slot a protocol-level change kind uses.
pub(crate) fn version_slot(kind: u8) -> Option<usize> {
    match kind {
        change::SET_GUARDIANS => Some(0),
        change::SET_ADMIN => Some(1),
        change::SET_LIFEBOAT_DESTINATION => Some(2),
        change::SET_LOOSEN_DELAY => Some(3),
        change::SET_RECOVERY => Some(4),
        _ => None,
    }
}

/// The current version of what a change of `kind` replaces: the vault's
/// limits, the asset record (absent: 0), or a protocol-level value. A change
/// records it when proposed and executes only if it has not moved, so a
/// loosening can never undo something applied after it was reviewed.
fn target_version(
    program_id: &Address,
    accounts: &[AccountView],
    p: &Protocol,
    kind: u8,
    target: &[u8; 32],
    (protocol_i, target_i): (usize, usize),
) -> Result<u32, ProgramError> {
    Ok(match kind {
        change::SET_LIMITS => {
            load_vault(program_id, &accounts[protocol_i], acc(accounts, target_i)?)?.limits_version
        }
        change::UPSERT_ASSET => {
            let a = acc(accounts, target_i)?;
            // Only the target mint's own record: another record's version
            // would let a loosening outlive a later tightening (`ChangeStale`).
            expect_pda(
                &[seeds::ASSET, &key(&accounts[protocol_i]), target],
                program_id,
                a,
            )?;
            if a.is_data_empty() {
                0
            } else {
                load(program_id, a, Asset::load)?.version
            }
        }
        _ => p.versions[version_slot(kind).ok_or(VaultError::InvalidInstruction)?],
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
            v.limits_version = v.limits_version.wrapping_add(1);
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
        Parsed::Guardians(set) => {
            p.guardians = set.keys;
            p.guardian_count = set.count;
            p.threshold = set.threshold;
            p.heartbeat_interval_s = set.interval_s;
            p.last_heartbeat = [t; MAX_GUARDIANS];
            p.versions[0] = p.versions[0].wrapping_add(1);
            Ok(())
        }
        Parsed::Key(k) => {
            match kind {
                change::SET_ADMIN => {
                    p.admin = k;
                    p.versions[1] = p.versions[1].wrapping_add(1);
                }
                change::SET_RECOVERY => {
                    p.recovery = k;
                    p.versions[4] = p.versions[4].wrapping_add(1);
                }
                _ => {
                    p.lifeboat_destination = k;
                    p.destination_set_s = t;
                    p.versions[2] = p.versions[2].wrapping_add(1);
                }
            }
            Ok(())
        }
        Parsed::Delay(d) => {
            p.loosen_delay_s = d;
            p.versions[3] = p.versions[3].wrapping_add(1);
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
    require_proposer(&p, acc(accounts, 1)?, kind)?;
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
            expect_pda(&[seeds::ASSET, &key(protocol), &target], program_id, asset)?;
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
    // An abdicated kind can never be loosened again, so tightening it is
    // final: a stolen admin key alone used to close a vault for good (bps 0,
    // a queue delay of 136 years) and nothing could reopen it (docs/09,
    // finding 88). Tightening an abdicated kind takes a live guardian quorum
    // too, signing anywhere after account 4.
    if abdicated && class == Class::Tighten {
        let mut bits = 0u8;
        for a in accounts.get(5..).unwrap_or(&[]) {
            if a.is_signer() {
                if let Some(i) = p.guardian_index(&key(a)) {
                    bits |= 1 << i;
                }
            }
        }
        let alive = p.alive_mask(t);
        if !quorum(bits & alive, alive, p.threshold) {
            return Err(VaultError::NoQuorum.into());
        }
    }
    // The recovery key replaces the admin even while a seal is under review,
    // and that ends the review: a stolen admin key used to swap the guardians,
    // propose the seal, and so lock the recovery key out until its own seal
    // had executed (docs/09, finding 88).
    let recovery_rotation =
        kind == change::SET_ADMIN && p.recovery != [0; 32] && key(acc(accounts, 1)?) == p.recovery;
    if class == Class::Loosen && !recovery_rotation {
        crate::genesis::require_no_seal_review(&p, t)?;
    }
    if recovery_rotation && crate::genesis::require_no_seal_review(&p, t).is_err() {
        p.seal_vetoed = true;
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
        sys::event(
            &key(&accounts[2]),
            &[b"vault:change_applied", &[kind], &target],
        );
        return Ok(());
    }

    // Loosening: a public, delayed, vetoable, expiring proposal.
    let payer = acc(accounts, 0)?;
    require_signer(payer)?;
    check_system(acc(accounts, 4)?)?;
    // The recovery key's new admin takes precedence: proposing it stales every
    // admin rotation proposed before, so a stolen admin key that proposed its
    // own first cannot execute first and keep stalling recovery (A4).
    if kind == change::SET_ADMIN && p.recovery != [0; 32] && key(acc(accounts, 1)?) == p.recovery {
        p.versions[1] = p.versions[1].wrapping_add(1);
    }
    let base_version = target_version(program_id, accounts, &p, kind, &target, (2, 5))?;
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
        base_version,
    };
    save(&mut accounts[3], |d| c.store(d))?;
    p.next_change_id += 1;
    save(&mut accounts[2], |d| p.store(d))?;
    sys::event(
        &key(&accounts[2]),
        &[
            b"vault:change_proposed",
            &idb,
            &[kind],
            &target,
            &s.executable_s.to_le_bytes(),
        ],
    );
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
    sys::event(
        &key(&accounts[0]),
        &[b"vault:change_vetoed", &c.id.to_le_bytes(), &who],
    );
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
    // Only the keys that hold the roles now may have their changes executed.
    // A recovery rotation replaced a stolen admin, yet the thief's queued
    // loosenings (a lifeboat destination, guardians, limits) still executed
    // after the delay, and nobody could cancel them: only a guardian veto
    // stood in the way (docs/09, finding 87). A rotation the admin made
    // itself voids its own pending changes the same way: propose them again.
    // The recovery key counts only for the kinds it may propose. The key
    // compared is the key as it is now: an admin key that queued a
    // loosening, was replaced, and was then made the recovery key (by the
    // new admin with a live quorum) would otherwise have that loosening
    // execute, which no reviewer saw coming from a recovery key (docs/09,
    // finding 133).
    let by_admin = c.proposer == p.admin;
    let by_recovery = p.recovery != [0; 32]
        && c.proposer == p.recovery
        && (c.kind == change::SET_ADMIN || c.kind == change::SET_RECOVERY);
    if !by_admin && !by_recovery {
        return Err(VaultError::ChangeStale.into());
    }
    // The target must be what the review saw: a tightening, another change or
    // an ejection since the proposal makes this change stale. It must be
    // proposed again, and waits again.
    if target_version(program_id, accounts, &p, c.kind, &c.target, (0, 2))? != c.base_version {
        return Err(VaultError::ChangeStale.into());
    }
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
    sys::event(
        &key(&accounts[0]),
        &[b"vault:change_executed", &c.id.to_le_bytes(), &[c.kind]],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 21. cancel_change (admin withdraws a pending change)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol, 1 change [w], 2 admin [s].
pub fn cancel_change(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let protocol = acc(accounts, 0)?;
    let p = load_protocol(program_id, protocol)?;
    let mut c = load_change(program_id, protocol, acc(accounts, 1)?)?;
    // Each key withdraws only what it proposed: a stolen admin key cannot
    // cancel the recovery key's rotation (docs/15, A4).
    let signer = acc(accounts, 2)?;
    require_signer(signer)?;
    let k = key(signer);
    let holds = k == p.admin || (p.recovery != [0; 32] && k == p.recovery);
    if k != c.proposer || !holds {
        return Err(VaultError::NotAdmin.into());
    }
    if c.executed {
        return Err(VaultError::ChangeExecuted.into());
    }
    c.vetoed = true; // a withdrawn change can never execute
    save(&mut accounts[1], |d| c.store(d))?;
    sys::event(
        &key(&accounts[0]),
        &[b"vault:change_cancelled", &c.id.to_le_bytes()],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 29. replace_recovery (the admin with a live guardian quorum, at once)
// ---------------------------------------------------------------------------
// Accounts: 0 protocol [w], 1 admin [s], 2.. guardians [s] forming a live quorum.
// Data: the new recovery key[32] (all zero: none).
//
// A stolen recovery key can only propose, but it can do that forever: each
// new admin it proposes stales the admin's own rotations, the guardians must
// veto every one, and nothing else could replace it. The admin and a live
// quorum together can; together they already decide more than this
// (`abdicate`), and neither can alone.
pub fn replace_recovery(
    program_id: &Address,
    accounts: &mut [AccountView],
    args: &[u8],
) -> ProgramResult {
    let recovery = R::args(args).key()?;
    let mut p = load_protocol(program_id, acc(accounts, 0)?)?;
    require_admin(&p, acc(accounts, 1)?)?;
    if recovery == p.admin || p.guardian_index(&recovery).is_some() {
        return Err(VaultError::InvalidInstruction.into());
    }
    // An abdicated recovery key is fixed for good, and nothing changes while
    // the seal is under review: the same rules as `propose_change`.
    // Removing the key only takes power away: allowed even then, or a stolen
    // key could stale every admin rotation for good (finding 62).
    if recovery != [0; 32] && Abdications(p.abdications).is_abdicated(change::SET_RECOVERY) {
        return Err(VaultError::Abdicated.into());
    }
    let t = now()?;
    crate::genesis::require_no_seal_review(&p, t)?;
    let alive = p.alive_mask(t);
    let signers = guardian_signers(&p, accounts.get(2..).unwrap_or(&[]))?;
    if !quorum(signers & alive, alive, p.threshold) {
        return Err(VaultError::NoQuorum.into());
    }
    p.recovery = recovery;
    // What the replaced key proposed (a new admin, a new recovery key) and any
    // pending new recovery key can no longer execute (`ChangeStale`).
    p.versions[1] = p.versions[1].wrapping_add(1);
    p.versions[4] = p.versions[4].wrapping_add(1);
    save(&mut accounts[0], |d| p.store(d))?;
    sys::event(
        &key(&accounts[0]),
        &[b"vault:recovery_replaced", &recovery, &[signers & alive]],
    );
    Ok(())
}
