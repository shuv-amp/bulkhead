//! Floor on the real agave loader (LiteSVM, mainnet feature set).
//!
//! Every protected program here is deployed through genuine loader-v3
//! instructions, and every code change goes through a real loader `Upgrade`
//! performed by Floor's CPI. Scenario S10 of docs/08-SCENARIOS.md is
//! `s10_full_lifecycle`.

mod common;

use bulkhead_core::floor::{ABORT_ELF, ABORT_MESSAGE, FLOOR_ABORT_CODE};
use common::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

const UPGRADE: u8 = 1;
const RESTORE: u8 = 2;
const RELEASE_AUTHORITY: u8 = 3;
const SET_GUARDIANS: u8 = 4;
const SET_DELAY: u8 = 6;

fn stopped_with_floor_code(env: &mut Env, program: &solana_address::Address) {
    let e = env.call(program).expect_err("program should be stopped");
    assert_eq!(custom_code(&e), Some(FLOOR_ABORT_CODE));
    let msg = std::str::from_utf8(ABORT_MESSAGE).unwrap();
    assert!(
        e.meta.logs.iter().any(|l| l.contains(msg)),
        "the stopped program says why:\n{}",
        e.meta.logs.join("\n")
    );
}

#[test]
fn s10_full_lifecycle() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let gs = p.guardians();

    // Registration moved the upgrade authority to Floor.
    assert_eq!(
        env.upgrade_authority(&f.programdata),
        Some(f.authority.to_bytes())
    );
    assert!(env.call(&f.program).is_ok(), "live program runs");
    let v = read_config(&env, f);
    assert_eq!((v.status, v.elf_is_v3, v.guardian_count), (0, 1, 3));

    // 1. An attacker holding the owner key proposes a drainer. It waits 72h in public.
    let drainer_buf = env.write_buffer(&drainer(), &p.owner);
    env.set_buffer_authority(&drainer_buf, &p.owner, &f.authority);
    env.ok(
        &[f.propose(
            &p.owner.pubkey(),
            UPGRADE,
            &drainer_buf,
            &[],
            Some(&drainer_buf),
        )],
        &[&p.owner],
    );
    let early = f.execute_code(&drainer_buf, &p.owner.pubkey());
    assert_eq!(env.fails(&[early], &[]), err::NOT_EXECUTABLE);
    // 2. A guardian vetoes it; even after the delay it can never execute.
    env.ok(&[f.veto(&gs[0])], &[&p.g[0]]);
    env.advance(3 * DAY + 1);
    let late = f.execute_code(&drainer_buf, &p.owner.pubkey());
    assert_eq!(env.fails(&[late], &[]), err::VETOED);
    env.ok(&[f.cancel(&p.owner.pubkey())], &[&p.owner]);
    assert!(env.call(&f.program).is_ok(), "still the honest code");

    // 3. A guardian stops the program in one instruction.
    env.ok(
        &[f.abort(&gs[1], &p.abort_buffer, Some(&p.snapshot))],
        &[&p.g[1]],
    );
    env.next_slot();
    stopped_with_floor_code(&mut env, &f.program);
    let v = read_config(&env, f);
    assert_eq!(
        (v.status, v.snapshot_valid),
        (1, 1),
        "aborted; snapshot verified at the stop"
    );

    // 4. A quorum restores exactly the code that ran before the stop.
    let restore = f.restore_snapshot(&p.snapshot, &p.owner.pubkey(), &gs[1..3]);
    env.ok(&[restore], &[&p.g[1], &p.g[2]]);
    env.next_slot();
    assert!(env.call(&f.program).is_ok(), "running again");
    assert_eq!(
        env.programdata_bytes(&f.programdata),
        p.original,
        "byte-identical to before"
    );
    assert_eq!(read_config(&env, f).status, 0);
}

#[test]
fn a_fix_goes_live_fast_only_with_quorum_approval_of_that_exact_buffer() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let (f, gs) = (&p.f, p.guardians());
    env.ok(&[f.abort(&gs[0], &p.abort_buffer, Some(&p.snapshot))], &[&p.g[0]]);
    env.next_slot();

    let fix = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&fix, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), RESTORE, &fix, &[], Some(&fix))],
        &[&p.owner],
    );
    // One approval is not a quorum.
    let id = read_config(&env, f).pending_id;
    env.ok(&[f.approve(id, &gs[0..1])], &[&p.g[0]]);
    let exec = f.execute_code(&fix, &p.owner.pubkey());
    assert_eq!(
        env.fails(std::slice::from_ref(&exec), &[]),
        err::NOT_EXECUTABLE
    );
    // A second live guardian approves: the fix installs at once.
    env.ok(&[f.approve(id, &gs[2..3])], &[&p.g[2]]);
    env.ok(&[exec], &[]);
    env.next_slot();
    assert!(env.call(&f.program).is_ok());
    assert_eq!(
        &env.programdata_bytes(&f.programdata)[..honest_fix().len()],
        honest_fix().as_slice()
    );
}

#[test]
fn a_proposed_fix_without_approvals_waits_the_full_delay() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let (f, gs) = (&p.f, p.guardians());
    env.ok(&[f.abort(&gs[0], &p.abort_buffer, Some(&p.snapshot))], &[&p.g[0]]);
    let fix = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&fix, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), RESTORE, &fix, &[], Some(&fix))],
        &[&p.owner],
    );
    env.advance(3 * DAY - 10);
    assert_eq!(
        env.fails(&[f.execute_code(&fix, &p.owner.pubkey())], &[]),
        err::NOT_EXECUTABLE
    );
    env.advance(11);
    env.ok(&[f.execute_code(&fix, &p.owner.pubkey())], &[]);
    env.next_slot();
    assert!(env.call(&f.program).is_ok());
}

#[test]
fn owner_upgrade_executes_after_the_delay_and_invalidates_the_snapshot() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let (f, gs) = (&p.f, p.guardians());
    let v2 = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&v2, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))],
        &[&p.owner],
    );
    env.advance(3 * DAY);
    env.ok(&[f.execute_code(&v2, &p.owner.pubkey())], &[]);
    env.next_slot();
    let v = read_config(&env, f);
    assert_eq!(
        v.snapshot_buffer, [0; 32],
        "the old snapshot no longer matches live code"
    );
    // The staged abort buffer survives upgrades (it doesn't depend on the code).
    assert_eq!(v.abort_buffer, p.abort_buffer.to_bytes());
    // A later abort has no snapshot to restore; only a proposed fix can.
    env.ok(
        &[f.abort(&gs[0], &p.abort_buffer, Some(&p.snapshot))],
        &[&p.g[0]],
    );
    assert_eq!(read_config(&env, f).snapshot_valid, 0);
    let r = f.restore_snapshot(&p.snapshot, &p.owner.pubkey(), &gs[0..2]);
    assert_eq!(env.fails(&[r], &[&p.g[0], &p.g[1]]), err::NO_VALID_SNAPSHOT);
}

#[test]
fn only_live_guardians_or_the_owner_can_stop_the_program() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let stranger = Keypair::new();
    env.fund(&stranger);
    let ix = f.abort(&stranger.pubkey(), &p.abort_buffer, Some(&p.snapshot));
    assert_eq!(env.fails(&[ix], &[&stranger]), err::NOT_LIVE_GUARDIAN);

    // Guardians that miss their 7-day heartbeat lose their powers.
    env.advance(7 * DAY + 1);
    let ix = f.abort(&p.g[0].pubkey(), &p.abort_buffer, Some(&p.snapshot));
    assert_eq!(env.fails(&[ix], &[&p.g[0]]), err::NOT_LIVE_GUARDIAN);
    let hb = f.heartbeat(&p.g[0].pubkey());
    assert_eq!(
        env.fails(&[hb], &[&p.g[0]]),
        err::NOT_LIVE_GUARDIAN,
        "a dead guardian can't revive itself"
    );

    // With no live quorum, the owner can still stop its own program.
    env.ok(
        &[f.abort(&p.owner.pubkey(), &p.abort_buffer, Some(&p.snapshot))],
        &[&p.owner],
    );
}

#[test]
fn heartbeats_keep_guardians_alive() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    env.advance(6 * DAY);
    env.ok(&[f.heartbeat(&p.g[0].pubkey())], &[&p.g[0]]);
    env.advance(2 * DAY);
    env.ok(
        &[f.abort(&p.g[0].pubkey(), &p.abort_buffer, Some(&p.snapshot))],
        &[&p.g[0]],
    );
}

#[test]
fn a_quorum_ejects_a_rogue_guardian_who_vetoes_everything() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let (f, gs) = (&p.f, p.guardians());
    // Guardian 0 vetoes a legitimate upgrade.
    let v2 = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&v2, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))],
        &[&p.owner],
    );
    env.ok(&[f.veto(&gs[0])], &[&p.g[0]]);
    // It can't eject itself or be saved by its own vote.
    let own = f.eject(0, &gs[0..2]);
    assert_eq!(env.fails(&[own], &[&p.g[0], &p.g[1]]), err::CANNOT_EJECT);
    // The other two eject it instantly.
    env.ok(&[f.eject(0, &gs[1..3])], &[&p.g[1], &p.g[2]]);
    assert_eq!(read_config(&env, f).guardian_count, 2);
    let ix = f.veto(&gs[0]);
    assert_eq!(env.fails(&[ix], &[&p.g[0]]), err::NOT_LIVE_GUARDIAN);
    // With 2 guardians and threshold 2, nobody else can be ejected.
    let ix = f.eject(0, &gs[1..3]);
    assert_eq!(env.fails(&[ix], &[&p.g[1], &p.g[2]]), err::CANNOT_EJECT);
}

#[test]
fn registration_requires_the_current_upgrade_authority() {
    let mut env = Env::new();
    let team = Keypair::new();
    env.fund(&team);
    let (program, _) = env.deploy(&honest_v1(), &team, 1024);
    let f = Floor::new(env.floor, program);
    let attacker = Keypair::new();
    env.fund(&attacker);
    let gs = [Keypair::new().pubkey(), Keypair::new().pubkey()];
    let ix = f.register(
        &env.payer.pubkey(),
        &attacker.pubkey(),
        &attacker.pubkey(),
        &gs,
        2,
        7 * DAY,
        3 * DAY,
    );
    assert_eq!(env.fails(&[ix], &[&attacker]), err::NOT_CURRENT_AUTHORITY);
    assert_eq!(
        env.upgrade_authority(&f.programdata),
        Some(team.pubkey().to_bytes())
    );
}

#[test]
fn registration_rejects_weak_settings() {
    let mut env = Env::new();
    let team = Keypair::new();
    env.fund(&team);
    let (program, _) = env.deploy(&honest_v1(), &team, 1024);
    let f = Floor::new(env.floor, program);
    let owner = Keypair::new().pubkey();
    let (a, b) = (Keypair::new().pubkey(), Keypair::new().pubkey());
    let pay = env.payer.pubkey();
    let cases = [
        (
            f.register(
                &pay,
                &team.pubkey(),
                &owner,
                &[a, b],
                2,
                7 * DAY,
                3 * DAY - 1,
            ),
            err::INVALID_DELAY,
        ),
        (
            f.register(&pay, &team.pubkey(), &owner, &[a, b], 1, 7 * DAY, 3 * DAY),
            err::INVALID_THRESHOLD,
        ),
        (
            f.register(&pay, &team.pubkey(), &owner, &[a, a], 2, 7 * DAY, 3 * DAY),
            err::INVALID_GUARDIANS,
        ),
        (
            f.register(
                &pay,
                &team.pubkey(),
                &owner,
                &[a, owner],
                2,
                7 * DAY,
                3 * DAY,
            ),
            err::INVALID_GUARDIANS,
        ),
        (
            f.register(&pay, &team.pubkey(), &owner, &[a], 1, 7 * DAY, 3 * DAY),
            err::INVALID_GUARDIANS,
        ),
    ];
    for (ix, code) in cases {
        assert_eq!(env.fails(&[ix], &[&team]), code);
    }
}

#[test]
fn registration_survives_a_prefunded_config_address() {
    let mut env = Env::new();
    let team = Keypair::new();
    env.fund(&team);
    let (program, _) = env.deploy(&honest_v1(), &team, 1024);
    let f = Floor::new(env.floor, program);
    // Griefer sends lamports to the config PDA to make CreateAccount fail.
    let ix =
        solana_system_interface::instruction::transfer(&env.payer.pubkey(), &f.config, 1_000_000);
    env.ok(&[ix], &[]);
    let gs = [Keypair::new().pubkey(), Keypair::new().pubkey()];
    let owner = Keypair::new().pubkey();
    let ix = f.register(
        &env.payer.pubkey(),
        &team.pubkey(),
        &owner,
        &gs,
        2,
        7 * DAY,
        3 * DAY,
    );
    env.ok(&[ix], &[&team]);
    assert_eq!(read_config(&env, &f).status, 0);
}

#[test]
fn only_the_exact_canonical_abort_binary_can_be_staged() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let stager = Keypair::new();
    env.fund(&stager);
    // A second buffer while one is staged is refused.
    let extra = env.write_buffer(&ABORT_ELF, &stager);
    env.set_buffer_authority(&extra, &stager, &f.authority);
    assert_eq!(
        env.fails(&[f.stage_abort(&extra)], &[]),
        err::ABORT_ALREADY_STAGED
    );
    // Consume the staged one, then try a lookalike.
    env.ok(
        &[f.abort(&p.g[0].pubkey(), &p.abort_buffer, Some(&p.snapshot))],
        &[&p.g[0]],
    );
    let mut fake = ABORT_ELF.to_vec();
    fake[ABORT_ELF.len() - 12] ^= 1;
    let fake_buf = env.write_buffer(&fake, &stager);
    env.set_buffer_authority(&fake_buf, &stager, &f.authority);
    assert_eq!(
        env.fails(&[f.stage_abort(&fake_buf)], &[]),
        err::NOT_CANONICAL_ABORT
    );
    // A buffer someone can still write to is refused (its bytes aren't frozen).
    let unfrozen = env.write_buffer(&ABORT_ELF, &stager);
    assert_eq!(
        env.fails(&[f.stage_abort(&unfrozen)], &[]),
        err::BUFFER_NOT_FROZEN
    );
}

#[test]
fn a_snapshot_must_be_byte_identical_to_the_live_program() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let stager = Keypair::new();
    env.fund(&stager);
    let wrong = env.write_buffer(&honest_fix(), &stager);
    env.set_buffer_authority(&wrong, &stager, &f.authority);
    assert_eq!(
        env.fails(&[f.pin_snapshot(&wrong)], &[]),
        err::SNAPSHOT_MISMATCH
    );
}

#[test]
fn abort_cancels_pending_proposals() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let v2 = env.write_buffer(&drainer(), &p.owner);
    env.set_buffer_authority(&v2, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))],
        &[&p.owner],
    );
    env.ok(
        &[f.abort(&p.g[0].pubkey(), &p.abort_buffer, Some(&p.snapshot))],
        &[&p.g[0]],
    );
    assert_eq!(read_config(&env, f).pending_kind, 0);
}

#[test]
fn the_delay_can_be_raised_instantly_but_lowered_only_after_the_delay() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let seven_days = (7 * DAY).to_le_bytes();
    let zero = solana_address::Address::default();
    env.ok(
        &[f.propose(&p.owner.pubkey(), SET_DELAY, &zero, &seven_days, None)],
        &[&p.owner],
    );
    assert_eq!(
        read_config(&env, f).upgrade_delay_s,
        7 * DAY,
        "raised at once"
    );
    let back = (3 * DAY).to_le_bytes();
    env.ok(
        &[f.propose(&p.owner.pubkey(), SET_DELAY, &zero, &back, None)],
        &[&p.owner],
    );
    env.advance(3 * DAY);
    assert_eq!(
        env.fails(&[f.execute_config()], &[]),
        err::NOT_EXECUTABLE,
        "waits the current 7 days"
    );
    env.advance(4 * DAY);
    env.ok(&[f.execute_config()], &[]);
    assert_eq!(read_config(&env, f).upgrade_delay_s, 3 * DAY);
    let too_low = (DAY).to_le_bytes();
    let ix = f.propose(&p.owner.pubkey(), SET_DELAY, &zero, &too_low, None);
    assert_eq!(
        env.fails(&[ix], &[&p.owner]),
        err::INVALID_DELAY,
        "never below 72h"
    );
    let too_high = (31 * DAY).to_le_bytes();
    let ix = f.propose(&p.owner.pubkey(), SET_DELAY, &zero, &too_high, None);
    assert_eq!(env.fails(&[ix], &[&p.owner]), err::INVALID_DELAY, "never above 30 days");
}

#[test]
fn proposals_expire_seven_days_after_becoming_executable() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let v2 = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&v2, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))],
        &[&p.owner],
    );
    env.advance(10 * DAY);
    assert_eq!(
        env.fails(&[f.execute_code(&v2, &p.owner.pubkey())], &[]),
        err::EXPIRED
    );
}

#[test]
fn a_new_guardian_set_waits_the_delay_and_is_vetoable() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let attacker_keys = [Keypair::new().pubkey(), Keypair::new().pubkey()];
    let set = Floor::guardian_set(&attacker_keys, 2, 7 * DAY);
    let zero = solana_address::Address::default();
    env.ok(
        &[f.propose(&p.owner.pubkey(), SET_GUARDIANS, &zero, &set, None)],
        &[&p.owner],
    );
    env.ok(&[f.veto(&p.g[2].pubkey())], &[&p.g[2]]);
    env.advance(3 * DAY);
    assert_eq!(env.fails(&[f.execute_config()], &[]), err::VETOED);
}

#[test]
fn release_authority_hands_the_key_back_after_the_delay() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let new_auth = Keypair::new().pubkey();
    env.ok(
        &[f.propose(&p.owner.pubkey(), RELEASE_AUTHORITY, &new_auth, &[], None)],
        &[&p.owner],
    );
    env.advance(3 * DAY);
    env.ok(
        &[f.execute_release(&p.owner.pubkey(), Some(&new_auth))],
        &[],
    );
    assert_eq!(
        env.upgrade_authority(&f.programdata),
        Some(new_auth.to_bytes())
    );
    assert!(
        env.svm
            .get_account(&f.config)
            .map(|a| a.lamports == 0)
            .unwrap_or(true),
        "config closed"
    );
}

#[test]
fn only_one_proposal_at_a_time_and_only_the_owner_proposes() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let v2 = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&v2, &p.owner, &f.authority);
    let ix = f.propose(&p.g[0].pubkey(), UPGRADE, &v2, &[], Some(&v2));
    assert_eq!(env.fails(&[ix], &[&p.g[0]]), err::NOT_OWNER);
    env.ok(
        &[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))],
        &[&p.owner],
    );
    let ix = f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2));
    assert_eq!(env.fails(&[ix], &[&p.owner]), err::PROPOSAL_PENDING);
}

#[test]
fn restoring_a_snapshot_needs_a_live_quorum() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let (f, gs) = (&p.f, p.guardians());
    env.ok(
        &[f.abort(&gs[0], &p.abort_buffer, Some(&p.snapshot))],
        &[&p.g[0]],
    );
    env.next_slot();
    let one = f.restore_snapshot(&p.snapshot, &p.owner.pubkey(), &gs[0..1]);
    assert_eq!(env.fails(&[one], &[&p.g[0]]), err::NO_QUORUM);
    stopped_with_floor_code(&mut env, &f.program);
}

#[test]
fn an_abort_binary_that_would_not_fit_is_refused_and_the_minimal_one_is_accepted() {
    let mut env = Env::new();
    let team = Keypair::new();
    env.fund(&team);
    // A program whose programdata holds only 200 bytes.
    let (program, _) = env.deploy(&honest_v1(), &team, 200);
    let f = Floor::new(env.floor, program);
    let owner = Keypair::new();
    let guardian = Keypair::new();
    env.fund(&guardian);
    let gs = [guardian.pubkey(), Keypair::new().pubkey()];
    let ix = f.register(
        &env.payer.pubkey(),
        &team.pubkey(),
        &owner.pubkey(),
        &gs,
        2,
        7 * DAY,
        3 * DAY,
    );
    env.ok(&[ix], &[&team]);
    let stager = Keypair::new();
    env.fund(&stager);
    let big = env.write_buffer(&ABORT_ELF, &stager); // 328 bytes
    env.set_buffer_authority(&big, &stager, &f.authority);
    assert_eq!(
        env.fails(&[f.stage_abort(&big)], &[]),
        err::ABORT_DOES_NOT_FIT
    );
    let small = env.write_buffer(&bulkhead_core::floor::ABORT_ELF_MINIMAL, &stager); // 136 bytes
    env.set_buffer_authority(&small, &stager, &f.authority);
    env.ok(&[f.stage_abort(&small)], &[]);
    env.ok(&[f.abort(&guardian.pubkey(), &small, None)], &[&guardian]);
    env.next_slot();
    let e = env.call(&f.program).expect_err("stopped");
    assert_eq!(custom_code(&e), Some(FLOOR_ABORT_CODE));
}

/// Compute cost of the stop on a realistically sized program (~200 KB):
/// the abort verifies the pinned snapshot byte-for-byte against the live code
/// (sol_memcmp_) and then swaps in the abort binary. Printed for docs/06 §9.
#[test]
fn stopping_a_200kb_program_with_snapshot_verification_is_cheap() {
    let mut env = Env::new();
    let big = program_returning(0, 25_000); // ~200 KB of code
    let p = protect(&mut env, &big);
    let (f, gs) = (&p.f, p.guardians());
    let m = env.ok(
        &[f.abort(&gs[0], &p.abort_buffer, Some(&p.snapshot))],
        &[&p.g[0]],
    );
    println!(
        "abort + snapshot check on {} bytes: {} CU",
        big.len(),
        m.compute_units_consumed
    );
    assert_eq!(read_config(&env, f).snapshot_valid, 1);
    assert!(m.compute_units_consumed < 100_000);
    env.next_slot();
    let r = f.restore_snapshot(&p.snapshot, &p.owner.pubkey(), &gs[0..2]);
    let m = env.ok(&[r], &[&p.g[0], &p.g[1]]);
    println!(
        "restore of {} bytes: {} CU",
        big.len(),
        m.compute_units_consumed
    );
    env.next_slot();
    assert!(env.call(&f.program).is_ok());
}

#[test]
fn a_named_veto_does_not_apply_to_a_different_proposal() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let buf = env.write_buffer(&drainer(), &p.owner);
    env.set_buffer_authority(&buf, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), UPGRADE, &buf, &[], Some(&buf))],
        &[&p.owner],
    );
    let id = u64::from_le_bytes(env.account(&f.config).data[528..536].try_into().unwrap());
    assert_eq!(
        env.fails(&[f.veto_id(&p.g[0].pubkey(), Some(id + 1))], &[&p.g[0]]),
        err::NO_PROPOSAL
    );
    assert_eq!(read_config(&env, f).pending_vetoed, 0);
    // An id that is not exactly 8 bytes is malformed, not a different proposal.
    let mut short = f.veto_id(&p.g[0].pubkey(), Some(id));
    short.data.truncate(5);
    assert_eq!(env.fails(&[short], &[&p.g[0]]), err::INVALID_INSTRUCTION);
    assert_eq!(read_config(&env, f).pending_vetoed, 0);
    env.ok(&[f.veto_id(&p.g[0].pubkey(), Some(id))], &[&p.g[0]]);
    assert_eq!(read_config(&env, f).pending_vetoed, 1);
}

#[test]
fn an_older_guardian_set_cannot_bring_back_an_ejected_guardian() {
    // The owner proposes a guardian set that still names g2; a quorum of the
    // others then ejects g2. Executing the older set must not restore it.
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let gs = p.guardians();
    let set = Floor::guardian_set(&gs, 2, 7 * DAY);
    env.ok(&[f.propose(&p.owner.pubkey(), SET_GUARDIANS, &solana_address::Address::default(), &set, None)], &[&p.owner]);
    env.ok(&[f.eject(2, &[gs[0], gs[1]])], &[&p.g[0], &p.g[1]]);
    env.advance(3 * DAY + 1);
    // Whatever is still pending, executing it must not bring g2 back.
    let _ = env.send(&[f.execute_config()], &[]);
    let d = env.account(&f.config).data;
    let n = d[424] as usize;
    let back = (0..n).any(|i| d[104 + 32 * i..136 + 32 * i] == gs[2].to_bytes());
    assert!(!back, "the ejected guardian came back through an older proposal");
}

const SET_OWNER: u8 = 5;
const SET_RECOVERY: u8 = 7;

fn floor_owner(env: &Env, f: &Floor) -> [u8; 32] {
    env.account(&f.config).data[72..104].try_into().unwrap()
}

/// The owner sets a recovery key: a delayed change like any other.
fn with_recovery(env: &mut Env, p: &Protected) -> solana_keypair::Keypair {
    let recovery = solana_keypair::Keypair::new();
    env.fund(&recovery);
    let f = &p.f;
    env.ok(&[f.propose(&p.owner.pubkey(), SET_RECOVERY, &recovery.pubkey(), &[], None)], &[&p.owner]);
    env.advance(3 * DAY + 1);
    env.ok(&[f.execute_config()], &[]);
    recovery
}

#[test]
fn a_recovery_key_replaces_a_stolen_owner_key_that_cannot_stop_it() {
    // A4 on Floor: only the owner could propose a new owner, and only one
    // proposal can wait at a time, so a thief holding the owner key could keep
    // the slot busy, cancel any rotation, or stop the program to wipe it.
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let gs = p.guardians();
    let recovery = with_recovery(&mut env, &p);
    // The thief holds the slot with its own proposal (a guardian set that
    // waits; raising the delay would apply at once and hold nothing).
    let set = Floor::guardian_set(&gs, 2, 7 * DAY);
    env.ok(&[f.propose(&p.owner.pubkey(), SET_GUARDIANS, &solana_address::Address::default(), &set, None)], &[&p.owner]);
    let fresh = solana_keypair::Keypair::new().pubkey();
    // The recovery key's proposal takes the slot anyway.
    env.ok(&[f.propose(&recovery.pubkey(), SET_OWNER, &fresh, &[], None)], &[&recovery]);
    // The thief cannot cancel it, cannot propose over it, and stopping the
    // program does not wipe it.
    assert_eq!(env.fails(&[f.cancel(&p.owner.pubkey())], &[&p.owner]), err::NOT_OWNER);
    assert_eq!(env.fails(&[f.propose(&p.owner.pubkey(), SET_GUARDIANS, &solana_address::Address::default(), &set, None)], &[&p.owner]), err::PROPOSAL_PENDING);
    // While the guardians are live, the thief cannot stop the program; a
    // guardian's stop does not wipe the recovery proposal either.
    assert_eq!(env.fails(&[f.abort(&p.owner.pubkey(), &p.abort_buffer, Some(&p.snapshot))], &[&p.owner]), err::NOT_LIVE_GUARDIAN);
    env.ok(&[f.abort(&gs[2], &p.abort_buffer, Some(&p.snapshot))], &[&p.g[2]]);
    env.next_slot();
    assert_eq!(read_config(&env, f).pending_kind, SET_OWNER);
    env.advance(3 * DAY + 1);
    env.ok(&[f.execute_config()], &[]);
    assert_eq!(floor_owner(&env, f), fresh.to_bytes());
    // The quorum restores the program; the old owner key is now nobody.
    // The snapshot's rent goes to the new owner, not to the replaced key.
    env.ok(&[f.restore_snapshot(&p.snapshot, &fresh, &[gs[0], gs[1]])], &[&p.g[0], &p.g[1]]);
    assert_eq!(env.fails(&[f.propose(&p.owner.pubkey(), SET_DELAY, &solana_address::Address::default(), &(4 * DAY).to_le_bytes(), None)], &[&p.owner]), err::NOT_OWNER);
}

#[test]
fn the_floor_recovery_key_can_only_replace_the_owner_or_itself() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let recovery = with_recovery(&mut env, &p);
    let buf = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&buf, &p.owner, &f.authority);
    // No code, no guardians, no delay: it has no say over the program.
    assert_eq!(env.fails(&[f.propose(&recovery.pubkey(), UPGRADE, &buf, &[], Some(&buf))], &[&recovery]), err::NOT_OWNER);
    // Owner and recovery stay distinct, in both directions.
    assert_eq!(env.fails(&[f.propose(&recovery.pubkey(), SET_OWNER, &recovery.pubkey(), &[], None)], &[&recovery]), err::INVALID_INSTRUCTION);
    assert_eq!(env.fails(&[f.propose(&p.owner.pubkey(), SET_OWNER, &recovery.pubkey(), &[], None)], &[&p.owner]), err::INVALID_INSTRUCTION);
    // Once a recovery key exists, only it replaces itself.
    let other = solana_keypair::Keypair::new().pubkey();
    assert_eq!(env.fails(&[f.propose(&p.owner.pubkey(), SET_RECOVERY, &other, &[], None)], &[&p.owner]), err::NOT_OWNER);
    env.ok(&[f.propose(&recovery.pubkey(), SET_RECOVERY, &other, &[], None)], &[&recovery]);
    // Its own proposal is its own to withdraw.
    env.ok(&[f.cancel(&recovery.pubkey())], &[&recovery]);
}

/// Account substitution over Floor's instructions (common/sweep.rs): program
/// A is the target, program B (registered with its own owner and guardians)
/// supplies look-alike accounts, and a stranger owns one more buffer. Every
/// swap must fail except where Floor leaves a position free on purpose.
#[test]
fn every_floor_account_substitution_is_refused() {
    use common::sweep::{any, role, Sweep};
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let q = protect(&mut env, &honest_fix());
    let stranger = Keypair::new();
    env.fund(&stranger);
    let stranger_buffer = env.write_buffer(&honest_fix(), &stranger);
    let (f, gs) = (&p.f, p.guardians());
    let payer = env.payer.pubkey();
    let mut decoys = vec![
        ("B's config".to_string(), q.f.config),
        ("B's program".into(), q.f.program),
        ("B's programdata".into(), q.f.programdata),
        ("B's Floor authority".into(), q.f.authority),
        ("B's abort buffer".into(), q.abort_buffer),
        ("B's snapshot".into(), q.snapshot),
        ("a stranger's buffer".into(), stranger_buffer),
        ("A's abort buffer".into(), p.abort_buffer),
        ("A's snapshot".into(), p.snapshot),
        ("A's Floor authority".into(), f.authority),
    ];
    decoys.push(("Floor program".into(), env.floor));
    let mut keys: Vec<&Keypair> = vec![&p.owner, &q.owner, &p.team, &q.team, &stranger];
    keys.extend(p.g.iter());
    keys.extend(q.g.iter());
    let mut s = Sweep::new(&env, decoys, &keys);
    let guardians = gs.clone();
    let spill = |at| any(at, "the stop's spill: whoever stops (a stop never fails on it); execute and restore pay the owner");
    let heartbeat_all = |env: &mut Env| {
        for g in &p.g {
            env.ok(&[f.heartbeat(&g.pubkey())], &[g]);
        }
    };

    s.run(&mut env, "heartbeat", f.heartbeat(&gs[0]), &[], &[role(1, guardians.clone(), "each guardian heartbeats for itself")]);

    // An upgrade: propose, veto, cancel; propose again, execute after the delay.
    let v2 = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&v2, &p.owner, &f.authority);
    s.run(&mut env, "propose upgrade", f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2)), &[], &[]);
    s.run(&mut env, "veto", f.veto(&gs[1]), &[], &[role(1, guardians.clone(), "any live guardian")]);
    s.run(&mut env, "cancel", f.cancel(&p.owner.pubkey()), &[], &[]);
    env.ok(&[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))], &[&p.owner]);
    env.advance(3 * DAY);
    heartbeat_all(&mut env);
    s.run(&mut env, "execute upgrade", f.execute_code(&v2, &p.owner.pubkey()), &[], &[]);
    env.next_slot();

    // The snapshot no longer matches: pin one of the new code; stage a fresh abort buffer.
    let snap2 = env.write_buffer(&honest_fix(), &stranger);
    env.set_buffer_authority(&snap2, &stranger, &f.authority);
    s.run(&mut env, "pin snapshot", f.pin_snapshot(&snap2), &[], &[]);
    env.next_slot();

    // Stop, then restore the snapshot with a quorum.
    s.run(&mut env, "abort (stop)", f.abort(&gs[0], &p.abort_buffer, Some(&snap2)), &[], &[
        role(1, guardians.clone(), "any live guardian"),
        spill(5),
    ]);
    env.next_slot();
    s.run(&mut env, "restore snapshot", f.restore_snapshot(&snap2, &p.owner.pubkey(), &gs[0..2]), &[], &[
        role(9, guardians.clone(), "any quorum"),
        role(10, guardians.clone(), "any quorum"),
    ]);
    env.next_slot();

    // The stop used the abort buffer: anyone stages a fresh one.
    let abort2 = env.write_buffer(&bulkhead_core::floor::ABORT_ELF, &stranger);
    env.set_buffer_authority(&abort2, &stranger, &f.authority);
    s.run(&mut env, "stage abort", f.stage_abort(&abort2), &[], &[]);
    env.next_slot();

    // Stopped again: a fix the quorum approves goes live at once.
    env.ok(&[f.abort(&gs[0], &abort2, None)], &[&p.g[0]]);
    env.next_slot();
    let fix = env.write_buffer(&honest_v1(), &p.owner);
    env.set_buffer_authority(&fix, &p.owner, &f.authority);
    env.ok(&[f.propose(&p.owner.pubkey(), RESTORE, &fix, &[], Some(&fix))], &[&p.owner]);
    let pid = read_config(&env, f).pending_id;
    s.run(&mut env, "approve", f.approve(pid, &gs[1..3]), &[], &[
        role(1, guardians.clone(), "any quorum"),
        role(2, guardians.clone(), "any quorum"),
    ]);
    s.run(&mut env, "execute approved fix", f.execute_code(&fix, &p.owner.pubkey()), &[], &[]);
    env.next_slot();

    // A raised delay applies at once; a quorum of the others ejects one guardian.
    let zero = solana_address::Address::default();
    let longer = (7 * DAY).to_le_bytes();
    s.run(&mut env, "propose a longer delay", f.propose(&p.owner.pubkey(), SET_DELAY, &zero, &longer, None), &[], &[]);
    s.run(&mut env, "replace recovery", f.replace_recovery(&p.owner.pubkey(), &solana_address::Address::new_unique(), &gs[0..2]), &[], &[
        role(2, guardians.clone(), "any quorum"),
        role(3, guardians.clone(), "any quorum"),
    ]);
    s.run(&mut env, "eject", f.eject(2, &gs[0..2]), &[], &[]);

    // Registering another program; releasing A's authority (closes A's config).
    let team3 = Keypair::new();
    env.fund(&team3);
    let (program3, _) = env.deploy(&honest_v1(), &team3, 8192);
    let f3 = Floor::new(env.floor, program3);
    s.key(&team3);
    let gs3: Vec<_> = p.g.iter().map(|k| k.pubkey()).collect();
    let reg = f3.register(&payer, &team3.pubkey(), &p.owner.pubkey(), &gs3, 2, 7 * DAY, 3 * DAY);
    s.run(&mut env, "register", reg, &[], &[any(0, "rent payer: any funded signer")]);
    let new_auth = Keypair::new().pubkey();
    env.ok(&[f.propose(&p.owner.pubkey(), RELEASE_AUTHORITY, &new_auth, &[], None)], &[&p.owner]);
    env.advance(7 * DAY);
    s.run(&mut env, "execute release", f.execute_release(&p.owner.pubkey(), Some(&new_auth)), &[], &[]);

    println!("{} substitutions over {} Floor transactions; {} needed a key nobody here holds", s.attempts, s.runs, s.unsignable);
    assert!(s.unexpected.is_empty(), "accepted substitutions ({}):\n{}", s.unexpected.len(), s.unexpected.join("\n"));
}

#[test]
fn a_stop_must_name_the_pinned_snapshot() {
    // Finding 53: the snapshot account was optional, and a stop without it
    // left the snapshot unusable, so whoever stopped the program decided that
    // the guardian quorum could not restore it by itself. While a snapshot is
    // pinned, the stop must now name it.
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let (f, gs) = (&p.f, p.guardians());
    let without = f.abort(&gs[0], &p.abort_buffer, None);
    assert_eq!(env.fails(&[without], &[&p.g[0]]), err::SNAPSHOT_MISMATCH);
    let wrong = f.abort(&gs[0], &p.abort_buffer, Some(&p.abort_buffer));
    assert_eq!(env.fails(&[wrong], &[&p.g[0]]), err::SNAPSHOT_MISMATCH);
    env.ok(&[f.abort(&gs[0], &p.abort_buffer, Some(&p.snapshot))], &[&p.g[0]]);
    assert_eq!(read_config(&env, f).snapshot_valid, 1);
    // So the quorum restores by itself, as G8 says.
    env.next_slot();
    let r = f.restore_snapshot(&p.snapshot, &p.owner.pubkey(), &gs[1..3]);
    env.ok(&[r], &[&p.g[1], &p.g[2]]);
    env.next_slot();
    assert!(env.call(&f.program).is_ok());
}

#[test]
fn approvals_name_their_proposal_and_buffers_stay_where_they_belong() {
    // Code review, 7 Oct (finding 58).
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let (f, gs) = (&p.f, p.guardians());

    // The staged abort buffer and the pinned snapshot are never an upgrade:
    // using one up would leave Floor pointing at a closed account.
    for b in [p.abort_buffer, p.snapshot] {
        let ix = f.propose(&p.owner.pubkey(), UPGRADE, &b, &[], Some(&b));
        assert_eq!(env.fails(&[ix], &[&p.owner]), err::WRONG_BUFFER);
    }

    // A guardian never becomes the owner.
    let ix = f.propose(&p.owner.pubkey(), SET_OWNER, &gs[1], &[], None);
    assert_eq!(env.fails(&[ix], &[&p.owner]), err::INVALID_INSTRUCTION);

    // Stopped: the owner proposes fix A; the guardians approve A by its id.
    env.ok(&[f.abort(&gs[0], &p.abort_buffer, Some(&p.snapshot))], &[&p.g[0]]);
    env.next_slot();
    let fix_a = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&fix_a, &p.owner, &f.authority);
    env.ok(&[f.propose(&p.owner.pubkey(), RESTORE, &fix_a, &[], Some(&fix_a))], &[&p.owner]);
    let id_a = read_config(&env, f).pending_id;
    // The owner swaps in B before the approvals land: they no longer count.
    env.ok(&[f.cancel(&p.owner.pubkey())], &[&p.owner]);
    let fix_b = env.write_buffer(&honest_v1(), &p.owner);
    env.set_buffer_authority(&fix_b, &p.owner, &f.authority);
    env.ok(&[f.propose(&p.owner.pubkey(), RESTORE, &fix_b, &[], Some(&fix_b))], &[&p.owner]);
    let late = f.approve(id_a, &gs[1..3]);
    assert_eq!(env.fails(&[late], &[&p.g[1], &p.g[2]]), err::NO_PROPOSAL);
    let exec = f.execute_code(&fix_b, &p.owner.pubkey());
    assert_eq!(env.fails(std::slice::from_ref(&exec), &[]), err::NOT_EXECUTABLE, "B was never approved");

    // B approved by its own id: it installs, and its rent returns to the owner only.
    let id_b = read_config(&env, f).pending_id;
    env.ok(&[f.approve(id_b, &gs[1..3])], &[&p.g[1], &p.g[2]]);
    let thief = f.execute_code(&fix_b, &env.payer.pubkey());
    assert_eq!(env.fails(&[thief], &[]), err::NOT_OWNER);
    let owner_before = env.svm.get_account(&p.owner.pubkey()).map(|a| a.lamports).unwrap_or(0);
    let rent = env.account(&fix_b).lamports;
    env.ok(&[exec], &[]);
    assert_eq!(env.account(&p.owner.pubkey()).lamports, owner_before + rent, "the buffer's rent went to the owner");
}

#[test]
fn a_restore_whose_buffer_became_the_abort_buffer_is_refused_at_execution() {
    // Finding 58, the execution-time check: the target was not staged when
    // proposed, but is the abort buffer by the time it would execute.
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let (f, gs) = (&p.f, p.guardians());
    env.ok(&[f.abort(&gs[0], &p.abort_buffer, Some(&p.snapshot))], &[&p.g[0]]);
    env.next_slot();
    // Stopped: no abort buffer is staged. The owner proposes a restore from B,
    // a buffer that holds the canonical abort binary.
    let b = env.write_buffer(&ABORT_ELF, &p.owner);
    env.set_buffer_authority(&b, &p.owner, &f.authority);
    env.ok(&[f.propose(&p.owner.pubkey(), RESTORE, &b, &[], Some(&b))], &[&p.owner]);
    // Anyone stages B as the abort buffer; the quorum approves the restore.
    env.ok(&[f.stage_abort(&b)], &[]);
    let id = read_config(&env, f).pending_id;
    env.ok(&[f.approve(id, &gs[1..3])], &[&p.g[1], &p.g[2]]);
    // Executing would use up the abort buffer: refused.
    let exec = f.execute_code(&b, &p.owner.pubkey());
    assert_eq!(env.fails(&[exec], &[]), err::WRONG_BUFFER);
    assert_eq!(read_config(&env, f).abort_buffer, b.to_bytes(), "the stop is still staged");
}

#[test]
fn a_vetoed_recovery_proposal_does_not_hold_the_owner_s_slot() {
    // A stolen recovery key proposes itself a new owner; a guardian vetoes it.
    // Only the recovery key may cancel its own proposal, so if a vetoed or
    // expired proposal kept the one slot, the owner could never propose again:
    // no upgrade, and after a stop no restore of a new fix.
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let gs = p.guardians();
    let recovery = with_recovery(&mut env, &p);
    let thief = solana_keypair::Keypair::new().pubkey();
    env.ok(&[f.propose(&recovery.pubkey(), SET_OWNER, &thief, &[], None)], &[&recovery]);
    env.ok(&[f.veto(&gs[0])], &[&p.g[0]]);
    env.next_slot();
    let v2 = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&v2, &p.owner, &f.authority);
    env.ok(&[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))], &[&p.owner]);
    assert_eq!(read_config(&env, f).pending_kind, UPGRADE);
    // A live one still holds it.
    env.ok(&[f.cancel(&p.owner.pubkey())], &[&p.owner]);
    env.ok(&[f.propose(&recovery.pubkey(), SET_OWNER, &thief, &[], None)], &[&recovery]);
    assert_eq!(env.fails(&[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))], &[&p.owner]), err::PROPOSAL_PENDING);
    // An expired one does not (nobody executed it in its 7 days).
    env.advance(3 * DAY + 7 * DAY + 1);
    env.ok(&[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))], &[&p.owner]);
    assert_eq!(read_config(&env, f).pending_kind, UPGRADE);
}

#[test]
fn a_stolen_floor_recovery_key_is_replaced_by_the_owner_with_a_live_quorum() {
    // A stolen recovery key can take the slot from every owner proposal, as
    // often as it likes, and only it could replace itself: no upgrade would
    // ever wait out its delay again. The owner and a live quorum replace it.
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let gs = p.guardians();
    let stolen = with_recovery(&mut env, &p);
    let v2 = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&v2, &p.owner, &f.authority);
    env.ok(&[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))], &[&p.owner]);
    let thief = solana_keypair::Keypair::new().pubkey();
    env.ok(&[f.propose(&stolen.pubkey(), SET_OWNER, &thief, &[], None)], &[&stolen]);
    assert_eq!(read_config(&env, f).pending_kind, SET_OWNER, "the owner's upgrade is gone");
    let fresh = solana_keypair::Keypair::new().pubkey();
    // Neither the owner alone, nor with too few guardians, nor a quorum
    // without the owner; and the owner cannot be its own recovery key.
    assert_eq!(env.fails(&[f.replace_recovery(&p.owner.pubkey(), &fresh, &[])], &[&p.owner]), err::NO_QUORUM);
    assert_eq!(env.fails(&[f.replace_recovery(&p.owner.pubkey(), &fresh, &[gs[0]])], &[&p.owner, &p.g[0]]), err::NO_QUORUM);
    assert_eq!(env.fails(&[f.replace_recovery(&gs[2], &fresh, &[gs[0], gs[1]])], &[&p.g[2], &p.g[0], &p.g[1]]), err::NOT_OWNER);
    assert_eq!(env.fails(&[f.replace_recovery(&p.owner.pubkey(), &p.owner.pubkey(), &[gs[0], gs[1]])], &[&p.owner, &p.g[0], &p.g[1]]), err::INVALID_INSTRUCTION);
    env.ok(&[f.replace_recovery(&p.owner.pubkey(), &fresh, &[gs[0], gs[1]])], &[&p.owner, &p.g[0], &p.g[1]]);
    env.next_slot();
    // The stolen key's proposal is void, it can propose nothing more, and the
    // owner's upgrade goes back in.
    assert_eq!(read_config(&env, f).pending_kind, 0);
    assert_eq!(env.fails(&[f.propose(&stolen.pubkey(), SET_OWNER, &thief, &[], None)], &[&stolen]), err::NOT_OWNER);
    env.ok(&[f.propose(&p.owner.pubkey(), UPGRADE, &v2, &[], Some(&v2))], &[&p.owner]);
    assert_eq!(&env.account(&f.config).data[852..884], fresh.as_ref(), "the new recovery key");
}
