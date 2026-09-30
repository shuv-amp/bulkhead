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
    let early = f.execute_code(&drainer_buf, &env.payer.pubkey());
    assert_eq!(env.fails(&[early], &[]), err::NOT_EXECUTABLE);
    // 2. A guardian vetoes it; even after the delay it can never execute.
    env.ok(&[f.veto(&gs[0])], &[&p.g[0]]);
    env.advance(3 * DAY + 1);
    let late = f.execute_code(&drainer_buf, &env.payer.pubkey());
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
    let restore = f.restore_snapshot(&p.snapshot, &env.payer.pubkey(), &gs[1..3]);
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
    env.ok(&[f.abort(&gs[0], &p.abort_buffer, None)], &[&p.g[0]]);
    env.next_slot();

    let fix = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&fix, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), RESTORE, &fix, &[], Some(&fix))],
        &[&p.owner],
    );
    // One approval is not a quorum.
    env.ok(&[f.approve(&gs[0..1])], &[&p.g[0]]);
    let exec = f.execute_code(&fix, &env.payer.pubkey());
    assert_eq!(
        env.fails(std::slice::from_ref(&exec), &[]),
        err::NOT_EXECUTABLE
    );
    // A second live guardian approves: the fix installs at once.
    env.ok(&[f.approve(&gs[2..3])], &[&p.g[2]]);
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
    env.ok(&[f.abort(&gs[0], &p.abort_buffer, None)], &[&p.g[0]]);
    let fix = env.write_buffer(&honest_fix(), &p.owner);
    env.set_buffer_authority(&fix, &p.owner, &f.authority);
    env.ok(
        &[f.propose(&p.owner.pubkey(), RESTORE, &fix, &[], Some(&fix))],
        &[&p.owner],
    );
    env.advance(3 * DAY - 10);
    assert_eq!(
        env.fails(&[f.execute_code(&fix, &env.payer.pubkey())], &[]),
        err::NOT_EXECUTABLE
    );
    env.advance(11);
    env.ok(&[f.execute_code(&fix, &env.payer.pubkey())], &[]);
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
    env.ok(&[f.execute_code(&v2, &env.payer.pubkey())], &[]);
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
    let r = f.restore_snapshot(&p.snapshot, &env.payer.pubkey(), &gs[0..2]);
    assert_eq!(env.fails(&[r], &[&p.g[0], &p.g[1]]), err::NO_VALID_SNAPSHOT);
}

#[test]
fn only_live_guardians_or_the_owner_can_stop_the_program() {
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let stranger = Keypair::new();
    env.fund(&stranger);
    let ix = f.abort(&stranger.pubkey(), &p.abort_buffer, None);
    assert_eq!(env.fails(&[ix], &[&stranger]), err::NOT_LIVE_GUARDIAN);

    // Guardians that miss their 7-day heartbeat lose their powers.
    env.advance(7 * DAY + 1);
    let ix = f.abort(&p.g[0].pubkey(), &p.abort_buffer, None);
    assert_eq!(env.fails(&[ix], &[&p.g[0]]), err::NOT_LIVE_GUARDIAN);
    let hb = f.heartbeat(&p.g[0].pubkey());
    assert_eq!(
        env.fails(&[hb], &[&p.g[0]]),
        err::NOT_LIVE_GUARDIAN,
        "a dead guardian can't revive itself"
    );

    // The owner can always stop its own program (denial of service at worst).
    env.ok(
        &[f.abort(&p.owner.pubkey(), &p.abort_buffer, None)],
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
        &[f.abort(&p.g[0].pubkey(), &p.abort_buffer, None)],
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
        &[f.abort(&p.g[0].pubkey(), &p.abort_buffer, None)],
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
        &[f.abort(&p.g[0].pubkey(), &p.abort_buffer, None)],
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
    let too_high = (30 * DAY + 1).to_le_bytes();
    let ix = f.propose(&p.owner.pubkey(), SET_DELAY, &zero, &too_high, None);
    assert_eq!(
        env.fails(&[ix], &[&p.owner]),
        err::INVALID_DELAY,
        "never above 30 days (docs/15, A7)"
    );
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
        env.fails(&[f.execute_code(&v2, &env.payer.pubkey())], &[]),
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
    let one = f.restore_snapshot(&p.snapshot, &env.payer.pubkey(), &gs[0..1]);
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
    let gs = [Keypair::new().pubkey(), Keypair::new().pubkey()];
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
    env.ok(&[f.abort(&owner.pubkey(), &small, None)], &[&owner]);
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
    let r = f.restore_snapshot(&p.snapshot, &env.payer.pubkey(), &gs[0..2]);
    let m = env.ok(&[r], &[&p.g[0], &p.g[1]]);
    println!(
        "restore of {} bytes: {} CU",
        big.len(),
        m.compute_units_consumed
    );
    env.next_slot();
    assert!(env.call(&f.program).is_ok());
}
