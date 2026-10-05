//! Floor program ↔ model differential (docs/09-VERIFICATION.md §7).
//!
//! Random sequences of every Floor instruction except `register` and
//! `release_authority` (which closes the config) run on the real loader, and
//! in parallel through a host model built only from `bulkhead-core`'s rules
//! (`guardian_alive`, `quorum`, `can_eject`, `can_execute`, `can_restore`,
//! `upgrade_eta`). After every step the test compares whether the instruction
//! succeeded, every config field the model tracks, and the live program bytes.
//! Signers include stale guardians, keys that were never guardians, a former
//! owner, and vetoes naming the wrong proposal or a malformed id.
//!
//! Depth: `BULKHEAD_FLOOR_STEPS` steps per seed (default 300) and
//! `BULKHEAD_FLOOR_SEEDS` seeds (default 8).

mod common;

use bulkhead_core::consts::{MAX_UPGRADE_DELAY_S, MIN_UPGRADE_DELAY_S};
use bulkhead_core::floor::{can_restore, upgrade_eta, RestoreSource, ABORT_ELF};
use bulkhead_core::governance::{can_eject, can_execute, guardian_alive, quorum, Schedule, CHANGE_EXPIRY_S, MAX_HEARTBEAT_INTERVAL_S, MIN_HEARTBEAT_INTERVAL_S};
use common::*;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::collections::BTreeMap;

const UPGRADE: u8 = 1;
const RESTORE: u8 = 2;
const SET_GUARDIANS: u8 = 4;
const SET_OWNER: u8 = 5;
const SET_DELAY: u8 = 6;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Code {
    V1,
    Fix,
    Abort,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    kind: u8,
    id: u64,
    vetoed: bool,
    approvals: u8,
    target: [u8; 32],
    eta: i64,
    expires: i64,
    /// What executing it changes.
    effect: Effect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Effect {
    Code(Code),
    Guardians(Vec<usize>, u8, i64),
    Owner(usize),
    Delay(i64),
}

/// The model of one Floor config. Guardians and owners are indices into
/// fixed key pools.
struct Model {
    owner: usize,
    guardians: Vec<usize>,
    heartbeats: Vec<i64>,
    threshold: u8,
    interval: i64,
    delay: i64,
    aborted: bool,
    abort_staged: bool,
    snapshot: Option<Code>,
    snapshot_valid: bool,
    live: Code,
    last_id: u64,
    pending: Option<Pending>,
}

impl Model {
    fn alive(&self, now: i64) -> u8 {
        let mut m = 0u8;
        for (i, &h) in self.heartbeats.iter().enumerate() {
            if guardian_alive(h, self.interval, now) {
                m |= 1 << i;
            }
        }
        m
    }
    fn index(&self, key: usize) -> Option<usize> {
        self.guardians.iter().position(|&g| g == key)
    }
    fn live_guardian(&self, key: usize, now: i64) -> Option<usize> {
        self.index(key).filter(|&i| self.alive(now) & (1 << i) != 0)
    }
    fn bits(&self, keys: &[usize]) -> Option<u8> {
        let mut b = 0u8;
        for k in keys {
            b |= 1 << self.index(*k)?;
        }
        Some(b)
    }
}

#[test]
fn floor_matches_the_core_model_on_random_sequences() {
    let steps = env_u64("BULKHEAD_FLOOR_STEPS", 300);
    let seeds = env_u64("BULKHEAD_FLOOR_SEEDS", 8);
    let mut totals = BTreeMap::<String, u64>::new();
    for seed in 0..seeds {
        for (k, v) in run(0xF100_0000 + seed, steps) {
            *totals.entry(k).or_default() += v;
        }
    }
    println!("floor-vs-model: {} steps; {totals:?}", steps * seeds);
    // Coverage: each instruction both succeeded and was refused.
    for op in ["heartbeat", "veto", "propose_delay", "propose_guardians", "propose_owner", "propose_upgrade", "propose_restore", "execute", "cancel", "eject", "abort", "approve", "restore_snapshot", "stage_abort", "pin_snapshot"] {
        for side in ["ok", "refused"] {
            let n = totals.get(&format!("{op}:{side}")).copied().unwrap_or(0);
            assert!(n > 0, "{op} never {side}: {totals:?}");
        }
    }
}

fn run(seed: u64, steps: u64) -> BTreeMap<String, u64> {
    let mut rng = Rng(seed);
    let mut env = Env::new();
    let p = protect(&mut env, &honest_v1());
    let f = &p.f;
    let stager = Keypair::new();
    env.fund(&stager);

    // Key pools: guardians 0..3 are registered; 3 and 4 are not. Owner 0 is
    // registered; owner 1 is a key a SetOwner proposal may name.
    let extra = [Keypair::new(), Keypair::new()];
    let gk: Vec<&Keypair> = p.g.iter().chain(extra.iter()).collect();
    for k in &extra {
        env.fund(k);
    }
    let other_owner = Keypair::new();
    env.fund(&other_owner);
    let ok_: Vec<&Keypair> = vec![&p.owner, &other_owner];

    let mut md = Model {
        owner: 0,
        guardians: vec![0, 1, 2],
        heartbeats: vec![env.time; 3],
        threshold: 2,
        interval: 7 * DAY,
        delay: 3 * DAY,
        aborted: false,
        abort_staged: true,
        snapshot: Some(Code::V1),
        snapshot_valid: false,
        live: Code::V1,
        last_id: 0,
        pending: None,
    };
    let elf = |c: Code| match c {
        Code::V1 => honest_v1(),
        Code::Fix => honest_fix(),
        Code::Abort => ABORT_ELF.to_vec(),
    };
    let fresh_buffer = |env: &mut Env, c: Code| {
        let b = env.write_buffer(&elf(c), &stager);
        env.set_buffer_authority(&b, &stager, &f.authority);
        b
    };
    let mut abort_buffer = p.abort_buffer;
    let mut snapshot_buffer = Some(p.snapshot);
    let mut counts = BTreeMap::<String, u64>::new();

    for step in 0..steps {
        let jump = match rng.below(10) {
            0..=5 => rng.below(3_600) as i64,
            6..=8 => rng.below(2 * DAY as u64) as i64,
            _ if rng.below(3) == 0 => 3 * DAY + rng.below(6 * DAY as u64) as i64,
            _ => DAY + rng.below(2 * DAY as u64) as i64,
        };
        env.advance(jump);
        let now = env.time;
        // A guardian service usually keeps the live guardians beating; some
        // steps it is down, so guardians also go stale and stay stale.
        if rng.below(4) != 0 {
            for i in 0..md.guardians.len() {
                let k = md.guardians[i];
                if md.live_guardian(k, now).is_some() {
                    env.ok(&[f.heartbeat(&gk[k].pubkey())], &[gk[k]]);
                    md.heartbeats[i] = now;
                }
            }
        }
        let at = format!("seed {seed} step {step}");
        let (op, sent, model_ok): (&str, bool, bool);

        match rng.below(16) {
            // Heartbeat, by a live, stale or unregistered key.
            0..=2 => {
                let k = rng.below(5) as usize;
                let r = env.send(&[f.heartbeat(&gk[k].pubkey())], &[gk[k]]);
                let i = md.live_guardian(k, now);
                if let Some(i) = i {
                    md.heartbeats[i] = now;
                }
                (op, sent, model_ok) = ("heartbeat", r.is_ok(), i.is_some());
            }
            // Veto, with no id, the pending id, another id, or a malformed one.
            3 => {
                let k = if rng.below(4) != 0 { md.guardians[rng.below(md.guardians.len() as u64) as usize] } else { rng.below(5) as usize };
                let pending_id = md.pending.as_ref().map(|x| x.id).unwrap_or(md.last_id);
                let variant = rng.below(4);
                let mut ix = f.veto_id(&gk[k].pubkey(), match variant {
                    0 => None,
                    1 => Some(pending_id),
                    _ => Some(pending_id + 1),
                });
                if variant == 3 {
                    ix.data.truncate(5);
                }
                let r = env.send(&[ix], &[gk[k]]);
                let ok = md.live_guardian(k, now).is_some()
                    && md.pending.is_some()
                    && match variant {
                        0 | 1 => true,
                        _ => false,
                    };
                if ok {
                    md.pending.as_mut().unwrap().vetoed = true;
                }
                (op, sent, model_ok) = ("veto", r.is_ok(), ok);
            }
            // Propose a delay: lower waits the delay, higher applies at once.
            4 => {
                let d = rng.pick(&[MIN_UPGRADE_DELAY_S - 1, MIN_UPGRADE_DELAY_S, 4 * DAY, 10 * DAY, MAX_UPGRADE_DELAY_S, MAX_UPGRADE_DELAY_S + 1]);
                let who = rng.below(2) as usize;
                let r = env.send(&[f.propose(&ok_[who].pubkey(), SET_DELAY, &Address::default(), &d.to_le_bytes(), None)], &[ok_[who]]);
                let valid = who == md.owner && md.pending.is_none() && (MIN_UPGRADE_DELAY_S..=MAX_UPGRADE_DELAY_S).contains(&d);
                if valid {
                    if d >= md.delay {
                        md.delay = d;
                    } else {
                        md.last_id += 1;
                        let eta = upgrade_eta(now, md.delay);
                        md.pending = Some(Pending { kind: SET_DELAY, id: md.last_id, vetoed: false, approvals: 0, target: [0; 32], eta, expires: eta + CHANGE_EXPIRY_S, effect: Effect::Delay(d) });
                    }
                }
                (op, sent, model_ok) = ("propose_delay", r.is_ok(), valid);
            }
            // Propose a new guardian set (sometimes invalid: the owner, a duplicate, a bad threshold or interval).
            5 => {
                let n = 2 + rng.below(3) as usize;
                let mut set: Vec<usize> = Vec::new();
                while set.len() < n {
                    let k = rng.below(5) as usize;
                    if !set.contains(&k) {
                        set.push(k);
                    }
                }
                let duplicate = rng.below(8) == 0;
                if duplicate {
                    set[1] = set[0];
                }
                let with_owner = rng.below(10) == 0;
                let th = rng.pick(&[1u8, 2, 2, 3, 4]);
                let interval = rng.pick(&[MIN_HEARTBEAT_INTERVAL_S - 1, MIN_HEARTBEAT_INTERVAL_S, 3 * DAY, 7 * DAY, MAX_HEARTBEAT_INTERVAL_S]);
                let mut keys: Vec<Address> = set.iter().map(|&k| gk[k].pubkey()).collect();
                if with_owner {
                    keys[0] = ok_[md.owner].pubkey();
                }
                let payload = Floor::guardian_set(&keys, th, interval);
                let who = rng.below(2) as usize;
                let r = env.send(&[f.propose(&ok_[who].pubkey(), SET_GUARDIANS, &Address::default(), &payload, None)], &[ok_[who]]);
                let valid = who == md.owner
                    && md.pending.is_none()
                    && !duplicate
                    && !with_owner
                    && th >= 2
                    && th as usize <= n
                    && (MIN_HEARTBEAT_INTERVAL_S..=MAX_HEARTBEAT_INTERVAL_S).contains(&interval);
                if valid {
                    md.last_id += 1;
                    let eta = upgrade_eta(now, md.delay);
                    md.pending = Some(Pending { kind: SET_GUARDIANS, id: md.last_id, vetoed: false, approvals: 0, target: [0; 32], eta, expires: eta + CHANGE_EXPIRY_S, effect: Effect::Guardians(set, th, interval) });
                }
                (op, sent, model_ok) = ("propose_guardians", r.is_ok(), valid);
            }
            // Propose a new owner.
            6 => {
                let to = rng.below(2) as usize;
                let who = rng.below(2) as usize;
                let r = env.send(&[f.propose(&ok_[who].pubkey(), SET_OWNER, &ok_[to].pubkey(), &[], None)], &[ok_[who]]);
                let valid = who == md.owner && md.pending.is_none();
                if valid {
                    md.last_id += 1;
                    let eta = upgrade_eta(now, md.delay);
                    md.pending = Some(Pending { kind: SET_OWNER, id: md.last_id, vetoed: false, approvals: 0, target: ok_[to].pubkey().to_bytes(), eta, expires: eta + CHANGE_EXPIRY_S, effect: Effect::Owner(to) });
                }
                (op, sent, model_ok) = ("propose_owner", r.is_ok(), valid);
            }
            // Propose new code: an upgrade while live, a restore while stopped.
            7 => {
                let code = rng.pick(&[Code::V1, Code::Fix]);
                let restore = rng.below(2) == 0;
                let buffer = fresh_buffer(&mut env, code);
                let who = rng.below(2) as usize;
                let kind = if restore { RESTORE } else { UPGRADE };
                let r = env.send(&[f.propose(&ok_[who].pubkey(), kind, &buffer, &[], Some(&buffer))], &[ok_[who]]);
                let valid = who == md.owner && md.pending.is_none() && md.aborted == restore;
                if valid {
                    md.last_id += 1;
                    let eta = upgrade_eta(now, md.delay);
                    md.pending = Some(Pending { kind, id: md.last_id, vetoed: false, approvals: 0, target: buffer.to_bytes(), eta, expires: eta + CHANGE_EXPIRY_S, effect: Effect::Code(code) });
                }
                (op, sent, model_ok) = (if restore { "propose_restore" } else { "propose_upgrade" }, r.is_ok(), valid);
            }
            // Execute whatever is pending.
            8..=9 => {
                let ix = match &md.pending {
                    Some(pd) if pd.kind == UPGRADE || pd.kind == RESTORE => f.execute_code(&Address::from(pd.target), &env.payer.pubkey()),
                    _ => f.execute_config(),
                };
                let r = env.send(&[ix], &[]);
                let ok = match md.pending.clone() {
                    None => false,
                    Some(pd) => {
                        let sched = Schedule { executable_s: pd.eta, expires_s: pd.expires };
                        let allowed = match pd.kind {
                            UPGRADE => !md.aborted && can_execute(&sched, now, pd.vetoed, false, false).is_ok(),
                            RESTORE => {
                                let alive = md.alive(now);
                                md.aborted && can_restore(RestoreSource::Proposed, &pd.target, &pd.target, quorum(pd.approvals & alive, alive, md.threshold), pd.vetoed, now, pd.eta, pd.expires)
                            }
                            _ => can_execute(&sched, now, pd.vetoed, false, false).is_ok(),
                        };
                        if allowed {
                            match pd.effect {
                                Effect::Code(c) => {
                                    md.live = c;
                                    md.aborted = false;
                                    md.snapshot = None;
                                    md.snapshot_valid = false;
                                }
                                Effect::Guardians(set, th, interval) => {
                                    md.heartbeats = vec![now; set.len()];
                                    md.guardians = set;
                                    md.threshold = th;
                                    md.interval = interval;
                                }
                                Effect::Owner(o) => md.owner = o,
                                Effect::Delay(d) => md.delay = d,
                            }
                            md.pending = None;
                        }
                        allowed
                    }
                };
                (op, sent, model_ok) = ("execute", r.is_ok(), ok);
            }
            // The owner withdraws the pending proposal.
            10 => {
                let who = rng.below(2) as usize;
                let r = env.send(&[f.cancel(&ok_[who].pubkey())], &[ok_[who]]);
                let ok = who == md.owner && md.pending.is_some();
                if ok {
                    md.pending = None;
                }
                (op, sent, model_ok) = ("cancel", r.is_ok(), ok);
            }
            // A quorum of the others ejects a guardian.
            11 => {
                let target = rng.below(md.guardians.len() as u64 + 1) as u8;
                let signers: Vec<usize> = md.guardians.iter().copied().filter(|_| rng.below(3) != 0).collect();
                let keys: Vec<Address> = signers.iter().map(|&k| gk[k].pubkey()).collect();
                let kps: Vec<&Keypair> = signers.iter().map(|&k| gk[k]).collect();
                let r = env.send(&[f.eject(target, &keys)], &kps);
                let approvals = md.bits(&signers).unwrap();
                let ok = can_eject(approvals, md.alive(now), md.threshold, target, md.guardians.len() as u8);
                if ok {
                    md.guardians.remove(target as usize);
                    md.heartbeats.remove(target as usize);
                    if let Some(pd) = md.pending.as_mut() {
                        pd.approvals = 0;
                    }
                }
                (op, sent, model_ok) = ("eject", r.is_ok(), ok);
            }
            // Stop the program: a guardian (live or stale) or an owner.
            12 => {
                let by_owner = rng.below(4) == 0;
                let (signer, ok_signer) = if by_owner {
                    let who = rng.below(2) as usize;
                    (ok_[who], who == md.owner)
                } else {
                    let k = if rng.below(2) == 0 { md.guardians[rng.below(md.guardians.len() as u64) as usize] } else { rng.below(5) as usize };
                    (gk[k], md.live_guardian(k, now).is_some())
                };
                let snap = if rng.below(4) == 0 { None } else { snapshot_buffer };
                let r = env.send(&[f.abort(&signer.pubkey(), &abort_buffer, snap.as_ref())], &[signer]);
                let ok = ok_signer && !md.aborted && md.abort_staged;
                if ok {
                    md.snapshot_valid = md.snapshot.is_some() && snap.is_some() && md.snapshot == Some(md.live);
                    md.live = Code::Abort;
                    md.aborted = true;
                    md.abort_staged = false;
                    md.pending = None;
                }
                (op, sent, model_ok) = ("abort", r.is_ok(), ok);
            }
            // Live guardians approve the pending restore.
            13 => {
                let signers: Vec<usize> = md.guardians.iter().copied().filter(|_| rng.below(2) == 0).collect();
                let keys: Vec<Address> = signers.iter().map(|&k| gk[k].pubkey()).collect();
                let kps: Vec<&Keypair> = signers.iter().map(|&k| gk[k]).collect();
                let r = env.send(&[f.approve(&keys)], &kps);
                let bits = md.bits(&signers).unwrap();
                let ok = matches!(&md.pending, Some(pd) if pd.kind == RESTORE) && bits != 0 && bits & md.alive(now) == bits;
                if ok {
                    md.pending.as_mut().unwrap().approvals |= bits;
                }
                (op, sent, model_ok) = ("approve", r.is_ok(), ok);
            }
            // A quorum restores the verified snapshot.
            14 => {
                let signers: Vec<usize> = md.guardians.iter().copied().filter(|_| rng.below(3) != 0).collect();
                let keys: Vec<Address> = signers.iter().map(|&k| gk[k].pubkey()).collect();
                let kps: Vec<&Keypair> = signers.iter().map(|&k| gk[k]).collect();
                let snap = snapshot_buffer.unwrap_or(p.snapshot);
                let r = env.send(&[f.restore_snapshot(&snap, &env.payer.pubkey(), &keys)], &kps);
                let alive = md.alive(now);
                let ok = md.aborted && md.snapshot_valid && quorum(md.bits(&signers).unwrap() & alive, alive, md.threshold);
                if ok {
                    md.live = md.snapshot.unwrap();
                    md.aborted = false;
                    md.snapshot = None;
                    md.snapshot_valid = false;
                    md.pending = None;
                    snapshot_buffer = None;
                }
                (op, sent, model_ok) = ("restore_snapshot", r.is_ok(), ok);
            }
            // Anyone re-arms: a new abort buffer, or a snapshot of the live code.
            _ => {
                if rng.below(2) == 0 {
                    let b = fresh_buffer(&mut env, Code::Abort);
                    let r = env.send(&[f.stage_abort(&b)], &[]);
                    let ok = !md.abort_staged;
                    if ok {
                        md.abort_staged = true;
                        abort_buffer = b;
                    }
                    (op, sent, model_ok) = ("stage_abort", r.is_ok(), ok);
                } else {
                    // Sometimes a snapshot of code that is not the live code.
                    let code = if rng.below(4) == 0 { rng.pick(&[Code::V1, Code::Fix]) } else { md.live };
                    let b = fresh_buffer(&mut env, code);
                    let r = env.send(&[f.pin_snapshot(&b)], &[]);
                    let ok = !md.aborted && code == md.live;
                    if ok {
                        md.snapshot = Some(code);
                        md.snapshot_valid = false;
                        snapshot_buffer = Some(b);
                    }
                    (op, sent, model_ok) = ("pin_snapshot", r.is_ok(), ok);
                }
            }
        }
        assert_eq!(sent, model_ok, "{at}: {op} succeeded on chain = {sent}, model says {model_ok}");
        *counts.entry(format!("{op}:{}", if sent { "ok" } else { "refused" })).or_default() += 1;
        env.next_slot();

        // The whole config the model tracks.
        let d = env.account(&f.config).data;
        let i64_at = |o: usize| i64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        let k32 = |o: usize| -> [u8; 32] { d[o..o + 32].try_into().unwrap() };
        let n = d[424] as usize;
        let chain_guardians: Vec<[u8; 32]> = (0..n).map(|i| k32(104 + 32 * i)).collect();
        let model_guardians: Vec<[u8; 32]> = md.guardians.iter().map(|&k| gk[k].pubkey().to_bytes()).collect();
        assert_eq!(chain_guardians, model_guardians, "{at}: guardians after {op}");
        let chain_heartbeats: Vec<i64> = (0..n).map(|i| i64_at(360 + 8 * i)).collect();
        assert_eq!(chain_heartbeats, md.heartbeats, "{at}: heartbeats after {op}");
        assert_eq!(k32(72), ok_[md.owner].pubkey().to_bytes(), "{at}: owner after {op}");
        assert_eq!((d[425], d[426] == 1, d[430] == 1, i64_at(432), i64_at(440)), (md.threshold, md.aborted, md.snapshot_valid, md.interval, md.delay), "{at}: threshold, status, snapshot validity, interval, delay after {op}");
        assert_eq!((k32(448) != [0; 32], k32(480) != [0; 32]), (md.abort_staged, md.snapshot.is_some()), "{at}: armed after {op}");
        assert_eq!(u64::from_le_bytes(d[528..536].try_into().unwrap()), md.last_id, "{at}: proposal id after {op}");
        match &md.pending {
            None => assert_eq!(d[520], 0, "{at}: nothing pending after {op}"),
            Some(pd) => assert_eq!(
                (d[520], d[521] == 1, d[522], k32(536), i64_at(568), i64_at(576)),
                (pd.kind, pd.vetoed, pd.approvals, pd.target, pd.eta, pd.expires),
                "{at}: pending after {op}"
            ),
        }
        let live = env.programdata_bytes(&f.programdata);
        let want = elf(md.live);
        assert_eq!(&live[..want.len()], &want[..], "{at}: live code after {op}");
    }
    counts
}
