// Approvals that cannot be replayed, and spending that cannot be fooled
// (docs/09, finding 71).
import { test } from "node:test";
import assert from "node:assert/strict";
import { assess, decode, newState, checkPolicy, changeApproval, floorApproval, pinnedChangeApproval, readPendingChange, pendingChangeVeto, dueApprovedChange, checkProposedChange, consumeApproval, spendExecution, observeExecutions, unpinnedChangeApprovals, DEFAULT_POLICY } from "../guardian/policy.mjs";
import { u64le, i64le, key } from "../lib/solana.mjs";

const owner = "5YMKnK8DcuUc5vSagDZTJB8VVGnQ1ZJP9Pxm9BAqUoPh";
const mint = "DmrC7P3uPGQ7zCMhLVkJVAtnWwPn6yzSg6tL9xVEmzzM";
const PROTOCOL = key("8sZ5d3jB3kGqEoTz6eYpNw2bR3aUqv1uJ8sZtLWGd7Vb");

/** A `BHCHNG01` account's bytes (Change::LEN), with the base version at 442. */
function changeBytes({ id, kind, baseVersion, executed = false, executableS = 1_000, expiresS = 9_000 }) {
  const bytes = new Uint8Array(448);
  bytes.set(new TextEncoder().encode("BHCHNG01"));
  const v = new DataView(bytes.buffer);
  v.setBigUint64(40, BigInt(id), true);
  bytes[48] = kind;
  bytes[50] = executed ? 1 : 0;
  v.setBigInt64(124, BigInt(executableS), true);
  v.setBigInt64(132, BigInt(expiresS), true);
  v.setUint32(442, baseVersion, true);
  return bytes;
}

test("a pinned approval approves only the proposal at its base version: a replay after execution never matches", () => {
  const ran = readPendingChange(changeBytes({ id: 4, kind: 2, baseVersion: 6, executed: true }));
  assert.equal(ran.baseVersion, 6, "read from the change account");
  const pinned = pinnedChangeApproval(ran);
  assert.equal(pinned, `${changeApproval(ran)}#6`);
  const policy = checkPolicy({ ...DEFAULT_POLICY, approvedChanges: [pinned] });
  const ours = { ...ran, executed: false };
  // Executing moved the target's version on: the same content proposed again
  // records version 7, and nothing here has to remember anything.
  const replay = { ...ran, id: 11n, executed: false, baseVersion: 7 };
  assert.equal(pendingChangeVeto(ours, policy, 500, new Set()), null);
  assert.equal(dueApprovedChange(ours, policy, 1_500, new Set()).changeId, 4n);
  assert.equal(pendingChangeVeto(replay, policy, 500, new Set()).changeId, 11n);
  assert.equal(dueApprovedChange(replay, policy, 1_500, new Set()), null);
  assert.equal(checkProposedChange(11n, replay, policy, 500, 500, new Set(), new Map()).changeId, 11n);
  assert.equal(checkProposedChange(4n, ours, policy, 500, 500, new Set(), new Map()), "ok");
  assert.equal(pendingChangeVeto({ ...ours, baseVersion: undefined }, policy, 500, new Set()).changeId, 4n, "an unknown version matches no pin");
  // The live event has no version: its kind and target have the account read.
  const live = decode({ name: "vault:change_proposed", fields: [u64le(11), Uint8Array.of(2), key(ran.target), i64le(0), PROTOCOL] });
  assert.deepEqual(assess(newState(), live, { worst1h: 0n, now: 0 }, policy), [{ type: "check_change", changeId: 11n }]);
  // Pinned with an expiry; no pinned Floor approvals.
  assert.doesNotThrow(() => checkPolicy({ ...DEFAULT_POLICY, approvedChanges: [`${pinned}@9000`] }));
  assert.throws(() => checkPolicy({ ...DEFAULT_POLICY, approvedChanges: [`${changeApproval(ran)}#x`] }), /approvedChanges/);
  assert.throws(() => checkPolicy({ ...DEFAULT_POLICY, approvedFloorProposals: [`${floorApproval({ program: mint, kind: 5, target: owner, payload: new Uint8Array(0) })}#3`] }), /approvedFloorProposals/);
  assert.equal(pendingChangeVeto(ours, { ...policy, approvedChanges: [`${pinned}@400`] }, 500, new Set()).changeId, 4n, "expired");
  // A pinned approval is never spent, and is not reported as unpinned.
  const s = newState();
  s.changeBaseline = true;
  assert.equal(spendExecution(s, policy.approvedChanges, changeApproval(ran), "c4", 500), null);
  assert.equal(s.consumed.size, 0);
  assert.deepEqual(unpinnedChangeApprovals(policy), []);
  assert.deepEqual(unpinnedChangeApprovals({ approvedChanges: [pinned, changeApproval(ran)] }), [changeApproval(ran)]);
});

test("a guardian with no record of executions spends nothing on changes that ran long ago (finding 71, 1)", () => {
  // The operators approve setting guardian set X again, long after the same
  // content ran as change 2. This guardian's state file was lost.
  const content = changeApproval({ kind: 2, target: mint, payload: Uint8Array.of(9) });
  const policy = checkPolicy({ ...DEFAULT_POLICY, approvedChanges: [`${content}@90000`] });
  const old = { id: 2n, kind: 2, target: mint, payload: Uint8Array.of(9), vetoed: false, executed: true, executableS: 100, expiresS: 200, baseVersion: 3 };
  const pending = { ...old, id: 9n, executed: false, executableS: 50_000, expiresS: 60_000, baseVersion: 4 };
  const s = newState();
  // A replayed execution event before the first scan spends nothing either.
  assert.equal(spendExecution(s, policy.approvedChanges, content, "c2", 40_000), null);
  assert.deepEqual(observeExecutions(s, [old, pending], policy.approvedChanges, 40_000), [], "the baseline spends nothing");
  assert.equal(s.changeBaseline, true);
  assert.equal(s.consumed.size, 0);
  assert.equal(pendingChangeVeto(pending, policy, 40_000, s.vetoed, s.consumed), null, "the operators' change is not vetoed");
  assert.deepEqual(observeExecutions(s, [old, pending], policy.approvedChanges, 41_000), [], "the old one is never new");
  // It runs: the approval is spent, and a replay is vetoed.
  const ran = { ...pending, executed: true };
  const spent = observeExecutions(s, [old, ran], policy.approvedChanges, 55_000);
  assert.deepEqual(spent.map((x) => x.approval), [`${content}@90000`]);
  assert.equal(pendingChangeVeto({ ...pending, id: 12n, baseVersion: 5 }, policy, 56_000, s.vetoed, s.consumed).changeId, 12n);
  // Its event, read too, spends nothing more.
  assert.equal(spendExecution(s, policy.approvedChanges, content, "c9", 55_000), null);
  // An execution seen as it happens spends even before the baseline.
  const fresh = newState();
  assert.equal(spendExecution(fresh, policy.approvedChanges, content, "c9", 55_000, { live: true }), `${content}@90000`);
  assert.deepEqual(observeExecutions(fresh, [ran], policy.approvedChanges, 56_000), []);
  assert.equal(fresh.consumed.size, 1, "the baseline does not spend it twice");
  // Floor executions are only ever read from events: no baseline needed.
  const fl = floorApproval({ program: owner, kind: 5, target: mint, payload: new Uint8Array(0) });
  assert.equal(spendExecution(newState(), [fl], fl, `e${owner}:3`, 0), fl);
});

test("an execution spends a live approval, the earliest to expire, never an expired one (finding 71, 2)", () => {
  const content = changeApproval({ kind: 3, target: owner, payload: new Uint8Array(0) });
  const list = [`${content}@100`, `${content}@500`];
  const policy = checkPolicy({ ...DEFAULT_POLICY, approvedChanges: list });
  const replay = { id: 8n, kind: 3, target: owner, payload: new Uint8Array(0), vetoed: false, executed: false, executableS: 300, expiresS: 900 };
  const consumed = new Map();
  // Change 7 ran at 200: the approval expiring at 100 approved nothing by then.
  assert.equal(consumeApproval(consumed, list, content, "c7", 200), `${content}@500`);
  assert.equal(pendingChangeVeto(replay, policy, 250, new Set(), consumed).changeId, 8n, "the replay is vetoed");
  assert.equal(dueApprovedChange(replay, policy, 300, new Set(), consumed), null);
  // Several live: the one expiring first goes, one without an expiry last.
  const more = [content, `${content}@900`, `${content}@600`];
  const c2 = new Map();
  assert.equal(consumeApproval(c2, more, content, "c1", 200), `${content}@600`);
  assert.equal(consumeApproval(c2, more, content, "c2", 200), `${content}@900`);
  assert.equal(consumeApproval(c2, more, content, "c3", 200), content);
  assert.equal(consumeApproval(c2, more, content, "c4", 200), null, "nothing left");
  assert.equal(consumeApproval(new Map(), [`${content}@100`], content, "c5", 200), null, "an expired one is not spent");
});
