#!/usr/bin/env node
// The guardian approval of each open Vault change of a market, and of a
// Floor's pending proposal: what to put in `policy.approvedChanges` or
// `approvedFloorProposals` to let exactly that proposal through. An approval
// names what a change does (kind, target, payload), never its id, so it can
// only ever match that change (docs/07 §6). Read-only; approve only what the
// operators agreed to.
//
//   node cloud/deploy/approvals.mjs <rpc> <vault-program> <protocol> [floor-program protected-program]
import { Rpc, decodeFloor } from "../lib/solana.mjs";
import { FloorClient } from "../lib/bulkhead.mjs";
import { activeChanges } from "../guardian/chain.mjs";
import { changeApproval, floorApproval } from "../guardian/policy.mjs";

const [url, vaultProgram, protocol, floorProgram, protectedProgram] = process.argv.slice(2);
if (!url || !vaultProgram || !protocol) {
  console.error("usage: approvals.mjs <rpc> <vault-program> <protocol> [floor-program protected-program]");
  process.exit(2);
}
const rpc = new Rpc(url);
const KINDS = ["limits", "asset", "guardians", "admin", "lifeboat destination", "loosen delay", "recovery key"];
const iso = (t) => new Date(t * 1000).toISOString();

const changes = (await activeChanges(rpc, vaultProgram, protocol)).sort((a, b) => (a.id < b.id ? -1 : 1));
if (!changes.length) console.log("vault: no open change");
for (const c of changes) {
  console.log(`vault change ${c.id} (${KINDS[c.kind] ?? `kind ${c.kind}`}, target ${c.target}, executable ${iso(c.executableS)} until ${iso(c.expiresS)})`);
  console.log(`  approvedChanges: ${JSON.stringify(changeApproval(c))}`);
}
if (floorProgram && protectedProgram) {
  const fc = await new FloorClient(floorProgram, protectedProgram).init();
  const acc = await rpc.account(fc.config);
  const f = acc ? decodeFloor(acc.bytes) : null;
  if (!f) console.log("floor: no Floor config for that program");
  else if (!f.pendingKind || f.pendingVetoed) console.log("floor: nothing pending");
  else if (f.pendingKind === 1 || f.pendingKind === 2) {
    console.log(`floor proposal ${f.pendingId} (code from buffer ${f.pendingTarget})`);
    console.log(`  approvedUpgradeBuffers: ${JSON.stringify(f.pendingTarget)}`);
  } else {
    console.log(`floor proposal ${f.pendingId} (kind ${f.pendingKind}, target ${f.pendingTarget}, executable ${iso(f.pendingEta)})`);
    console.log(`  approvedFloorProposals: ${JSON.stringify(floorApproval({ program: f.program, kind: f.pendingKind, target: f.pendingTarget, payload: f.pendingPayload }))}`);
  }
}
