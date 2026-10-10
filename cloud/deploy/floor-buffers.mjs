#!/usr/bin/env node
// Lists the buffers Floor holds for a program, says what each is for, and
// with --close returns the orphans' rent to the owner (docs/09, finding 78).
//
//   node cloud/deploy/floor-buffers.mjs <rpc> <floor-program> <protected-program> [--close <owner.json>]
//
// A buffer whose authority is Floor's PDA is the staged abort buffer, the
// pinned snapshot, the pending upgrade's or restore's buffer, a spare snapshot
// (identical to the live code: a stop may name it, so it stays while the
// program runs; finding 85), or an orphan: a
// pin that was replaced (a re-pin, or a stop naming another identical buffer)
// or cleared by an upgrade, or a proposal's buffer after a cancel or a stop.
// Nothing else frees an orphan's rent. Only the owner may close one, and the
// program refuses the other three whatever this script thinks (`BufferInUse`).
//
// Exit 0: listed (and, with --close, every orphan closed). 1: a close failed.
// 2: usage, no Floor config, or the key is not the owner.
import { Rpc, decodeFloor, b58encode, key } from "../lib/solana.mjs";
import { Keypair, send } from "../lib/signer.mjs";
import { FloorClient, floorBufferRole } from "../lib/bulkhead.mjs";

const argv = process.argv.slice(2);
const at = argv.indexOf("--close");
const ownerPath = at >= 0 ? argv[at + 1] : null;
const [url, floorProgram, protectedProgram] = argv.filter((_, i) => at < 0 || (i !== at && i !== at + 1));
if (!url || !floorProgram || !protectedProgram || (at >= 0 && !ownerPath)) {
  console.error("usage: floor-buffers.mjs <rpc> <floor-program> <protected-program> [--close <owner.json>]");
  process.exit(2);
}
const rpc = new Rpc(url);
const fc = await new FloorClient(floorProgram, protectedProgram).init();
const acc = await rpc.account(fc.config);
if (!acc) {
  console.error(`no Floor config for ${protectedProgram}`);
  process.exit(2);
}
const config = decodeFloor(acc.bytes);
const sol = (l) => (l / 1e9).toFixed(6);
const held = (await fc.heldBuffers(rpc)).map((b) => ({ ...b, role: floorBufferRole(config, b.address) }));
// A buffer identical to the live code is a spare snapshot while the program
// runs: a stop may name it, so the program refuses to close it (finding 85).
// Asked by simulation, which sends nothing.
for (const b of held.filter((x) => x.role === "orphan")) {
  const sim = await rpc.simulate(key(config.owner), [fc.closeBuffer(config.owner, b.address)]).catch(() => null);
  if (sim?.err?.InstructionError?.[1]?.Custom === 7036) b.role = "spare";
}
console.log(`Floor holds ${held.length} buffer(s) for ${protectedProgram} (authority ${b58encode(fc.authority)}, owner ${config.owner})`);
for (const b of held) console.log(`  ${b.role.padEnd(7)} ${b.address}  ${sol(b.lamports)} SOL`);
const orphans = held.filter((b) => b.role === "orphan");
const spares = held.filter((b) => b.role === "spare").length;
console.log(`${orphans.length} orphan(s), ${sol(orphans.reduce((t, b) => t + b.lamports, 0))} SOL the owner can take back${spares ? `; ${spares} spare snapshot(s) identical to the live code, kept until the code changes or the program is stopped; a release closes them if passed to it` : ""}`);
if (!ownerPath || !orphans.length) process.exit(0);

const owner = Keypair.load(ownerPath);
if (b58encode(owner.publicKey) !== config.owner) {
  console.error(`${b58encode(owner.publicKey)} is not the owner (${config.owner}): only the owner may close a buffer`);
  process.exit(2);
}
let failed = 0;
for (const b of orphans) {
  // Read again right before: a buffer someone consumed meanwhile is done.
  if (!(await rpc.account(b.address))) {
    console.log(`  ${b.address} is already gone`);
    continue;
  }
  try {
    const sig = await send(rpc, owner, [fc.closeBuffer(owner.publicKey, b.address)]);
    console.log(`  closed ${b.address}: ${sol(b.lamports)} SOL to the owner (${sig})`);
  } catch (e) {
    failed++;
    console.log(`  could not close ${b.address}: ${String(e.message ?? e).slice(0, 200)}`);
  }
}
process.exit(failed ? 1 : 0);
