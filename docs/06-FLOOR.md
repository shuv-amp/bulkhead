# 06 — Floor (Tier 0): a floor under the upgrade key

Floor is a small program (`programs/floor`, Pinocchio, one dependency: `bulkhead-core`). It holds another program's loader-v3 **upgrade authority** and enforces rules the owner cannot lower:

1. **Change is slow.** New code waits at least 72 hours (a compile-time constant), in public, and any live guardian can veto it.
2. **Stopping is fast.** Any single live guardian, or the owner, stops the program in one instruction by swapping in a pre-staged abort binary. The binary logs why it fails and returns `Custom(0x464C4F52)` ("FLOR").
3. **Undoing a stop is cheap and can't smuggle in code.** A live guardian quorum restores the *snapshot*: a buffer verified on-chain, at the moment of the abort, to be byte-identical to the code that was running. New code (a fix) needs a quorum's approval of that exact buffer, or the full delay.
4. **The only fast path to new code goes through a visible stop.**
5. `Close` (which destroys a program forever) is never reachable.

It is a separate program from the Vault so each has a small audit surface and its own blast radius.

Status: built, 21 tests on the real agave loader (LiteSVM with the mainnet feature set), sBPF v3 (`e_flags = 3`), 56 KB. Deployed on devnet on 28 Sep 2026 (`HARLZqMwqocBnbhbSTWkd5i8EHmjHXLHr1T9su3SR31E`), byte-identical to this checkout's build, and the full lifecycle has run there (§7). Unaudited.

## 1. Why it exists

- **Adoption:** one transaction, zero code changes. A protocol adopts Floor before it adopts the Vault.
- **Measured need:**
  - of 54 multisigs governing solgov-tracked protocols, 37 have no timelock and none reaches 72h;
  - 8 of 183 programs are upgradeable by one plain key (`01 §4`).
- **The stop button exists, but nobody wired it in safely.** Dean Little's `sbpf-asm-abort` (136 bytes) showed a program can be stopped by upgrading it to a two-instruction binary. Floor turns that pattern into a control system (§2). The pattern is credited to Dean; his repository has no license, so Floor ships its own binaries, assembled in `bulkhead-core` from source (§5).

What Floor does **not** do: bound a Drift-style drain. Drift was drained with admin instructions inside the existing code, not by an upgrade. Only the Vault's in-path limits bound that. The pitch never blurs this line.

## 2. Floor versus a bare abort binary

| | Bare abort (upgrade to an abort binary) | Floor |
|---|---|---|
| Who can stop | Whoever holds the upgrade key, the same key that can deploy *anything* | Any single live guardian, or the owner; guardians can't deploy code |
| Stop under a timelocked multisig | Waits for the timelock, like any upgrade | Instant: the delay applies to change, not to stopping |
| At the moment of the emergency | Write a buffer, then upgrade, under stress | One 11-account instruction with a pre-staged, verified buffer; a bot can send it |
| Undoing the stop | Re-upload the whole binary (hundreds of transactions), by the same key | One instruction: a quorum restores a snapshot verified byte-identical to the stopped code |
| Installing a fix after a stop | Same key, no checks | Quorum approval of that exact frozen buffer, or the full 72h+ delay with veto |
| What users and integrators see | `Custom(1)`, the same as an ordinary app error | A log line ("stopped by its Bulkhead Floor guardians…") and `Custom(0x464C4F52)` |
| Destroying the program (`Close`) | Available to the key | Unreachable |
| A malicious stopper | Is the key holder | A live quorum ejects the guardian instantly; restore in the same transaction |
| SIMD-0500 | Not considered | The live binary's sBPF version is recorded at every install and shown |
| Whether the stop can land | Unchecked | Staging refuses an abort buffer that wouldn't fit the program's data account |

## 3. Loader facts Floor is built on

Each was checked in agave's source (master `f771659`, 26 Sep 2026) or on-chain; `13-SOURCES` lists the paths.

1. **A program may CPI loader-v3 only for `Upgrade`, `SetAuthority`, `SetAuthorityChecked` and `Close`** (`program-runtime/src/cpi.rs`, `check_authorized_program`).
   - So Floor can never *write* a buffer. Anyone writes one and hands its authority to Floor's PDA; Floor then *verifies* the bytes.
   - Once Floor is a buffer's authority, nobody can write to it again (`Write` needs the authority's signature, and Floor can't CPI `Write`). Its bytes are frozen.
2. **`Upgrade` copies the buffer to the front of programdata and zero-fills the rest** (`programs/bpf_loader/src/lib.rs`). So "restores the exact bytes" means: the buffer equals the programdata prefix, and everything after it is zero. That is `bulkhead_core::floor::snapshot_matches`, proved against a model of `Upgrade` by Kani (`09 §5`).
3. **A program is upgraded at most once per slot**, and new code is visible from the next slot.
4. **Loader-v4 was abandoned.** Its feature id is `LoaderV4WasAbandoned11111111111111111111111`. Swapping in an abort binary through loader-v3 is the only way to stop a program.
5. **SIMD-0500** (`disable_sbpf_v0_v1_v2_deployment`, feature `B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g`) makes `Upgrade` accept only sBPF v3.
   - v3 means `e_flags == 3`. agave's `max_sbpf_version` is V3; `e_flags = 4` decodes to an unenabled V4.
   - Not active on mainnet or devnet as of 27 Sep 2026. sBPF v3 deployment is active on both (mainnet since slot 428,976,000).

## 4. State

`FloorConfig`, PDA `["floor", program]`, 916 bytes, a fixed little-endian layout (`programs/floor/src/state.rs`):

| Field | Meaning |
|---|---|
| `program`, `programdata` | The protected program and its loader-v3 data account |
| `owner` | Proposes upgrades, restores and configuration changes (e.g. a Squads vault) |
| `guardians[≤8]`, `last_heartbeat[≤8]`, `threshold` (≥ 2), `heartbeat_interval_s` (1–30 days) | Only guardians that heart-beat within the interval can act (Lido pattern) |
| `upgrade_delay_s` | ≥ 72h (constant floor), ≤ 30 days (`15`, A7); **7 days recommended** (L2BEAT Stage-1 exit window) |
| `status` | Live or Aborted |
| `elf_is_v3` | Whether the live code is deployable after SIMD-0500 (updated at every install) |
| `abort_buffer` | The staged canonical abort binary (frozen buffer) |
| `snapshot_buffer`, `snapshot_valid` | A frozen buffer pinned as a copy of the live code; "valid" is decided at the moment of an abort |
| `pending_*` | At most one proposal: kind, target, payload, ETA, expiry, veto flag, approval bitmap, id |

The upgrade authority is a second PDA, `["authority", program]`, with no data: it only signs. Buffers pinned by Floor have that PDA as authority.

## 5. The abort binaries

Assembled at compile time in `bulkhead-core/src/floor.rs` by a small encoder (the file shows the assembly). Built independently in Python; both builders produce identical bytes (golden `FA`).

```
rodata (vaddr 0):  "Program stopped by its Bulkhead Floor guardians. The stop moves no funds. Restart needs a guardian quorum."
text (vaddr 2^32): mov64 r1, 0 ; mov64 r2, len ; syscall sol_log_ ; mov64 r0, 0x464C4F52 ; exit
```

- **`ABORT_ELF`** (328 bytes) logs the line and fails with `Custom(0x464C4F52)`. The syscall id is `murmur3_32("sol_log_") = 0x207559bd`; the murmur3 implementation is checked against published vectors.
- **`ABORT_ELF_MINIMAL`** (136 bytes, no syscall) only fails with the code. It exists for very small programs and as a fallback if logging ever changed.
- Both satisfy the sBPF v3 strict ELF rules (SIMD-0189), restated in `crates/bulkhead-core/tests/floor.rs`. Both deploy through a real loader `Upgrade` in the program tests.
- The error code is outside every range programs use for their own errors.

## 6. Instructions

Account lists and data layouts are documented above each handler in `programs/floor/src/lib.rs`.

| # | Instruction | Signer | Effect |
|---|---|---|---|
| 0 | `register(owner, guardians, threshold, interval, delay)` | the **current** upgrade authority | Creates the config and moves the authority to Floor's PDA **in the same instruction** (CPI `SetAuthority`). There is no window in which Floor holds a key but someone else chose the guardians. Survives a pre-funded config address. |
| 1 | `stage_abort` | anyone | Accepts a frozen buffer holding exactly a canonical abort binary that fits the programdata account |
| 2 | `pin_snapshot` | anyone | Accepts a frozen buffer byte-identical to the live code (`sol_memcmp_`) |
| 3 | `abort` | a live guardian or the owner | Re-checks the snapshot against the live bytes, then CPIs `Upgrade(abort buffer)`. Never fails because of the snapshot. Cancels any pending proposal. |
| 4 | `propose(kind, target, payload)` | owner | Upgrade (while live), Restore (while aborted), ReleaseAuthority, SetGuardians, SetOwner, SetDelay. Raising the delay is instant; everything else waits the delay and expires 7 days after it becomes executable. |
| 5 | `veto` | any live guardian | Blocks the pending proposal |
| 6 | `approve` | live guardians | Approves the pending Restore (its exact buffer) |
| 7 | `execute` | anyone | Runs the pending proposal once allowed. A Restore runs at once with a quorum's approval. |
| 8 | `restore_snapshot` | a live guardian quorum | Reinstalls the verified snapshot |
| 9 | `heartbeat` | a live guardian | Keeps it alive; a dead guardian can't revive itself |
| 10 | `eject(target)` | a live quorum of the *other* guardians | Removes a guardian at once; never below the threshold |
| 11 | `cancel` | owner | Withdraws the pending proposal |

## 7. Measured

Real agave loader, LiteSVM with the mainnet feature set (`programs/tests/tests/floor.rs`):

| Operation | Compute units |
|---|---|
| Stop a ~200 KB program, including byte-for-byte snapshot verification | 10,261 |
| Restore the ~200 KB snapshot (guardian quorum) | 8,110 |

A snapshot buffer costs rent for a copy of the program (about 5,080 lamports per byte at current rent, the same on mainnet and devnet on 28 Sep 2026; about 1.04 SOL for 200 KB). The rent is returned when a restore consumes the buffer. That is the price of a one-instruction, trustless undo.

**On a real program** (`scripts/floor-demo.sh <program-id>`, 27 Sep 2026): the script runs a mainnet program's actual bytes on a local validator, with mainnet's feature set and a local team key as the upgrade authority. Run on SPL Stake Pool (`SPoo1Ku8…`, 1,080,464 bytes of sBPF v0 code), it went like this:
1. `register` moved the upgrade key to Floor in one transaction, and the code was unchanged.
2. The abort buffer and a snapshot were staged and pinned.
3. **One** guardian stopped the program (confirmed in ~1.5 s). The same call then failed with `Custom(0x464C4F52)` and Floor's log line.
4. **Two** guardians restored it. The code's sha256 was identical to before, and so was the program's behaviour.

The run took 17 s, with zero code changes. The program is v0, so once SIMD-0500 is active, this restore would need a v3 build (§8).

**On devnet** (`scripts/floor-devnet.sh`, 28 Sep 2026), against the deployed Floor with real transactions, on a target program (a copy of Harbor's binary under its own id):
1. `register`, then the stop staged and a snapshot pinned.
2. The owner proposed an upgrade. It could not execute before 72h, one guardian vetoed it, and the owner withdrew it.
3. **One** guardian stopped the program (confirmed in 4.9 s); every call then failed with `FLOR`.
4. **Two** guardians restored it: byte-identical code, identical behaviour. Then it was re-armed with a new abort and a new snapshot.

Between the steps, 17 forbidden actions were simulated, and each failed with its exact error. The signatures are in `08`, under "Devnet signatures".

## 8. SIMD-0500: the one-way door

After SIMD-0500 activates, `Upgrade` accepts only sBPF v3. So:
- **The abort binaries must be v3.** They are, and CI checks them.
- **A pre-v3 program can still be stopped, but can't come back** until it ships a v3 build. Its snapshot is pre-v3 too.
- Floor records `elf_is_v3` at registration and at every install, and the status page flags a pre-v3 program ("build and test a v3 binary"). A stop of such a program after SIMD-0500 can only be undone with a v3 build.
- About 17,279 upgradeable programs were pre-v3 when SIMD-0500 was written. The same check runs, free, on any program: `python3 tools/floor_check.py <program-id>`, which also reports who holds the upgrade key (a single plain key, or a program-controlled address).

## 9. Threats specific to Floor

| Threat | Answer |
|---|---|
| Stolen owner key proposes a malicious binary | Waits ≥ 72h in public; any live guardian vetoes |
| Stolen owner key stops the program | Denial of service only; a quorum restores the snapshot in one instruction |
| Malicious guardian stops the program, or vetoes everything | A live quorum of the other guardians ejects it and restores, in one transaction |
| A guardian quorum is malicious | Out of scope: it holds Security Council power (fast restore). The status page checks the set against the on-chain parts of L2BEAT's bar (≥ 8 members, ≥ 75% threshold); the third part (≥ 50% outside the team) must be published by the team (§10). |
| Bug in Floor | Every protected program at once. Mitigations: small instruction set, no arbitrary CPI, one dependency, verified core, devnet only until audited. |
| Pre-signed (durable-nonce) proposals | Proposals expire 7 days after becoming executable, and are public for ≥ 72h |
| The stop lands one slot late | New code is visible from the next slot, and a program can be upgraded once per slot. Guardians send stops with a priority fee, to several RPCs. One runtime-level interaction is under responsible disclosure; see `SECURITY.md`. |
| Snapshot made stale by an upgrade | Decided at the moment of the abort against the live bytes; a stale snapshot only removes the fast undo, never blocks the stop |
| Abort buffer too large for the program | Refused at staging (`AbortDoesNotFit`); the 136-byte minimal binary fits almost any program |

## 10. Exit window and the guardian bar (L2BEAT lens)

- **Exit window.** With the Vault, own-deposit withdrawals are never throttled or frozen by Bulkhead, so a protocol's exit window equals Floor's upgrade delay. The status page labels ≥ 7 days a "Stage-1-grade exit window", matching L2BEAT's Stage 1 rule ("at least a 7 days exit window").
- **Guardian bar.** The fast-restore path lets a guardian quorum act without the delay, which is Security-Council power. Floor requires a threshold of at least 2 live guardians. The status page (`cloud/status`) checks the two parts of L2BEAT's bar visible on-chain: ≥ 8 members and a ≥ 75% threshold. The third part, ≥ 50% of members outside the team, must be published by the team.
