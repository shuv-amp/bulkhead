# 17. External review (22 Oct 2026)

**What this is.** A full-tree review of Bulkhead at `main` (`1045cd9`, PR #86) run the way an external audit firm runs one: a line-by-line read of every on-chain program (`crates/bulkhead-core`, `programs/vault`, `programs/floor`, `programs/harbor`) by one reviewer, and three independent reviewers on the off-chain guardian, the verification layer (proofs, tests, reference model, fuzzing, mutation evidence) and the build, deployment and supply chain. Every finding was reproduced against the code before it was recorded, every fix carries a test that fails on the previous build, and the findings are entries 132–141 of `09` §4. The three reviewers of the off-chain and verification scopes were AI agents given the code and the docs, not the hypotheses; the on-chain review and every fix were checked by hand.

Between the reviewed commit and this report's merge, `main` gained findings 105–131 of its own (refusal tests, the AUD-2 margin, the loader's extent rule, the guardian's cluster and alert checks); the entries here are numbered after them, and two of the review's findings had been fixed on `main` meanwhile (alert markup, finding 123; an independent restatement of the extent rule in the fuzz target, findings 109, 115 and 116) and are left out.

**What this is not.** It is not an independent audit by a named firm, and it does not change `SECURITY.md`'s status: unaudited, devnet only, not for real funds. It makes the audit faster.

## 1. Results

No finding allows a theft without a key. The on-chain custody and limiter logic, the account checks, the arithmetic and the Floor state machine held up: the three on-chain findings are a silent loss of a guarantee (132), a governance edge that needs the new admin and a quorum to reach (133) and an exit a freeze did not stop (134). The weight of the review fell on the guardian, where an honest protocol could be frozen for a day and held for a week by an RPC quirk (135, 136), and a restart could silently lose the incident hold (137).

| Severity | Found | Fixed | Stated / to decide |
|---|---|---|---|
| Critical / High | 0 | | |
| Medium | 5 (135–138, and 140's reference claim) | 4 | 1 (140: the reference stays a port) |
| Low | 13 (132–134, 139 a–g, 141's three script gaps) | 13 | |
| Informational | 9 (§3) | 2 | 7 |

| ID | Scope | Finding | Status |
|---|---|---|---|
| 132 | Vault | A deposit into a full ledger went through with no backing, taking G2 away in silence | Fixed: `NoSlot` |
| 133 | Vault | `execute_change` accepted the recovery key's changes whatever their kind | Fixed |
| 134 | Vault | A lifeboat exit executed while frozen | Fixed: `Frozen` |
| 135 | Cloud | Replayed outflows with no block time were dated "now": a false 24h freeze and 7-day hold | Fixed |
| 136 | Cloud | A mint with no `attest` was judged against a worst case of 0: the first honest payout froze the protocol | Fixed |
| 137 | Cloud | A restart on a lagging node closed the incident hold for good | Fixed |
| 138 | Cloud | One censoring primary RPC blinded a guardian; the cross-check saw lag, not omission | Fixed: monotone counters |
| 139 | Cloud | Seven lower findings: unbounded cancel sweep, throwing decoders, a throwing balance parser, no instance lock, hold log spam, config mode unchecked, zero-padded keys | Fixed |
| 140 | Verification | The Python reference is a port of the Rust where it matters; the overflow region of the search was compared against itself; the stated counts were stale | Partly fixed, rest stated |
| 141 | Build | Unpinned, silently failing toolchain install; no `--locked`; partial deploy gates; a demo script that deployed on an RPC error; hygiene | Fixed; the release workflow and the authority's custody to decide |

## 2. What was checked and held

**Core (`crates/bulkhead-core`).** The dual-bucket limiter against the G1 proof (requests reserve, cancels do not refund, resets clamp to "just emptied", the rescale keeps the used fraction; every arithmetic path for overflow at `u64::MAX` amounts, 2^61 saturated costs and windows to 2^32 s); the ledger's soundness and monotonicity, including the one non-interval region; the conservative price bracket; the EMA and low-water base against flash deposits and clock steps; guardian liveness, quorum and ejection bitmaps; the ELF checks and the abort binaries' layout; the classification table.

**Vault.** Every handler's account list against substitution, aliasing and ownership (the token program's own validation where a transfer of 0 skips the CPI); PDA derivation and bump storage; the caller PDA as the only path to `deposit` and `release`; the recipient's owner as the ledger key; the loan-consent signature and its caller-PDA exception; the freeze's effect on each path; the seal's cover check; abdication across genesis paths; the change versions; the recovery key's powers and limits; the lifeboat's three stages; Token-2022's extension policy against the current enum; closed-account revival (pinocchio `close` zeroes the owner, lamports and length); the Pyth receiver ids and discriminator, recomputed.

**Floor.** The loader facts (CPI set, one upgrade per slot, zero-fill); the frozen-buffer argument; the stop, pin, restore and release paths against a stolen owner key, a rogue guardian, a stranger's re-pin, and the spill; the proposal slot's rules for the recovery key; `elf_extent`'s bounds.

**Guardian.** Event attribution to the emitting program (the runtime's own `invoke` frames); the hand-rolled Ed25519, base58, compact-u16 and message compilation; key handling; the escalating freeze; the double-count defences across lagging nodes; approvals by content and base version; the state file's write path.

**Build.** Every action SHA-pinned, no secrets, no `pull_request_target`, untrusted values through `env:`; cargo-deny enforcing on three lockfiles with every crate from crates.io; `pinocchio` pinned exactly; a pure Harbor `build.rs`; a third-party verification path that rebuilds from source in a digest-pinned image.

## 3. Stated, and for the team to decide

1. **The backed lane's economics (E1–E3 in `16` §4)** are unchanged by this review and remain the gate for a lending integrator: loan consent by any signature in the instruction, liquidations queuing in a crash.
2. **Guardian liveness (AUD-2).** A 2-of-3 set can still reach 2-of-2 by ejection. The operational rule (`threshold + 2`) stands; the protocol change belongs with the audit.
3. **Dead guardians cannot veto or stop.** By design (the Lido pattern), but it means a stolen owner or admin key can wait for guardians to miss a heartbeat and then push a change through its 72 hours with nobody able to veto. Allowing a dead guardian's stop powers (veto, freeze, abort; never restore or unfreeze) would be strictly safer against theft at the cost of griefing by a stale key, which ejection already bounds.
4. **After a restore, no abort buffer is staged** until someone stages one (`stop.mjs` says so). A restore could take a fresh abort buffer in the same instruction.
5. **Pyth's age window** is capped at one hour; within it a client picks the most favourable genuine update. The EMA bracket and haircuts bound it; the recommended per-asset `max_age_s` should be far lower (Pyth's own guidance is tens of seconds).
6. **`close_buffer`** lets the owner close a buffer a stranger just froze for a pin or a re-staged abort, before it is pinned or staged; the stranger loses rent to the owner.
7. **The release workflow and provenance** (141): nothing binds a devnet binary to a reviewed commit but the weekly rebuild; a tag-triggered build in the digest-pinned image with provenance is the fix. **The upgrade authority** is a hot key with no multisig step before the burn.
8. **The reference model** (140): an independent formulation of the limiter and the ledger (a `Fraction`-based limiter, a scanning search on small cases) would make the differential a conformance check rather than a port-fidelity check.
9. **The security contact** in `SECURITY.md` names no address or key.

## 4. Verification of the fixes

Run after the changes, rebased onto `main` at `f75c99a` (PR #148), on 22 Oct:

- `scripts/check.sh`: passed. fmt, the claims checker (every stated count equals the tree), the mutant-exclusion checks, clippy, the 90 host tests (the two new exhaustive ones among them), the golden vectors, the 36 regression fixtures, the 3×50,000-case Python-vs-Rust differential (identical), the extreme-value runs (0 mismatches), the floor checker's self-test and the 265 Cloud tests (7 new).
- `scripts/prove.sh`: all 20 Kani harnesses verified, 0 failures (734 s of verification); the new `low_water_never_counts_fresh_capital` holds at full width (29 checks).
- `programs/tests`: the LiteSVM harness compiles and is clippy-clean. Run against the **14 Oct binaries** (the build before this tree's on-chain changes), 174 of the 182 tests pass; the 8 that fail are exactly the tests of on-chain rules that build lacks: this review's three (findings 132–134, each "expected failure, got success", the previous behaviour they catch) and `main`'s five for the guardian margin and the loader's extent rule (findings 107, 115 and 116).
- **Not run here:** the programs rebuilt for sBPF v3 from this tree, and the 182 tests against them. The review machine could not fetch platform-tools v1.57 (a 430 MB download at under 40 KB/s). `scripts/build-programs.sh` now installs it explicitly and fails loudly if it cannot; `scripts/check-programs.sh` is the one command left to run, and CI runs it on the pull request. The on-chain changes are 24 lines in three handlers, host-compiled and clippy-clean.
