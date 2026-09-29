# 09 — Verification

Bulkhead's value is a set of guarantees. This file says how each one is checked, what has run, and what each check found. Everything here is reproducible from the repository (§3).

## 1. The method: every rule stated more than once

This is the method SP-Differ used on Bitcoin's BIP-352 wallets (where it found a real bug, now an official test vector), turned on our own code:

| Statement | Where | Written how |
|---|---|---|
| Rust core | `crates/bulkhead-core` | Fixed-width integers, checked arithmetic, `no_std`, zero dependencies |
| Python reference | `reference/bulkhead_ref.py` | Unbounded integers with explicit overflow limits, written separately |
| Property predicate | `crates/bulkhead-core/tests/properties.rs` | A third, direct formulation of each guarantee (e.g. `sound_after`) |
| JavaScript (status page numbers only) | `cloud/lib/limits.mjs` | A fourth statement of the four functions a public page needs |

The programs are checked against the core as a model (§7). Two implementations can share a mistake; this project has already met one such shared bug (§4, item 3), which only the third statement caught.

## 2. Layers and current results (27 Sep 2026)

| Layer | What it checks | Result |
|---|---|---|
| **Golden vectors** | 117 curated outputs (`reference/golden/`): every worked example in `03`, exact boundaries (including the backed-amount search where the valid set excludes 0), the abort binaries' bytes, loader-v3 layouts, restore and eject rules | 117/117 identical (Rust = Python) |
| **Regression fixtures** | `reference/regressions/`: 35 cases from real past mismatches, each with its current expected output (`reference/golden/regressions-expected.txt`) | 35/35 reproduced by the Rust core in `cargo test` |
| **Differential runner** | Random cases for 29 commands (limiter, capacity, EMA, value, price, ledger, classification, ELF, governance, eject, Floor parsers, snapshot identity, murmur3, restore), weighted to edge values | 6,943,561 lines identical in the final 6-seed run (seeds 101–106, 200k cases each, 27 Sep; ~1.15M lines per seed) |
| **Property tests** | 21 tests, seeded SplitMix64; `BULKHEAD_CASES` scales depth; coverage floors (proportional to depth) make vacuous passes fail | Pass at 1.5k, 3k, 20k and 100k cases each |
| **Exhaustive checks** | 5 tests: every input of a small domain for the arithmetic properties (§5.2) | ~25.7M inputs |
| **Floor core tests** | 10 tests: the sBPF v3 strict ELF rules restated, murmur3 published vectors, loader-v3 headers, snapshot identity | Pass |
| **Targeted unit tests** | 17 tests: 16 each written to kill a surviving mutant (§6), and `capacity_base` | Pass |
| **Adversarial tests** | 7 tests (`crates/bulkhead-core/tests/adversarial.rs`): the attacks of `15` run through the real core, before and after each fix | Pass |
| **Bounded proofs (Kani)** | 13 harnesses: logic at full width, 2 at small width (§5) | **13/13 verified**, 209 s |
| **Mutation testing** | `cargo-mutants` on the core: 647 mutants (§6) | Every non-equivalent mutant killed; 22 equivalents, each explained |
| **Program tests** | Floor (21) and Vault (27) on the real agave runtime: LiteSVM, mainnet feature set, the mainnet token program | 48/48 |
| **Program ↔ model differential** | Random operation sequences on-chain vs a host model built only from the core; invariants after every step (§7) | 12,000 steps across 24 seeds, identical |
| **End-to-end** | `solana-test-validator` + the programs + the Cloud guardian + an attacker (`cloud/e2e/run.sh`) | Attacker ordered 1.2M and got 100k: the burst is 2% of what is in the vault at each payout, so the second 100k no longer fit (200k before the 29 Sep fix); guardian froze 2–6 s after the triggering block (across runs); every queued payout cancelled; page numbers equal to `attest`; the run fails unless all of this holds |
| **Client tests** | 25 JavaScript tests: base58, legacy messages, PDA derivation against an on-chain address, 256 curve25519 vectors from `curve25519-dalek`, RFC 8032 test vector 1, the guardian's policy and its follower, a paced attacker against the policy, the 40,000-case JS-vs-Python differential | 25/25 |
| **`floor check` self-test** | The Python on-curve test against the same 256 dalek vectors | Agrees on all 256 |
| **Lint** | `cargo fmt --check`, `cargo clippy -D warnings` on every crate and program | Clean |

### Property tests (what each proves)

| Test | Guarantee |
|---|---|
| `g1_dual_bucket_bound_holds_with_freezes_cancels_and_resets` | G1 over every `(t0, T)`, with random freezes, cancellations and resets that are only legal with zero pending. Also: no instant payout while frozen; ETA ≥ now + D; ETA ≥ freeze end; ETA within horizon. |
| `tickets_are_fifo` | ETAs never go backwards without freezes, cancels or resets |
| `available_now_is_exact` | The attestation's "instant now" is instant; one more unit is not |
| `lane_closed_and_zero_amount` | Closed lane and zero amount error without touching state |
| `ema_moves_toward_balance_and_never_overshoots` | Reference stays between old reference and balance; reaches it after 24h |
| `value_rounding_and_monotonicity` | floor ≤ ceil ≤ floor + 1; monotone in amount and price; overflow → None |
| `conservative_price_brackets_spot_and_ema` | lo ≤ min(spot, EMA) ≤ max ≤ hi |
| `g2_own_deposit_always_comes_back_without_prices` | G2 with every price missing |
| `g3_backed_amount_is_sound_and_maximal` | G3 against an independent `sound_after`; `b+1` is unsound; `debit_backed` refuses unsound debits |
| `backed_amount_is_monotone_in_request` | `backed(a) == min(a, backed(max))` |
| `fail_closed_and_price_monotone` | Removing a price, halving a collateral price or doubling a liability price never increases the backed amount |
| `junk_collateral_backs_nothing` | The Drift pattern: 750M CVT backs 0 USDC; withdrawing your own CVT is fine |
| `from_positions_rejects_malformed` | Stored ledgers with duplicates, zeros or > 8 slots are refused |
| `tighten_never_raises_the_bound` | Any `Tighten` limits change lowers or keeps the G1 bound |
| `tighten_asset_never_adds_value` | Any `Tighten` asset change lowers or keeps collateral value and raises or keeps liability value |
| `simd0500_gate` | v3 header passes; v0, SBPF-machine v2 and non-Solana ELFs fail |
| `upgrade_delay_is_a_floor` | Floor's delay can't go below 72h; restore rules (snapshot: quorum only; proposed: quorum on the exact buffer, or delay with no veto and no expiry) |
| `governance_loosen_never_early_and_never_after_veto_or_expiry` | G4 |
| `governance_freeze_quorum_heartbeat_abdication` | G5 building blocks |
| `snapshot_matches_iff_upgrade_leaves_program_unchanged` | Snapshot identity against a direct model of loader-v3 `Upgrade`, on programs up to 300 bytes with truncations, flipped bytes, nonzero tails |
| `eject_matches_its_definition` | Ejection exactly when a live quorum (≥ 2) of the *other* guardians approves and ≥ threshold remain |

## 3. Commands

```bash
scripts/check.sh                       # fmt, clippy, core tests, golden + fixtures, 150k differential, model,
                                       # floor_check self-test, JavaScript tests
scripts/check-programs.sh              # build the programs, then every LiteSVM test (E2E=1: also cloud/e2e)
BULKHEAD_CASES=100000 cargo test --release -p bulkhead-core    # deeper properties
python3 reference/diff_runner.py --cases 200000 --seed 7
scripts/prove.sh                       # Kani, 13 harnesses (~3.5 min)
scripts/mutants.sh                     # mutation testing (~40 min)
scripts/build-programs.sh              # Floor, Vault, Harbor for sBPF v3; checks e_flags == 3
(cd programs/tests && cargo test --release)            # 48 program tests + the program-vs-model differential
(cd programs/tests && BULKHEAD_PROGRAM_SEEDS=24 BULKHEAD_PROGRAM_STEPS=500 cargo test --release --test differential)
cloud/e2e/run.sh                       # validator + guardian + attacker
node --test cloud/test/*.test.mjs      # client, policy, JS-vs-Python differential
python3 tools/floor_check.py --self-test
scripts/deploy-dryrun.sh               # the devnet deploy on a fresh validator: re-run and resume spend nothing, a takeover and an early seal are refused, deployed bytes verified, Floor's lifecycle and the market check pass
scripts/floor-demo.sh <program-id>     # Floor on a real mainnet program's bytes: register, stop, restore byte-identical
scripts/verify-deployed.sh <url> <id>=<name>   # deployed code == this checkout's deterministic build
scripts/floor-devnet.sh <url> <team.json> <dir>   # Floor's full lifecycle on a live cluster; forbidden actions simulated
node cloud/deploy/vault-check.mjs <url> <market>  # a live market, checked without sending anything
cloud/e2e/s1.sh <url> <market>                    # S1 with the guardian on any sealed market (the E2E run uses it)
```

## 4. What this process found (every item fixed or stated)

| # | Date | Found by | Finding | Resolution |
|---|---|---|---|---|
| 1 | 26 Sep | Differential, first 100k-case run (106 mismatches) | `capacity_from_ref` **truncated** `reference × bps / 10 000` to u64. For `bps > 10 000` the capacity silently wrapped to a small number. | Saturate in both implementations; the program also rejects `bps > 10 000`. 15 fixtures. |
| 2 | 27 Sep | Reading agave and solana-sbpf source | The SIMD-0500 check accepted `e_flags ≥ 3`. But `e_flags = 4` decodes to V4, which agave doesn't enable, so a v4 ELF would have been labelled deployable. | Exactly `== 3`, in both implementations; golden G-13b; Kani `elf_gate_is_total` now states the exact set. |
| 3 | 27 Sep | Property predicate (the *third* statement) | `can_eject` counted approval bits above the guardian count. **The Rust core and the Python reference shared the bug** (same spec wording), so the differential couldn't see it. | Mask by the guardian count in both; golden regression; the quorum's caller invariant documented. |
| 4 | 27 Sep | Differential, the first run after a performance change | An early exit ("if one unit is invalid, nothing is payable") assumed the valid set is an interval. It isn't where a collateral valuation overflows u128 (that collateral counts 0). | Never shipped. Replaced by two exact early exits, stated identically in both implementations (`03 §4.4`). 20 fixtures. |
| 5 | 27 Sep | Program ↔ model differential, seed 2832 step 483 | A fully *backed* withdrawal failed: earlier unbacked payouts had drained the pool. **Our G2 wording ("your deposit always comes back") overclaimed.** | G2 restated: Bulkhead never throttles, freezes or prices an own-deposit return; the tokens being there is the pool's liquidity (`03 §4.6`, T23, D24). |
| 6 | 27 Sep | Program tests | `release` set its return data *before* its token-transfer CPI; every CPI clears return data, so integrators saw none. | Set after the last CPI (`05 §4`). |
| 7 | 27 Sep | Program tests | An abort buffer larger than a program's data account would be staged but could never land. | `stage_abort` refuses it (`AbortDoesNotFit`); the 136-byte minimal binary exists for small programs. |
| 8 | 27 Sep | Mutation testing (baseline run failed) | Coverage floors were absolute numbers, so reduced-depth runs failed spuriously. | Proportional to depth; verified at 1.5k–100k cases. |
| 9 | 27 Sep | Mutation testing | Test gaps: `params_from_config` and `config_is_valid` were only exercised by the program tests (another workspace); truncated loader headers; an empty buffer against an all-zero region. | Exact unit and Floor tests; the targeted rerun kills all of them (§6). |
| 10 | 27 Sep | End-to-end on a validator | The status page simulated `attest` with a dummy fee payer: `AccountNotFound` on every real network. | The page computes the figures itself (`cloud/lib/limits.mjs`), checked against Python (40,000 cases) and equal to `attest` on the validator (D26). |
| 11 | 27 Sep | End-to-end on a validator | The guardian anchored its "already seen" point after a slow startup heartbeat and missed the first payout; reads at `finalized` commitment were stale. | Anchor first; reads at `confirmed`. The guardian now freezes as the burst completes. |
| 12 | 26 Sep | Kani (7 attempts ran 20 minutes without an answer) | SAT solvers can't finish multiplier/divider equivalence at useful widths. | Split: Kani for logic, exhaustive enumeration for arithmetic (§5). |
| 13 | 27 Sep | Mutation testing, the full run after the Floor helpers | Two more test gaps. `program_programdata` was never given another account kind of sufficient length. The backed-amount search's upper bound was untested where the valid set excludes 0; **a 3M-case random search had wrongly suggested that mutant was equivalent**. | A wrong-kind assertion; golden E7 (both implementations, `03 §4.4`). The targeted rerun kills both (§6). |
| 14 | 27 Sep | Review, while wiring CI | The regression outputs file sat inside `reference/regressions/`, so `scripts/check.sh` tried to replay it as a fixture and failed. | Moved to `reference/golden/regressions-expected.txt`; the fixture directory holds only fixtures. |
| 15 | 28 Sep | Review, before the devnet deploy | Market setup could not be re-run safely. After a dropped confirmation, a re-run would either fail for good on the already-registered protocol, or **propose the seal again, silently restarting its 72h clock**. Harbor lets anyone register it, so a stranger could also take the protocol first. | Setup resumes: keys saved before use, every step checked on chain, the seal proposed at most once, a foreign registration refused. `scripts/deploy-dryrun.sh` proves each (a lost-progress resume that spends nothing; a takeover refused). |
| 16 | 28 Sep | The live-market check, on devnet | The page-vs-`attest` cross-check took its clock from `getBlockTime` before simulating. While the reference catches up after a deposit (about 116 units per second here), the two sides saw different seconds and the check failed at random; it had passed once by luck. | Both sides now use the simulation's own Clock sysvar (`cloud/status/snapshot.mjs`, `cloud/deploy/vault-check.mjs`). |
| 17 | 28 Sep | Review, before the devnet deploy | The JavaScript client wrote keypair files readable by every local user, and a 5xx page from a public RPC crashed it instead of being retried. | Key files owner-only (0600), key folders 0700; 5xx retried with backoff like 429. |
| 18 | 28 Sep | Adversarial review (`15`, A1) | Capacities came from the reference, a 24-hour average that also *falls* slowly. After a large backed exit or a bank run, the unbacked lane stayed sized for money that had left: 7.8× the daily bound on what was left. **"2% of a vault" overclaimed.** | Fixed 29 Sep: capacities from `min(reference, live balance)` (`capacity_base`) in the program, the JavaScript port and the program-vs-model differential; `after_a_large_backed_withdrawal_the_burst_shrinks_at_once`. The devnet Vault was upgraded in place. |
| 19 | 29 Sep | Review of that fix (`15`, A1b) | `min` alone does not stop an attacker who parks their own capital in the vault, drains while it is there, then takes it back through the backed lane: 19.8% of the honest deposits in a 2-minute attack. | Stated. Absolute caps (the existing `short_cap`, `long_cap`) bring it back to the G1 bound (2.1%); calibration now sets them (`07 §4`), and the devnet demo market runs with them. `finding_a1b_parked_capital_needs_absolute_caps`. |
| 20 | 28 Sep | Adversarial review (`15`, A2) | The guardian bot watched only a 1-hour window: a paced attacker dripped the daily bucket out forever without a freeze. The first fix forgot the drip on restart and could skip events. | Fixed: a 24-hour rule, a 24-hour replay from block times at startup, paging to the cursor, retried freezes, integer thresholds. |
| 21 | 28 Sep | Adversarial review (`15`, A3) | An admin key alone could abdicate `SetAdmin` or `SetGuardians`, instantly and forever: a thief locks the protocol to the stolen key. Abdicating `SetLimits` also blocked later tightening. | Fixed 29 Sep: abdication needs a live guardian quorum, and an abdicated kind refuses only loosening. Two program tests. |
| 22 | 29 Sep | Review of the guardian fixes | Tickets were cancelled only when a new payout arrived, so a freeze sent late (after a restart, or a retry) left queued tickets to pay out when it expired. A single-vault freeze was read as protocol-wide, and the bot then stopped freezing. The S1 script attacked before the guardian had finished its replay. | Fixed: every successful freeze sweeps the recorded tickets once, each against its own vault; freeze events are read with their scope; S1 waits for "caught up". Two policy tests. |

A method that finds a real bug in its own authors' code within minutes, twice, is the best argument for keeping it in CI.

## 5. Bounded proofs (Kani) and exhaustive checks

Random tests sample inputs. The checks in this section cover **every** input in a stated domain:
- **Kani** (bounded model checking, `crates/bulkhead-core/src/proofs.rs`) for **logic**: branches, clamps, time arithmetic, bit masks, byte parsing.
- **Exhaustive enumeration** (`crates/bulkhead-core/tests/exhaustive.rs`) for **arithmetic**: properties about products and quotients of symbolic values, where SAT solvers stall (§5.3).

Domains:
- **FULL:** every value of the Rust types involved, except stated time bounds of ~35,000 years.
- **SMALL-WIDTH:** amounts, capacities and windows below 2^20 (branch logic is width-independent).
- **Enumerated:** the ranges stated on each test.

### 5.1 Kani harnesses (13) and results

Kani 0.68.0, CBMC 6.11.0, Kissat for arithmetic harnesses, Apple M3, 27 Sep 2026. `scripts/prove.sh`: **Complete - 13 successfully verified harnesses, 0 failures, 13 total** (209 s).

| Harness | Domain | Property | Time |
|---|---|---|---|
| `governance_g4_holds` | FULL | A loosening never executes before now + 72h; nothing executes after veto, execution, abdication or expiry | 0.1 s |
| `governance_g5_building_blocks` | FULL | Freeze never shortens and adds ≤ 24h; quorum never counts a dead guardian; liveness needs a recent heartbeat; abdication never clears a bit | 0.2 s |
| `eject_rules_hold` | FULL | Ejection only of a current guardian, never by its own vote, only by a live quorum of the others (bits above the count ignored), never below the threshold, never with a threshold under 2 | 0.1 s |
| `elf_gate_is_total` | FULL (every 64-byte header) | Exactly the BPF-machine ELFs with `e_flags == 3` pass the SIMD-0500 gate | 0.3 s |
| `snapshot_matches_iff_upgrade_is_identity` | FULL (every byte; buffer ≤ 6, region ≤ 8) | `snapshot_matches` is true exactly when upgrading from the buffer (copy + zero-fill, as loader-v3 does) leaves the region unchanged | 0.7 s |
| `restore_rules_are_exact` | FULL | Snapshot: exactly a live quorum. Proposed: quorum on the exact buffer, or no veto and `eta ≤ now < expires`. | 0.1 s |
| `loader_parsers_are_total` | FULL (every 48-byte prefix) | The loader-v3 parsers never panic and accept only their own account kind | 1.2 s |
| `classify_tighten_is_sound` | FULL | A `Tighten` limits change never raises bps, floors or caps, and never shortens windows or delays | 0.1 s |
| `capacity_clamp_is_monotone` | FULL | Capacity respects floor and cap; a tighter (raw, floor, cap) never yields more | 0.3 s |
| `reset_never_exceeds_an_empty_bucket` | FULL | Reset refuses with pending tickets; otherwise each TAT is unchanged or exactly "empty at now" | 0.1 s |
| `conservative_price_brackets` | FULL | `lo ≤ min(spot, EMA)`, `hi ≥ max(spot, EMA)`; `None` exactly for non-positive inputs | 1.1 s |
| `request_rules_hold_for_all_inputs` | SMALL-WIDTH | The inductive step of the G1 proof (`03 §2.5`): instant only when unfrozen and conforming; tickets respect min delay, freeze end, horizon and their conformance time; TAT never decreases; errors leave state unchanged | 10 s |
| `ema_is_bounded` | SMALL-WIDTH (every time) | Reference stays between old reference and balance; equals the balance after 24h | 189 s |

### 5.2 Exhaustive checks (5 tests, ~25.7M inputs, < 1 s)

| Test | Domain (every input) | Property |
|---|---|---|
| `cost_is_exact_ceiling` | capacity, window ∈ 1..=64; amount ∈ 0..=512 (2.1M) | `cost_ms` is exactly `⌈u·W/C⌉` |
| `raw_capacity_is_monotone_in_bps` | reference ∈ 0..=2048; bps ∈ 0..=10⁴ (20.5M) | Raw capacity ≤ reference and non-decreasing in bps; with the clamp proof, a tighter config never yields more |
| `value_rounding_is_exact` | amount, mantissa ∈ 0..=40; expo ∈ −12..=0; decimals ∈ 0..=12; 9 boundary weights (2.6M) | Floor and ceil are the exact rational floor and ceiling; no overflow |
| `g2_and_fail_closed_without_prices` | own deposit ∈ 1..=64; other position ∈ ±1..=4; request ∈ 0..=130 | G2 exactly; owing something with no prices → 0 backed |
| `g1_holds_for_every_three_request_sequence` | both buckets' capacity, window ∈ 1..=3; 0 ≤ t1 ≤ t2 ≤ t3 ≤ 6; amounts ∈ 1..=4 (435k sequences) | G1 over every interval, counting instant payouts and tickets at their payable time |

### 5.3 What Kani could not finish, and where it went

Each of these ran for the full 20-minute cap without an answer:

| Tried in Kani | Why it stalls | Now covered by |
|---|---|---|
| G2 at full width and below 2^16 (`backed_amount`) | A 64-step search × 32-byte `memcmp` blew up symbolic execution | `g2_and_fail_closed_without_prices` |
| Capacity monotone in bps | Proving `⌊r·b/10⁴⌋` monotone in `b` | `capacity_clamp_is_monotone` (Kani) + `raw_capacity_is_monotone_in_bps` |
| `cost_ms`, `value_v` rounding below 2^20 | Symbolic divisors and multiplier chains | `cost_is_exact_ceiling`, `value_rounding_is_exact` |
| G1 for two instant payouts below 2^20 | Two symbolic divisions compared to a product | `g1_holds_for_every_three_request_sequence` + the Kani inductive step |
| EMA at full width | u128 product divided by 86,400 | `ema_is_bounded` at SMALL-WIDTH |

## 6. Mutation testing

`scripts/mutants.sh` runs [cargo-mutants](https://mutants.rs) on `bulkhead-core`, with every workspace test counting (the golden and regression tests included). Each mutant is a small injected bug: a flipped comparison, a swapped operator, a function body replaced by a constant. Every mutant must be:
- **caught** by a test;
- **timed out** (the mutant loops forever, which cargo-mutants counts as detected); or
- listed below as **equivalent**, meaning it behaves identically on every reachable input, with the reason.

| Run | Date | Scope | Mutants | Caught | Timeout | Missed | Unviable |
|---|---|---|---|---|---|---|---|
| 1 | 26 Sep | The core; property and golden tests only | 412 | 350 | 5 | 48 | 9 |
| 2 | 26 Sep | + the first targeted unit tests | 412 | 369 | 5 | 29 | 9 |
| 3 | 26 Sep | + price, value, horizon and zero-credit tests | 414 | 384 | 3 | **18, all equivalent** | 9 |
| 4 | 27 Sep | The core after the Floor helpers, the governance rules and the limiter's config functions | 650 | 540 | 3 | 51 | 56 |
| 5 | 27 Sep | The four changed files, after new unit and Floor tests | 520 | 442 | 3 | 23 | 52 |
| 6 | 27 Sep | The whole core (38 min) | 650 | 565 | 3 | 26 | 56 |
| 7 | 27 Sep | `floor.rs` and `ledger.rs` after the fixes below | 318 | 256 | 3 | 10, all equivalent | 49 |

**Run 6's 26 survivors.** 18 are run 3's equivalents (some at new line numbers). The other 8:
- **`program_programdata` (`||` → `&&`): a real test gap.** The parser was never given another kind of loader account long enough to parse. Now asserted in `loader_v3_headers_parse_exactly`.
- **The backed-amount search bound (`amount - 1` → `amount / 1`): a real test gap.** An earlier random search of 3M cases found no input that told the two apart, and suggested the mutant was equivalent. It is not. Where the valid set excludes 0 (the overflow region of `03 §4.4`), the two bounds probe different midpoints: for the valid set `[4, 6]` and a request of 7, the search returns 0 and the mutant returns 6. Golden E7 now pins the exact search in both implementations. Lesson: random sampling rarely reaches a region that needs two coordinated extremes; construct the case from the code's structure.
- **`insn` (2 mutants).** Its source-register argument was 0 at every call. The argument is gone, and with it 3 mutants (the core now yields 647); the abort binaries' bytes are unchanged (golden vectors).
- **4 new equivalents**, listed below.

Every timeout since run 3 is in the backed-amount search: the mutated `hi - lo` or `mid - 1` makes the loop never end.

**Result:** every non-equivalent mutant is killed. Each real gap the tool found became a named test or golden vector:
- a lowered nonzero cap classifying as `Tighten`;
- malformed ELF headers;
- exact abdication bits;
- the net after a debit;
- cost saturation;
- the freeze boundary;
- exact conformance ETAs;
- price staleness and confidence boundaries;
- negative decimal shifts;
- the ±38 exponent limit;
- the inclusive horizon;
- crediting zero;
- the limit-config bounds and parameters;
- truncated loader headers and an empty snapshot;
- a loader account of the wrong kind;
- the search bound (golden E7).

**Equivalent mutants (22), each with the reason it can't change behavior:**

| Location | Mutant | Why it is equivalent |
|---|---|---|
| `classify.rs` `cap_tighter_or_equal` | `new > 0` → `new >= 0` in the `old == 0` branch | `new == old == 0` already returned `true` earlier |
| `ledger.rs` `contribution` | `net > 0` → `net >= 0` | `net == 0` returns earlier |
| `ledger.rs` `has_liability`, `backed_amount` (others' liabilities) (2) | `< 0` → `<= 0` | Stored positions are never 0 (enforced by `set` and `from_positions`; tested by `crediting_zero_never_occupies_a_slot`) |
| `ledger.rs` `backed_amount` slot check | `after < 0` → `<= 0` | `after == 0` with the mint absent means `b == 0`, which the search never evaluates |
| `ledger.rs` `backed_amount` overflow fallback (3) | `c > 0` → `==`, `<`, `>=` | Unreachable: each contribution is ≤ `u128::MAX/10⁴ + 1`, and 8 of them stay below `i128::MAX` (`health_sum_cannot_overflow_with_eight_positions`) |
| `limiter.rs` `capacity_from_ref`, `clamp_capacity` (3) | `>`/`<` → `>=`/`<=` at saturation, floor and cap | At equality both branches yield the same value |
| `limiter.rs` `cost_ms` | `c > COST_MAX` → `>=` | At equality both return `COST_MAX` |
| `limiter.rs` `reset_backlog` (2) | `>` → `>=` | Clamping an equal value is a no-op |
| `limiter.rs` `available_now` (2) | The saturation guard | Unreachable: the result is ≤ C ≤ `u64::MAX` |
| `value.rs` `value_v` (2) | The `v > i128::MAX` guard | Unreachable: `v ≤ u128::MAX/10⁴ + 1 < i128::MAX` |
| `floor.rs` `murmur3_32` tail (3) | `k ^= byte << s` → `k \|= byte << s` | `k` starts at 0 and each tail byte lands in its own 8 bits, so XOR and OR agree. The code keeps the published algorithm's form, and its vectors are tested. |
| `governance.rs` `can_eject` | `count > threshold` → `count >= threshold` | When `count == threshold`, the other guardians number `threshold − 1`, so the quorum check already fails. The explicit condition states the rule ("at least `threshold` remain") and keeps it true if `quorum` ever changes. |

The overflow guards stay in the code as defense in depth; the tests document why they never fire.

## 7. The program layer

| Check | What it does | Result |
|---|---|---|
| **Program ↔ model differential** (`programs/tests/tests/differential.rs`) | Random deposits, withdrawals, admin payouts (to users and outsiders), settlements, cancellations, freezes and time jumps (minutes to two days) on the real runtime. A host model built only from `bulkhead-core` (ledger, limiter, EMA) predicts every outcome. After every step it compares the release outcome, the vault balance (I12), the queue against the pending tickets (I14), and the balance around guardian actions (I11); at the end, every owner's ledger. | 12,000 steps (24 seeds × 500): 4,843 releases (3,701 backed, 281 instant, 1,140 queued, 1,092 refused), 618 settlements, 474 cancellations, 2,405 deposits, **all identical** |
| **Scenarios** | S1 (G-1 second-for-second, including the EMA reference), S4 (a 20-depositor bank run during a freeze, 100% instant, no prices), S7, S8 (ten payouts in one transaction), S9 (backed exactly as the core computes), S10 (Floor lifecycle) | Pass |
| **Negative tests** | Wrong caller, missing or foreign asset account, wrong feed, frozen settlement, early settlement, wrong recipient, tickets pending, not sealed, import exceeding balance, seal veto, permanent-delegate mint, delay below 72h, abdicated kind, freeze too long, no quorum, admin unfreeze, eject below threshold, and Floor's full set (`06 §6`) | Pass |
| **Floor on a real program** | `scripts/floor-demo.sh <program-id>`: a mainnet program's bytes on a local validator with mainnet's feature set; register, stop with one guardian, restore with two | SPL Stake Pool (1.08 MB, v0): stopped with Floor's code, restored byte-identical (`06 §7`) |
| **Our own SIMD-0500 check** | `scripts/build-programs.sh` reads each built `.so` with the reference's `elf_info` and fails unless `e_flags == 3` | Floor, Vault, Harbor: v3 |
| **Compute** | Measured through Harbor's CPI (`05 §10`) and for Floor (`06 §7`) | Within targets |
| **End-to-end** | A real validator booted with a sealed market; the guardian freezes on its own and cancels; the page's figures equal `attest` | Pass |
| **On devnet** | The demo market before its seal, checked without sending anything (`cloud/deploy/vault-check.mjs`); Floor's lifecycle with real transactions on a target program (`scripts/floor-devnet.sh`) | Market: as configured, page = `attest`, 11/11 forbidden actions refused (with the Vault upgraded in place on 29 Sep: an admin abdicating without a guardian quorum is refused). Floor: stopped, restored byte-identical, 17/17 refused (`08`) |
| **Reproducible builds** | A clean rebuild in a different directory reproduces all three binaries' sha256; `scripts/verify-deployed.sh` dumps deployed programs and requires the local build byte for byte (run inside `scripts/deploy-dryrun.sh`, and on devnet) | Deterministic; the three devnet programs are byte-identical to it (hashes in `SECURITY.md`) |
| **After the hackathon** | Certora (CVLR) rules for I8, I11, I12; Trident flows; registering the builds with `solana-verify` | Planned; cut from this submission (they add little a judge can check in the time) |

## 8. Road to mainnet (not claimed in the submission)

Two independent audits (a Solana specialist; a formal-methods review of the core); CVLR rules on both programs; verifiable builds; a public bug bounty; a staged TVL cap with the first design partner; then burn the upgrade authorities of Floor and Vault.
