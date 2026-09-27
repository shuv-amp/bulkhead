# 08 — Scenarios (the demo is real)

Every number shown in a video or on a page comes from a scenario that actually executed, with the test name (LiteSVM), the log (`cloud/e2e`) or the signature (devnet) next to it. Models are labelled "model".

Environments:
- **LiteSVM** (`programs/tests`): the real agave runtime and loader, the mainnet feature set and the mainnet token program; deterministic clock. Every scenario runs here.
- **Local validator** (`cloud/e2e/run.sh`): `solana-test-validator` with the programs, a sealed market, the Cloud guardian and an attacker.
- **Devnet**: public signatures. Pending the team's go-ahead. One command sets it up: `scripts/deploy.sh <url> <deployer.json>` deploys the programs, builds the market and proposes the seal, and `scripts/deploy-dryrun.sh` rehearses exactly that on a fresh local validator (it passes). The seal waits 72h, so deploy ≥ 3 days before recording. After the seal, the S1 attacker (`cloud/e2e/attack.mjs`) and the guardian (`cloud/guardian/main.mjs`) take the market it writes (`world.json`, `keys/`).

Status (27 Sep 2026):

| Scenario | Where it runs | Status |
|---|---|---|
| S1 compromised admin | `tests/vault.rs::s1_…`, `cloud/e2e/run.sh` | **Runs** |
| S1 with the full Drift asset mix (31 borrows) | model: `reference/drift_model.py` | Model; devnet run planned |
| S4 bank run | `tests/vault.rs::s4_…` | **Runs** |
| S7 slow loosening | `tests/vault.rs::s7_…`, `an_unvetoed_loosening…` | **Runs** |
| S8 one-transaction attack | `tests/vault.rs::s8_…` | **Runs** |
| S9 honest borrower | `tests/vault.rs::s9_…` | **Runs** |
| S10 Floor lifecycle | `tests/floor.rs::s10_full_lifecycle` (+ 20 more Floor tests); on a real mainnet program's bytes: `scripts/floor-demo.sh` (`06 §7`) | **Runs** |

## S1: a compromised admin (Drift class)

**Harbor** (`programs/harbor`) is a deliberately naive protocol whose custody is a Bulkhead vault. Its `AdminPayout` pays anyone anything: the power an attacker holding a protocol's admin key has.

**LiteSVM, golden G-1 on-chain** (`s1_compromised_admin_gets_exactly_the_burst_then_a_public_queue`):
- Setup: 10,000,000 USDC vault, default limits, sealed.
- The attacker orders 150k, 50k, 10k, 400k and 1M USDC, one per minute (the Drift cadence).
- Every outcome and every ticket ETA equals the core model's to the second, including the EMA reference moving with the draining balance.
- The attacker receives **exactly 200,000 USDC** (the 2% burst); three requests wait in public.
- A guardian freezes; a due ticket then can't settle (`Frozen`); guardians cancel all tickets; the attacker keeps the burst only.

**Validator, with the Cloud guardian** (`cloud/e2e/run.sh`, log in `target/e2e/`):

| Measure | Result |
|---|---|
| Ordered by the attacker (12 × 100,000 USDC, every 800 ms) | 1,200,000 USDC |
| Received | **200,000 USDC** |
| Guardian freeze | Automatic, 2–6 s after the block that completed the burst, across runs (2 s in the latest, 27 Sep). Policy: freeze once unbacked payouts to non-allowlisted owners reach ½ of `worst_1h` within an hour. |
| Queued payouts | 10 tickets, all cancelled by the guardian within 2–9 s of their blocks (across runs) |
| After | 0 pending, protocol frozen 24h, 9,800,000 USDC in the vault |
| Status page figures | Equal to the program's own `attest` |

**Model, the full Drift book** (`reference/drift_model.py`, the $550M TVL **assumption**): a 2-minute freeze bounds the loss at $11.4M instead of $285M (`01 §7`).

## S4: a bank run, legitimately

`s4_bank_run_every_depositor_gets_their_own_deposit_back_instantly`:
- 20 depositors, 9.8M USDC in total.
- A guardian **freezes the protocol**, then every depositor withdraws their whole deposit, one a minute, with **no price accounts at all**.
- Assertions: each withdrawal is 100% backed and instant, with no tickets; 100% of TVL leaves; the vault ends at 0.

Headline: **"Nobody noticed Bulkhead."**

## S7: a loosening attempt

`s7_tightening_is_instant_loosening_waits_72h_and_a_guardian_can_veto`:
- A tightening (`short_bps` 200 → 100) applies at once; `attest` shows the lower burst.
- A loosening (`short_bps` 200 → 1,000) becomes a public `Change`:
  - executing it early fails (`ChangeNotExecutable`);
  - a guardian vetoes it;
  - after 72h it still fails (`ChangeVetoed`), and the tighter limit stands.

`an_unvetoed_loosening_executes_after_the_delay` shows the other branch. `a_delay_below_72h_is_refused_and_an_abdicated_kind_is_gone_forever` covers the constant and abdication.

## S8: one transaction beats any stop button

`s8_one_transaction_drain_gets_only_the_burst`:
- **Legacy:** a pool whose token account the admin key controls. One transaction drains 100%.
- **Bulkhead:** the same attacker packs **ten 100,000 USDC payouts into one transaction**.
  - Exactly 200,000 (the burst) pays inside the transaction.
  - 8 tickets (800,000) wait in public.
- The stop button fires in the next slot: too late for legacy, in time here. Guardians freeze and cancel; **98% stays**.

Headline: **"A stop button can't reach inside a transaction. The limit is inside it."**

## S9: an honest borrower

`s9_honest_borrower_is_backed_exactly_as_the_core_computes`:
- A lender deposits 5M USDC; a borrower deposits 10 SOL (Pyth-format prices: SOL $150 ± 0.075, EMA $151, 2× confidence multiplier; haircut 85%).
- Borrowing 1,200 USDC is **100% backed and instant**, exactly `bulkhead_core::Ledger::backed_amount`.
- Asking for 5,000 USDC: the backed part equals the core's answer to the unit, and the rest goes to the limiter.

Headline: **"Normal borrowing never touches the limiter."**

Related: `a_backed_borrow_is_paid_during_a_freeze_and_only_the_unbacked_rest_waits` (a freeze stops only the unbacked lane), `omitting_a_price_never_increases_what_is_backed` (fail closed), `an_allowlisted_asset_cannot_be_made_to_look_unlisted_by_omission`, `junk_collateral_backs_nothing_but_its_owner_can_take_it_back` (the Drift CVT pattern: 750M CVT backs 0 USDC; the attacker may take the CVT back).

## S10: Floor

`s10_full_lifecycle`, on a program deployed through real loader-v3 instructions:
1. Registration moves the upgrade authority to Floor's PDA in one instruction.
2. An attacker holding the owner key proposes a drainer upgrade:
   - it can't execute before 72h;
   - a guardian vetoes it;
   - after the delay it still fails (`Vetoed`).
3. A guardian stops the program in one instruction. Every call now fails with `Custom(0x464C4F52)` and the log line "Program stopped by its Bulkhead Floor guardians…". The snapshot was verified against the live bytes at the moment of the stop.
4. Two guardians restore the snapshot in one instruction; the program runs again, and its bytes are **identical** to before.

The other Floor tests cover:
- fast fixes only with quorum approval of the exact buffer;
- the full delay otherwise;
- a stale snapshot after an upgrade;
- dead guardians and heartbeats;
- ejecting a rogue guardian;
- registration front-running and pre-funding;
- non-canonical, unfrozen and oversized abort buffers;
- the delay rules, expiry and release of the authority;
- measured compute on a 200 KB program (`06 §7`).

## What the video shows (`12 §4`)

1. `scripts/check.sh` and the `scripts/prove.sh` summary: the core verified four ways.
2. S8 and S1 from the terminal; the E2E run live, with the guardian freezing on its own.
3. S4 and S9: "nobody noticed Bulkhead".
4. S7 and S10: slow loosening; Floor's stop and byte-identical restore.
5. The status page: "Worst case right now: …".
