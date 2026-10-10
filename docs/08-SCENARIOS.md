# 08 — Scenarios (the demo is real)

Every number shown in a video or on a page comes from a scenario that actually executed, with the test name (LiteSVM), the log (`cloud/e2e`) or the signature (devnet) next to it. Models are labelled "model".

Environments:
- **LiteSVM** (`programs/tests`): the real agave runtime and loader, the mainnet feature set and the mainnet token program; deterministic clock. Every scenario runs here.
- **Local validator** (`cloud/e2e/run.sh`): `solana-test-validator` with the programs, a sealed market, the Cloud guardian and an attacker.
- **Devnet**: public signatures ([below](#devnet-signatures)). Deployed 28 Sep 2026 by `scripts/deploy.sh`, rehearsed first by `scripts/deploy-dryrun.sh` on a fresh local validator. The demo market was sealed on 1 Oct, and S1 ran there that day (below) with `cloud/e2e/s1.sh`, the same script the local end-to-end run uses, on the market that `scripts/deploy.sh` wrote (`world.json`, `keys/`). Floor S10 needs no seal and has already run there.

Status (28 Sep 2026):

| Scenario | Where it runs | Status |
|---|---|---|
| S1 compromised admin | `tests/vault.rs::s1_…`, `cloud/e2e/run.sh`; devnet: `cloud/e2e/s1.sh` | **Runs**; **ran on devnet 1 Oct**: 100,000 of 1,200,000 left, 11 tickets cancelled by the guardian ([signatures](#devnet-signatures)) |
| S1 with the full Drift asset mix (31 borrows) | model: `reference/drift_model.py` | Model; devnet run planned |
| S4 bank run | `tests/vault.rs::s4_…` | **Runs** |
| S7 slow loosening | `tests/vault.rs::s7_…`, `an_unvetoed_loosening…` | **Runs** |
| S8 one-transaction attack | `tests/vault.rs::s8_…` | **Runs** |
| S9 honest borrower | `tests/vault.rs::s9_…` | **Runs** |
| S10 Floor lifecycle | `tests/floor.rs::s10_full_lifecycle` (+ 35 more Floor tests); on a real mainnet program's bytes: `scripts/floor-demo.sh` (`06 §7`); on devnet: `scripts/floor-devnet.sh` | **Runs**, also on devnet |
| S11 liquidation cascade | core only: `crates/bulkhead-core/tests/cascade.rs`; synthetic market | **Runs** (core); a program-level run and a replay of real Pyth history are not done |

## S1: a compromised admin (Drift class)

**Harbor** (`programs/harbor`) is a deliberately naive protocol whose custody is a Bulkhead vault. Its `AdminPayout` pays anyone anything: the power an attacker holding a protocol's admin key has.

**LiteSVM, golden G-1 on-chain** (`s1_compromised_admin_gets_exactly_the_burst_then_a_public_queue`):
- Setup: 10,000,000 USDC vault, default limits, sealed.
- The attacker orders 150k, 50k, 10k, 400k and 1M USDC, one per minute (the Drift cadence).
- Every outcome and every ticket ETA equals the core model's to the second, including the capacity following the draining balance (the least of the EMA reference, the live balance and the low-water balance, `03 §3`): the last ticket is due in 54h 37m, not the golden vector's 53h 12m at a fixed capacity.
- The attacker receives **exactly 200,000 USDC** (the 2% burst); three requests wait in public.
- A guardian freezes; a due ticket then can't settle (`Frozen`); guardians cancel all tickets; the attacker keeps the burst only.

**Validator, with the Cloud guardian** (`cloud/e2e/run.sh`, log in `target/e2e/`):

| Measure | Result |
|---|---|
| Ordered by the attacker (12 × 100,000 USDC, every 800 ms) | 1,200,000 USDC |
| Received | **100,000 USDC**: after the first payout the vault holds 9.9M, and the second 100,000 no longer fits the burst (2% of what is in the vault at each payout; 200,000 before the 29 Sep fix, `15` A1) |
| Guardian freeze | Automatic, 2–6 s after the block that reached the threshold, across runs (6 s in the latest, 29 Sep). Policy: freeze once unbacked payouts to non-allowlisted owners reach ½ of `worst_1h` within an hour. |
| Queued payouts | 11 tickets, all cancelled by the guardian within 2–10 s of their blocks (29 Sep) |
| After | 0 pending, protocol frozen 24h, 9,900,000 USDC in the vault |
| Status page figures | Equal to the program's own `attest` |

**Model, the full Drift book** (`reference/drift_model.py`, the $550M TVL **assumption**): a 2-minute freeze bounds the loss at $11.4M instead of $285M (`01 §7`).

## S4: a bank run, legitimately

`s4_bank_run_every_depositor_gets_their_own_deposit_back_instantly`:
- 20 depositors, 9.8M USDC in total.
- A guardian **freezes the protocol**, then every depositor withdraws their whole deposit, one a minute, with **no price accounts at all**.
- Assertions: each withdrawal is 100% backed and instant, with no tickets; 100% of TVL leaves; the vault ends at 0.

Headline: **"Nobody noticed Bulkhead."**

After the run, the unbacked burst is sized from what is left, not from the 24-hour average that still remembers the money that left: `after_a_large_backed_withdrawal_the_burst_shrinks_at_once` (a 9M backed exit from a 10M vault takes the burst from 200,000 to 20,000 at once; `15` A1).

## S7: a loosening attempt

`s7_tightening_is_instant_loosening_waits_72h_and_a_guardian_can_veto`:
- A tightening (`short_bps` 200 → 100) applies at once; `attest` shows the lower burst.
- A loosening (`short_bps` 200 → 1,000) becomes a public `Change`:
  - executing it early fails (`ChangeNotExecutable`);
  - a guardian vetoes it;
  - after 72h it still fails (`ChangeVetoed`), and the tighter limit stands.

`an_unvetoed_loosening_executes_after_the_delay` shows the other branch. `a_delay_below_72h_is_refused_and_an_abdicated_kind_is_gone_forever` covers the constant and abdication, which needs a live guardian quorum besides the admin; `an_abdicated_kind_can_still_be_tightened_but_never_loosened` shows what abdication gives up.

## S8: one transaction beats any stop button

`s8_one_transaction_drain_gets_only_the_burst`:
- **Legacy:** a pool whose token account the admin key controls. One transaction drains 100%.
- **Bulkhead:** the same attacker packs **ten payouts into one transaction**, sized to fill the burst exactly.
  - 199,000 pays inside the transaction: 100,000 of the 10M, then 99,000 of the 9.9M left (the burst is 2% of what is in the vault at each payout, `03 §3`).
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

**Devnet** (`scripts/floor-devnet.sh`, 28 Sep): the same lifecycle with real transactions on a target program, a copy of Harbor's binary under its own id. Register; stage the stop and pin a snapshot; an upgrade proposal that can't execute before 72h, vetoed by one guardian and withdrawn; one guardian stops the program (confirmed in 4.9 s, every call then fails with `FLOR`); two guardians restore it byte-identical, and it answers exactly as before; re-armed. Along the way 17 forbidden actions were simulated and each failed with its exact error. Signatures: [below](#devnet-signatures).

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

## S11: a liquidation cascade (the honest worst day)

The question a lending protocol asks first (`15` §4, item 3): in a crash, do Bulkhead's limits hold back honest liquidations while prices are still falling? A liquidation that waits 6 hours in a falling market is one a rational liquidator won't take, and the protocol keeps the bad debt.

`cascade.rs` runs the liquidator's backing (`Ledger::backed_amount` at `conservative` prices), the reference, the capacity base and the limiter through the real core. The market is **synthetic**, and every input is stated in the file:
- a 1,000,000 SOL collateral vault at $150;
- −20% in a fast leg (2 hours, 30 minutes or 10 minutes), then to −30% by hour 24;
- Pyth's EMA as a 1-hour average; confidence 0.25% of spot in the fast leg, 0.08% after; confidence multiplier 2;
- G-11 weights (USDC haircut 99%, SOL liability 105%) and a 5% liquidation bonus;
- a share S of the vault seized over the day, in proportion to the fall, in requests of at most 1,000 SOL.

**What it showed.**

| | Fast leg 2 h | 30 min | 10 min |
|---|---|---|---|
| Unbacked share of each liquidation | 14.4% | 16.2% | 17.1% |
| Defaults (2%/h, 5%/day) first delay a liquidation at S = | 43% | 22% | 17% |
| At S = 30%: liquidations queued (SOL) | 0 | 12,801 | 20,427 |
| At S = 30%: what the delayed liquidators lose to the price falling while they wait | $0 | $88,568 | $157,412 |

- **More than the bonus is unbacked:** about three times the 5% bonus. The repayment backs collateral at the conservative *high* price times the 105% liability weight, and while the price falls Pyth's EMA sits above spot.
- **Every delayed payout waits the 6-hour minimum.** None is rejected.
- **The A1b absolute caps change nothing here.** During a cascade the capacity base only falls, so the caps never bind.
- **What would absorb it:** 4%/h and 10%/day absorb a 30% cascade even in the 10-minute crash, with nothing queued. That also doubles what a thief can take (G1 scales with the limits). A lending market chooses between the two and publishes the choice (`07 §4`, step 5).

Not done: the same run on the programs (LiteSVM), and a replay of a real crash day from Pyth history instead of a synthetic path.

## Devnet signatures

Deployed 28 Sep 2026; the Vault upgraded in place on 29 Sep; all three upgraded in place on 6 Oct (#8, #12, #16); Floor and Vault twice on 8 Oct, to the PR #35 build (findings 63–73); the Vault again on 9 Oct, to PR #49 (findings 74–75), then Floor and Vault to PR #52 (findings 78–80) to PR #57 (finding 85), the Vault to PR #59 (finding 86), Floor and Vault to PR #61 (findings 87–89), the Vault to PR #63 (finding 90), and Floor and Vault on 10 Oct to PR #75 (findings 91–93). Every transaction below is finalized and succeeded. Program ids, hashes and the upgrade authority are in `SECURITY.md`.

**Programs**

| What | Transaction |
|---|---|
| Floor deployed ([`HARLZqMw…`](https://explorer.solana.com/address/HARLZqMwqocBnbhbSTWkd5i8EHmjHXLHr1T9su3SR31E?cluster=devnet)) | [`2C7ZdVsN…`](https://explorer.solana.com/tx/2C7ZdVsNAnbPGhvkbdz4AzJ1JCaEPYv3du8P8Tq6GcnYMy5S5iqmEBZ8YEfG7t5WjKMg7ZhM1yCRHLh66GB71h7e?cluster=devnet) |
| Vault deployed ([`HK5FbaLt…`](https://explorer.solana.com/address/HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b?cluster=devnet)) | [`GvwetgZP…`](https://explorer.solana.com/tx/GvwetgZPFJiXbPTLB63CaRAc96T5cxKt8QwMUwdcmXPi6VCAKjJNZHvwDUwvEh8Dfr3FnkdW6a6L4U9KzHjgoez?cluster=devnet) |
| Harbor deployed ([`6w9t76W2…`](https://explorer.solana.com/address/6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh?cluster=devnet)) | [`3mB9Uy9i…`](https://explorer.solana.com/tx/3mB9Uy9iwEdfCmDKFXNkLU1U9dvnYKwM7mRUE2mSLesaQeuWakYxzjjAgwYUen4tJjZYxAUcq44v5Y4fwEXNhGwY?cluster=devnet) |
| Vault upgraded in place, 29 Sep: capacities from `min(reference, live balance)`, abdication needs a guardian quorum (`15`, A1 and A3). Same id, market and seal time; `79b0a47f…a62d9c93`, verified byte-identical | [`5vRRUkGd…`](https://explorer.solana.com/tx/5vRRUkGdJJoX5jBxiERWBDSJDy5L7tugqKZJcauTqZNSLAPWEiLqNWbMx5NRzwC7fk3EUhkvvXuc9Gaywzc7Gmgj?cluster=devnet) |
| Vault upgraded in place, 6 Oct (A7–A13, findings 30–39): `e1961181…`, verified byte-identical; the existing market reads unchanged | [`57uVm7WA…`](https://explorer.solana.com/tx/57uVm7WA3p7wHkHSDKaLgYDMdLLKemVRcLR55weXtc2F2T1t5QE5LdXySNov2mLNj13iVMGwfhHzNfkLQWkmLcu4?cluster=devnet) |
| Vault upgraded in place again, 6 Oct (the token readers made pure for fuzzing, `09` §2): `b8a2fbf8…`, verified byte-identical; the market and both pending changes read unchanged | [`tjCrUmzz…`](https://explorer.solana.com/tx/tjCrUmzzPrbnezNtosgRxNL5mSH7BNeUeKngqNy562dkC9pmstWHZpXg442hN78W6fhNrojTdUFNit3eJLmyPyX?cluster=devnet) |
| Vault upgraded in place a third time, 6 Oct: the same source as `b8a2fbf8…`, now the canonical Linux x86_64 build `c73b058d…` (CI's binary, after its LiteSVM and end-to-end runs; `09`, finding 43), verified byte-identical | [`27WnYt2b…`](https://explorer.solana.com/tx/27WnYt2bkuur5QSE3nwyrmijHNdMnaV9w41PwfijDS5e6B3ucKJG8i9ctnduYd8hyHkCZycsA16zae8GuuSbRHQH?cluster=devnet) |
| Floor upgraded in place, 6 Oct: `844f4678…`, verified byte-identical |
| Floor upgraded in place again, 7 Oct: a stop must name the pinned snapshot (`09`, finding 53). CI's build `3639b131…`, after its LiteSVM tests, the account sweep and a 200,000-step differential; verified byte-identical | [`CBidpJQa…`](https://explorer.solana.com/tx/CBidpJQaxuBmdSY5xYVgnDUjg6xyGD6bbuaHRfEe3FtHcvGwGoekEJBeXG5fdrMN1u8psMrHzHAzFWGnqEYhmmJ?cluster=devnet) | [`rYB7M4Er…`](https://explorer.solana.com/tx/rYB7M4ErEBTA2yKFGi3Dr4XKt72ChZhSUxpriGjZAoAwnAFv1ss5FBKf2HphqoeyQPwEozXxDsxxHNa5ovaG3HM?cluster=devnet) |
| Vault upgraded in place, 7 Oct: delisted collateral stays locked while its loan is open (`09`, finding 56, critical) and a guardian never becomes the admin (57). CI's build `aba7e697…`, after its LiteSVM tests, the account sweep, the end-to-end run and the deploy rehearsal; verified byte-identical; the market reads unchanged | [`2RduYXgh…`](https://explorer.solana.com/tx/2RduYXghwDFKHhLYvJEABoJNCxPLpxj1XkFZ4RTwt3shUQnXvVDL4wFo4s1g89YZa3x19iqqvYDinYnHbd5TJMx1?cluster=devnet) |
| Floor upgraded in place, 7 Oct: approvals name their proposal, the abort buffer and snapshot are never an upgrade, buffer rent returns to the owner (58), the owner is never a guardian (57). CI's build `d04e4b55…`; verified byte-identical | [`338Xk79P…`](https://explorer.solana.com/tx/338Xk79PpprQ3KgnNvNbhiaEnNibvrkvzMiZFNFfA3E9WP3rqigBdgpTA8qZgMB2Ukrr3ssWWW3DvCuCDmky9RcV?cluster=devnet) |
| Floor and Vault upgraded in place, 7 Oct, to the first version of finding 62 (`09`): `ef013d01…` and `3173b14a…`, CI's builds | [`2xzPLuoW…`](https://explorer.solana.com/tx/2xzPLuoWVRkLbqo7iQvWRCHGWR7hGLjBDV8ZuDo4bhfMzLgHAhKWjBJjGet512LPFvBCKg1tAxMdLm82N1DVtvkc?cluster=devnet), [`5LZCj796…`](https://explorer.solana.com/tx/5LZCj796zmw5mU7N1ANFjXmAkqYb57fTWBwhbTEMc53FJWQBw8217EQtveEmJTB4uswLFsW7CDESKhrYNg3ooouq?cluster=devnet) |
| Floor upgraded in place, 8 Oct: a stolen recovery key is replaced by the owner with a live quorum, a dead recovery proposal frees the slot, a delay raise passes a recovery proposal, no key is both guardian and recovery key (`09`, finding 62). CI's build `913b2eca…`, after its LiteSVM tests, the account sweep, the guardian scenarios and a 200,000-step differential; verified byte-identical | [`2Ttdu64x…`](https://explorer.solana.com/tx/2Ttdu64xhen8k7GH97CMWcULmmw2YNP8n5EnRU39WXhA7yZ8qjhcsE2Rp6sgFS7d9pG6xq7aJk8ppRR787PKEP1F?cluster=devnet) |
| Vault upgraded in place, 8 Oct: `replace_recovery` (the admin with a live quorum; never during the seal review or once abdicated), no key both guardian and recovery key (`09`, finding 62). CI's build `067434af…`, after its LiteSVM tests, the account sweep, the end-to-end run and the deploy rehearsal; verified byte-identical; the market reads unchanged (`vault-check`: the same admin, guardians, limits and caps, and `attest` equal to the status page's figures) | [`3wvN6uVn…`](https://explorer.solana.com/tx/3wvN6uVnrfYrwgHGxNzim12tgNYLBRUGGVqGVoASAvsK6x3DwSdmsbU1oaJFUmJQCnLv71cdpU4LReRv6Dq2tRcw?cluster=devnet) |
| Vault program data extended by 10,240 bytes, 8 Oct (the PR #35 build is 504 bytes larger than the space left; Agave extends by at least 10,240) | [`EVkeXusj…`](https://explorer.solana.com/tx/EVkeXusj7zaVhAEiNzAhxPUyGvUnnz2JcsdrEDtnNrZvAGbyVQFSVPceAtwegEoiYVWfz796qyy9Luf3SZaPba8?cluster=devnet) |
| Floor upgraded in place, 8 Oct, to PR #35: a stop accepts any snapshot identical to the live code (`09`, finding 66), the recovery-key rules of findings 63 and 70. CI's build `ff8bda42…`, after its tests, Kani (15/15), the account sweep and the guardian scenarios; verified byte-identical with the upgrade authority checked | [`t9eSgHg4…`](https://explorer.solana.com/tx/t9eSgHg4yJAFYPkf989JcyTupjMA49a44c9s3tK8iqc7vQ9XaUmJkiVQnfv8jtoEGL4fxvtZJk5GN5ePwyuvSea?cluster=devnet) |
| Vault upgraded in place, 8 Oct, to PR #35: the low-water base (65), events name their protocol (64), ticket ids (67), rescaling mints never priced (68), lifeboat, seal and admin edges (72), and 63 and 70. CI's build `b53ce331…`; verified byte-identical with the authority checked; `vault-check` on the market: the same admin, guardians, limits and caps, `attest` equal to the status page's figures, every forbidden action refused. Its three failures are guardians 1 and 2 still stale until the renewal below executes (9 Oct) | [`4jEHW7qY…`](https://explorer.solana.com/tx/4jEHW7qYfGryKXs2jmsyxubGAYv25nTSGpvGNK9cDyHmWu48XVRTx2WT3gnNURe1QRjq9CvXyKZFFSMgy3b3FzNk?cluster=devnet) |
| Vault upgraded in place, 9 Oct, to PR #49: a backed loan needs the borrower's signature (`09`, finding 74), settle reports a short vault, the reference clock never steps back (75). CI's build `cb1971ef…` (it fits the space extended on 8 Oct); verified byte-identical with the authority checked; the status page equals `attest`; `vault-check`: configuration and every forbidden action as before, guardians 1 and 2 still stale until the renewal executes | [`vfZ9qZVn…`](https://explorer.solana.com/tx/vfZ9qZVnf3pSY495n21TCaPMDm16Qco8y7SqvmbBKMgmT6BkP8FLRVsrzN6ZJnNbm9qK5gAbpDo5sVJ5DVJsf2L?cluster=devnet) |
| Floor upgraded in place, 9 Oct, to PR #52: `close_buffer` (`09`, finding 78) and a release that the new authority signs (80). Its program data was first extended by 10,240 bytes (the new build is 67,504 bytes; the space held 66,824). CI's build `e06a86e7…`; verified byte-identical with the authority checked. Simulated against the S10 target: closing its pin or abort buffer is refused (`BufferInUse`), and so is closing its programdata (`WrongBuffer`). S10 holds no orphaned buffer | [`2P4J6gym…`](https://explorer.solana.com/tx/2P4J6gymLSsp3wSUbLJQK57XU1Cr3oQ49HSQmrVSUoje6ysATFhn9tRHNdnWhCvPpeY6wLtRv58Es16Fa1JpwRcv?cluster=devnet) |
| Vault upgraded in place, 9 Oct, to PR #52: a lifeboat exit never pays an account this program owns (`09`, finding 79). CI's build `ecf2c226…`, from the same commit; verified byte-identical with the authority checked; the status page equals `attest`; `vault-check` as before | [`23yF8sHz…`](https://explorer.solana.com/tx/23yF8sHz6M81o6NHMDPA4N7md1FPHBTt6T4vnUq8sqhVRjzRxHbfa33H5FTe4kSc8XQoEg5tjVBdnLELckrX1Lev?cluster=devnet) |
| Floor upgraded in place, 9 Oct, to PR #57: while the program runs, `close_buffer` refuses a buffer identical to the live code, a snapshot a stop may name (`09`, finding 85). CI's build `58159d04…` (it fits the space extended earlier that day); verified byte-identical with the authority checked; simulated against S10, closing its pin, its abort buffer or its programdata is refused | [`2gRhJT69…`](https://explorer.solana.com/tx/2gRhJT69DA5MnZ4xHDhgZBe2tARQ9apUHbXx1JyQPBNDeEcGVBq2DT8kmF1jV99TFmn9guebAdnypHmMakUY6CCn?cluster=devnet) |
| Vault upgraded in place, 9 Oct, to PR #57: the lifeboat exit's destination signs (`09`, finding 85). CI's build `8cf8d163…`; verified byte-identical with the authority checked; `vault-check` passes in full and `attest` equals the status page | [`2gEXkoUz…`](https://explorer.solana.com/tx/2gEXkoUz6sAVMsYRxSuGoKJmKVHCHKfpijBpqUAGMCChcNiU27yaqkmJC2KWUXY2vAiA7v4YGNHPtZhEbYt8dHmg?cluster=devnet) |
| Vault upgraded in place, 9 Oct, to PR #59: the lifeboat opens with the seal (`09`, finding 86; the market was sealed on 1 Oct, so nothing changes for it). CI's build `9ec83cc9…`; verified byte-identical with the authority checked; `vault-check` passes in full | [`2L4SiL9H…`](https://explorer.solana.com/tx/2L4SiL9HXungkE8BMXwYpncVdTqaR3mCKqSV49od79WpCJix1Qrgv6vLoxXVZbku9crJd8kNqz5QQuyuBmzBKva9?cluster=devnet) |
| Floor upgraded in place, 9 Oct, to PR #61 (`09`, finding 88: snapshot length, a replaceable abort binary, the spill). CI's build `505688c7…`; verified byte-identical with the authority checked. S10's existing pin still passes the new rule (a re-pin simulated: accepted, 1,865 CU), and closing its pin, its abort buffer or its programdata is refused | [`mszSfWew…`](https://explorer.solana.com/tx/mszSfWew6LKCJShTkScBhLwH1aw4mV8Fej46Ktq1iAKQB5axRFyv2Jem71oZEXyB5NbrbpbsNVKfpE3PoX6pLeB?cluster=devnet) |
| Vault upgraded in place, 9 Oct, to PR #61 (`09`, findings 87–89). CI's build `e1493007…`; verified byte-identical with the authority checked; `vault-check` passes in full; the market sealed on 1 Oct reads `sealed_at` as 0, so its lifeboat rules are unchanged | [`43cXsDNS…`](https://explorer.solana.com/tx/43cXsDNSNKRDeeHv2F83u5CpxHUKNzsq1m52kdGvVVuW4TuGpfzshXWmXUJAqyB55U3AbfaGbNznnxqM5hn8r1pp?cluster=devnet) |
| Vault upgraded in place, 9 Oct, to PR #63 (`09`, finding 90: a freeze stops new loans; own deposits still leave). CI's build `69f2d6a1…`; verified byte-identical with the authority checked; `vault-check` passes in full; Floor and Harbor were already identical to that build | [`3oKjiLw6…`](https://explorer.solana.com/tx/3oKjiLw6QR36HfRYLWHviEmuNLYhQhG9Pat75Y1FXNdngwNUKHh6beGNswRZ1U91ocBD6qsgoR74eoBXk5hqHFA7?cluster=devnet) |
| Floor upgraded in place, 10 Oct, to PR #75 (`09`, finding 93: a release closes any further frozen buffer it is passed). CI's build `cb0992a7…`; verified byte-identical with the authority checked; programdata large enough, no extension. S10's config reads unchanged: `floor-buffers.mjs` finds its abort buffer and pin, and no orphans | [`518c4LW3…`](https://explorer.solana.com/tx/518c4LW3kkmtf1qKpSd5Uqmx6jRBaBm7DSnQyydrtr2Kyb32f7EbtDdZzoSDE3AoUo1EjFPRf4RjnzgvK3pNKPNt?cluster=devnet) |
| Vault upgraded in place, 10 Oct, to PR #75 (`09`, findings 91 and 92: a lifeboat exit executes only while its proposer is still the admin; abdications bind `upsert_asset` and `create_vault` before the seal). CI's build `b0cda14c…`; verified byte-identical with the authority checked; `vault-check` passes in full. No exit was pending (the lifeboat is empty), so nothing had to be proposed again; Harbor was already identical to that build, and no buffers are left | [`5LfX3zy7…`](https://explorer.solana.com/tx/5LfX3zy7VV1qExVxAYnJWG5oFp2MPh9uo1KiK1rmY9V4KRu2wDTnJAtH3CwhEmpJygrVnh6NxXbUHQj9qXfoeh7g?cluster=devnet) |
| Harbor upgraded in place, 6 Oct (built-in Vault id, A11): `543be60b…`, verified byte-identical | [`ZkpJvwHA…`](https://explorer.solana.com/tx/ZkpJvwHARZ7EpjSdNnYvP8EaEgcyeF8HMKMXC3gSSWpCMH1fGpz89swWac4so9FBfnJi7KUa1jqSkxHNxSSJFqL?cluster=devnet) |
| Guardians 1 and 2 had gone stale (last heartbeat 27 Sep). The admin proposed the same guardian set again (change 0, executable from 9 Oct 06:17 UTC; anyone executes it with `market.mjs execute-change`) | [`5vkjPJKP…`](https://explorer.solana.com/tx/5vkjPJKP5UUM2F5ektPRfQtANLtXTFcEujdMdfo9Z4cfYhjuy44ws5ga7a3W55qQXcM42xZiMx32A167Bddz3iT7?cluster=devnet) |
| The admin proposed a recovery key for the market (change 1, executable from 9 Oct 06:17 UTC; `09 §4`, finding 38). Until both execute, run S1 on devnet with `APPROVED_CHANGES` set to the two approvals `node cloud/deploy/approvals.mjs` prints for them (comma-separated), or its guardian vetoes them. `node cloud/deploy/finish-renewals.mjs <rpc> <market-dir> <payer> <floor> <target>` executes all three once due (safe to run any time; it skips what is done and reports what is not yet due) | [`3TGZtTtk…`](https://explorer.solana.com/tx/3TGZtTtkMKyQVzf2heEEnXFs1exrvshWqnkqRz3ne6q1gu9Xq7gN4pkSjp3HqnTpqRLKLafWWG2frzbSM1xNh8Ee?cluster=devnet) |
| Floor S10 target: all three guardians stale; the owner proposed the same set again (executable from 9 Oct 06:17 UTC) | [`GMAF37tw…`](https://explorer.solana.com/tx/GMAF37twXPr9o3DqKm7aw3nX4GvcBvN6zm7NxpU8bHE6CSZJX1s71bTUAQccXWKSuZvMuZHK3hDzYajKNNbS4UM?cluster=devnet) |
| All three executed on 9 Oct at 06:18 UTC with `finish-renewals.mjs` (a minute after they became due, on the first attempt): the market's guardian set (change 0) and recovery key `89JbvL3s…` (change 1), and the S10 target's guardian set. `vault-check` then passed in full: 3/3 guardians live, guardian 1 can freeze again, and the admin with a quorum can abdicate. All three S10 guardians are live. They stay live only while their keys heartbeat at least every 7 days | [`4gKM3seg…`](https://explorer.solana.com/tx/4gKM3segjeNzMwtxKcz6KfwwjgyNqx4m3A8P9CsQ3C3fVahWYcgf14zYrWYmGXnMAHBRsbywGcaEA4jrsi7TBMTk?cluster=devnet), [`3fDsaffg…`](https://explorer.solana.com/tx/3fDsaffg84hHLpyUysewg2sqt5cEtbiNr82Rf1TT1tRmSriWKUewCCJQoXWN8HB5p2JKMaJhXJbshSWQpTgU56CZ?cluster=devnet), [`3aeVKqXF…`](https://explorer.solana.com/tx/3aeVKqXF8UBT3Ys1vNdLFiMstR1Y2ZrxdPbz29dnyPJ14mnWy1PVLdqKtX9jX6W1u8GnqQh6tfjBLCVLPXSSBRVA?cluster=devnet) |

**The demo market**: protocol [`26dY2HWr…`](https://explorer.solana.com/address/26dY2HWrczKyPYh8jB4cBgzFsf5gkYo789BfCBQXRvSq?cluster=devnet), vault [`7qrrXwX5…`](https://explorer.solana.com/address/7qrrXwX5uYeCDTfdQbbRNJC7tdLYRFCLfq6sswKuZqZw?cluster=devnet), test USDC mint [`CBK36QrH…`](https://explorer.solana.com/address/CBK36QrH6fzjrDYwkKHF6jeEAEfHcm8iSVN9BZrCxHSB?cluster=devnet); 3 guardians, quorum 2; 2% per hour, 5% per day.

| What | Transaction |
|---|---|
| Harbor registered with Bulkhead | [`2jJdQGiL…`](https://explorer.solana.com/tx/2jJdQGiLbWgB9KVA22bpHLj9K9QaeWi5KvhbYQ9CkumNKcXdd68QtZjCeKusXJzVopYHpaGf7bxCxwgSDkH8M2Gu?cluster=devnet) |
| Vault created with the default limits | [`4aKAYC96…`](https://explorer.solana.com/tx/4aKAYC96oBp8kyomNytkniARUGVxV5vswztFXor13rti3aR1Cbeu3gMptcgq6stccLLAPakkpbz31TJjNSdJh1eW?cluster=devnet) |
| 10,000,000 test USDC deposited through Harbor | [`eJWkSy6f…`](https://explorer.solana.com/tx/eJWkSy6finkhisTUAjxGrNHYCgfMNv1NgkvvysCSGfF7zWGi76KoPuU6GnK1zKwmzfreFSbXMmXsX2if1dbicPP?cluster=devnet) |
| Seal proposed: executable from 30 Sep, 20:32:27 UTC until 7 Oct, 20:32:27 UTC | [`3ZJH4YW4…`](https://explorer.solana.com/tx/3ZJH4YW47LZFbkb51yrDiMmSYaNyzJokYJ8ifRhqUWxcN5A2gbAzibk4BRk7u46kZPurDuJyffMv9oZaFnVoGbQJ?cluster=devnet) |
| Absolute caps set, 29 Sep: 200,000 per 1h and 500,000 per 24h, 2% and 5% of the 10M (the calibration rule, `07 §4`; `15` A1b). A tightening, applied at once; the worst case is unchanged at 10M | [`63WTyNAF…`](https://explorer.solana.com/tx/63WTyNAFuwodQwKHjmz5feTCGB43z2ErJ9ekDf3sYGeXfhAgA3khdeKiGfqMJqHXJYEtVUBsdUXysuKtsodLAAYa?cluster=devnet) |
| Guardian 0's heartbeat: the Cloud guardian's first live run | [`2bsgiHmt…`](https://explorer.solana.com/tx/2bsgiHmtjSYkXBgCzwKFmMrkVoGJkgvY5N5Y9vrzXcXg7dGRUT2JKWvWycCP1AxdR38hqgDPLBU7u7sCZCqrbwwR?cluster=devnet) |
| Seal executed, 1 Oct 15:28:19 UTC (open to anyone once the 72h passed) | [`52ayyXpC…`](https://explorer.solana.com/tx/52ayyXpCuDXibu9aK2zEmxaFQXqFX8FHA6CrpzaWmubEbFRiyCXsLp1nNz2GuUGyNoVoge8Amg1G9sBD3trGv2rk?cluster=devnet) |
| S1 with the admin key, through Harbor: the first of 12 payouts of 100,000 USDC, 15:28:32; instant, the 2% burst | [`2zBFf6Ho…`](https://explorer.solana.com/tx/2zBFf6Ho6oQLULthoJfHtpqYWGfz3NmJbbxFo3JqbceQFQNeq4d6nnHsfTRYHoPtA7RTmRQAqTTZne4zbg64fUKb?cluster=devnet) |
| The other 11, 15:28:34 to 15:29:17: each queued as a ticket (nothing moved; a ticket waits at least 6h) | [`1b5zSvhd…`](https://explorer.solana.com/tx/1b5zSvhdgfDrdmoSZGJ1QMtLREDw2LEmwqcSdybYLiJPepzbAFWJ7t8ZLkfL7mXu1YN9TNAUsrGsmwY7nYMihEs?cluster=devnet) … [`2BFBRDBb…`](https://explorer.solana.com/tx/2BFBRDBbUu9X8HK87QJ6F2wETzNr9SjZFMAZcaYDDfzrK3cadCfogFWBE8i2crvPFACHRzYDRs8nA6jRRiLGvBKw?cluster=devnet) |
| The Cloud guardian was running and saw the first payout within 3 s, but every freeze it sent was refused in simulation: a mistyped Compute Budget program id in its transactions (`09`, finding 47). The run timed out with 11 tickets queued. With the id corrected (`544e4bc`), a restarted guardian heartbeats at 15:41:26 and freezes at 15:41:51, 12 min 34 s after the first payout. The queued payouts could not have settled for 6h, so nothing more left; guardian transactions now drop a refused budget instead of failing | [`vM45ZRV7…`](https://explorer.solana.com/tx/vM45ZRV7v1AW6AGdA2KMk1Wuc2Gsoez4CaPQXLpQsbH6QQU9Dxp82EqeW3y8KRGH1xFzPBufd4Q3h1d4CJ4igvF?cluster=devnet), [`3mjsHTaP…`](https://explorer.solana.com/tx/3mjsHTaPDCu7q5MdtSZyYgBBUCSAxMDtnH4wPe6RPe49GYJWcE266fHbC51pgpyXMKtQGgeNErL4YGpCngSH5nUR?cluster=devnet) |
| Guardian 0 cancels all 11 tickets, 15:41:52 to 15:42:19. Result: 100,000 USDC out, 9,900,000 in the vault, 0 pending, the same as the local run | [`5zUEB2uj…`](https://explorer.solana.com/tx/5zUEB2ujHs8z1vt4iUGvxhJ3ad6ScMKTwqyK6J7ZPEpcuKZJm82E4XXWsVe4idYhoCYz57hR2H6TgALepqnhETQ1?cluster=devnet) … [`61KFMxEj…`](https://explorer.solana.com/tx/61KFMxEjB2r8NvUannWbRU2zcJuV6oPHRr7QF9BZiSKLL6FSGNNMpFwUipEqVQ2RNjg39PiaaCKdvmRXn2LbK8iu?cluster=devnet) |

Before the seal, `cloud/deploy/vault-check.mjs` (simulations; nothing sent) found:
- every setting as configured, and since 29 Sep the calibrated absolute caps (200,000 per 1h, 500,000 per 24h);
- the status page's figures equal to the program's own `attest`, at the same clock;
- S1's payout and the whale's withdrawal of its own deposit refused (`NotSealed`), and so is an early seal (`SealNotExecutable`);
- strangers refused (`NotAdmin`, `NotGuardian`), a 25h freeze refused (`FreezeTooLong`), and so are registering Harbor again and a second vault for the mint (`AlreadyInitialized`);
- after the Vault upgrade (29 Sep): the admin abdicating "set admin" alone, or with one guardian, refused (`NoQuorum`); with a live guardian quorum, allowed;
- the guardians' heartbeat, freeze and seal veto allowed.

**Floor S10** on the target program [`CvZEMDwM…`](https://explorer.solana.com/address/CvZEMDwMaD8zDsWjvj8RgR2M2MNyFeoW5b4DYEz6eWbs?cluster=devnet): an owner and 3 guardians, quorum 2, a 72h upgrade delay.

| Step | Transaction |
|---|---|
| Registered: the upgrade authority moves to Floor's PDA | [`3wkXh4A2…`](https://explorer.solana.com/tx/3wkXh4A2Wt73WcstsvtkZVfV7nSu4ynjCTBnGDHR6Lxw1Y6kGUo7mc9gujKsnb3bxj4wqhH5DaREkP7CmMmGaoJX?cluster=devnet) |
| Abort staged | [`2G6TgzFi…`](https://explorer.solana.com/tx/2G6TgzFinXsig1RvWsHVhaxxPaTMAx4p8TQaifoUknZvBvqe3Uqz1zeuh1MqtodGgZvUA3UzqZH9mtWMy7i5VfNg?cluster=devnet) |
| Snapshot pinned | [`e3nB78tY…`](https://explorer.solana.com/tx/e3nB78tYnF3Ljbhk9uZZQGXHLEPGpvERmAoxTfecLPpnhLuu8age1tqEQ3KQevz2Bn89u67v9SWVpa4uUBxE6Di?cluster=devnet) |
| The owner proposes an upgrade (executable only after 72h) | [`5P4HwpUA…`](https://explorer.solana.com/tx/5P4HwpUAJTZFjvB5J7oBRpnQHbayxwR4yxY25PCFXiu5deJpEYV1h9kVw4ZASUNvxteD6Ahzvz5j49uKTbCQttzr?cluster=devnet) |
| Guardian 2 vetoes it | [`4NPhVt79…`](https://explorer.solana.com/tx/4NPhVt79iLJxPHDC4dZbJiVMMsqWB7yJvU2Lcgb9VBxHsPXTrX7CEZDeVzR4dTjGhUCnyTYa5zf1Hfi6XTi7P4fA?cluster=devnet) |
| The owner withdraws it | [`4bHT2YEr…`](https://explorer.solana.com/tx/4bHT2YErL2Bi8F7RbD74Mv62Nzsx5f2tbN9dGU2p6mqVouVRfmCUHqZMeFc2UriTShUVDKHQ3yuuDREc7rCGxb87?cluster=devnet) |
| **Guardian 0 stops the program** | [`VzwPxcMz…`](https://explorer.solana.com/tx/VzwPxcMzikf5YRxGvoBhH4qWc8hKteDRKYrHPTEkfZ6BeP3t1xmugaKWNiATmQQaAZp3obrLuSxrPP4CYAQ5jhY?cluster=devnet) |
| **Guardians 0 and 1 restore it, byte-identical** | [`4j61VvmW…`](https://explorer.solana.com/tx/4j61VvmWHfdNSgZnvvuzHsVzBML9NXYcfZLT6SU2AEeRtkD5Wyf39bDq4XvwQy77FmS8C92fPzjAZ2WboDLQR9DY?cluster=devnet) |
| Re-armed: a new abort staged | [`4Doc1zHp…`](https://explorer.solana.com/tx/4Doc1zHpynHiVLzUnGquHYRDao9UpgVk6ByEgPMmfBSP3asKAzuJf3oojLaaMuhfW1Gt3vTUJatNuzHu1ma4cdtd?cluster=devnet) |
| Re-armed: a new snapshot pinned | [`5VxEe7sr…`](https://explorer.solana.com/tx/5VxEe7srvw1X1YA3MJWLWPnjzCCbjRP7E8JBBLHUwfXwhTeJRLE8Sz5AYkYTMkQC4Ytfuu9x88KaE1X68TsVgN9q?cluster=devnet) |
| Guardian 2's heartbeat | [`2e3Z36nE…`](https://explorer.solana.com/tx/2e3Z36nE4LMNsbLCgkNiABPDXFZR21QRrG94kHwqY7aVQbeuQt1q6p8TNj57pRcoTv2vgCzmcLCJ7NhgrAHeeo47?cluster=devnet) |

The 17 forbidden actions, simulated between the steps, each failed with its exact error. Among them:
- a stranger stopping the program (`NotLiveGuardian`) or proposing an upgrade (`NotOwner`);
- the old key registering the program again (`NotCurrentAuthority`);
- an unfrozen or non-canonical abort buffer (`BufferNotFrozen`, `NotCanonicalAbort`);
- executing the upgrade early or after the veto (`NotExecutable`, `Vetoed`);
- stopping twice (`NotLive`), and one guardian restoring alone (`NoQuorum`).

## What the video shows (`12 §4`)

1. `scripts/check.sh` and the `scripts/prove.sh` summary: the core verified four ways.
2. S8 and S1 from the terminal; the E2E run live, with the guardian freezing on its own.
3. S4 and S9: "nobody noticed Bulkhead".
4. S7 and S10: slow loosening; Floor's stop and byte-identical restore.
5. The status page: "Worst case right now: …".
