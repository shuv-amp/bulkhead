# 08 — Scenarios (the demo is real)

Every number shown in a video or on a page comes from a scenario that actually executed, with the test name (LiteSVM), the log (`cloud/e2e`) or the signature (devnet) next to it. Models are labelled "model".

Environments:
- **LiteSVM** (`programs/tests`): the real agave runtime and loader, the mainnet feature set and the mainnet token program; deterministic clock. Every scenario runs here.
- **Local validator** (`cloud/e2e/run.sh`): `solana-test-validator` with the programs, a sealed market, the Cloud guardian and an attacker.
- **Devnet**: public signatures ([below](#devnet-signatures)). Deployed 28 Sep 2026 by `scripts/deploy.sh`, rehearsed first by `scripts/deploy-dryrun.sh` on a fresh local validator. The demo market's seal executes from 30 Sep, 20:32 UTC. After it, S1 runs there with `cloud/e2e/s1.sh`, the same script the local end-to-end run uses, on the market that `scripts/deploy.sh` wrote (`world.json`, `keys/`). Floor S10 needs no seal and has already run there.

Status (28 Sep 2026):

| Scenario | Where it runs | Status |
|---|---|---|
| S1 compromised admin | `tests/vault.rs::s1_…`, `cloud/e2e/run.sh`; devnet: `cloud/e2e/s1.sh` once the seal executes (30 Sep, 20:32 UTC) | **Runs**; on devnet, refused until the seal as it must be |
| S1 with the full Drift asset mix (31 borrows) | model: `reference/drift_model.py` | Model; devnet run planned |
| S4 bank run | `tests/vault.rs::s4_…` | **Runs** |
| S7 slow loosening | `tests/vault.rs::s7_…`, `an_unvetoed_loosening…` | **Runs** |
| S8 one-transaction attack | `tests/vault.rs::s8_…` | **Runs** |
| S9 honest borrower | `tests/vault.rs::s9_…` | **Runs** |
| S10 Floor lifecycle | `tests/floor.rs::s10_full_lifecycle` (+ 20 more Floor tests); on a real mainnet program's bytes: `scripts/floor-demo.sh` (`06 §7`); on devnet: `scripts/floor-devnet.sh` | **Runs**, also on devnet |

## S1: a compromised admin (Drift class)

**Harbor** (`programs/harbor`) is a deliberately naive protocol whose custody is a Bulkhead vault. Its `AdminPayout` pays anyone anything: the power an attacker holding a protocol's admin key has.

**LiteSVM, golden G-1 on-chain** (`s1_compromised_admin_gets_exactly_the_burst_then_a_public_queue`):
- Setup: 10,000,000 USDC vault, default limits, sealed.
- The attacker orders 150k, 50k, 10k, 400k and 1M USDC, one per minute (the Drift cadence).
- Every outcome and every ticket ETA equals the core model's to the second, including the capacity following the draining balance (the lower of the EMA reference and the live balance): the last ticket is due in 54h 37m, not the golden vector's 53h 12m at a fixed capacity.
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

## Devnet signatures

Deployed 28 Sep 2026; the Vault upgraded in place on 29 Sep. Every transaction below is finalized and succeeded. Program ids, hashes and the upgrade authority are in `SECURITY.md`.

**Programs**

| What | Transaction |
|---|---|
| Floor deployed ([`HARLZqMw…`](https://explorer.solana.com/address/HARLZqMwqocBnbhbSTWkd5i8EHmjHXLHr1T9su3SR31E?cluster=devnet)) | [`2C7ZdVsN…`](https://explorer.solana.com/tx/2C7ZdVsNAnbPGhvkbdz4AzJ1JCaEPYv3du8P8Tq6GcnYMy5S5iqmEBZ8YEfG7t5WjKMg7ZhM1yCRHLh66GB71h7e?cluster=devnet) |
| Vault deployed ([`HK5FbaLt…`](https://explorer.solana.com/address/HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b?cluster=devnet)) | [`GvwetgZP…`](https://explorer.solana.com/tx/GvwetgZPFJiXbPTLB63CaRAc96T5cxKt8QwMUwdcmXPi6VCAKjJNZHvwDUwvEh8Dfr3FnkdW6a6L4U9KzHjgoez?cluster=devnet) |
| Harbor deployed ([`6w9t76W2…`](https://explorer.solana.com/address/6w9t76W2w8q38xTvUPuDDzSwrjTKbq4dM8nAckYXScYh?cluster=devnet)) | [`3mB9Uy9i…`](https://explorer.solana.com/tx/3mB9Uy9iwEdfCmDKFXNkLU1U9dvnYKwM7mRUE2mSLesaQeuWakYxzjjAgwYUen4tJjZYxAUcq44v5Y4fwEXNhGwY?cluster=devnet) |
| Vault upgraded in place, 29 Sep: capacities from `min(reference, live balance)`, abdication needs a guardian quorum (`15`, A1 and A3). Same id, market and seal time; `79b0a47f…a62d9c93`, verified byte-identical | [`5vRRUkGd…`](https://explorer.solana.com/tx/5vRRUkGdJJoX5jBxiERWBDSJDy5L7tugqKZJcauTqZNSLAPWEiLqNWbMx5NRzwC7fk3EUhkvvXuc9Gaywzc7Gmgj?cluster=devnet) |

**The demo market**: protocol [`26dY2HWr…`](https://explorer.solana.com/address/26dY2HWrczKyPYh8jB4cBgzFsf5gkYo789BfCBQXRvSq?cluster=devnet), vault [`7qrrXwX5…`](https://explorer.solana.com/address/7qrrXwX5uYeCDTfdQbbRNJC7tdLYRFCLfq6sswKuZqZw?cluster=devnet), test USDC mint [`CBK36QrH…`](https://explorer.solana.com/address/CBK36QrH6fzjrDYwkKHF6jeEAEfHcm8iSVN9BZrCxHSB?cluster=devnet); 3 guardians, quorum 2; 2% per hour, 5% per day.

| What | Transaction |
|---|---|
| Harbor registered with Bulkhead | [`2jJdQGiL…`](https://explorer.solana.com/tx/2jJdQGiLbWgB9KVA22bpHLj9K9QaeWi5KvhbYQ9CkumNKcXdd68QtZjCeKusXJzVopYHpaGf7bxCxwgSDkH8M2Gu?cluster=devnet) |
| Vault created with the default limits | [`4aKAYC96…`](https://explorer.solana.com/tx/4aKAYC96oBp8kyomNytkniARUGVxV5vswztFXor13rti3aR1Cbeu3gMptcgq6stccLLAPakkpbz31TJjNSdJh1eW?cluster=devnet) |
| 10,000,000 test USDC deposited through Harbor | [`eJWkSy6f…`](https://explorer.solana.com/tx/eJWkSy6finkhisTUAjxGrNHYCgfMNv1NgkvvysCSGfF7zWGi76KoPuU6GnK1zKwmzfreFSbXMmXsX2if1dbicPP?cluster=devnet) |
| Seal proposed: executable from 30 Sep, 20:32:27 UTC until 7 Oct, 20:32:27 UTC | [`3ZJH4YW4…`](https://explorer.solana.com/tx/3ZJH4YW47LZFbkb51yrDiMmSYaNyzJokYJ8ifRhqUWxcN5A2gbAzibk4BRk7u46kZPurDuJyffMv9oZaFnVoGbQJ?cluster=devnet) |
| Absolute caps set, 29 Sep: 200,000 per 1h and 500,000 per 24h, 2% and 5% of the 10M (the calibration rule, `07 §4`; `15` A1b). A tightening, applied at once; the worst case is unchanged at 10M | [`63WTyNAF…`](https://explorer.solana.com/tx/63WTyNAFuwodQwKHjmz5feTCGB43z2ErJ9ekDf3sYGeXfhAgA3khdeKiGfqMJqHXJYEtVUBsdUXysuKtsodLAAYa?cluster=devnet) |
| Guardian 0's heartbeat: the Cloud guardian's first live run | [`2bsgiHmt…`](https://explorer.solana.com/tx/2bsgiHmtjSYkXBgCzwKFmMrkVoGJkgvY5N5Y9vrzXcXg7dGRUT2JKWvWycCP1AxdR38hqgDPLBU7u7sCZCqrbwwR?cluster=devnet) |

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
