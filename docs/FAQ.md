# FAQ

Short answers to the questions judges, integrators and depositors ask. Each links to the full treatment.

## The idea

**Isn't this just a rate limiter?**
Drift had a rate limiter, and its compromised admin raised it. Bulkhead's limits live outside the protocol's reach:
- tightening is instant;
- loosening waits at least 72 hours, a constant in the program, in public, and any guardian can veto it;
- the limiter tells apart an owner taking back their own deposit, which is never limited, from money nobody's ledger supports, which is limited.

See `03 §2–§5`.

**Why would a protocol limit itself? Who pays?**
The people who want the admin constrained are the ones whose money sits under it: depositors, curators, allocators, insurers. Bulkhead gives them a worst case enforced on-chain (`attest`: "at most $X now, $Y in the next hour, $Z in a day"). Protocols pay for Bulkhead Cloud: a hosted guardian, calibration on their own flows, and the attestation feed. The core stays free and open source. See `11`.

**What exactly does "2% per hour and 5% per day" mean?**
Each rate refills a bucket of the same size. So the most unbacked money that can leave in any window of length `T` is `min(2% × (1 + T/1h), 5% × (1 + T/24h))` of the vault (of the lower of its live balance and its 24-hour average, `03 §3`):
- up to 4% in any hour;
- up to 10% in any day;
- half a vault takes 9 days with nobody responding.

This is guarantee G1, proved in `03 §2.5` and checked by Kani and the exhaustive tests (`09 §5`).

**What happens in a bank run?**
Nothing special. Every depositor who owes nothing gets their own deposit back instantly, without prices, even while the protocol is frozen. Scenario S4 withdraws 100% of a 9.8M USDC vault this way, one depositor a minute, with zero tickets (`08`). Whether the tokens are in the vault is the pool's liquidity: lending moves deposits out, and Bulkhead doesn't change that (`03 §4.6`).

**What happens to an honest large withdrawal that isn't backed?**
It becomes a public ticket with an ETA, at least 6 hours out, and anyone can settle it once it's due. The protocol shows "arriving at ETA" in its own UI. Calibration against a protocol's real flows aims for zero honest requests queueing (`07 §4`).

## Guardians

**Who are the guardians?**
Two to eight keys the protocol names at registration: for example its operations key, the Bulkhead Cloud bot and a security firm. Only guardians that heartbeat within their interval count. They can freeze, cancel or extend a ticket, veto a change, and (Floor) stop the program. No guardian instruction moves tokens or chooses a recipient (G5).

**What if a guardian key is stolen?**
The attacker gets denial of service, not money:
- **A Vault freeze** lasts at most 24 hours per call and can be repeated. It stops only the unbacked lane. Own-deposit returns and backed payouts continue (tested: S4 and `a_backed_borrow_is_paid_during_a_freeze_and_only_the_unbacked_rest_waits`). The unbacked part of a liquidation, its bonus, waits until the freeze ends.
- **A Floor stop** halts the whole program, liquidations included, like any pause.
- **In both cases** a live quorum of the *other* guardians ejects the rogue guardian at once. Under Floor, the quorum restores the stopped code in the same transaction.

See `04` T7.

**Who is liable for a wrongful freeze by the hosted guardian?**
The Cloud service terms will define it; they aren't written yet. The worst a wrongful freeze can do is delay unbacked payouts, by at most 24 hours per freeze. It can never take funds.

## Floor and the abort pattern

**Why not just upgrade to Dean Little's abort binary?**
It is the fastest stop on Solana, and Floor builds on the pattern (credited in `DISCLOSURE.md`). But a bare abort:
- is pressed by whoever holds the upgrade key, the key that can also deploy anything;
- waits for the timelock under a timelocked multisig;
- fails with an ordinary error code (`Custom(1)`);
- is undone only by re-uploading the whole program.

Floor separates stopping from upgrading:
- any live guardian stops the program with a staged, verified binary that logs why;
- new code waits 72 hours in public;
- a quorum restores the stopped code, verified byte-identical, in one instruction.

See `06 §2`.

**Does Floor stop a Drift-style attack?**
No. Drift was drained through admin instructions in the existing code, not by an upgrade. Floor protects against malicious *new code*. Only Vault's in-path limits bound a drain like Drift's, and no stop button reaches inside a transaction.

**Does registering with Floor change my program?**
No. `register` moves the upgrade authority to Floor's PDA in one instruction, and the program's code is untouched. Your owner key then proposes upgrades, which wait the delay, and you can take the key back through `ReleaseAuthority` after the delay (`06 §6`).

**What about SIMD-0500?**
Once active, it lets loader-v3 deploy only sBPF v3 binaries. Floor's abort binaries are v3, and Floor records whether your live code is v3. A stopped pre-v3 program can only come back with a v3 build. `python3 tools/floor_check.py <program-id>` reports this for any program (`06 §8`).

## Safety of Bulkhead itself

**Can the admin open the backed lane by adding junk collateral or changing a price feed?**
No. Allowlisting a new asset, changing its feed or raising its collateral weight counts as a loosening, so it waits 72 hours and can be vetoed (`03 §5`). The backed lane values collateral at the lower of spot and EMA, minus a confidence margin. A missing, stale or wide price counts as zero (G7). The Drift pattern, 750M CVT of junk collateral, backs 0 USDC (golden E5).

**Is Bulkhead custodial? Can the team move funds?**
No. Tokens sit in accounts owned by the Vault program's PDA. No key can transfer them except through `release`, which the protocol's own program signs and the limits bound. The one emergency move is into a Bulkhead-held lifeboat, and leaving it waits 72 hours and goes only to a destination committed 72 hours earlier (G6). After audit, Bulkhead's own upgrade authorities are burned (G9).

**What if Bulkhead has a bug?**
It is the top risk, so every rule is stated independently more than once and checked:
- a Rust core against a Python reference, over 6.9M differential lines;
- property tests, 13 Kani harnesses, exhaustive tests and mutation testing;
- the programs against a model built from the core;
- every finding listed in `09 §4`.

It is still unaudited. The mainnet path is two audits, a bug bounty, a TVL-capped first partner, then immutability (`SECURITY.md`).

**Receipt tokens (LP shares) sold on a secondary market?**
A buyer who didn't deposit has no backing, so their redemption uses the rate-limited lane. It is a known limitation (`SECURITY.md`).

**What does it cost in compute?**
Measured on the real runtime, through a protocol's CPI:

| Instruction | Compute units |
|---|---|
| `deposit` | ~9.8k |
| `release`, own deposit | ~12.8k |
| `release`, priced borrow | ~17.5k |
| Floor stop of a 200 KB program | ~10k |

See `05 §10` and `06 §7`.

**Is it live?**
On devnet, yes: since 28 Sep 2026, byte-identical to this repository's build, with test tokens only (ids in the README). Not on mainnet. The programs also pass their tests on the real Solana runtime (LiteSVM) and in an end-to-end run on a local validator. Nothing is audited; don't use it with real funds.
