# 15 — Adversarial review (28 Sep 2026)

An internal red-team pass over the idea and the implementation, done by someone who did not write the code. The question for every rule: an attacker knows it exactly; what do they do?

Unaudited, like everything else here. This is not a substitute for the external audit in `11 §8`.

## 1. Scope and method

| Area | Read | Attacked with |
|---|---|---|
| `bulkhead-core` (limiter, EMA, ledger, governance, Floor checks) | All | New tests in `crates/bulkhead-core/tests/adversarial.rs`, run through the real core functions |
| `programs/vault` (custody, brakes, governance, lifeboat, genesis, token, Pyth) | All | Account-validation review against `05 §5b`; admin- and guardian-key abuse walked through by hand |
| `programs/floor` | Abort, propose, veto, approve, execute, restore, eject | Owner- and guardian-key abuse walked through by hand |
| `cloud/guardian` | Policy and main loop | New tests in `cloud/test/adversarial.test.mjs`: an attacker who paces payouts against the policy |
| The idea (`00`–`04`, README, pitch) | All | Section 4 |

**What ran:** `cargo fmt`, `cargo clippy -D warnings`, and `cargo test --release` for the workspace (Rust 1.92.0); the golden, regression, model and `floor_check` self-tests; all Cloud tests. All pass, including the new ones.

**What did not run here:** `scripts/check-programs.sh` (LiteSVM; needs the Agave CLI), `scripts/prove.sh` (Kani), `scripts/mutants.sh`. None of the on-chain code was changed, so their earlier results still apply to it.

## 2. Findings

Severity is for a mainnet deployment: **High** = more value can leave than the product promises; **Medium** = a stolen key does more than the threat model says, or a promised response does not happen; **Low** = operational gap.

| # | Severity | Finding | Status |
|---|---|---|---|
| A1 | **High** | Capacity follows a lagging reference, not the live balance: a parked-then-withdrawn deposit, or an honest bank run, multiplies the unbacked drain | Demonstrated; fix recommended (on-chain) |
| A2 | **Medium** | The guardian bot only watches a 1-hour window: a paced attacker drips the daily bucket out forever without a freeze | **Fixed in this PR** (24-hour rule), residual stated |
| A3 | **Medium** | A stolen admin key can abdicate `SetAdmin` / `SetGuardians` instantly and forever | Fix recommended (on-chain) |
| A4 | **Medium** | No recovery path from a compromised Vault admin or Floor owner key | Design decision needed |
| A5 | Low | Floor's stop button is unarmed after every abort until someone stages a new abort buffer; the fast-restore snapshot must be re-pinned after every upgrade | Operational; recommend the status page shows both |
| A6 | Low | A borrower can pick the most favourable fully-verified Pyth update within `max_age_s` | Residual; calibrate haircuts against it |

### A1 — The reference balance can be inflated (High)

**What happens.** Capacities are `bps × reference`, and the reference is an EMA that moves toward the live balance by at most `dt/24h` per touch, *in both directions* (`ema.rs`). The slow move up is the point (golden G-8: a deposit one minute before an attack buys nothing). The slow move down is the hole: when a large balance leaves through the backed lane, which is instant and cannot be frozen (G2), the capacity stays sized for the money that is gone.

**Attack.** A whale deposits 90M USDC into a 10M vault and leaves it for three days, with ordinary hourly traffic. It then takes the 90M back (backed, instant). An attacker holding the protocol's admin key (the Drift class) drains the unbacked lane for the next 24 hours:

| | 24h unbacked drain | vs the advertised 10%-a-day bound on the vault that is left |
|---|---|---|
| Today (capacity from the reference) | **7,799,995 USDC** of 10,000,000 | **7.8×** |
| With `min(reference, live balance)` | 953,517 USDC | within the bound |

The same happens with no whale at all: after an honest bank run (S4) takes 90% of a vault out through the backed lane, the first attacker gets an instant burst of 195,054 USDC out of the 1,000,000 left, **9.8×** the 2% burst.

Evidence: `finding_a1_*` and `mitigation_a1_*` in `crates/bulkhead-core/tests/adversarial.rs` (`cargo test --release -p bulkhead-core --test adversarial -- --nocapture`).

**Why G1 still "holds".** G1 (`02 §3`) is stated in `C_k`, which is a function of the reference, so it is not violated. The README and `02` used to say "2% of a vault", which reads as a share of the tokens that are actually there. That sentence was false after a large exit. They now say "of the reference balance".

**Recommendation.** Compute capacities from `min(reference, live balance)`. Up moves stay slow (G-8 keeps holding, see the mitigation test); down moves are instant, which only ever lowers capacity, so it is a tightening at every instant. That reverses the other half of `ema.rs`: a drain currently does not shrink the limit at once, so honest unbacked users keep the old capacity. `min` takes that availability away. It also does nothing for a non-zero floor (`capacity_from_ref` can still clamp up to the floor) and it does not close a quiet-day donation (section 3). Call sites: `programs/vault/src/custody.rs:311` (`release`/`quote`), `views.rs:33` (`attest`), `brakes.rs:205` (`reset_backlog`), and the ports that must stay equal to `attest` (`cloud/lib/limits.mjs::attestLocal`, the program-vs-model differential in `programs/tests/tests/differential.rs`, and the Python model). This changes the deployed programs, so it needs `scripts/check-programs.sh`, a redeploy and fresh `verify-deployed.sh` hashes.

### A2 — The guardian bot can be paced (Medium, fixed here)

**What happens.** `cloud/guardian/policy.mjs` froze only when unbacked outflow in the last *hour* reached half of `worst_1h`. An attacker who knows that keeps every rolling hour one unit below the threshold: the bot never fires, and the daily bucket leaves at its refill rate.

**Measured** (`cloud/test/adversarial.test.mjs`, 10M vault, default limits): over 72 hours the paced attacker takes **more than 14% of the vault with no freeze**, and it would continue at about 5% a day.

**Fix in this PR.** A second rule: freeze when unbacked outflow in the last *24 hours* reaches `freezeFractionOfWorst24h × worst_24h` (default 0.5, that is 5% of the reference). The bot reads `worst_24h` from `attest` alongside `worst_1h`. Against the same attacker it freezes within 6 hours, with under 7% gone (the test's assertions). Honest unbacked flow at the calibration ceiling (3.3% a day, from `07 §4`: the 5% default is 1.5× that ceiling, spread evenly) never trips either rule over 7 days.

The first cut of that fix did not actually hold. The sum lived only in process memory and the process anchored at chain head, so a restart forgot the drip. Events were stamped with the wall clock. `getSignaturesForAddress` was asked for 100 signatures and the cursor jumped to the newest, which drops any gap larger than one page. A failed freeze set `freezing` and was never retried. Thresholds went through `Number()`, which is not exact past 2^53, and a missing attest borrowed another mint's worst case. Outflows from every mint were one bucket. Those are closed: startup replays the last 24 hours from block times and freezes once if that window is still over and the protocol is not frozen; signature pages walk until the cursor; a failed freeze is retried; thresholds are integer; a missing attest is 0 for new releases (history alone does not freeze a mint with no figure); each mint has its own window. A proposal the bot missed while down is still missed: catch-up does not re-send old vetoes.

**Residual (stated, not fixed).** An attacker who also stays under the 24-hour rule is limited to that threshold per day (≤ 15% over three days in the test). A threshold bot bounds a drip; it cannot end one. Humans reading the alerts, and tight calibration, still have to. The README's "freezes seconds after the burst" is true for a greedy attacker (the end-to-end run), not for a patient one; the pitch should not imply otherwise.

### A3 — Abdication by a thief is permanent (Medium)

**What happens.** `abdicate(kind)` (`brakes.rs:224`) is admin-only, instant and irreversible, and accepts every change kind, including `SetAdmin` (3) and `SetGuardians` (2). It is treated as a tightening (D18), but in this threat model the admin *is* the attacker (D20).

**Attack.** A thief with the admin key abdicates `SetAdmin`: the team can never rotate the stolen key out. The thief keeps, forever, every admin power: repeated 24h freezes, cancelling honest tickets, moving the whole vault into the lifeboat. None of these is theft, but together they are a permanent denial of service that the threat model (`04`, "DoS only") does not describe. Abdicating `SetGuardians` as well means dead or ejected guardians can never be replaced; once too few are alive for a quorum, nothing can unfreeze or return the lifeboat. Abdicating `SetLimits` also blocks later *tightening* of limits (the check happens before classification).

**Recommendation.** Either (a) make `SetAdmin` and `SetGuardians` non-abdicable, or (b) require a live guardian quorum to co-sign any abdication. (b) keeps the Morpho V2 feature for honest teams and costs one extra signer set. Both are small changes to `brakes.rs::abdicate`, plus a negative test in `programs/tests/tests/vault.rs`.

### A4 — No recovery from a compromised admin or owner key (Medium, design decision)

Only the Vault admin can propose `SetAdmin`, and only it can `cancel_change`; only the Floor owner can propose `SetOwner`, and only it can `cancel`. So if the key is *shared* with an attacker (a multisig with a compromised quorum, a leaked key the team still holds), the attacker cancels every rotation the team proposes. Under Floor, a stolen owner key can also `abort` whenever an abort buffer is staged (staging is permissionless); the quorum restores, the thief aborts again.

This is the same "DoS only" as A3 but reachable without abdication. Options for the team: let a live guardian quorum propose a key rotation (still 72h and vetoable by any *other* guardian), or remove the owner's own `abort` right in Floor (guardians already have it). Either should be decided before the pitch claims "a stolen key can only grief".

### A5 — Floor re-arming (Low)

`abort` consumes the abort buffer (`abort_buffer = 0`) and every executed upgrade clears the snapshot. Until someone stages a new canonical abort buffer and pins a new snapshot (both permissionless, but each needs a program-sized, Floor-frozen buffer), the program is live with no stop button or no fast restore. Recommend: the status page and the guardian bot alert while either is missing, and the guardian runbook re-stages both right after every abort, restore and upgrade.

### A6 — Pyth update cherry-picking (Low)

Anyone can post a fully verified `PriceUpdateV2`, so a borrower can present whichever genuine update within `max_age_s` values their collateral highest. `conservative()` (min of spot and EMA, minus confidence) and haircuts cover this only if `haircut ≥` the largest move the asset makes within `max_age_s`. Add that to the calibration rule for weights (`03 §4.7`).

## 3. Attacks that did not work

Each was tried and found closed; listed so nobody re-spends the time.

| Attack | Why it fails |
|---|---|
| Clock stepping backwards between requests to reuse capacity | The limiter uses `max(TAT, now)`; 2,000 random sessions with backward steps stayed within G1 over the real elapsed span (worst 0.9987 of the bound). `clock_stepping_backwards_never_beats_g1` |
| Flash-loan deposit to raise the reference inside one transaction | `touch_reference` uses the balance *before* the operation and sets `ref_updated_s = now`, so a second touch in the same second moves nothing |
| Donating tokens to the vault account before the first touch after a quiet day | After a quiet day (`dt ≥ 24h`) the next touch moves the reference the whole way to the donated balance. The donation has no backing, so it leaves through the limiter it just sized. `min(reference, balance)` does not close this: after the jump the two are equal. Measured: 9,535,175 USDC in the next day against a 1,000,000 USDC bound on the pre-donation vault (9.5×). `donation_after_a_quiet_day_inflates_even_with_min_balance` |
| Crediting backing to someone else | Backing goes to the signer of the source token account; nobody can sign for another owner's account |
| Fake recipient account to borrow another owner's backing | `release` reads the owner from the recipient token account (owner-checked against both token programs, initialized state checked) and loads that owner's backing PDA by re-derivation |
| Omitting an asset account so an allowlisted mint looks unlisted | `price_table` requires the asset PDA at the derived address; an empty account there is accepted only as "not listed" |
| Partial-verification or wrong-feed price accounts | Only `Full` updates owned by the Pyth receiver count as prices (anything else is unpriced, which fails closed); a wrong feed id is refused |
| Token-2022 extensions in the custody path | Allowlist by extension number; hooks, permanent delegate, confidential transfers, pausable and non-transferable are refused |
| Old guardian approvals counted after an ejection shifts indices | Floor clears `pending_approvals` on eject |
| A proposal made before an abort executing after it | `abort` clears the pending proposal |
| Re-proposing a vetoed lifeboat exit to skip the veto | A new proposal restarts the full 72h and is vetoable again; the destination must predate the proposal by 72h |

## 4. The idea, attacked

Weaknesses in the product argument rather than the code. None of these kills it; each is a question a judge or a protocol's risk team will ask.

1. **"2% of a vault" is 2% of the reference.** See A1. The README and `02` now say "of the reference balance", which lags the live balance by up to 24 hours. The pitch should use the same words until the A1 fix ships.
2. **Transferable receipt tokens break the backed lane.** Backing belongs to whoever deposited. When a protocol's position is transferable (LP tokens, cTokens, kTokens, LSTs), a buyer on the secondary market withdraws with no backing, so honest withdrawals go through the unbacked lane and can queue. Calibration then pushes the limits up and the bound weakens. The integration guide (`07`) should name which protocol designs fit well (non-transferable positions) and which need a backing-transfer hook.
3. **A circuit breaker can turn a crash into insolvency.** Liquidation bonuses and cross-mint seizures are partly unbacked. In a cascade, liquidations that exceed the daily bucket queue for at least 6 hours while prices keep falling, which leaves bad debt. `07 §3` says "size the daily bucket for cascades"; that is the whole question for lending protocols, and it deserves a scenario with a historical crash (a Pyth replay of a −30% day).
4. **"Guardians can only grief" understates a stolen key.** See A3 and A4: without the fixes, griefing can be permanent.
5. **The freeze response is a bot plus people.** See A2: thresholds can be paced, and the bot needs uptime, RPC access and a funded key. The claim that should appear in the pitch is the on-chain bound, not the response time.
6. **Bulkhead's own key is the biggest key.** Until the upgrade authorities are burned after audit (G9), whoever holds the Bulkhead team key can replace the code that holds every protected vault. It is disclosed in `SECURITY.md`; protocols will ask how and when it is burned, so the burn plan (and whether Bulkhead itself sits under Floor meanwhile) should be one slide.
7. **Immutable means unpatchable.** After the burn, a bug in Bulkhead can't be fixed in place; the only way out for funds is each protocol's lifeboat exit (72h plus the destination rule). The docs should say that migration to a new version is the upgrade path, and how long it takes.

## 5. Recommended order

1. A1 on-chain fix, then redeploy and re-verify (it changes the headline number).
2. A3 (small), then decide A4.
3. README and pitch wording for items 1, 4 and 5 of section 4.
4. A liquidation-cascade scenario (section 4, item 3).
5. A5 alerts in the status page and the bot.
