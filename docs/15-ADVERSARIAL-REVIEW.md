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

**Update, 29 Sep.** The fixes for A1 and A3 change the Vault program. `scripts/check.sh`, `scripts/check-programs.sh`, the end-to-end run and the deploy rehearsal all pass on them, and the devnet Vault was upgraded in place (same program id, market and seal time; `08`, devnet). The Kani harnesses pass in CI on the same change; mutation testing was not re-run (it covers the core, where the only new function, `capacity_base`, is a `min` with its own exact unit test).

**Update, 8 Oct.** Later reviews (`09 §4`, findings 63–73) reopened three of these and found new edges. A1 was reopened by capital held for one transaction (65): fixed with the low-water balance. A5 by a re-pin race that made a prepared stop fail (66). A13 by another protocol's events, which one Vault program writes for every protocol (64). New: governance edges (63: an asset loosening that outlived a later tightening), ticket address reuse (67: a guardian's cancel or extension could land on another ticket), rescaling mints (68: InterestBearing and ScaledUiAmount are never priced), guardian gaps (69), proof and tooling gaps (70), lifeboat, seal and admin edges (72), and release tooling (73). All are fixed, and on devnet since 8 Oct (PR #35).

## 2. Findings

Severity is for a mainnet deployment: **High** = more value can leave than the product promises; **Medium** = a stolen key does more than the threat model says, or a promised response does not happen; **Low** = operational gap.

| # | Severity | Finding | Status |
|---|---|---|---|
| A1 | **High** | Capacity follows a lagging reference, not the live balance: a parked-then-withdrawn deposit, or an honest bank run, multiplies the unbacked drain | **Fixed on-chain, 29 Sep** (`min(reference, live balance)`); reopened 8 Oct by capital held for one transaction (`09`, finding 65), fixed with the low-water balance (`min(reference, live balance, low)`); not on devnet yet |
| A1b | **High** | An attacker who parks their own capital drains while it is still in the vault: the live balance is inflated too, so `min` alone does not help | Absolute caps bound it (existing feature); calibration now sets them |
| A2 | **Medium** | The guardian bot only watches a 1-hour window: a paced attacker drips the daily bucket out forever without a freeze | **Fixed** (24-hour rule), residual stated; late-freeze gaps fixed 29 Sep |
| A3 | **Medium** | A stolen admin key can abdicate `SetAdmin` / `SetGuardians` instantly and forever | **Fixed on-chain, 29 Sep** (guardian quorum; loosening only) |
| A4 | **Medium** | No recovery path from a compromised Vault admin or Floor owner key | **Fixed 6 Oct**: a recovery key (`09 §4`, 38–39); the admin lost `cancel_ticket` (35); a stolen recovery key is replaced at once (62); edges 69(a), 70(d), 72 fixed 8 Oct |
| A5 | Low | Floor's stop button is unarmed after every abort until someone stages a new abort buffer; the fast-restore snapshot must be re-pinned after every upgrade | **Alerted, 30 Sep:** the status page shows both; the guardian bot warns when either is missing (`floorProtected`). A re-pin race that made a prepared stop fail fixed 8 Oct (66) |
| A6 | Low | A borrower can pick the most favourable fully-verified Pyth update within `max_age_s` | Residual; calibrate haircuts against it |
| A7 | **Medium** | The loosen delay has no upper bound, and raising it applies at once | **Fixed in this tree** (30-day cap). Devnet still runs the previous program until the in-place upgrade |
| A8 | Low | `MintCloseAuthority` with an authority set is accepted at vault creation | **Fixed in this tree** (allowed only when the authority is unset) |
| A9 | **Medium** | The backed lane trusts Pyth, and Full verification is now 3 of 5 Pyth Pro keys | Stated in `04` assumption 2. A rate limit on new backed liabilities waits for the audit build |
| A10 | **High** | The seal checks imported backing against the balance, not deposits made before the seal | **Fixed in this tree** (`imported + total_in ≤ balance + lifeboat`) |
| A11 | **Medium** | Harbor signs its caller PDA for whatever program the caller names | **Fixed in this tree** (Vault id baked in at build time) |
| A12 | **Medium** | Docs said freezes use priority fees and several RPCs; the bot used one RPC and no compute budget | **Fixed** (off-chain) |
| A13 | **Medium** | The bot trusts any `Program data:` line in a transaction that touches the protocol account, and ignores log truncation | **Fixed** (off-chain): attribute to Vault/Floor, and read accounts when the log is truncated. 8 Oct: events name their protocol (64, on-chain), and a transaction without logs counts as truncated (69f) |

### A1 — The reference balance can be inflated (High)

**What happens.** Capacities are `bps × reference`, and the reference is an EMA that moves toward the live balance by at most `dt/24h` per touch, *in both directions* (`ema.rs`). The slow move up is the point (golden G-8: a deposit one minute before an attack buys nothing). The slow move down is the hole: when a large balance leaves through the backed lane, which is instant and cannot be frozen (G2), the capacity stays sized for the money that is gone.

**Attack.** A whale deposits 90M USDC into a 10M vault and leaves it for three days, with ordinary hourly traffic. It then takes the 90M back (backed, instant). An attacker holding the protocol's admin key (the Drift class) drains the unbacked lane for the next 24 hours:

| | 24h unbacked drain | vs the advertised 10%-a-day bound on the vault that is left |
|---|---|---|
| Before the fix (capacity from the reference) | **7,799,995 USDC** of 10,000,000 | **7.8×** |
| Since the fix: `min(reference, live balance)` | 953,517 USDC | within the bound |

The same happens with no whale at all: after an honest bank run (S4) takes 90% of a vault out through the backed lane, the first attacker gets an instant burst of 195,054 USDC out of the 1,000,000 left, **9.8×** the 2% burst.

Evidence: `finding_a1_*` and `mitigation_a1_*` in `crates/bulkhead-core/tests/adversarial.rs` (`cargo test --release -p bulkhead-core --test adversarial -- --nocapture`).

**Why G1 still "holds".** G1 (`02 §3`) is stated in `C_k`, which is a function of the reference, so it is not violated. The README and `02` used to say "2% of a vault", which reads as a share of the tokens that are actually there. That sentence was false after a large exit. They now say "of the reference balance".

**Fix (29 Sep).** Capacities come from `capacity_base(reference, balance) = min(reference, live balance)` (`bulkhead-core::limiter`), with the balance read before the operation. Up moves stay slow (G-8 keeps holding); down moves count at once, which only ever lowers capacity, so it is a tightening at every instant. Where it is used: `release` and `quote_release` (`custody.rs`), `attest` (`views.rs`), and the ports that must stay equal to `attest`: `cloud/lib/limits.mjs::attestLocal` and the program-vs-model differential. `reset_backlog` never reads a capacity (it clamps each bucket to "now + window"), so it is unchanged. The Python reference ports only the core functions, which did not change.

**Not enough within a transaction (8 Oct, `09`, finding 65).** The live balance is read inside the release's transaction. After a large exit the reference lags above the balance for a day, so a compromised protocol could deposit up to the reference, take an unbacked payout sized from it, and withdraw the deposit through the backed lane, all in one transaction; with a flash loan, at no cost (19.5% of what was left in the first burst after a 90% bank run). The base is now `min(reference, live balance, low)`, where `low` (core `ema::WindowLow`) is the least balance any touch saw before its operation in the current and the previous 30-minute window. A flash deposit, or capital parked for less than 30 minutes, cannot lift the base; an honest withdrawal that comes straight back lowers it for at most an hour. The reference itself is the plain 24-hour EMA again. The Python reference, the JavaScript port (`windowLowTouch`) and the program-vs-model differentials now port `WindowLow`.

What it costs, deliberately: after a drain, honest unbacked users lose the old capacity at once. And every unbacked payout shrinks the base, so a burst is 2% of what is in the vault at each payout: in `s8_one_transaction_drain_gets_only_the_burst`, 100,000 of the 10M, then 99,000 of the 9.9M left (199,000 in all, not 200,000); in the end-to-end run, twelve 100,000 payouts now get 100,000 instantly, because the second no longer fits. It still does nothing for a non-zero floor (`capacity_from_ref` can clamp up to the floor), and it does not help against capital the attacker parks in the vault itself (A1b).

Tests: `after_a_large_backed_withdrawal_the_burst_shrinks_at_once` (program: a 9M backed exit from a 10M vault takes `available_now` from 200,000 to 20,000 at once), `mitigation_a1_*` and `caps_alone_do_not_fix_the_bank_run_but_with_capacity_base_they_do` (core), `capacity_base_is_the_lower_of_reference_and_live_balance` (unit).

### A1b — Parked capital (High; absolute caps)

**What happens.** The attacker (who also holds the admin key) deposits their own 90M into a 10M vault and waits three days: the reference and the live balance are both near 100M. They drain the unbacked lane while the 90M is still there, then take the 90M back through the backed lane, which is instant and cannot be frozen. The honest depositors' 10M paid for the drain.

| Honest depositors lose (10M vault, 90M parked) | 2-minute attack | 24-hour attack |
|---|---|---|
| Before the A1 fix | 19.8% | 95.4% |
| `min(reference, live balance)` only | 19.8% | 94.3% |
| `min` + absolute caps at 2% / 5% of the honest vault (200,000 / 500,000) | **2.1%** | **10.0%** |

Caps alone do not fix the bank-run half of A1 (after a 90% exit they still pay about 20% of what is left); `min` and caps together hold both. Evidence: `finding_a1b_parked_capital_needs_absolute_caps`, `caps_alone_do_not_fix_the_bank_run_but_with_capacity_base_they_do`.

**Status.** Caps (`short_cap`, `long_cap`) already exist: setting or lowering one is a tightening (instant), raising one waits 72h. The calibration rule now sets them at the same percentages of the vault's honest size (`07 §4`), and the devnet demo market runs with them since 29 Sep (200,000 / 500,000; `08`, devnet). A cap that tracks the vault automatically would need a trusted notion of "honest size", which is what the reference was; that is the open design question.

### A2 — The guardian bot can be paced (Medium, fixed here)

**What happens.** `cloud/guardian/policy.mjs` froze only when unbacked outflow in the last *hour* reached half of `worst_1h`. An attacker who knows that keeps every rolling hour one unit below the threshold: the bot never fires, and the daily bucket leaves at its refill rate.

**Measured** (`cloud/test/adversarial.test.mjs`, 10M vault, default limits): over 72 hours the paced attacker takes **more than 14% of the vault with no freeze**, and it would continue at about 5% a day.

**Fix in this PR.** A second rule: freeze when unbacked outflow in the last *24 hours* reaches `freezeFractionOfWorst24h × worst_24h` (default 0.5, that is 5% of the reference). The bot reads `worst_24h` from `attest` alongside `worst_1h`. Against the same attacker it freezes within 6 hours, with under 7% gone (the test's assertions). Honest unbacked flow at the calibration ceiling (3.3% a day, from `07 §4`: the 5% default is 1.5× that ceiling, spread evenly) never trips either rule over 7 days.

The first cut of that fix did not actually hold. The sum lived only in process memory and the process anchored at chain head, so a restart forgot the drip. Events were stamped with the wall clock. `getSignaturesForAddress` was asked for 100 signatures and the cursor jumped to the newest, which drops any gap larger than one page. A failed freeze set `freezing` and was never retried. Thresholds went through `Number()`, which is not exact past 2^53, and a missing attest borrowed another mint's worst case. Outflows from every mint were one bucket. Those are closed: startup replays the last 24 hours from block times and freezes once if that window is still over and the protocol is not frozen; signature pages walk until the cursor; a failed freeze is retried; thresholds are integer; a missing attest is 0 for new releases (history alone does not freeze a mint with no figure); each mint has its own window. A proposal the bot missed while down is still missed: catch-up does not re-send old vetoes.

**8 Oct (`09`, finding 69c, d).** A step that failed every poll (one transaction the node will not return halts ingestion) only logged a warning; it now raises an urgent "stalled" alert after 120 s. A refused cancel was re-sent every poll; it now backs off (15 s to 10 min), and a refusal no retry changes (`NotGuardian`, `WrongVault`, `WrongTicket`) is final.

**Residual (stated, not fixed).** An attacker who also stays under the 24-hour rule is limited to that threshold per day (≤ 15% over three days in the test). A threshold bot bounds a drip; it cannot end one. Humans reading the alerts, and tight calibration, still have to. The README's "freezes seconds after the burst" is true for a greedy attacker (the end-to-end run), not for a patient one; the pitch should not imply otherwise.

**9 Oct (`09`, finding 76): the residual was larger than stated, and silent.** 0.5 × `worst_24h` is 5% of the base a day, which is the program's own sustained daily rate (`long_bps` 500), so the 24-hour rule only trims the first day. Measured over 30 days (`cloud/test/adversarial.test.mjs`, 10M vault, default limits, 5-minute ticks), an attacker who keeps every rolling hour and every rolling day under the thresholds took **77.2% of the vault, was never frozen, and raised zero alerts** (release events were info lines). What changed:

- **Alerts.** Unbacked outflow to non-allowlisted owners over 24 hours past half the 24-hour freeze threshold raises an urgent alert ("unbacked outflow at N% of the 24h freeze threshold", at most every 6 hours per mint), and reaching it on 2 of the last 3 days raises a "sustained drip" alert (daily; each day's high is kept in the state file).
- **A 72-hour rule.** Freeze when unbacked outflow over 72 hours reaches `freezeFractionOfWorst72h` × the most the program allows over 72 hours (limiter port, 20% of the base with the defaults). The default is **0.55**, not 0.5: at 0.5 (exactly the honest ceiling of 3.3% a day) honest flow at the ceiling on a vault with no deposits froze after ~69 hours, because the window looks back at a larger base.

Measured with all rules on: the attacker who stays under only the 1h and 24h rules is now **frozen after 48 hours with 11.2% taken**. One who also stays under the 72-hour rule is never frozen and takes **4.8% on day 1, 22.8% in 7 days (29.1% before), 65.0% in 30 days (77.2% before)**: about 3.7% of the base a day instead of 5%. The first alert fires 65 minutes in, the sustained-drip alert on day 2. Honest unbacked flow at the calibration ceiling (3.3% of the base a day, evenly) never freezes over 30 days, on a shrinking vault or a steady one; at the ceiling it is 66% of the 24-hour threshold, so it does raise the (rate-limited) alerts. A protocol that runs near its ceiling every day should raise `alertFractionOfThreshold` or recalibrate.

This does not fix the residual. A threshold bot cannot tell a drip under the honest ceiling from honest flow, and the 72-hour rule only moves the line from the program's rate to just above the honest one. What limits a patient attacker is the on-chain bound (G1); what ends one is people acting on the alerts (a guardian freeze, then the incident hold).

### A3 — Abdication by a thief is permanent (Medium)

**What happens.** `abdicate(kind)` (`brakes.rs:224`) is admin-only, instant and irreversible, and accepts every change kind, including `SetAdmin` (3) and `SetGuardians` (2). It is treated as a tightening (D18), but in this threat model the admin *is* the attacker (D20).

**Attack.** A thief with the admin key abdicates `SetAdmin`: the team can never rotate the stolen key out. The thief keeps, forever, every admin power: repeated 24h freezes, cancelling honest tickets, moving the whole vault into the lifeboat. None of these is theft, but together they are a permanent denial of service that the threat model (`04`, "DoS only") does not describe. Abdicating `SetGuardians` as well means dead or ejected guardians can never be replaced; once too few are alive for a quorum, nothing can unfreeze or return the lifeboat. Abdicating `SetLimits` also blocks later *tightening* of limits (the check happens before classification).

**Recommendation.** Either (a) make `SetAdmin` and `SetGuardians` non-abdicable, or (b) require a live guardian quorum to co-sign any abdication. (b) keeps the Morpho V2 feature for honest teams and costs one extra signer set. Both are small changes to `brakes.rs::abdicate`, plus a negative test in `programs/tests/tests/vault.rs`.

**Fix (29 Sep): (b), plus loosening only.** `abdicate` now needs the admin and a live guardian quorum (`NoQuorum` otherwise), and an abdicated kind refuses only loosening: tightening it still applies at once, so abdicating `SetLimits` no longer blocks a later tightening. A pending loosening of that kind can no longer execute. Tests: `a_delay_below_72h_is_refused_and_an_abdicated_kind_is_gone_forever` (admin alone and admin plus one guardian are refused; with a quorum, `SetAdmin` is gone) and `an_abdicated_kind_can_still_be_tightened_but_never_loosened`. A4 is unchanged.

### A4 — No recovery from a compromised admin or owner key (Medium, design decision)

Only the Vault admin can propose `SetAdmin`, and only it can `cancel_change`; only the Floor owner can propose `SetOwner`, and only it can `cancel`. So if the key is *shared* with an attacker (a multisig with a compromised quorum, a leaked key the team still holds), the attacker cancels every rotation the team proposes. Under Floor, a stolen owner key can also `abort` whenever an abort buffer is staged (staging is permissionless); the quorum restores, the thief aborts again.

This is the same "DoS only" as A3 but reachable without abdication. Options for the team: let a live guardian quorum propose a key rotation (still 72h and vetoable by any *other* guardian), or remove the owner's own `abort` right in Floor (guardians already have it). Either should be decided before the pitch claims "a stolen key can only grief".

**Decision (6 Oct): a separate recovery key, not guardian rotation.** Guardians stop and never move funds; letting a quorum appoint the admin would let a malicious quorum appoint itself and then move funds into the lifeboat. The established answer is separation of duties: Morpho Vaults V2's owner appoints the curator but has no control over assets or risk, and a sentinel can only reduce risk. So each Vault protocol and Floor config may name a **recovery key** that can only propose a new admin/owner or a new recovery key: it waits the delay, any guardian vetoes it, the admin/owner cannot cancel it, on Floor it displaces a pending owner proposal and survives a stop, and it stales any earlier admin rotation, so a thief cannot get ahead of it. A protocol whose guardians meet L2BEAT's Stage 1 council bar (≥ 8 members, ≥ 75% threshold, ≥ half outside the team) can make the guardians' multisig its recovery key, which gives quorum rotation as a configuration, not as a power every guardian set gets. Two more levers went: the admin no longer cancels tickets (35), and the Floor owner stops the program only while no guardian quorum is live (39). What remains for a thief is bounded: freezes a quorum undoes, lifeboat moves a quorum returns, raising the delay, which postpones recovery by at most the 30-day cap, and loosenings proposed with the stolen key (guardians, limits, the lifeboat destination). Each of those waits the delay and is stopped by one live guardian's veto, which is the only thing that stops it: the thief proposed first, so it becomes executable before the recovery key's rotation lands, and a new admin cannot cancel another key's proposal. The guardian vetoes every loosening that was not pre-approved. **A stolen recovery key (7 Oct, `09`, finding 62).** The recovery key itself had no way out: once set, only it could replace itself. Stolen, it could propose forever. On Floor each proposal took the one slot from the owner's (and a vetoed or expired one kept it, since only the recovery key may cancel its own), so no upgrade or proposed fix could wait out its delay again. On the Vault each new admin it proposed staled the admin's own rotations, and the guardians had to veto every one. Now a vetoed or expired recovery proposal no longer holds Floor's slot, and the admin (Floor: the owner) with a live guardian quorum replaces the recovery key at once (`replace_recovery`), voiding what it proposed. Neither can alone. Together they already decide more than this: on Floor a guardian's stop and a quorum-approved restore install code at once, and on the Vault they abdicate.

**8 Oct edges.** (a) A content approval in the guardian (finding 61) never expired and was never spent, so a thief could re-propose an approved change after it executed and the guardian let it through; an approval is now spent when its change executes and may carry an expiry (`09`, finding 69a). (b) `register` (Vault and Floor) read a cut-off recovery key as "none"; it is now refused (`InvalidInstruction`, 70d). (c) Once `SetRecovery` was abdicated, a compromised recovery key could not even be removed; `replace_recovery` now accepts all zero (removal) while abdicated and still refuses any other key (`Abdicated`, 72). (d) A stolen admin key could park the vault in the lifeboat again after every quorum return; `lifeboat_move` is now refused while the protocol or the vault is frozen, so a freeze makes the return stick, and `SetAdmin` refuses the lifeboat destination, so the key that parks the vault never receives its exit (72).

### A5 — Floor re-arming (Low)

`abort` consumes the abort buffer (`abort_buffer = 0`) and every executed upgrade clears the snapshot. Until someone stages a new canonical abort buffer and pins a new snapshot (both permissionless, but each needs a program-sized, Floor-frozen buffer), the program is live with no stop button or no fast restore. Recommend: the status page and the guardian bot alert while either is missing, and the guardian runbook re-stages both right after every abort, restore and upgrade.

**Re-pin race (8 Oct, `09`, finding 66).** `pin_snapshot` is permissionless, and since finding 53 `abort` refused any stop not naming the current pin. Anyone with two buffers identical to the live code could re-pin them in turn, so every guardian stop built against an earlier read failed with `SnapshotMismatch`, during an exploit. Now a stop accepts any frozen buffer byte-identical to the live code and makes it the pin; anything else must be the pin, and the abort buffer never is.

### A6 — Pyth update cherry-picking (Low)

Anyone can post a fully verified `PriceUpdateV2`, so a borrower can present whichever genuine update within `max_age_s` values their collateral highest. `conservative()` (min of spot and EMA, minus confidence) and haircuts cover this only if `haircut ≥` the largest move the asset makes within `max_age_s`. Add that to the calibration rule for weights (`03 §4.7`).

### A7 — The loosen delay can be raised without a bound (Medium)

**What happens.** `classify_delay` accepted any delay ≥ 72h, and a raise is a tightening, so it applies in the same transaction. A stolen or mistyped admin key can set the delay to a value that pushes every later loosening — including replacing the admin, the guardians and the lifeboat destination — past the point where `now + delay` overflows and the schedule aborts. Floor already capped its own delay for this reason.

**Fix.** `classify_delay` returns none outside `[72h, 30 days]` (`MAX_LOOSEN_DELAY_S`). Registration and `SetLoosenDelay` refuse the same window (`DelayBelowMinimum` / `DelayAboveMaximum`). Floor's upgrade delay uses the same cap. The Python reference and golden `CD` vectors match. Tests: `delay_outside_72h_to_30d_is_rejected_and_a_raise_inside_is_a_tightening`, `a_delay_below_72h_is_refused_and_an_abdicated_kind_is_gone_forever` (31 days), `the_delay_can_be_raised_instantly_but_lowered_only_after_the_delay` (31 days).

### A8 — A mint close authority can replace the mint (Low)

**What happens.** Token-2022 extension 3 was on the allowlist with no look at its authority. The close authority can close the mint once supply is zero, and the address can be created again with a permanent delegate or a transfer hook.

**Fix.** Extension 3 is allowed only when its 32-byte authority is all zeros. Test: `a_mint_close_authority_is_refused_unless_it_is_unset`.

### A9 — Pyth's trust root changed (Medium, stated)

Since 26 Aug 2026, Full verification on Solana is 3 of the Pyth Pro set's 5 keys. The backed lane is not rate-limited, so a price those keys sign is final. Both receiver programs the Vault accepts are official Pyth programs. Assumption 2 in `04` now names the set. Bounding new backed liabilities is a separate design item for the audit build.

### A10 — The seal does not cover pre-seal deposits (High)

**What happens.** `execute_seal` required `imported ≤ balance`. `import_backing` credits a ledger without moving tokens. A deposit before the seal moves tokens and credits another ledger, which raises the balance the check looks at. Import 1,000 after a deposit of 1,000: imported is 1,000, the balance is 1,000, the check passes, and backing claims are 2,000. After the seal the imported owner withdraws through the backed lane, which is not rate-limited, and takes the depositor's tokens.

**Fix.** The seal requires `imported + total_in ≤ balance + lifeboat_amount`, in u128. Test: `pre_seal_deposits_cannot_hide_an_uncovered_import`. Since 8 Oct the lifeboat balance excludes what a live (unvetoed) exit will take (`09`, finding 72).

### A11 — Harbor forwards its caller signature (Medium)

**What happens.** Harbor's caller PDA is the signature the Vault trusts as the protocol. The first account is the program Harbor invokes, taken from the transaction. Signer privileges carry into that call, so a copied integration signs for any program a caller names.

**Fix.** Harbor compares that account with `VAULT_ID`, baked in by `programs/harbor/build.rs` (`BULKHEAD_VAULT_ID`, default the devnet Vault) and returns `IncorrectProgramId` otherwise. Local deploys rebuild Harbor for their Vault keypair. The integration guide says to check the program id before signing. Test: `harbor_will_not_sign_for_a_different_vault_program`.

### A12 — Guardian delivery did not match the docs (Medium)

**What happens.** `cloud/lib/signer.mjs` sent one transaction to one RPC, with no Compute Budget instructions. Under congestion the freeze lands later. G1 bounds the loss by when it lands.

**Fix.** Guardian transactions set a compute-unit limit and a price (`policy.computeUnits`, `policy.priorityMicroLamports`) and the signed transaction is submitted to `rpc` and every URL in `rpcs`. The Compute Budget program id is the 43-character address; the 42-character truncation is not a program, and every guardian transaction then fails simulation with `ProgramAccountNotFound`. The docs no longer say "bundle tips". Tests: `compute-budget instructions encode limit and price`, `base58 round-trips well-known ids`, `a signed transaction is broadcast to every configured rpc`.

**8 Oct (`09`, finding 69b).** When a backup RPC landed the budgeted freeze with an error (compute exhausted), the unbudgeted fallback (finding 47) never ran; it now does. A send was also broadcast once; it is now re-broadcast every 2 s until confirmed or the blockhash expires.

### A13 — The guardian believes any log line (Medium)

**What happens.** `parseEvents` returned every `Program data:` line. `getSignaturesForAddress` lists every transaction that mentions the protocol account, so another program in that transaction can emit `vault:released` or `vault:frozen`. The runtime also truncates logs at 10 KB and the bot did not notice, which can hide a payout or invent one. Wormhole's Solana watcher had the truncation bug (wormhole#4065). The on-chain bound does not depend on the bot; the response layer does.

**Fix.** A line counts only when the innermost invoked program is the Vault or Floor. A `Log truncated` line sets `truncated`, and that transaction's events are ignored. Each cycle the bot sets `frozenUntil` from the protocol account. Instant outflow missing from the logs is `unbacked_out - settled` minus what complete events already recorded (settling a ticket increases both, so it is not a second instant). Ticket ids in `(last seen, next_ticket_id)` that no event reported are loaded and judged under the same rules. A ticket whose vault is not a configured mint is counted on its own (worst case 0, so any amount freezes) and the cancel uses that ticket's vault and its id (finding 67); it is not charged to the first configured mint. Tests: `cloud/test/events.test.mjs`, `cloud/test/policy.test.mjs`.

**8 Oct.** One Vault program serves every protocol, so "emitted by the Vault" was not enough: anyone who registers a protocol could put its events in a transaction that also lists the watched one, end its incident hold or make its guardian veto an approved change (`09`, finding 64). Every Vault event now ends with its protocol's key; the guardian acts only on events naming its own protocol and drops events naming none (an older Vault build, such as the one on devnet). A transaction returned without logs read as "no events"; it now counts as truncated (69f).

## 3. Attacks that did not work

Each was tried and found closed; listed so nobody re-spends the time.

| Attack | Why it fails |
|---|---|
| Clock stepping backwards between requests to reuse capacity | The limiter uses `max(TAT, now)`; 2,000 random sessions with backward steps stayed within G1 over the real elapsed span (worst 0.9987 of the bound). `clock_stepping_backwards_never_beats_g1` |
| Flash-loan deposit to raise the base inside one transaction | **This row was false until 8 Oct** (`09`, finding 65). `touch_reference` uses the balance *before* the operation and sets `ref_updated_s = now`, so the reference did not move, but the live balance did, and after a large exit the reference lagged above it. Now the base is also capped by the low-water balance, which still holds the balance before the deposit |
| Donating tokens to the vault account before the first touch after a quiet day | After a quiet day (`dt ≥ 24h`) the next touch moves the reference the whole way to the donated balance, and neither `min` nor the low-water balance changes that (after a quiet window both equal the balance). Measured: 9,535,175 USDC in the next day against a 1,000,000 USDC bound on the pre-donation vault (9.5×). **But it is not an attack on depositors:** the 90M donated belong to nobody, the drain comes out of them first, and the depositors' 10M are still there (asserted). The donor gets back part of their own gift. Absolute caps bound the figure anyway. `donation_after_a_quiet_day_inflates_even_with_min_balance` |
| Crediting backing to someone else | Backing goes to the signer of the source token account; nobody can sign for another owner's account |
| Fake recipient account to borrow another owner's backing | `release` reads the owner from the recipient token account (owner-checked against both token programs, initialized state checked) and loads that owner's backing PDA by re-derivation |
| Omitting an asset account so an allowlisted mint looks unlisted | `price_table` requires the asset PDA at the derived address; an empty account there is accepted only as "not listed". A neighbouring gap stayed open until 8 Oct: an `UpsertAsset` loosening read an unchecked asset record, so it could outlive a later tightening (finding 63); the record must now be the target's PDA |
| Partial-verification or wrong-feed price accounts | Only `Full` updates owned by the Pyth receiver count as prices (anything else is unpriced, which fails closed); a wrong feed id is refused |
| Token-2022 extensions in the custody path | Allowlist by extension number; hooks, permanent delegate, confidential transfers, pausable and non-transferable are refused. InterestBearing (10) and ScaledUiAmount (25) are allowed in custody but never priced (finding 68, 8 Oct) |
| Old guardian approvals counted after an ejection shifts indices | Floor clears `pending_approvals` on eject |
| A proposal made before an abort executing after it | `abort` clears a pending owner proposal. A recovery-key proposal survives the stop on purpose: otherwise a stolen owner key could erase it by stopping the program |
| Re-proposing a vetoed lifeboat exit to skip the veto | A new proposal restarts the full 72h and is vetoable again; the destination must predate the proposal by 72h |

## 4. The idea, attacked

Weaknesses in the product argument rather than the code. None of these kills it; each is a question a judge or a protocol's risk team will ask.

1. **"2% of a vault" was 2% of the reference.** See A1, fixed on 29 Sep and again on 8 Oct: it is now 2% of the least of the live balance, the reference and the low-water balance. A parked-capital attacker still needs absolute caps (A1b), so the pitch claim is "2% of the vault, with calibrated caps".
2. **Transferable receipt tokens break the backed lane.** Backing belongs to whoever deposited. When a protocol's position is transferable (LP tokens, cTokens, kTokens, LSTs), a buyer on the secondary market withdraws with no backing, so honest withdrawals go through the unbacked lane and can queue. Calibration then pushes the limits up and the bound weakens. The integration guide (`07`) should name which protocol designs fit well (non-transferable positions) and which need a backing-transfer hook.
3. **A circuit breaker can turn a crash into insolvency.** Liquidation bonuses and cross-mint seizures are partly unbacked. In a cascade, liquidations that exceed the daily bucket queue for at least 6 hours while prices keep falling, which leaves bad debt. `07 §3` says "size the daily bucket for cascades"; that is the whole question for lending protocols, and it deserves a scenario with a historical crash (a Pyth replay of a −30% day). **Measured 30 Sep** on a synthetic −30% day (`08` S11): 14–17% of each liquidation is unbacked, about three times the bonus. With the defaults, a 10-minute −20% crash that liquidates 17% of a vault already queues some liquidations for 6 hours (22% for a 30-minute crash, 43% for a 2-hour one). 4%/h and 10%/day absorb a 30% cascade, at the price of doubling G1. A replay of real Pyth history is still to do.
4. **"Guardians can only grief" understates a stolen key.** A3 and A4 are fixed: the recovery key replaces a compromised admin or owner key, and a compromised recovery key is replaced at once. What remains is denial of service until the replacement executes (at least the loosen delay), and only for protocols that named a recovery key.
5. **The freeze response is a bot plus people.** See A2: thresholds can be paced, and the bot needs uptime, RPC access and a funded key. The claim that should appear in the pitch is the on-chain bound, not the response time.
6. **Bulkhead's own key is the biggest key.** Until the upgrade authorities are burned after audit (G9), whoever holds the Bulkhead team key can replace the code that holds every protected vault. It is disclosed in `SECURITY.md`; protocols will ask how and when it is burned, so the burn plan (and whether Bulkhead itself sits under Floor meanwhile) should be one slide.
7. **Immutable means unpatchable.** After the burn, a bug in Bulkhead can't be fixed in place; the only way out for funds is each protocol's lifeboat exit (72h plus the destination rule). The docs should say that migration to a new version is the upgrade path, and how long it takes.

## 5. Recommended order

1. ~~A1 on-chain fix, then redeploy and re-verify.~~ Done 29 Sep (devnet upgraded in place); absolute caps in calibration (A1b).
2. ~~A3.~~ Done 29 Sep. ~~Decide A4.~~ Decided and fixed 6 Oct (a recovery key).
3. README and pitch wording for items 1, 4 and 5 of section 4.
4. ~~A liquidation-cascade scenario (section 4, item 3).~~ Synthetic run done 30 Sep (`08` S11); a real Pyth replay and a program-level run remain.
5. ~~A5 alerts in the status page and the bot.~~ Done 30 Sep.

## 6. Second review (30 Sep 2026)

A line-by-line pass over every program, the core, the Cloud guardian and the tooling, with the external facts re-read from primary sources (Token-2022 and Agave source, Pyth's SDK, docs and DAO proposals). The HumanLayer research and design documents for it are `02-research` and `03-design-discussion` in the task folder.

| # | Severity | Finding | Status |
|---|---|---|---|
| A7 | **Medium** | The Vault's loosen delay had no upper bound; raising it is a tightening, so one key could put every later loosening (admin and guardian replacement included) out of reach | **Fixed** 1 Oct (#8): a 30-day cap in the core, the Vault and Floor; on devnet since 6 Oct |
| A8 | Low | The mint policy allowed `MintCloseAuthority` with an authority set; a zero-supply mint can then be closed and created again with extensions the policy refuses | **Fixed** 1 Oct (#8): extension 3 only with no close authority |
| A9 | **Medium** | Pyth's trust root changed on 26 Aug 2026 (3 of the Pyth Pro set's 5 keys); backed borrowing trusts a verified price completely | Documented in `04` (assumption 2, T5); a rate limit on new backed liabilities is a design item for the audit build |
| A10 | **Medium** | The seal compared imported backing with balances but not the backing pre-seal deposits create, so total claims could exceed the tokens held | **Fixed** 1 Oct (#8): `imported + total_in ≤ balance + lifeboat_amount` |
| A11 | **Medium** | Harbor, the reference integration, didn't check which program it forwarded its caller-PDA signature to, and the guide didn't say to | **Fixed** 1 Oct (#8): Harbor checks a built-in Vault id; guide step added |
| A12 | **Medium** | The docs said guardian freezes use priority fees and several RPCs; the code used neither | **Fixed**: compute budget with an automatic priority price, broadcast to every configured RPC |
| A13 | **High** (response layer) | The guardian believed any `Program data:` line in any transaction touching the protocol, and didn't notice truncated logs | **Fixed**: events count only when the Vault or Floor emitted them; freeze state and tickets come from the chain; a truncated log's outflow comes from token balances |

The on-chain bound (G1) was never affected by A12 or A13: they concern how fast, and on what information, the response layer acts.

Hardening in the same change (#8): the account-type byte in `token::account_info`, a checked age in `price::is_usable`, `attest` capping "available now" at the balance, and two stale comments rewritten line-for-line. Design notes recorded without change: vaults created after the seal, a queued loosening replacing a later tightening, loosenings executing during a freeze, a threshold equal to the guardian count. A4 was open then; its fix (6 Oct) inherits A7's cap.
