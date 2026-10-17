# 00 — Decision record

Status: decided, Sat 26 Sep 2026. Supersedes the earlier Bulkhead build package and the SP-Differ-on-Solana plan.
Change this file only with new evidence, and add a dated entry to the log at the bottom.

## The company in one sentence

**Bulkhead is a circuit breaker for Solana protocols that the protocol's own admin can't turn off.**

It is one small immutable program family with two products:

| Product | What the protocol hands over | What it gets | Integration |
|---|---|---|---|
| **Floor** (Tier 0) | Its program's **upgrade authority** | Upgrades wait at least 72 hours, in public, and any guardian can veto. Any guardian can stop the program in one transaction. | One transaction, zero code changes |
| **Vault** (Tier 1) | Its **vault token accounts** (and optionally mint authority) | Unbacked payouts count against 2% per hour and 5% per day when they are requested (each a refill rate on a bucket of the same size), and above that wait at least 6h in a public queue; an owner taking back their own deposit is never throttled, frozen or priced. | About 40 lines of CPI calls |

Floor is how a protocol says yes in one afternoon. Vault is what bounds a Drift. The pitch never claims Floor bounds a Drift.

## Why this, in four facts

1. **Guardrails the admin controls don't protect you from the admin.**
   - Drift lost about $285M on 1 Apr 2026. The attacker, holding admin power, raised the protocol's own withdrawal limits (Halborn, BlockSec, Chainalysis).
   - Drift had removed its timelock on 27 Mar, five days earlier. Its fix after the hack is more timelocks.
2. **Timelocks on Solana are settings, not floors.** Of 54 Squads multisigs governing the 62 protocols solgov tracks:
   - 37 have no timelock.
   - The longest is 24 hours; none reaches 72.
   - 16 of 43 have changed their timelock at least once.

   Also, 8 of 183 tracked programs can be upgraded by a single plain key. (`evidence/solgov_census.py`, snapshot of 26 Sep 2026, spot-checked on-chain.)
3. **Stop buttons are too late.** In 183 DeFi incidents:
   - 87 protocols had a pause, and only **1** used it within the first hour.
   - **44% of attacks finished inside a single transaction** (Zhou et al., *SoK: DeFi Attacks*, IEEE S&P 2023).
   - Since 15 Sep 2026 a Solana transaction can be 4,096 bytes instead of 1,232 (SIMD-0296), so more of an attack fits in one atomic shot.
4. **Therefore the brake has to sit in the path of the money.** On Solana the only path an admin or upgrade key cannot bypass is the owner of the token account. Bulkhead becomes that owner.

Evidence with exact quotes: `01-EVIDENCE.md`.

## Decisions

Each row is a choice we will not reopen without new evidence.

| # | Decision | Choice | Why | Rejected alternative (and why) |
|---|---|---|---|---|
| D1 | What to build | Bulkhead (Floor + Vault) | Largest verified failure of 2026, measured governance weakness, a primitive with provable bounds, and a founder whose record is finding bugs in shipped crypto code | SP-Differ for Solana stealth (~50–100 sweeps/week, no payer). A v3-migration replay tool (svmscope and QEDGen already do it). A governance monitor (solgov exists, and a monitor acts only after the damage). A signer or durable-nonce guard (Drift disabled nonces; shield and Blockaid cover it). |
| D2 | Where to enforce | **In the money path** (custody of the vault token account) | Only in-path enforcement bounds an atomic attack (44% of incidents) and an admin who changes the rules | Detect-then-pause (Hypernative, Holdfast, Sentinel's trip, a bare abort button). All of these act after the transaction that did the damage. |
| D3 | Limiter shape | **Two GCRA buckets**: 2% per hour (burst) and 5% per 24h (daily cap) | With one hourly bucket, a patient attacker who only takes the refill gets 50% in a day. With the daily cap, 24h of total silence costs 10% (Drift model: $55M instead of $275M). | Single bucket (the original spec). Fixed daily withdrawal limit (resets create cliffs; GCRA has none). |
| D4 | Queue semantics | FIFO tickets that **reserve** capacity, **no refund** on cancel, `reset_backlog` only with **zero pending tickets**, 7-day horizon | Each rule is required for the G1 proof (`03 §2.5`). The reset rule stops a cancelled attack from locking honest flows for days. | Refund on cancel (breaks the bound through idle-time credit). Reset while tickets are pending (breaks the bound; the property test would fail). |
| D5 | Backed lane | Per-owner shadow ledger, **value-based** at conservative Pyth prices, allowlist, fail closed | Honest users never notice: own deposits need no prices; borrows against real collateral are backed. Junk collateral backs nothing, which is the Drift, Mango, Cashio and Loopscale pattern, unless the junk is allowlisted with a Pyth feed (Mango's MNGO had one): only allowlist deep assets. | Same-mint only (throttles every normal borrow, so the limit must be set loose). No backed lane at all (every withdrawal throttled, so nobody adopts). |
| D6 | Loosen delay | **72 hours, a compile-time constant**; tightening is instant | Longest timelock we measured on Solana is 24h; 72h spans a weekend in every timezone; a constant cannot be "migrated away" the way Drift's timelock was | A configurable timelock (that's what Drift removed) |
| D7 | Emergency moves | **Lifeboat**: admin can move funds instantly into a Bulkhead-held lifeboat; leaving the lifeboat waits 72h and goes only to a pre-committed destination | The original instant, unlimited "rescue to an address" is a hole if the same signers are tricked (Drift's signers pre-signed transactions) | Instant rescue (exfiltration path). No rescue at all (a protocol bug would leave funds exposed to the buggy program). |
| D8 | Guardians | Can freeze, cancel, extend, veto, abort (Floor). **Can never move funds or choose recipients.** | Bounded damage from a malicious guardian: denial of service, not theft | Guardians with rescue power |
| D9 | Floor (Tier 0) | Separate small program holding upgrade authorities: 72h constant delay, guardian veto, a stop by any live guardian through a pre-staged abort binary that says why it fails, undo through a snapshot verified byte-identical on-chain (D23), a fix only with quorum approval of its exact frozen buffer or the full delay, `Close` unreachable | Zero-code adoption; the "stolen upgrade key" attack surface is closed; Dean Little's abort pattern (credited) turned into a control system (`06 §2`); SIMD-0500 recorded at every install | Asking every protocol to move vaults on day one; a bare abort binary pressed by the upgrade key itself |
| D10 | SIMD-0500 | Floor reads the protected program's ELF header at registration and warns if it is not sBPF v3 | After Agave v4.4 activates SIMD-0500, `Upgrade` rejects pre-v3 ELFs, so aborting a v0 program is a one-way door until a tested v3 build exists; 17,279 upgradeable programs were v0 when the SIMD was written | Ignoring it (a real outage risk for integrators) |
| D11 | Core math | `bulkhead-core`: pure Rust, **zero dependencies**, `no_std`, checked arithmetic | The enforcement math has no supply chain, and the same crate runs on-chain, in tests and in the differential worker | Math inside the program (untestable in isolation) |
| D12 | Verification | Three independent statements of every rule: Rust core, Python reference, property-test predicate. Differential runner on millions of cases. | SP-Differ's method, which found a real BIP-352 bug; here it already found a truncation bug in our own code (`09 §4`) | Unit tests only |
| D13 | Program framework | **Pinocchio** for Floor and Vault (revised 27 Sep); all math stays in the zero-dependency core | Floor showed it works: 56 KB, a 10k-CU stop of a 200 KB program, no framework code. Both programs share one dependency (the verified core) and one test harness. Every account check is explicit and has a negative test. | Anchor (the 26 Sep choice): faster to write, but a framework and IDL layer between the audit and the bytes |
| D14 | Test environment | LiteSVM for deterministic tests and scenarios; devnet for public signatures | Clock control, speed, no infra | Surfpool mainnet fork as the primary (heavier; optional later) |
| D15 | Money | Open-source core (Apache-2.0), immutable after audit. Revenue from **Bulkhead Cloud** (hosted guardian, calibration, attestations, STRIDE evidence). No token. No on-chain fee. | Fees in the enforcement path add attack surface and slow adoption; security budgets already exist | Token, protocol fee on releases, selling insurance ourselves |
| D16 | Scope of the chain | Solana only | The custody model, the loaders, SIMD-0500 and the measured census are Solana-specific | EVM port (Spark, Phylax, Venn already serve EVM) |
| D17 | Guardian liveness | Guardians must heart-beat (interval 1–30 days, default 7). A dead guardian can't act; reviving it is a loosening. Quorums count live guardians only. | Lido CircuitBreaker's heartbeat rule; public proof that someone is awake behind the "freeze in 2 minutes" claim | Unmonitored guardian keys that quietly go stale |
| D18 | Abdication | A protocol can permanently give up *loosening* a change kind (e.g. never add an asset). Needs the admin **and** a live guardian quorum; irreversible; tightening that kind stays instant. (Until 29 Sep the admin alone could abdicate, and an abdicated kind refused tightening too: `15`, A3.) | Morpho Vaults V2; lets a protocol prove a power is gone forever. The quorum stops a stolen admin key from locking itself in by abdicating `SetAdmin` | Only time-delayed loosening; admin-only abdication |
| D19 | Exit window | Floor's constant minimum stays 72h; **recommended default 7 days**; status page labels ≥ 7 days "Stage-1-grade exit window" (L2BEAT) and checks the fast-restore quorum against L2BEAT's Security Council bar (≥ 8 members, ≥ 75%, ≥ 50% outside; the page checks the first two, which are on-chain) | Adopts the industry's accepted standard without forcing teams whose longest timelock today is 24h | Forcing 7 days (adoption); ignoring the standard |
| D20 | Guardian freezes are repeatable | Each freeze ≤ 24h, re-freezable; only a live quorum unfreezes | In our threat model the admin is the attacker, so single-use pauses (Lido) that the admin must re-arm would fail exactly when needed | Single-use pauses |
| D21 | Verification depth | Add **Kani** bounded proofs and **mutation testing** to the core now; **Certora Solana Prover** (CVLR) rules and **Trident** fuzzing for the program | Kani and Certora are the strongest open tools for Rust/Solana (Certora verified Squads v4); mutation testing proves the tests bite | Tests only |
| D22 | Guardian model | **Security Council model:** any single live guardian may stop (freeze, veto, cancel, abort); a live quorum may always undo a minority (unfreeze, restore) and **eject a guardian at once** (never below the threshold, which is ≥ 2) | Without ejection one malicious guardian could veto its own removal forever and keep re-freezing or re-aborting; rotation would never finish. No new trust: a quorum can already restore approved code under Floor. | Rotation through a vetoable 72h change (deadlocks); a bounded pause budget like Project 0's (an attacker holding the admin key can wait it out) |
| D23 | Undoing a stop | Floor restores a **snapshot**: a frozen buffer verified on-chain, at the moment of the abort, to be byte-identical to the stopped code. A quorum restores it in one instruction. | Makes a single-guardian stop safe to hand out: the undo is cheap and can't smuggle in new code. It follows from a loader fact: programs can't CPI `Write`, but can verify frozen buffers with `sol_memcmp_`. | Re-uploading the binary under stress (the bare-abort path); trusting off-chain hashes |
| D24 | What G2 promises | Bulkhead never throttles, freezes or prices the return of an owner's own deposit. It does not promise the tokens are in the vault: lending and bounded losses reduce the pool. | The program-vs-model differential showed the earlier wording overclaimed | "Your deposit always comes back" (not true of any pool) |
| D25 | Cloud guardian | Zero-dependency JavaScript (Node's built-in Ed25519); pure, unit-tested policy rules; one JSON line per decision | The key that can freeze protocols should have no supply chain, like the core | A framework SDK with hundreds of transitive dependencies |
| D26 | Status page numbers | Computed from raw account data by a JavaScript port of four core functions, checked against the Python reference and the Rust core (40,000 cases, 10,000 of them full-range, and every available-now view in 1,500 limiter sessions) and equal to the program's own `attest` in the end-to-end test | `attest` simulation needs a funded fee payer, which a public page doesn't have | Calling `simulateTransaction` with a borrowed third-party fee payer (fragile) |

## What we will not build (ever, in this company's current plan)

| Not building | Reason |
|---|---|
| A general monitoring dashboard | solgov, Range, Hypernative exist and do it well. Bulkhead consumes their alerts. Its status page shows only Bulkhead's own on-chain bound. |
| An oracle | We consume Pyth (and optionally SVI-style on-chain valuations); owning price risk is a different company |
| User-wallet protection (drainers, phishing) | Different threat, different product (wallet vendors own it) |
| AMM / DEX pool protection | Every swap output is unbacked by definition; the model does not fit |
| A token | Nothing in the product needs one |
| An insurance underwriter | We make losses bounded and publish the bound; partners price and carry the risk |
| An EVM port | See D16 |
| An AI agent | Not needed; adds nothing to a deterministic safety primitive |

## Kill criteria (pre-committed)

1. **Crowding.** Stop and rethink if a *shipped* Solana product does all three of these:
   - holds vault custody;
   - separates backed from unbacked value;
   - enforces a loosen delay the admin cannot reduce.

   Not found as of 28 Sep (`01 §8`, decision log).
2. **Floor only.** If Squads (or anyone) ships a non-reducible minimum upgrade delay with a guardian abort, drop Floor and point integrators there. Vault is unaffected.
3. **Technical.** If the S1 scenario does not pass on the real runtime, drop the web page and ship core, programs and terminal scenarios. (S1 passed on LiteSVM on 27 Sep and on devnet on 1 Oct.)
4. **Demand.** If none of the protocol teams contacted answers in writing, keep the product and narrow go-to-market to new launches and relaunches.

## Decision log

| Date | Entry |
|---|---|
| 24 Sep 2026 | Original Bulkhead package chosen out of ~100 ideas (single bucket, instant rescue, ~19-day plan). |
| 26 Sep 2026 | Research pass: Drift sources verified; Colosseum crowding checked (Sentinel, Holdfast: not custody). |
| 26 Sep 2026 | Prince (SVI) pointed to Dean Little's `sbpf-asm-abort`. Added Floor (Tier 0), scenario S8, the SIMD-0500 check. |
| 26 Sep 2026 | State-of-the-art pass (`14`): compared against Wormhole NTT, CCIP, xERC20, Kamino, Spark, MetaMorpho, Morpho V2, Aave stewards, Lido GateSeal/CircuitBreaker/Dual Governance, L2BEAT Stages, network calculus, Kani, Certora, Trident. Added D17–D21. Verification deepened: governance rules moved into the proven core; 14 Kani harnesses; mutation testing (every non-equivalent mutant killed; 18 equivalents documented); 6.9M differential lines identical. |
| 26 Sep 2026 | Redesign: dual bucket (D3), reset rule (D4), lifeboat instead of instant rescue (D7), fail-closed rule narrowed to non-allowlisted mints (D5). Core + reference + differential harness built; the harness found and we fixed a saturation bug in `capacity_from_ref`. |
| 27 Sep 2026 | Built: the Floor and Vault programs (Pinocchio, sBPF v3), Harbor (a demo integrator), the Cloud guardian and status page, `tools/floor_check.py`. Research: loader-v4 abandoned; CPI to loader-v3 allows only Upgrade/SetAuthority/Close; SIMD-0500 not active, v3 active; Project 0's limiter design (`01 §9`). Decisions D13 (revised), D22–D26. Findings recorded in `09 §4`: eject bitmap masking, a non-exact early exit, the G2 overclaim, the status page's fee payer, the guardian's start anchor. One runtime-level interaction held for responsible disclosure. |
| 28 Sep 2026 | Deployed on devnet: Floor, Vault and Harbor, byte-identical to the build; the demo market's seal proposed (executable from 30 Sep, 20:32 UTC). Competitor sweep (`01 §8`): Ellipsis Labs' `timelock-program-authority` (prior art for Floor's delay; 2023, not deployed), veto's Hold (a wallet-level vault, Sep 2026), Hexagate GateSigner (signing layer), Squads v5 (hooks and adaptive timelocks, not yet on mainnet; no guardian stop or non-reducible delay described). No kill criterion met. No design change: each idea that differs was already rejected (instant recovery, D7; per-user and net-flow limits, `01 §9`; a pause budget, D22), and a quorum "skip" of a ticket would break the G1 proof. |
| 29 Sep 2026 | Adversarial review (`15`) acted on. Capacities now come from `min(reference, live balance)` (A1: after a large backed exit, the old capacity paid 7.8× the daily bound on what was left); absolute caps are part of calibration (A1b: capital the attacker parks in the vault); abdication needs a guardian quorum and gives up only loosening (A3, D18). Guardian: freezes sent late now cancel queued tickets; single-vault freezes are read as such. The devnet Vault was upgraded in place before the seal (same id, market and seal time; `08`). |
| 30 Sep 2026 | Second review (`15 §6`), run with the HumanLayer workflow (research, design discussion, outline). Guardian: events count only from the Vault or Floor, freeze state and tickets come from the chain, truncated logs fall back to token balances, and every transaction carries a priority price and goes to every configured RPC (A12, A13). On-chain fixes (A7 delay cap, A8 mint close authority, A10 seal coverage, A11 Harbor's Vault id) land in their own PR, merged with the devnet upgrade after the S1 run. |
| 1 Oct 2026 | On-chain half of the second review merged: loosen and upgrade delays capped at 30 days (A7); the seal covers pre-seal deposits as well as imports (A10); a mint close authority is accepted only when unset (A8); Harbor signs only for the Vault it was built for (A11). Pyth's trust root since 26 Aug 2026 is stated (A9); a bound on new backed liabilities waits for the audit build. The devnet binaries are still the 29 Sep upgrade until they are upgraded in place. |
