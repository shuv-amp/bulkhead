# 14 — State of the art: what the best systems do, and what Bulkhead takes from them

Researched 26 Sep 2026. For each part of Bulkhead:
1. The strongest shipped or published prior art, read from source code or primary docs where possible.
2. What Bulkhead adopts.
3. What it rejects, and why.

The goal is that no judge, auditor or competitor can name a better-known mechanism we haven't considered.

## 1. The rate limiter

| System | Mechanism (read from source/docs) | Weakness for our threat model |
|---|---|---|
| **Wormhole NTT** (Solana program `queue/rate_limit.rs`) | One bucket, linear refill over 24h. Over-limit transfers are queued for 24h. The source says: "Transactions that exceeded the capacity do not count, they are just delayed"; `consume_or_delay` returns `Delayed(now + 24h)` without reserving anything. "Backflow": inbound transfers refill outbound capacity. | Queued transfers don't reserve capacity, so all of them become releasable after 24h: the delay *is* the defense, and it requires someone to act. Backflow lets inflows create outflow room. |
| **Chainlink CCIP** token pools | Token bucket per lane and direction (`capacity`, `rate`); over-limit transfers revert | Bounded, but no queue: large honest transfers just fail |
| **xERC20 / ERC-7281** | Per-bridge mint and burn limits with linear 24h replenishment | Bridges only; set by the token owner |
| **Kamino** (klend `withdrawal_cap_operations.rs`) | Per-reserve `deposit_withdrawal_cap` and `debt_withdrawal_cap`: a **fixed-window** counter that resets to 0 when the interval elapses. Depositors' own redemptions (`redeem_reserve_collateral`) count toward it; deposits subtract. Capacities are admin reserve config. | Fixed windows allow ~2× the cap across a window boundary. Honest depositors are throttled in a bank run. The admin can raise the cap (the Drift pattern). |
| **Spark ALM Controller** (Sky) | Rate limits so a fully compromised relayer can only do bounded damage; a freezer can only remove the relayer | EVM; one protocol protecting its own relayer |
| **Zodiac Roles v2**, **Squads spending limits** | Refilling allowances per role / per member | Treasury permissions, not protocol vault custody |
| **Network calculus** (Le Boudec & Thiran; ATM Forum dual GCRA for VBR; IETF IntServ T-SPEC, RFC 2212) | Several token buckets in parallel; the conformant flow's arrival curve is `α(t) = min_i(b_i + r_i·t)` | — (theory) |

**What Bulkhead takes:**
- **The dual bucket is the textbook shape.** Our burst + daily cap is the peak + sustained pair of ATM's dual GCRA and IntServ's T-SPEC. Our G1 bound, `min(C_s + C_s·T/W_s, C_l + C_l·T/W_l)`, is exactly the network-calculus arrival curve of two buckets in parallel. This is well-understood math, not a new invention.
- **GCRA, not a fixed window.** No boundary cliff (Kamino's weakness), and O(1) state.
- **Queue like NTT, but reserve like CCIP.**
  - Over-limit requests become tickets (honest users are delayed, not failed).
  - Unlike NTT, tickets **reserve** capacity. The G1 bound holds even if nobody ever responds.

  We have not found another system that combines both.

**What Bulkhead rejects:**
- **Backflow / netting deposits against withdrawals** (NTT, Kamino). If inflows refilled the unbacked bucket, an attacker could deposit worthless tokens to open room for real withdrawals. Bulkhead handles "deposits come back" per owner, in the backed lane (§2), never by refilling the global limiter.

## 2. The backed lane (own deposits never throttled)

We searched for a shipped system that exempts each depositor's own funds from a protocol-level outflow limit using a per-owner record, and did not find one:
- Kamino and NTT net flows *globally*.
- Allowance systems (Zodiac Roles, Squads) limit *roles*, not depositors.
- Bridges have no notion of "your own deposit."

The closest idea is a per-account ledger inside the protocol itself. That is exactly what a compromised admin controls.

**Our claim, stated carefully:** "not found in any system we checked" (the list above). Not "first."

Valuation follows established practice: haircuts, confidence-interval bounds and EMA-vs-spot (Pyth's own recommended conservative pricing). Collateral is valued low, liabilities high, and missing prices fail closed.

## 3. Tighten fast, loosen slow

| System | Rule |
|---|---|
| **MetaMorpho (Morpho Vaults V1)** | Timelock 1 day to 2 weeks. "Increasing … takes effect immediately"; decreasing waits "the current (longer) timelock duration." Cap increases are timelocked; the guardian can revoke pending actions. |
| **Morpho Vaults V2** | Per-function timelocks. Decreasing a function's timelock waits that function's current timelock. A timelock can be set to infinity ("abdication"). |
| **Aave Risk Stewards** (v3, v4) | Bounded changes: e.g. caps can move at most ±50% per update, with 36–72h cooldowns per parameter; "each entry must independently land within ±maxPercentChange" (no chaining). |
| **Maker DC-IAM** (`dss-auto-line`) | Debt ceiling rises automatically but at most `gap` per `ttl` |

**What Bulkhead takes:**
- The MetaMorpho asymmetry, as a **constant** floor (72h) no admin can lower.
- Guardian revocation (our veto).
- **Abdication** (Morpho V2): a protocol can permanently give up a change kind, e.g. "never allowlist a new asset." It is a tightening, instant and irreversible. Implemented in `bulkhead-core::governance::Abdications` and proved monotone with Kani.

**What Bulkhead rejects (for now):**
- **Aave-style bounded fast loosening** (e.g. +25% capacity after 24h). It helps growing protocols but adds a second path to loosen. The single 72h path is easier to explain, test and audit. Revisit only if calibration with a design partner shows 72h is too slow for honest growth.

## 4. Stop buttons and guardians

| System | Design |
|---|---|
| **Lido GateSeal** (archived) | One-time panic button, expiring after at most 1 year, pause ≤ 14 days |
| **Lido CircuitBreaker** (2026 successor) | Permanent contract. Pausers must send periodic **heartbeats**; "a pauser whose heartbeat has expired cannot pause or refresh their heartbeat." After a pause, the pauser assignment is cleared and must be re-assigned. |
| **Aave (Sep 2026 proposal)** | Emergency stewards can freeze markets but not unfreeze them |
| **Dean Little's `sbpf-asm-abort`** | 136-byte sBPF v3 program; upgrading to it stops a Solana program in one transaction, state preserved |

**What Bulkhead takes:**
- **Guardian heartbeats** (Lido). A guardian that has not heart-beat within its interval (1–30 days, default 7) can't freeze, veto, approve or abort. Reviving it is a loosening (72h). The status page shows "live guardians: k of n," which is public evidence that someone is awake. `governance::guardian_alive`, `governance::quorum` (quorum counts live guardians only).
- **Freeze without unfreeze** (Aave): any guardian freezes; only a live quorum unfreezes.
- **Dean's abort pattern** for Floor (our own binaries, credited), turned into a control system: stop by any live guardian, change only after the delay, undo through a snapshot verified byte-identical on-chain, and a binary that says why it fails (`06 §2` compares the two point by point).

**What Bulkhead rejects:**
- **Single-use pauses** (Lido). Lido's DAO is trusted and a pause hurts stakers. In Bulkhead's threat model **the admin is the attacker**. If every guardian freeze were single-use and needed the admin to re-arm, the attacker (who holds admin) simply wouldn't re-arm. Guardians must be able to keep re-freezing (each call ≤ 24h). Griefing is bounded because freezes never touch the backed lane, and a live quorum of the other guardians ejects a griefer at once (a vetoable rotation would never finish: the griefer could veto its own removal).

### 4b. In-protocol limits already shipping on Solana: Project 0 (marginfi v2)

The strongest in-protocol design we found (`01 §9`):
- hourly and daily net-outflow limits per bank and per group;
- a price circuit breaker;
- a panic pause bounded to 6h × 4 consecutive, 3 per day.

| Question | Project 0 | Bulkhead | Why Bulkhead differs |
|---|---|---|---|
| Who can loosen a limit | Admin or limit admin, immediately (0 disables) | Nobody faster than 72h, public, vetoable | The admin is in our threat model (Drift) |
| What counts against the limit | Net outflow: inflows restore capacity for everyone | Unbacked outflow only; a deposit backs only its own depositor | Honest inflows never enlarge an attacker's budget |
| Pause budget | Bounded (anti-grief) | Freezes repeatable; a quorum ejects a griefer | A bounded budget can be waited out by an attacker who holds the admin key |
| Liquidations and flash loans | Skip the limiter | Liquidation repayment creates backing; the bonus is unbacked; flash loans are net-zero in one transaction | The limit stays in the path for every non-backed payout |

Project 0's choices fit its threat model (bugs, outside attackers). Bulkhead is a floor *under* limits like these. It is complementary, and Project 0 is a natural design partner.

## 5. Exit windows (the L2BEAT lens)

**L2BEAT Stages**, the de facto standard for rollup security:
- **Stage 1:** "Upgrades initiated by entities outside of the Security Council are allowed if they provide at least a 7 days exit window."
- **Stage 2:** at least 30 days, including upgrades initiated by a DAO.
- **Security Council bar:** at least 8 members, a threshold ≥ 75%, and at least half of members outside the organization.

Solana DeFi has no equivalent. Our census: 37 of 54 tracked multisigs have a 0-hour window.

**What Bulkhead takes:**
- **Floor's upgrade delay is an exit window.** With Vault, own-deposit withdrawals are instant, so the exit window equals the upgrade delay.
  - The constant minimum stays 72h (agility for Solana teams whose longest timelock today is 24h).
  - **The recommended default is 7 days**, and the status page labels a protocol "Stage-1-grade exit window" only at ≥ 7 days.
- **The fast restore path needs a Security-Council-grade quorum.** Floor lets a guardian quorum restore a stopped program without the delay, which is Security-Council-level power. The status page shows whether the guardian set meets L2BEAT's bar (≥ 8, ≥ 75%, ≥ 50% outside). Floor requires quorum ≥ 2 regardless.

**What Bulkhead rejects (for now):**
- **Lido Dual Governance's dynamic timelock** (delay grows with depositor opposition, plus rage-quit). It is elegant, but it needs an escrow and a state machine we can't verify well in 16 days. The fixed 72h floor plus guardian veto plus instant own-deposit exits covers the same user need ("I can leave before a bad change lands") more simply.

## 6. Verification: beyond differential testing

| Practice | Where it is state of the art | Bulkhead |
|---|---|---|
| Differential testing against a reference | Firedancer vs Agave (`solfuzz`, `solana-conformance` test vectors); SpecTrum (spec-guided differential fuzzing of Ethereum clients, 2026); SP-Differ (BIP-352) | Python reference vs Rust core on millions of cases; **programs vs the core model** on the real runtime (12,000 random steps); JavaScript vs Python for the status page (40,000 cases). Findings in `09 §4`. |
| Property-based testing with coverage checks | Standard | 21 property tests with coverage floors that scale with depth, 16 targeted unit tests written from mutation results, 5 exhaustive tests over ~25.7M inputs |
| **Bounded model checking** | **Kani** (AWS; used on the Rust standard library and s2n-quic; ASE '26 paper) | **Adopted:** proof harnesses in `crates/bulkhead-core/src/proofs.rs` for logic; arithmetic that SAT solvers cannot finish is enumerated exhaustively instead (`09 §5`) |
| **Mutation testing** | `cargo-mutants` | **Adopted:** measures whether our tests catch injected bugs (results in `09`) |
| Formal verification of Solana programs | **Certora Solana Prover** (open source; CVLR). Squads v4 was formally verified with it; Certora lists Kamino and Jito among users. | **Next:** CVLR rules for I1, I8, I11, I12 on the built programs (before any audit) |
| Guided fuzzing of Solana programs | **Trident** (Ackee; flows + invariants) | Our program-vs-model differential covers the same ground with an exact oracle; Trident flows are a planned addition |
| Verifiable builds | OtterSec `solana-verify` | Required before any mainnet claim |

## 7. Product-level check: what won recently, and what is crowded

- **Colosseum Frontier (Apr–May 2026):**
  - 2,857 submissions, 26 winners, grand champion a robotics DePIN (CrowdBrain).
  - Exactly one security winner: **Sudont**, "agentic crypto security platform providing bare-metal execution firewall and local RPC." That is user/agent-side, not protocol custody.
  - YieldCompass (risk scoring; builds `solana-upgrade-watch`) also won.

  Security can win, but winners showed users and a clear product. Our answers: Floor's one-transaction adoption, and the status page / exit-window view that users and curators can read.
- **Crowding for custody-level limits on Solana:** Sentinel (loosenable, not custody) and Holdfast (human pause) remain the closest (`01 §8`). Nothing found holds vault custody with a backed/unbacked split.

## 7b. STRIDE (the Solana ecosystem's own scorecard)

STRIDE's framework has 8 pillars and 40 controls. Bulkhead gives on-chain evidence for:
- **G2** Upgrade authority;
- **G3** Timelock & delay mechanisms;
- **G5** Risk parameter controls;
- **E3** Staleness & liveness handling;
- **E4** Blast radius containment;
- **P4** Defense-in-depth (rate limits, per-epoch caps, graduated withdrawal limits);
- **M2** Automated circuit breakers.

Our own build practice targets:
- **P5** Automated security tooling (Kani, mutation testing, differential);
- **S1** Dependency pinning (zero-dependency core, pinned toolchain);
- **S4** Signed & reproducible releases (solana-verify).

## 8. Decisions this research changed (logged in `00`)

1. Guardian heartbeats and live-only quorum (Lido CircuitBreaker, Aave).
2. Abdication (Morpho V2).
3. Floor's recommended upgrade delay is 7 days, labelled as an exit window with L2BEAT's Stage-1 bar; the fast-restore quorum is checked against L2BEAT's Security Council bar.
4. Verification adds Kani proofs and mutation testing now, and Certora + Trident for the program.
5. Kept, with reasons written down: repeatable guardian freezes (not single-use), no backflow, no bounded fast-loosening, no dynamic timelock.
6. (27 Sep) The Security Council model: a live quorum can eject a guardian instantly, so one bad key can't hold a protocol hostage (D22).
7. (27 Sep) Floor's snapshot restore: undoing a stop can't introduce new code (D23). This follows from a loader fact: a program may not CPI `Write`, only verify frozen buffers.
8. (27 Sep) Per-owner backing instead of net-flow limits, stated against Project 0's design (§4b).
