# 01 — Evidence

Every number Bulkhead uses in a pitch, a README or a video comes from this file.

Each fact carries a label:
- **measured**: we read it ourselves from a primary source or on-chain.
- **reported**: a named third party says it; quoted exactly.
- **model**: computed by our code from stated inputs and assumptions.
- **assumption**: a stated input we could not verify.

URLs are in `13-SOURCES.md`. Access dates are 26 Sep 2026 unless noted.

## 1. Drift, 1 April 2026

| Fact | Label | Exact text | Source |
|---|---|---|---|
| Loss ~$285M | reported | "an estimated $285 million from its vaults"; "$285 million (over 50% of its TVL)" | Chainalysis |
| Exact loss | reported | "The total loss is $285,279,417.69" | BlockSec |
| Start time | reported | "approximately 16:05 UTC on 01 April 2026" | Chainalysis |
| The attacker raised limits | reported | "list CVT as approved collateral and increase withdrawal limits" | Halborn |
| Same, second source | reported | "relax withdrawal protections and circuit breakers" | BlockSec |
| Same, third source | reported | "Withdrawal limits were removed" | Chainalysis |
| How a limit is changed in Drift's code | measured | `handle_update_withdraw_guard_threshold` takes the admin signer (`AdminUpdateSpotMarket`: `admin: Signer`, `state` `has_one = admin`), has no delay, and applies the new value in one line: `spot_market.withdraw_guard_threshold = withdraw_guard_threshold;` | drift-labs/protocol-v2, commit `13e8e9b` (23 Jun 2026), `programs/drift/src/instructions/admin.rs` |
| Speed | reported | "31 rapid withdrawals over approximately 12 minutes"; Chainalysis also notes "vault drainage continued for over two hours" | BlockSec, Chainalysis |
| Signing compromise | reported | "through social engineering, got real Drift Security Council members to sign" transactions using "durable nonces" | Chainalysis |
| Governance shortcut | reported | "2-of-5 threshold configuration with zero timelock"; the council "eliminated timelocks a few days earlier" | BlockSec, Halborn |
| Date of timelock removal | reported | on 27 March Drift "removed its timelock entirely" | Bitcoin.com (citing Drift) |
| Fake collateral | reported | "CarbonVote Token (CVT)", created 12 March 2026, 750 million supply | Chainalysis |
| Per-asset drained | reported | JLP $159.3M, USDC $71.4M, cbBTC $11.3M, USDT $5.6M, USDS $5.3M, WETH $4.7M, dSOL $4.5M, WBTC $4.4M, FARTCOIN $4.1M, JitoSOL $3.6M | Chainalysis |
| Drift's fix | reported | "Timelocks will be enforced on all critical administrative actions"; "Durable nonces will be disabled for all signers" | Drift, 16 Apr update |
| Recovery money | reported | Recovery pool funded by Tether ($127.5M) and partners ($20M) | Drift, 16 Apr update |
| Recommendation | reported | "pause contracts when critical thresholds are exceeded, such as rapid large-scale withdrawals across multiple vaults" | Chainalysis |
| Pre-hack TVL $550M | **assumption** | Analyst estimate; consistent with "over 50% of its TVL" | spec source; Chainalysis |

**How we say it:** "Drift lost $285M. The withdrawals took about twelve minutes. The attacker had admin power and raised the protocol's own withdrawal limits. Drift had removed its timelock five days earlier."
**How we never say it:** "We would have saved Drift." Say "modeled" or "replayed."

## 2. Stop buttons are pressed late

Zhou et al., *SoK: Decentralized Finance (DeFi) Attacks*, IEEE S&P 2023 (arXiv 2208.13035v3). The dataset covers 183 incidents from 30 Apr 2018 to 30 Apr 2022. It is Ethereum/BSC-heavy, and that is stated wherever we cite it.

| Fact | Label | Exact text |
|---|---|---|
| Pause availability | reported | "87 of the 183 victims support the emergency pause mechanism (47.5%)" |
| Pause speed | reported | "only 51 of the 87 protocols (58.6%) pause their protocol within 48 hours, and only one protocol pauses within the first hour of the incident" |
| Distribution (Table VI) | reported | ≤1h: 1 · ≤6h: 24 · ≤12h: 11 · ≤24h: 7 · ≤48h: 8 |
| Atomic attacks | reported | "103 (56%) attacks are not executed atomically, granting a rescue time frame for defenders." So 80 of 183 (44%) **were** atomic. |

## 3. One transaction carries more since 15 Sep 2026

| Fact | Label | Source |
|---|---|---|
| Max transaction size raised from 1,232 to 4,096 bytes (SIMD-0296, v1 transaction format SIMD-0385), feature active at epoch 1035, 15 Sep 2026 | reported | Solana upgrades page; press coverage |
| Stated purpose includes landing workloads "as single atomic transactions instead of stitching them together with address lookup tables or Jito bundles" | reported | same |

**Use:** a single atomic transaction can now hold more attack steps. Anything that reacts after a transaction (pause, abort, monitor) cannot recover what that transaction took.

## 4. Governance census (our measurement)

Source: solgov's public API (`https://api.solgov.xyz/api/state`), a Colosseum Frontier project that reads Squads multisigs and upgrade authorities from chain. Snapshot of 26 Sep 2026, 04:56 UTC, committed as `evidence/solgov_state_2026-09-26.json.gz`. Reproduce with `python3 evidence/solgov_census.py`.

| Fact | Label | Value |
|---|---|---|
| Protocols tracked | measured | 62 (54 governed by Squads multisigs) |
| Multisigs with **zero** timelock | measured | **37 of 54** |
| Longest timelock | measured | **24 hours** |
| Multisigs with timelock ≥ 72h | measured | **0** |
| Multisigs that changed their timelock at least once (full history) | measured | **16 of 43** with complete history |
| Programs upgradeable by a single plain key (on-curve authority) | measured | **8 of 183** |
| Median fastest proposal execution | measured | 0.6 minutes |

**On-chain spot checks** (public RPC, `solana-upgrade-watch`, 26 Sep). Use them for internal confidence only; never name a protocol's weak setup on stage.

| Program | Result |
|---|---|
| Kamino kLend | Squads 5/10, 24h timelock |
| Project 0 Lending V2 | Squads 7/15, no timelock, 2 approved upgrade proposals queued |
| Jupiter Lend Liquidity | Squads 4/7, 12h timelock |
| A high-volume AMM | upgradeable by one wallet key |
| Drift Velocity (new program) | Squads 4/6, 1h timelock |

**Caveat to state out loud:** "tracked protocols", not "all of Solana."

## 5. SIMD-0500 and sBPF v3

| Fact | Label | Source |
|---|---|---|
| After activation, loader-v3 `DeployWithMaxDataLen`, `Upgrade` and finalization "must return `InstructionError::InvalidAccountData`" for SBPFv0/v1/v2 ELFs | reported | SIMD-0500 text |
| Planned for Agave v4.4; v4.4 is at alpha.5 (18 Sep 2026); v4.3.0 released 18 Sep | measured / reported | QEDGen issue #426; anza-xyz/agave releases |
| Mainnet counts when written: upgradeable loader-v3 programs SBPFv0 **17,279**, v1 12, v2 41 | reported | SIMD-0500 impact table (Blueshift program-sync) |
| Of the 183 programs of solgov-tracked protocols: 181 upgradeable, of which **179 are not sBPF v3** (only 2 are); 8 upgradeable by a single plain key | measured | `tools/floor_check.py` on every program, public mainnet RPC, 27 Sep 2026 (read-only; published only as totals) |
| v3 changes behavior: "a load that aborted under SBPFv0 now succeeds and execution continues" | reported | Anza migration guide |
| SBPFv3 activated on mainnet in June 2026 | reported | Anza, press |
| Dean Little's abort binary: 136 bytes, `e_machine 0xF7`, `e_flags 3` (v3) | measured | our read of `deploy/sbpf-asm-abort.so` |

| On-chain status, queried 26–27 Sep 2026 (`getAccountInfo` on the feature accounts): sBPF v3 deployment active on **mainnet since slot 428,976,000** and on devnet since slot 461,808,000; **SIMD-0500 not active** on either; mainnet and devnet run Agave 4.3.0 | measured | public RPC; feature ids in agave `feature-set/src/lib.rs` |
| SIMD-0500's feature: `disable_sbpf_v0_v1_v2_deployment` (`B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g`); a v3 ELF has `e_flags == 3` exactly (`e_flags 4` decodes to an unenabled V4; agave's `max_sbpf_version` is V3) | measured | agave `syscalls/src/lib.rs`, solana-sbpf `get_sbpf_version` |
| **Loader-v4 was abandoned**: its feature id is `LoaderV4WasAbandoned11111111111111111111111` | measured | agave `feature-set/src/lib.rs` |

**Use:** aborting a pre-v3 program is a one-way door after SIMD-0500 until the team has a tested v3 build. Floor records this at registration and at every install; `tools/floor_check.py` reports it for any program.

## 6. Market

| Fact | Label | Value | Source |
|---|---|---|---|
| Solana DeFi TVL | measured | $6.64B | DefiLlama API, 26 Sep |
| Solana stablecoins | measured | $16.63B | DefiLlama API |
| Solana protocols ≥ $10M TVL in categories Bulkhead fits (lending, perps, basis, yield, curators, capital allocators, CDP-like; excluding DEX, LST, bridge, RWA, CEX) | measured | **28** | DefiLlama API |
| Largest of those | measured | Kamino Lend $1.47B, Jupiter Lend $1.19B, Jupiter Perps $829M, Sentora Curator $362M, Solstice $216M | DefiLlama API |
| Private key compromises, share of stolen funds in 2024 | reported | 43.8% | Chainalysis (search result; not reopened) |
| STRIDE first findings | reported | "Only ~17% of protocols include advanced IR capabilities"; "~17% … logging and alerting"; "~13% … verifiable builds" | STRIDE (Asymmetric Research), June 2026 |

**Corrections to claims made earlier by the team.** Use the right column.

| Earlier claim | Correct statement |
|---|---|
| "60–100 Solana protocols ≥ $10M" | 28 in the categories Bulkhead fits |
| "17% have circuit breakers" | ~17% have advanced incident-response capabilities (STRIDE) |
| "Drained in 2.5 hours" | 31 withdrawals in ~12 minutes; activity continued for over two hours |
| Umbra "48.3% / 65.6%", "$155M, 70k users", "deanonymized at the sweep stage" | Paper: recipient identified in 48.5% (Ethereum), 25.8% (Polygon), 65.7% (Arbitrum), 52.6% (Optimism) of transactions; the other phrases are unverified and dropped |
| "CVT: 500M minted" (old scenario) | 750M supply (Chainalysis) |

## 7. Loss model outputs (label: model)

From `reference/drift_model.py` (output committed in `evidence/drift_model_output.md`). Inputs: §1 per-asset amounts, the $550M TVL **assumption**, vault balances proportional to drained amounts. Defaults: 2%/h and 5%/24h.

| Nobody freezes for | Dual bucket | Hourly bucket only | Without Bulkhead |
|---|---|---|---|
| 2 min (guardian bot) | **$11.4M** (2.1%) | $11.4M | $285M in ~12 min |
| 1 h | **$22.0M** (4.0%) | $22.0M | |
| 2.5 h | **$30.4M** (5.5%) | $38.5M | |
| 24 h | **$55.0M** (10.0%) | $275.0M | |
| 72 h | **$110.0M** (20.0%) | $285.0M | |

The time for half a vault to leave with nobody responding at all is **9 days** (dual bucket) against **24 hours** (hourly only). Drift actually lost 52% of TVL in about 12 minutes.

## 8. Prior art and crowding (checked 26 Sep)

| Item | What it is | Why it is not Bulkhead |
|---|---|---|
| Drift's own limits | In-protocol, admin-set | The admin raised them |
| Squads v4/v5 | Multisig timelocks, spending limits, v5 hooks | Treasury accounts; timelock is a setting |
| Wormhole Governor | Per-chain USD thresholds, 24h delay for large transfers | Bridge-only, guardian-enforced |
| **Spark ALM Controller (Sky)** | Rate limits bound a fully compromised relayer; freezer can only remove the relayer | **Closest shipped analog.** EVM, one protocol protecting itself. We cite it as validation. |
| EIP-7265, Phylax, Venn | EVM proposals / sequencer assertions / firewall | EVM |
| Blockaid Cosigner | Signing-layer policy | Prevents only if the policy catches it |
| Hypernative, Range | Detection, alerting, optional automated pause | Detectors; act after the fact |
| hand1111/sentinel (Apr 2026) | CPI-called rate limits, permissionless trip | Authority can loosen instantly; protocol can stop calling it; no custody |
| Yonkoo11/holdfast (Aug 2026) | 2-of-3 human pause via MagicBlock | Human quorum, after the fact |
| deanmlittle/sbpf-asm-abort | 136-byte one-transaction stop | Human-pressed, after the fact; we build it into Floor (credited) |
| solana-asm/shield | User-side transaction guards | The user chooses them; an attacker would not |
| solgov | Governance transparency, public API | Monitor; our data source |
| svmscope, QEDGen | Upgrade replay, verification tooling | Developer tools; possible partners |
| Colosseum arena search | — | Not possible without login (client-rendered); re-check logged in on 1 Oct |
| **Project 0 (marginfi v2)** (checked 27 Sep) | Hourly and daily net-outflow limits per bank and per group, a price circuit breaker, a bounded panic pause (§9) | The strongest in-protocol design we found. Its limits are configured by the protocol's admin or limit admin with immediate effect, so they protect against bugs and outside attackers, not against the admin key. Bulkhead is complementary: a floor under limits like these. |
| alizeeshan1234/solana-circuit-breaker (Apr 2026, 0 stars) | CPI-called outflow windows, auto-trip, a configurable delay for loosening single-transaction limits | Advisory (the protocol must keep calling it); no custody; the delay is configurable |

## 9. Project 0 (marginfi v2): a strong in-protocol design, and what it can't do

Source: `github.com/0dotxyz/marginfi-v2` (Apache-2.0), commit `35b5c66` (16 Sep 2026). Label: measured (read from the code).

| Mechanism | What the code does | File |
|---|---|---|
| Rate limiter | Hourly and daily windows per bank (native units) and per group (USD). A sliding-window counter weights the previous window by the time left. **Inflows (deposits, repays) credit outflow capacity.** Skipped for flash loans, liquidations and deleverage. | `programs/marginfi/src/state/rate_limiter.rs` |
| Who sets the limits | "Either the group admin or delegate limit admin can configure rate limits. Setting a limit to 0 disables rate limiting." Immediate effect. | `instructions/marginfi_group/configure_rate_limits.rs` |
| Price circuit breaker | Tiered halts when price deviates from an EMA or a long-window reference; cleared by the admin or risk admin; can be disabled through bank configuration | `state/bank.rs`, `instructions/marginfi_group/clear_circuit_breaker.rs` |
| Panic pause | 6 hours per pause, at most 4 consecutive and 3 per day, auto-expiring; by the fee admin or a pause delegate | `type-crate/src/types/panic_state_cache.rs`, `state/panic_state.rs` |
| Flash loans | The start instruction refuses CPI (instructions sysvar and stack height) and checks the end instruction's program and discriminator | `instructions/marginfi_account/flashloan.rs` |
| Losses travel through composability | Banks can hold positions in other venues (Kamino, Drift, JupLend, Solend) as collateral. `drift_claim_bad_debt` claims a "Drift bad-debt portal allocation" through a merkle distributor. | `instructions/drift/claim_bad_debt.rs` |

**What we take from it.**
- The market already wants outflow limits and circuit breakers; a top Solana lender ships them.
- Two design contrasts. Neither is a claim that Project 0 is unsafe; the choices fit its threat model.
  1. **Net-flow vs per-owner backing.** In a net-flow limiter, anyone's deposit raises everyone's withdrawal allowance, the attacker's included. In Bulkhead, a deposit backs only its own depositor, so honest inflows never enlarge an attacker's budget.
  2. **Admin-set vs slow loosening.** A limit its admin can raise instantly can't bound the admin. Bulkhead's loosenings wait ≥ 72h and are vetoable. Bulkhead's freezes are repeatable (the admin may be the attacker), with quorum ejection instead of a pause budget.
- Composability spreads loss, which is why `attest` exposes a venue's worst case to other programs on-chain.
