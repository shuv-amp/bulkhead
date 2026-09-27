# 11 — Business

## 1. The one-line business

**Bulkhead makes a protocol's worst case a published number, and sells the operations that keep that number small.** The core is free and immutable. Protocols pay for **Bulkhead Cloud**:
- a guardian that freezes in minutes, not hours;
- calibration on their own flows;
- the public attestation;
- evidence for STRIDE.

## 2. Market (measured 26 Sep 2026 unless marked)

| Fact | Number | Label |
|---|---|---|
| Solana DeFi TVL | $6.64B | measured (DefiLlama) |
| Solana stablecoins | $16.63B | measured |
| Solana protocols ≥ $10M in Bulkhead-shaped categories | **28** | measured |
| Solana tracked protocols whose governing multisig has **no timelock** | 37 of 54 | measured (solgov census) |
| Upgradeable Solana programs still on sBPF v0 when SIMD-0500 was written | 17,279 | reported (SIMD-0500) |
| Upgradeable programs of solgov-tracked protocols that are not yet sBPF v3 | **179 of 181** | measured (`floor_check`, 27 Sep) |
| Largest DeFi hack of 2026 so far | Drift, $285M, Solana | reported |
| Hacked protocols that paused within the first hour | 1 of 87 | reported (SoK) |

**Honest read:**
- The paying market on Solana today is small (28 protocols above $10M in our categories).
- Floor's free market is large: every upgradeable program, including the thousands of v0 programs that must face SIMD-0500.

The company grows by making "Bulkhead-protected" the default for new launches and relaunches, then expanding to every protocol a curator or fintech routes money into.

## 3. Customers and why they pay

| Segment | Pain | What they buy | Budget signal |
|---|---|---|---|
| **New protocols** (Colosseum portfolio, MetaDAO raises, hackathon teams going live) | Credibility at launch; no migration cost | Floor free; Vault with Cloud Starter | Security spend already exists (audits) |
| **Relaunches and post-incident protocols** | Must show depositors a hard bound | Vault + Cloud Pro | Drift's recovery needed $147.5M after the fact |
| **Protocols ≥ $10M** | Drift-class risk; STRIDE scoring; curator questions | Cloud Pro / Enterprise | Monitoring and audit budgets |
| **Curators and fintech distributors** | Need a bounded worst case for their risk committee | Attestation API | Fees on AUM |
| **Security firms** (SIRN members, auditors) | Want recurring revenue after audits | Operate guardians for clients (revenue share) | Channel |

## 4. Pricing (to test with the first 10 conversations)

| Tier | Includes | Price |
|---|---|---|
| **Core** | Vault and Floor programs, JavaScript client, self-hosted guardian (`cloud/guardian`), status page, `floor_check` CLI (all built today) | Free, Apache-2.0 |
| **Cloud Starter** | Hosted status page, alerts, community guardian | Free under $10M TVL |
| **Cloud Pro** | Hosted guardian bot (freeze ≤ 2 min, 24/7), 90-day calibration report, attestation API, STRIDE evidence pack | **$2,500 / month** |
| **Cloud Enterprise** | Guardian operations with a named security partner, SLAs, incident drills, custom rules | **$10,000+ / month** |

- **Why no on-chain fee:** a fee in the enforcement path is attack surface and a reason not to integrate. Security budgets already exist.
- **Why no token:** nothing in the product needs one.

Unit math:
- 10 Pro customers = $300k ARR.
- 28 of today's Solana protocols at an average of $4k/month = $1.3M ARR.

The model is SaaS margins. The cost is guardian operations (people and infrastructure), largely shared across customers.

## 5. Go-to-market

1. **Floor first.** A one-transaction yes. Free. The free CLI (`tools/floor_check.py <program>`, built) tells any team who can upgrade their program and whether it is ready for SIMD-0500.
2. **Replay Friday.** Every notable exploit replayed against Bulkhead within 48 hours, with signatures (content that builds trust and inbound).
3. **Launch-secure program.** New protocols integrate Vault before launch, when migration cost is zero.
4. **Security-firm channel.** Firms run guardians for their audit clients (revenue share).
5. **Curator pull.** One sentence for a risk committee: "Worst case is $X now, then $Y per hour until frozen, at most $Z per day, enforced on-chain."
6. **STRIDE alignment.** STRIDE (Asymmetric Research with the Solana Foundation) scores 40 controls in 8 pillars. Bulkhead gives on-chain evidence for 7 of them:
   - **G2** Upgrade authority and **G3** Timelock & delay mechanisms ("enforced on-chain timelocks with duration proportional to impact"): Floor, plus the 72h loosen floor.
   - **G5** Risk parameter controls: tighten instantly, loosen after a delay.
   - **E3** Staleness & liveness handling: fail-closed pricing.
   - **E4** Blast radius containment: the Vault limiter.
   - **P4** Defense-in-depth ("rate limits on transfer volume, per-epoch caps", "graduated withdrawal limits"): the Vault limiter.
   - **M2** Automated circuit breakers: the guardian bot and Floor abort.

   The Cloud evidence pack exports exactly these.

**First names to ask (in order):**
- Unwind (@0xsubal).
- Hylo and Project 0 (via @princedotrs).
- Loopscale and Save.
- Pacifica, Exponent, Perena, Solstice.
- One named guardian partner.

**Goal by Thu 8 Oct:** at least 3 written statements.

## 6. Competition and position

| | In the money path | Survives admin/upgrade-key compromise | Own deposits never throttled | Solana | Bounds loss (vs detects) |
|---|---|---|---|---|---|
| **Bulkhead** | ✅ | ✅ | ✅ | ✅ | ✅ |
| In-protocol limits (Drift, Fluid/Jupiter Lend, Project 0) | ✅ | ❌ admin-set | ❌ | ✅ | partial |
| Squads timelocks / spending limits | treasury | a setting | ❌ | ✅ | slows everything |
| Sentinel (Apr 2026) | CPI-called | ❌ instant loosen | ❌ | ✅ | partial |
| Holdfast, Hypernative, Range, solgov | ❌ | ❌ | — | ✅ | detect / pause after the fact |
| Spark ALM Controller | ✅ | ✅ (for its relayer) | — | ❌ EVM, one protocol | ✅ |
| Phylax, Venn, EIP-7265 | varies | varies | ❌ | ❌ EVM | varies |

**Partner, don't fight:**
- Detectors (Range, Hypernative, solgov) trigger our guardians.
- Squads is where the admin lives; Floor sits under it.
- Verification tools (QEDGen, svmscope) help integrators test upgrades during Floor's 72h window.

## 7. Moat, stated honestly

Open-source code can be copied. What can't be copied quickly:
1. **Trust in one immutable deployment.** Audits, verified builds, burned upgrade authority, and a public record of replays. Integrators pick the standard others already use.
2. **Custody switching cost.** Once vaults live behind Bulkhead, moving is a migration.
3. **Calibration data.** Flow data across protected protocols makes limits tighter without queueing honest users.
4. **Guardian network.** Security firms operating guardians tie incident response to our rails.
5. **Method.** Three-way verification and a differential corpus that grows with every integration.

## 8. Twelve-month milestones (post-hackathon)

| Month | Milestone |
|---|---|
| Nov 2026 | 3 design partners on devnet (at least one Floor, one Vault) |
| Dec 2026 | Audit 1 (Solana specialist); SIMD-0500 CLI used by 50+ programs |
| Q1 2027 | Audit 2 (formal methods on core); mainnet with a TVL-capped partner; bug bounty |
| Q2 2027 | 10 paying Cloud Pro customers; burn upgrade authorities |

## 9. Risks

| Risk | Answer |
|---|---|
| Protocols refuse to move custody | Floor needs no custody; Vault starts with new launches and relaunches |
| "Squads or Blockaid will add this" | Floor overlaps only if they ship a non-reducible delay (kill criterion); Vault is a different layer (in-path, backed vs unbacked) |
| A Bulkhead bug causes correlated losses | `04 §4`: verification, audits, TVL caps, immutability |
| Revenue slower than adoption | Cloud tiers from day one; security-firm channel |

## 10. Company setup (not legal advice)

Crypto activity is prohibited for residents in Nepal. Before taking investment, form an entity abroad (e.g. a Delaware C-corp) with qualified counsel, and don't serve Nepal-resident users.
