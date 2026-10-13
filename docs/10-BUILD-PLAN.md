# 10 — Build log and what comes next

Bulkhead was designed on 24 Sep 2026 and built from 26 Sep to 12 Oct 2026 by Shuvam Pandey (programs, guardian, verification) and Praful (outreach, business, fixes to the guardian and CI). Every date below can be checked against the commit history and the devnet signatures in `08`.

## 1. What was built, by week

| Week | Built |
|---|---|
| 26 Sep – 27 Sep | The core (dual-bucket limiter, EMA, value, prices, ledger, governance, Floor checks and abort binaries), the independent Python reference and differential runner, golden vectors, Kani harnesses, mutation testing. Floor, Vault and Harbor on Pinocchio for sBPF v3; the Cloud guardian; the status page; `tools/floor_check.py`. One runtime-level interaction reported privately (`SECURITY.md`). |
| 28 Sep – 4 Oct | Deployed on devnet (28 Sep), verified byte-identical to the build; Floor S10 run there the same day. Adversarial reviews (`15`): capacities from the least of reference and live balance (A1), absolute caps (A1b), quorum-gated abdication (A3), delay caps, seal coverage, mint close authority. The demo market's seal executed on 1 Oct, and S1 ran on devnet that day. Liquidation cascade scenario (S11). |
| 5 Oct – 11 Oct | Coverage-guided fuzzing (8 targets); CI with per-change jobs and a weekly deep run; canonical Linux builds matched against devnet (finding 43). Guardian hardening for mainnet conditions: failover RPCs, an escalating freeze, quorum-final unfreezes, webhook alerts, a supervised systemd unit. The account-substitution sweep of every instruction. A six-reviewer pre-audit (`16`). Findings 30–95, each fixed with a test or stated (`09 §4`). Every on-chain fix upgraded in place on devnet and re-verified, most recently PR #77 on 11 Oct. |

## 2. Planned and not done

These were in the plan and did not make the submission. None is claimed anywhere in this repository.

| Item | Why not, and when |
|---|---|
| S8 and S9 on devnet (S9 with Pyth prices posted from Hermes) | Both run on LiteSVM against the real runtime (`08`). The devnet runs need a Pyth posting setup; next, with the first design partner |
| The full Drift asset mix on devnet | Modelled only (`reference/drift_model.py`) |
| Certora (CVLR) rules and Trident flows | Kani, the exhaustive checks and the differentials cover the core; prover rules for the programs come with the audit build (`09 §9`) |
| A hosted status page | The page is a static file that runs locally against devnet (README); hosting comes with the first partner's vault |
| Registering builds with `solana-verify` | Builds are already reproducible and checked against devnet weekly in CI (`scripts/verify-devnet.sh`) |
| Mint gates and flash loans | Out of scope by decision (`07 §7`) |

## 3. Next

The twelve-month plan is in `11 §8`: three design partners on devnet in November (at least one on Floor, one on Vault), a Solana-specialist audit in December, a formal-methods audit of the core and a TVL-capped mainnet partner in Q1 2027, then the upgrade authorities burned.

Before any mainnet deployment, the decisions in `16 §4` must be made: the guardian set's minimum size (AUD-2, and finding 96), a bound on new backed liabilities, and the oracle settings for a lending integration.

## 4. Risk register

| Risk | Probability | Impact | Mitigation | Status |
|---|---|---|---|---|
| sBPF v3 toolchain friction | — | — | Built with `cargo-build-sbf --arch v3`; checked in CI | Retired |
| LiteSVM lacks loader-v3 `Upgrade` | — | — | S10 runs on LiteSVM through real loader-v3 instructions | Retired |
| Compute above target | — | — | Measured (`05 §10`, `06 §7`) | Retired |
| Seal's 72h wait on devnet | — | — | Proposed 28 Sep; executed 1 Oct | Retired |
| Devnet faucet limits or outages | — | — | A pre-funded devnet key; a loader that needs no account reads (`cloud/deploy/loader.mjs`) | Retired |
| Pyth on devnet (Hermes posting) | M | M | LiteSVM uses Pyth-format accounts | Open |
| A Bulkhead bug causes correlated losses | M | H | Verification (`09`), two audits, TVL caps, then immutability (`04 §4`) | Open |
| "Unaudited" read as "unsafe" | H | M | Stated first in the README and `SECURITY.md`; mainnet only after audits | Open |
| Saying too much about the disclosed item | L | H | Say only what `SECURITY.md` says until the maintainer agrees or a fix ships | Open (reported and acknowledged 27 Sep) |
| Protocols won't move custody | M | H | Floor needs no custody; Vault starts with new launches and relaunches (`11`) | Open |
| A competitor ships the same | L | H | Kill criteria (`00`) | Open |
