# 10 — Build plan: Sun 27 Sep → Mon 12 Oct 2026

**Deadline:** Mon 12 Oct, 11:59 pm PT = **Tue 13 Oct, 12:44 NPT**. **Internal submit:** Mon 12 Oct, 12:00 PT = Tue 13 Oct, 00:45 NPT. The last 12 hours are buffer, not build time.

The original plan (26 Sep) scheduled the programs from Mon 28 Sep to Wed 7 Oct. They are built. The time this frees is **not** spent on new scope. It goes to what judges and integrators can check for themselves:
- public devnet signatures;
- proofs about the programs themselves, not only the core;
- outside attackers;
- written demand.

## 1. Where we are (Sun 27 Sep)

Built, and passing (`09` has every number):

| Part | State |
|---|---|
| `bulkhead-core` | Limiter (dual GCRA), EMA, value, prices, ledger, classification, governance rules, Floor helpers (loader-v3 parsers, snapshot identity, restore and eject rules, the abort binaries). Zero dependencies, `no_std`. |
| Verification of the core | An independent Python reference and differential runner, 119 golden outputs, 36 regression fixtures, 25 property tests, 6 exhaustive tests, 15 Kani harnesses (all verified on 6 Oct; three strengthened on 8 Oct and not rerun since), and mutation testing |
| Programs (Pinocchio 0.11.2, sBPF v3, Agave 4.3.0 toolchain) | Floor (64 KB), Vault (189 KB), Harbor, the demo protocol (9 KB), on a macOS build of 8 Oct. Each binary passes our SIMD-0500 check (`e_flags == 3`). |
| Program tests (LiteSVM, the real agave runtime and loader, mainnet features) | 102 tests (36 Floor, 66 Vault: every scenario S1, S4, S7, S8, S9, S10; negative tests; compute; the account-substitution sweep) and the program-vs-model differentials (`09 §7`) |
| Bulkhead Cloud | Zero-dependency JavaScript client, guardian bot, status page |
| End to end | A local validator, the programs, the guardian and an attacker. The attacker ordered 1.2M USDC and received 100k (the burst is 2% of what is in the vault at each payout since the 29 Sep fix; 200k before). The guardian froze the protocol on its own and cancelled every queued payout. |
| Tools | `tools/floor_check.py`: who can upgrade a program, and whether it is ready for SIMD-0500 |
| CI | Every pull request and a weekly full run: `check`, `programs`, `scenarios`, `fuzz`, `kani`, `mutants`, `deny`, `workflows`, `devnet` (`09 §8`) |

Not built, by decision: mint gates and flash loans (`07 §7`).

## 2. Team and rhythm

| Role | Who | Owns |
|---|---|---|
| **P**: program engineer | Shuvam | Programs, tests, devnet, proofs |
| **F**: full-stack | Lxaman | Status page hosting, scenario pages, video editing |
| **B**: founder/BD | Praful, a fixed 90 min every day | Outreach, LOIs, weekly updates, X posts |

Daily rhythm (NPT):
- 09:00–13:00 deep build.
- 13:30–15:00 B block (US evenings overlap).
- 15:00–20:00 build.
- 20:00 three lines in `docs/LOG.md` (done / blocked / tomorrow).

Commit at least daily. The repository's first commit date is our prior-code disclosure.

## 3. What remains, in dependency order

| # | Work | Owner | Needs | Exit criterion |
|---|---|---|---|---|
| 1 | First commit and push; CI green on a fresh clone | P | Team go-ahead | All three CI jobs green |
| 2 | Report the runtime-level item privately (`SECURITY.md`) **before** the repository is public | P | — | **Done (27 Sep):** reported and acknowledged. The repository contains no details. Remaining: agree with the maintainer what may be said publicly, and when |
| 3 | Devnet: `scripts/deploy.sh <devnet-url> <deployer.json>` deploys Floor, Vault and Harbor, registers Harbor, creates the test-USDC vault, deposits 10M and **proposes the seal** (it waits 72h). Rehearsed end to end by `scripts/deploy-dryrun.sh` | P | Team go-ahead; ~5 devnet SOL | **Done (28 Sep):** deployed, byte-identical to the build; seal proposed, executable from Thu 1 Oct, 02:17 NPT. Ids and signatures in the README and `08` |
| 4 | Devnet, after the seal: S1 and S8 against Harbor; S9 with real Pyth updates posted from Hermes; Floor S10 on a devnet program | P | #3, then 72h | Every signature opens in the explorer. **Floor S10 done (28 Sep; it needs no seal).** S1: `cloud/e2e/s1.sh` on the devnet market, rehearsed by the local run |
| 5 | Status page hosted, reading devnet | F | #3 | Works on phone and desktop |
| 6 | ~~Prover rules (Certora CVLR) and Trident flows~~ **Cut (27 Sep, LLM council):** judges won't check them in the time. After the hackathon. | — | — | — |
| 7 | Verifiable builds | P | #3 | **Done locally (27 Sep):** the build is deterministic, and `scripts/verify-deployed.sh` proves the deployed code equals the local build (rehearsed). **On devnet (28 Sep): run; the three hashes are published in `SECURITY.md`.** Optional: register with `solana-verify` (needs its CLI installed; team decision) |
| 8 | "Break it" hour: three outside builders attack the rules; each finding becomes an issue | B + P | — | Findings list; each fixed or stated |
| 9 | Demo video (≤ 3:00) and pitch video (2–3 min); three outsiders watch the drafts | F + B | #4 | Exported, captioned, confusion list resolved |
| 10 | Outreach, calls, LOIs (§6) | B | — | ≥ 3 written statements by Thu 8 Oct |
| 11 | Submission (`12`), final kill sweep | all | everything | Confirmation screenshot saved |

## 4. Day by day

| Day | Build (P / F) | Business and content (B) | Exit criterion (all true) |
|---|---|---|---|
| **Sun 27 Sep** | Docs and CI final pass | Weekly update #1. **Chitwan pitch: date to confirm** (it is not 27 Sep) | `scripts/check.sh` and `E2E=1 scripts/check-programs.sh` pass |
| **Mon 28** | #1 push, CI; #3 devnet deploy and **seal proposed** (#2 is done) | 15 DMs (§6) | CI green (**open**: the repository has no remote yet); seal proposal signature recorded (**done**, in `08`; it executes Thu 1 Oct) |
| **Tue 29** | Record the fallback demo (the local end-to-end run and `scripts/floor-demo.sh`); have an outsider read the README top and FAQ (drafted 27 Sep) | Village "break it" hour (#8) | Recording saved; the outsider's confusion list written |
| **Wed 30** | Fix break-it findings; Chitwan pitch variant | In-room asks: Subal (Unwind); Prince (Hylo, Project 0) | Every finding fixed or stated |
| **Thu 1 Oct** | #4: the seal executes; S1 and S8 on devnet | **Kill check #1** (sweep: Colosseum arena, GitHub, Squads, Drift) | S1/S8 signatures open in the explorer |
| **Fri 2** | #4: S9 with Hermes-posted Pyth prices; ~~Floor S10 on a devnet program~~ (done 28 Sep) | 2 calls with protocol teams | S9 and S10 signatures |
| **Sat 3** | #5 status page on devnet; #7 verifiable builds | X thread draft | Page works on a phone |
| **Sun 4** | Buffer | **Weekly update #2** (S8 GIF); publish the thread | — |
| **Mon 5** | Deeper program differential (100k steps); compute snapshot | **Kill check #2** (demand) | Differential clean |
| **Tue 6** | Hardening from #8 and the prover work | Ask a security firm to be a named guardian | — |
| **Wed 7** | Scope freeze; tag `v0.9`; self-review against `04` | Landing copy | Tag pushed |
| **Thu 8** | Fresh-clone reproduction from the README | Close LOIs (target ≥ 3 written) | Reproduction works on a clean machine |
| **Fri 9** | Fix-only | **Demo video draft**; three outsiders watch; list what confused them | Draft exists; confusion list written |
| **Sat 10** | Fix what the video exposed | **Pitch video**; re-record the demo | Both exported, captioned, unlisted |
| **Sun 11** | Release `v1.0-cwf` | **Weekly update #3**; fill in the submission (`12`); final kill sweep | Every link opened in an incognito window |
| **Mon 12** | On call | **Submit by 12:00 PT** | Confirmation screenshot saved |

## 5. Pre-committed cut rules

| Trigger (measured) | Cut | Never cut |
|---|---|---|
| Devnet not deployed by Wed 30, 23:59 NPT | Devnet signatures in the videos. Show the LiteSVM scenarios and the validator run, and say "devnet next". | Core checks, program tests, the end-to-end run, honest labels |
| Seal not executed by Sat 3 | S1/S8 on devnet. Keep Floor S10 on devnet (it needs no seal). | Same |
| Any claim not reproducible from the repository | Remove it | Same |
| A break-it finding not fixed by Wed 7 | State it in `04` and `SECURITY.md` | Same |

## 6. Kill criteria and outreach

Kill criteria: `00 §Kill criteria`. Checks on Thu 1 Oct, Mon 5 Oct and Sun 11 Oct.

**Outreach order:**
1. Unwind (in the room).
2. Hylo and Project 0 via Prince.
3. Loopscale and Save.
4. Pacifica, Exponent, Perena, Solstice.
5. One guardian partner (Asymmetric Research, OtterSec, Neodyme, Sec3 or Range).

**DM (≤ 90 words):**
> Hi {name}, I'm building Bulkhead: a circuit breaker for Solana protocols that your own admin or upgrade key can't switch off. Depositors taking back their own funds are never throttled; unbacked outflow is capped at 2%/hour and 5%/day, and loosening waits 72h. Floor (one transaction, zero code changes) makes upgrades wait 72h, with a guardian stop button and a byte-identical restore. Could you look at a 2-minute replay and tell me what would stop you from using it? {link}

**LOI (any written form counts):**
> {Org} reviewed Bulkhead on devnet. If it passes an independent audit, we would {pilot Floor on {program} / pilot a Vault / run a guardian}. Requirements: {…}. {name, role, date}

## 7. Risk register

| Risk | Probability | Impact | Mitigation | Status |
|---|---|---|---|---|
| sBPF v3 toolchain friction | — | — | Built with `cargo-build-sbf --arch v3`; checked in CI | Retired |
| LiteSVM lacks loader-v3 `Upgrade` | — | — | S10 runs on LiteSVM through real loader-v3 instructions | Retired |
| Compute above target | — | — | Measured (`05 §10`, `06 §7`) | Retired |
| Pyth on devnet (Hermes posting) | M | M | LiteSVM uses Pyth-format accounts; S9 on devnet is the only dependency | Open |
| Seal's 72h wait on devnet | M | H | Propose on Mon 28 | Mitigated: proposed 28 Sep; executable from Thu 1 Oct, 02:17 NPT, until Thu 8 Oct |
| Devnet faucet limits or outages | M | L | A pre-funded devnet key; the validator run as the fallback; a loader that needs no account reads (`cloud/deploy/loader.mjs`, after public devnet's reads failed on 27 Sep) | Retired: deployed 28 Sep with the pre-funded key |
| "Unaudited" read as "unsafe" | H | M | Say it first; show the verification; TVL-capped mainnet only after audits | Open |
| Saying too much about the disclosed item | L | H | Say only what `SECURITY.md` says until the maintainer agrees or a fix ships | Open (reported and acknowledged 27 Sep) |
| Village days reduce build hours | H | M | The build is ahead; cut rules | Open |
| No written demand | M | H | In-room asks first; Floor lowers the ask to one transaction | Open |
| A competitor ships the same | L | H | Kill criteria | Open |
