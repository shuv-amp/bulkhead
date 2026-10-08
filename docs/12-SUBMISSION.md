# 12 — Colosseum submission kit

Colosseum Crypto World's Fair.
- **Submissions close:** Mon 12 Oct 2026, 11:59 pm PT.
- **Prizes:** $30k grand prize; 20 × $15k; Solana track 10 × $10k; Public Good $5k; University $5k; accelerator $250k.
- **Judging criteria:** functionality, potential impact, novelty, UX, open-source, business plan.
- **Prior code:** allowed if disclosed.

Re-read the official rules on Sun 11 Oct.

## 1. Checklist (in order)

- [ ] Project page: **Bulkhead**, one-liner (§3), track **Solana**; flag Public Good eligibility (open-source core)
- [ ] **Pitch video**, 2–3 min (§2); captioned; unlisted
- [ ] **Demo video**, ≤ 3 min (§4); screen only
- [ ] **Repo** public, Apache-2.0; README quickstart; `SECURITY.md` (unaudited, devnet only). The private report in `SECURITY.md` is sent and acknowledged; say nothing more about it than `SECURITY.md` does
- [ ] **Prior-code disclosure** (§6)
- [ ] **Go-to-market** text (§5)
- [ ] Links: devnet program ids, scenario signatures, status page, `tools/floor_check.py`, the green CI run
- [ ] Weekly updates posted (27 Sep, 4 Oct, 11 Oct)
- [ ] Team: names, roles, GitHub/X, time zone
- [ ] Every link opened in an incognito window; final form screenshotted

## 2. Pitch video (target 2:30)

| Time | On screen | Voice |
|---|---|---|
| 0:00–0:15 | Black. "$285,000,000 · 12 minutes" | "April first. Drift lost two hundred eighty-five million dollars. Drift had withdrawal limits. The attacker got admin power and raised them. Five days earlier, Drift had removed its own timelock." |
| 0:15–0:35 | Census numbers | "It's not just Drift. Of fifty-four multisigs governing tracked Solana protocols, thirty-seven have no timelock. The longest is a day. A guardrail the admin controls doesn't protect you from the admin." |
| 0:35–0:55 | SoK numbers | "And stop buttons are too late. In 183 DeFi hacks, eighty-seven of the victims had a pause button. One used it within the first hour. Forty-four percent of attacks finish inside a single transaction. The brake has to sit in the path of the money." |
| 0:55–1:30 | Diagram: protocol → Bulkhead → vault; two lanes | "Bulkhead is a circuit breaker for Solana protocols that the admin can't turn off. The vault sits under one small program that, once audited, nobody can change. The protocol decides who gets paid; Bulkhead decides how fast. Taking back your own deposit is never limited, frozen or priced. Everything else leaves at most two percent an hour and five percent a day. Loosening takes seventy-two hours by constant. Guardians can stop things, never move money." |
| 1:30–1:55 | S8 split screen | "Here's one transaction draining an unprotected protocol while a perfect stop button fires in the very next slot. Too late. Same transaction against Bulkhead: two percent. Then a public queue." |
| 1:55–2:15 | Floor | "And if you won't move your vault on day one: hand Floor your upgrade key in one transaction. Upgrades wait seventy-two hours. Any guardian can stop the program, and a quorum restores the exact bytes that were stopped." |
| 2:15–2:30 | Founder + repo | "I find bugs in shipped wallet code; one is now an official Bitcoin test vector. Every bug I found had already shipped. Bulkhead is for the one nobody finds. Open source, and every number you just saw ran on the real Solana runtime." |

## 3. Descriptions

- **One-liner (≤ 100 chars):** The circuit breaker your Solana protocol's own admin can't turn off.
- **Short (≤ 280 chars):** Drift had withdrawal limits; the attacker raised them. Bulkhead holds protocol vaults: taking back your own deposit is never throttled, everything else leaves at most 2%/hour and 5%/day, and loosening waits 72h. Floor puts a 72h floor under the upgrade key.
- **Long:** the README's first section.

## 4. Demo video (≤ 3:00, screen only)

1. **0:00–0:30** Terminal: `scripts/check.sh` and the `scripts/prove.sh` summary. Every rule stated independently in Rust and Python and checked on millions of cases; 14 bounded proofs; the bugs these checks found in our own code (`09 §4`).
2. **0:30–1:20** S8: the one-transaction attack. Legacy drained despite a next-slot stop; protected: ten payouts in one transaction, 199k paid (the 2% burst, sized to what is in the vault at each payout), 800k waiting in public.
3. **1:20–1:50** S1 live (`E2E=1 scripts/check-programs.sh`, or devnet once deployed): the attacker orders 1.2M and gets 100k; the Cloud guardian freezes on its own within seconds and cancels every queued payout; the status page shows the worst case. Say "against this attacker": a patient one who stays under the bot's thresholds is bounded by the on-chain limit, which is the claim (`15` A2).
4. **1:50–2:15** S4 and S9: bank run 100% instant with zero tickets; honest borrower 100% backed. "Nobody noticed Bulkhead."
5. **2:15–2:40** S7 and S10: a loosening waits 72h and gets vetoed. Then `scripts/floor-demo.sh` on a real mainnet program's bytes: Floor takes its key with zero code changes, one guardian stops it, and two restore it byte-identical (the Dean Little question, answered on screen).
6. **2:40–3:00** Status page line: "Worst case right now: $X, then $Y/hour, at most $Z/day."

## 5. Go-to-market (paste-ready)

> **Who pays first.**
> - New and relaunching Solana protocols, then the 28 protocols above $10M TVL in lending, perps, stablecoins and vaults.
> - Their users, curators and STRIDE now ask for a worst-case number. Drift showed that admin-controlled limits don't give one.
> - The core is free and open source. Protocols pay for Bulkhead Cloud: a hosted guardian that freezes in minutes, calibration on their own flows, a public attestation, and STRIDE evidence ($2.5k–$10k/month).
>
> **How we reach them.**
> 1. Floor: a one-transaction, zero-code step every upgradeable program can take, plus a free SIMD-0500 readiness CLI.
> 2. "Replay Friday": notable exploits replayed against Bulkhead within 48 hours.
> 3. Launch-secure: new protocols integrate before launch.
> 4. Security firms run guardians for their audit clients.
>
> **Milestones.** {n} written LOIs during the hackathon; 3 devnet design partners in November; audits and a TVL-capped mainnet partner in Q1 2027.

## 6. Prior-code disclosure (paste-ready)

> **Repository:** Bulkhead was started on 26 Sep 2026, during the hackathon. The design was drafted on 24 Sep 2026.
> **Prior work by the founder, not included:** SP-Differ (https://github.com/shuv-amp/sp-differ), a BIP-352 differential harness. Bulkhead reuses its *method* (independent implementations plus a differential runner), not its code.
> **Pattern credited:** the one-transaction abort pattern is from Dean Little's `sbpf-asm-abort`. Bulkhead's abort binaries are generated byte by byte by our own code, and an independent Python builder produces the same bytes.
> **Libraries:** Pinocchio (on-chain), LiteSVM (tests), the Solana SDK crates; all Apache-2.0. No third-party code copied (`DISCLOSURE.md`).
> **Third-party data:** Chainalysis, BlockSec, Halborn, Drift (incident facts); Zhou et al., IEEE S&P 2023 (incident statistics); solgov public API (governance census, snapshot committed); DefiLlama (market data).

## 7. Weekly updates (60 s each)

- **#1 (Sun 27 Sep):** the Drift insight + the census; the core, the three programs and the guardian built and tested; "our own checks found real bugs in our own code, including one the Rust and Python versions shared."
- **#2 (Sun 4 Oct):** S8 GIF: one transaction beats a perfect stop button; Bulkhead holds it to 2%.
- **#3 (Sun 11 Oct):** S1 on devnet with signatures, S4/S9 "nobody noticed," Floor abort, LOIs.

## 8. X thread (post Sun 4 Oct)

1. Drift had withdrawal limits. The attacker raised them. We built the circuit breaker the admin can't turn off, and tested it against a one-transaction attack. 🧵
2. 37 of 54 multisigs governing tracked Solana protocols have no timelock. The longest is 24h. Timelocks are settings, not floors.
3. Stop buttons are too late: 1 of 87 hacked protocols paused within an hour; 44% of attacks are a single transaction (IEEE S&P '23).
4. (GIF) One transaction vs a perfect next-slot abort: drained. Same transaction vs Bulkhead: 2%, then a public queue.
5. Your own deposits never touch the limit. Bank-run test, during a freeze: 20 depositors take back 100% of TVL, every withdrawal instant, zero queued.
6. Loosening waits 72h by constant; guardians can stop, never steal. Floor gives any program a 72h upgrade floor in one transaction.
7. Open source. Every rule stated independently in Rust and Python and cross-checked on millions of cases, 14 bounded proofs, and every scenario on the real Solana runtime. Protocol teams: DM for a replay of your worst case. {repo}

## 9. Interview answers (≤ 30 s each)

| Question | Answer |
|---|---|
| Isn't this a rate limiter? | "Drift had a rate limiter the admin controlled. Ours sits outside the admin's reach and knows the difference between returning your own deposit, never limited, and paying out someone else's money, limited." |
| Why would Kamino move custody? | "Kamino won't move first. Floor needs no custody: one transaction, a 72h floor under the upgrade key. Vault starts with new launches and relaunches, where migration costs nothing." |
| Why not just pause? | "One of 87 hacked protocols paused within an hour; 44% of attacks are one transaction. We build the stop button in, but the limit is what works inside the transaction." |
| What if Bulkhead has a bug? | "It's the top risk. Every rule is stated independently more than once and checked on millions of cases; those checks have already caught real bugs in our own code, one of them shared by two implementations. Then audits, TVL caps, immutability." |
| Slow drain under the limit? | "The daily cap: with nobody watching for a full day, at most 10% leaves (the day's 5% on top of a full 5% bucket), not everything. Half a vault takes nine days. Guardians and alerts do the rest." |
| Won't it block liquidations in a crash? | "It can, and we measured it. On a synthetic −30% day, the defaults start queuing liquidations once a 10-minute crash liquidates 17% of a vault. A lending market sets 4% an hour and 10% a day and a 30% cascade goes through, at the cost of a bigger theft bound. We publish that trade-off per market." (`08` S11) |
| Who controls Bulkhead itself? | "Today a disclosed team key, on devnet. On mainnet: two audits, a capped first partner, then we burn it. After that nobody can change Bulkhead, including us; a new version is a new deployment that protocols move to through their 72-hour lifeboat exit." |
| What if the admin key is stolen for good? | "It can't steal. Today it can block its own rotation, which is a denial of service we list as open (A4). The option we're weighing is letting a guardian quorum rotate the key after 72 hours." |
| Business? | "Free, immutable core. Protocols pay for Cloud: a guardian that freezes in minutes, calibration, attestations, STRIDE evidence. 10 Pro customers is $300k ARR." |
| Why you? | "I find bugs in shipped crypto code. One is an official BIP-352 test vector; two Bitcoin Core PRs merged. Bulkhead is verified the same way." |
| What do you need? | "Intros to three protocol design partners and one security firm to run a guardian." |
