# Landing page copy (draft)

The Bulkhead project page. Sources: `docs/02-PRODUCT.md` (what it does), `docs/01-EVIDENCE.md` (every number), `docs/12-SUBMISSION.md` (story, scenarios, FAQ answers). The page itself is `index.html` next to this file.

- **Audience:** Colosseum judges. They know Solana and DeFi. They are reviewing many projects, they're skeptical, and they are scoring functionality, impact, novelty, UX, open source and business.
- **One action:** watch the 3-minute demo (`12 §4`).
- **Conversion:** the demo plays. Opening the repo is a secondary link, never a second button.
- **Style:** calm, one idea per fullscreen scene, scroll sets the pace (reference sites: moto-card.com, lukebaffait.fr, koisei-minimalist.aura.build). No fear marketing: the data does the scaring (`02 §4.6`).

Rules for every line below:
- Each number keeps its label from `01`: measured, reported, model or assumption. Show the label as a small caption under the number.
- Never say "we would have saved Drift." Say "modeled" or "replayed."
- Only Vault limits a Drift-style drain. Floor does not. Never put a Drift number next to Floor.
- Census numbers say "tracked protocols," not "all of Solana."
- `{braces}` are filled from a real run before publishing. Never invent them.

---

## 1. Page outline

Layout **B (long-form story)**, told as fullscreen scenes. Judges need a problem they believe, a mechanism they understand and proof they can check, in that order. The demo button stays fixed in the corner on every scene, so the one action is always a click away.

| # | Scene | Job | Visual |
|---|---|---|---|
| 0 | Hero | What it is, plus play the demo | S8 split-screen still as the poster, play button |
| 1 | Drift | The problem, in one fact | Black. Two numbers. |
| 2 | Not just Drift | It's structural | One number grows: 37 of 54 |
| 3 | Stop buttons | Why pausing isn't enough | A one-hour clock with one dot |
| 4 | The idea | Who decides what | Protocol → Bulkhead → vault, two lanes |
| 5–8 | Four guarantees | Benefits, one per scene | One mechanism per scene, live state |
| 9 | Floor | The zero-code first step | Upgrade countdown, 72h |
| 10 | How it works | Three steps | Three lines, nothing else |
| 11 | Proof | Replay + verification + model | S8 split screen; check.sh output |
| 12 | The one line | The worst case, live | One sentence, devnet numbers |
| 13 | FAQ | Objections | Plain Q/A |
| 14 | Final CTA | Same as the top | Poster + play |

---

## 2. Hero (scene 0)

**Headline:**
> The circuit breaker your protocol's admin can't turn off.

**Subheadline:**
> Bulkhead puts a Solana protocol's vaults under one small, immutable program. Your own deposit always comes back instantly. Everything else leaves at most 2% an hour and 5% a day. Loosening any limit waits 72 hours.

**Primary CTA:** `Watch the 3-minute demo` (plays in place, fullscreen, captioned)

**Proof line (under the button):**
> One attack transaction against an unprotected protocol: drained before a perfect stop button could fire. The same transaction against Bulkhead: held to the hourly limit, the rest queued in public. Devnet signatures in the video.

**Top bar (small):** `Bulkhead` · `Code` · `Docs` · demo button (stays on screen).

---

## 3. The argument (scenes 1–4)

### Scene 1: Drift
> **$285,000,000 · 12 minutes**
> *reported: Chainalysis, BlockSec*
>
> On 1 April, Drift lost $285 million. Drift had withdrawal limits. The attacker got admin power and raised them. Five days earlier, Drift had removed its own timelock.

### Scene 2: Not just Drift
> **37 of 54**
> *measured: solgov census, 26 Sep 2026, tracked protocols*
>
> Of 54 multisigs governing tracked Solana protocols, 37 have no timelock. The longest is 24 hours. None waits 72. A limit the admin controls doesn't protect you from the admin.

### Scene 3: Stop buttons arrive late
> **1 of 87**
> *reported: Zhou et al., IEEE S&P 2023 (183 incidents, mostly Ethereum and BSC)*
>
> Of 87 hacked protocols that had a pause button, one pressed it within the first hour. 44% of attacks finish inside a single transaction, before anyone can react. The brake has to sit in the path of the money.

### Scene 4: The idea
> **The protocol decides who gets paid. Bulkhead decides how fast.**
>
> Every token movement goes through Bulkhead. Paying an owner back what their own ledger supports goes through the **backed lane**, which is never throttled. Everything else (profits, bonuses, admin withdrawals, borrowing against unlisted collateral) goes through the **unbacked lane**, which is rate-limited.

---

## 4. Benefits (scenes 5–8, one per scene)

- **Your own deposit always comes back.** Withdrawing what you put in never touches the limit, needs no price feed and can't be frozen. Bank-run test: {60%} of TVL out in an hour, 100% paid instantly, zero tickets. *(G2; scenario S4)*
- **A compromised admin gets a budget, not the vault.** Unbacked money leaves at most 2% an hour and 5% a day, even with the admin and upgrade keys stolen. Anything over the limit becomes a public ticket that waits at least 6 hours. *(G1)*
- **Tighten now, loosen later.** Tightening a limit applies instantly. Loosening one waits at least 72 hours, a constant in the code that no setting can change. It's public, and any guardian can veto it. Drift's attacker would have waited three days in public. *(G4; scenario S7)*
- **Guardians can stop, never steal.** Guardians can freeze, cancel, extend, veto and abort. No guardian instruction can move tokens or choose a recipient. *(G5)*

Caption on scene 6, shown with the model label:
> If a guardian bot freezes within 2 minutes, an attacker who fully controls the protocol gets about 2% of the vault. Within an hour, 4%. With nobody watching for a full day, 10%. Half a vault takes nine days.
> *model: `reference/drift_model.py`; dual bucket, 2%/h and 5%/24h*

---

## 5. Floor (scene 9)

> **Not ready to move your vaults? Start with your upgrade key.**
>
> Point your program's upgrade authority at Floor in one transaction, with no code changes. Every upgrade then waits at least 72 hours in public, and any guardian can veto it. Any single guardian can stop the program in one transaction. Funds and accounts stay where they are.

No Drift numbers on this scene. Floor slows the upgrade key; it does not limit withdrawals.

---

## 6. How it works (scene 10)

1. **Hand over custody.** Move vault token accounts under Bulkhead PDAs, or begin with Floor (one transaction, no custody).
2. **Route every token movement.** About 40 lines of CPI. The protocol keeps all of its business logic.
3. **Seal.** From then on, the limits belong to the program, not the admin. Guardians watch, and loosening waits 72 hours.

---

## 7. Proof (scene 11)

Three pieces, each next to the claim it supports:

- **The replay (S8).** Split screen: one attack transaction against the legacy protocol and against Bulkhead. Legacy is drained, even with an abort in the next slot (signature shown). Bulkhead pays 0 through the backed lane, no more than the burst instantly, and the rest as tickets. `{devnet signatures}`
- **Checked three ways.** Every rule is written once in Rust, once in Python and once as property tests, then compared on `{6.9M}` random cases. The harness found a real bug in our own code: `{one line on the bug}`. Anyone can rerun it with `scripts/check.sh`.
- **Modeled against Drift.** With Drift's reported per-asset losses and Bulkhead's default limits, a 2-minute freeze leaves **$11.4M** of $285M taken. *model; assumes $550M pre-hack TVL (assumption)*. A modeled number, not a claim that Drift would have been saved.

**Builder line:**
> {Founder name}. I find bugs in shipped wallet code. One is now an official BIP-352 test vector, and two Bitcoin Core PRs are merged. Every bug I found had already shipped. Bulkhead is for the one nobody finds.

**Closest prior art, named as validation:** Sky's Spark ALM Controller bounds a fully compromised relayer with rate limits on EVM. Bulkhead brings that idea to Solana as shared infrastructure that any protocol can adopt.

---

## 8. The one line (scene 12)

Live from devnet state, refreshed on load:

> **Worst case right now: ${X} instantly, then ${Y} per hour until a guardian freezes (${Z} per day at most).**
> *computed from on-chain state; display prices only, never used on-chain*

When frozen: **Frozen: $0 can leave unbacked until {time}.**

---

## 9. FAQ (scene 13)

**Isn't this just a rate limiter?**
Drift had a rate limiter; the admin controlled it. Bulkhead's limit sits outside the admin's reach. It also tells the difference between returning your own deposit, which is never limited, and paying out someone else's money, which is.

**Why not just pause?**
In the largest study of DeFi hacks, one of 87 protocols with a pause button used it within the first hour. 44% of attacks are a single transaction. Bulkhead includes a stop button, but the limit is what works inside the transaction.

**Does it slow normal users down?**
No. Deposits, withdrawals of your own funds and ordinary borrows never touch the limiter. The bank-run test paid 100% instantly with zero tickets.

**What if a guardian is malicious?**
A guardian can delay unbacked payouts by freezing for up to 24 hours per call. It can't move funds, choose a recipient or block anyone's own deposit. Only live guardians count, and unfreezing needs a live quorum.

**What about a slow drain under the limit?**
That's what the daily cap is for. With nobody watching for a full day, 10% leaves, not everything. Half a vault takes nine days. Guardians and alerts handle the rest.

**What if Bulkhead itself has a bug?**
That's the biggest risk, and the reason every rule is stated three ways and checked on millions of cases. The harness has already caught one bug in our own code. Before mainnet: audits, TVL caps, then burning Bulkhead's own upgrade key.

**Why would a large protocol move custody?**
A large protocol probably won't move custody first. Floor needs no custody move: one transaction puts a 72-hour floor under the upgrade key. Vault starts with new launches and relaunches, where migration costs nothing.

**What can't it do?**
It doesn't detect attacks, protect user wallets, protect AMM pools or run an oracle. It buys time; people still have to use that time.

**Is it audited?**
Not yet. It runs on devnet, the code is open source under Apache-2.0, and `SECURITY.md` says plainly what is unaudited.

**How does it make money?**
The core is free and immutable. Protocols pay for Bulkhead Cloud: a hosted guardian that freezes within minutes, calibration on their own flows, a public worst-case attestation and STRIDE evidence ($2.5k–$10k a month).

---

## 10. Final CTA (scene 14)

> **Three minutes. One transaction. Two outcomes.**
> `Watch the demo`
>
> Everything in it can be checked: open source, devnet signatures, one command to rerun the math. `Read the code →`

This is risk reversal for a judge: nothing has to be taken on trust.

---

## 11. SEO / AEO

- **Index it.** The offer is evergreen and outlives the hackathon. Judges arrive from the Colosseum link either way.
- **Title (≤ 60):** `Bulkhead: a circuit breaker your admin can't turn off`
- **Meta description (≤ 155):** `Bulkhead keeps Solana protocol vaults under an immutable program: own deposits return instantly, other outflow is capped at 2%/hour, loosening waits 72h.`
- **OG image:** the S8 split-screen poster with the headline.
- **FAQ:** plain Q/A in HTML (`FAQPage` schema optional). The questions above are the ones people search for.

---

## 12. Before publishing

- [ ] Fill every `{...}` from a real run: S4 bank-run share, differential case count, the bug line, S8 signatures, live worst-case numbers, founder name.
- [ ] Every number keeps its `01` label caption.
- [ ] No Drift number appears next to Floor.
- [ ] The demo video is captioned and plays in place. The fixed demo button is visible on every scene, including at phone width.
- [ ] Every link opens in a private window.
