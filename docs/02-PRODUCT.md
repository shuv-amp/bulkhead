# 02 — Product

## 1. Who it is for and what they need

| User | Their question | What Bulkhead gives them |
|---|---|---|
| **Protocol founder / security lead** (lending, perps, CDP stablecoins, yield vaults, treasuries) | "If our admin key, upgrade key or code is compromised, how much can leave before we react?" | A worst case, set in advance, enforced on-chain, that holds against their own compromised keys |
| **Depositor** | "Can I always get my money out? How bad can a hack get?" | Own deposits are never throttled, frozen or priced by Bulkhead. A public line: "worst case right now: $X, then $Y per hour" |
| **Guardian** (the team's ops key, the Bulkhead Cloud bot, a security firm) | "Let me stop the bleeding without being able to steal." | Freeze, cancel, extend, veto, abort. No power to move funds. |
| **Curator / fintech distributor** | "Which venues can I explain to my risk committee?" | A published, verifiable bound per venue |
| **Solana Foundation / STRIDE** | "Raise the security floor across protocols." | An open-source control that maps to circuit-breaker and incident-response checks |

## 2. The two products

### Floor (Tier 0): the upgrade key can't act quickly or alone

A protocol points its program's upgrade authority at a Floor PDA. Its existing multisig becomes Floor's **owner**.
- **Upgrades** wait at least 72 hours (a constant; **7 days recommended**, the L2BEAT Stage-1 exit window). Every pending upgrade is public, and any guardian can veto it.
- **Stop:** any single guardian (or the owner) can swap in a two-instruction abort binary in one transaction. Every instruction of the protected program then fails. All accounts and funds stay where they are.
- **Restore:**
  - Fast, if a guardian quorum approves a specific buffer. The buffer is Floor-owned, so its bytes can't change after review.
  - Otherwise slow: after the 72h delay with no veto.
- **Leaving Floor** (moving the authority away) is a loosening, so it also waits 72h.
- **At registration**, Floor reads the program's ELF header. If it is not sBPF v3, it records a warning: after SIMD-0500, an abort can only be undone with a v3 build.

Integration: one transaction, zero code changes.

### Vault (Tier 1): the money path itself

The protocol moves its vault token accounts (and optionally mint authority) under Bulkhead PDAs. It keeps all business logic. Every token movement becomes a CPI into Bulkhead:
- The **protocol** decides **who** gets paid.
- **Bulkhead** decides **how fast**.

Two lanes:
- **Backed lane (never throttled, never frozen by Bulkhead):** paying an owner back what their own ledger supports. That means their own deposit, plus borrowing against allowlisted collateral at conservative prices.
- **Unbacked lane (rate-limited):** everything else. Borrows against unlisted collateral, profits, bonuses, admin withdrawals, unbacked mints.
  - Instant up to 2% of the vault per hour and 5% per day, measured on the lower of the live balance and its 24-hour average (the reference balance). Absolute caps in tokens bound capital an attacker parks in the vault first ([15](15-ADVERSARIAL-REVIEW.md)).
  - Beyond that, the request becomes a public **ticket** that waits at least 6 hours.
  - Guardians can freeze the lane or cancel tickets.

Integration: a CPI per token movement, signed by the protocol's caller PDA; Harbor is the reference (`07-INTEGRATION.md`).

## 3. Guarantees

These are the product. Each has a proof or a test (`03`, `09`).

| ID | Plain words | Precise statement |
|---|---|---|
| **G1** | Unbacked money leaves at most 2% per hour and 5% per day of the vault | For any `t0, T ≥ 0`: the unbacked amount requested in `[t0, t0+T]` and paid by `t0+T` is ≤ `C_s·(W_s+T)/W_s` and ≤ `C_l·(W_l+T)/W_l`. It holds with the protocol's admin and upgrade keys compromised. `C` is a fraction of `min(reference, live balance)`, clamped to the absolute caps when set (`03 §3`); over a window, the largest `C` in it applies. |
| **G2** | Your own deposit is never throttled, frozen or priced | An owner with no liabilities is paid at least `min(amount, own net deposit)` of that mint through the backed lane: no prices are needed, and no freeze or limit applies. (Whether the tokens are in the vault is the pool's liquidity: lending moves deposits out, and a bounded unbacked loss reduces the pool; `03 §4.6`.) |
| **G3** | The backed lane never pays more than the owner's ledger supports | After any backed payment, either nobody in that ledger owes anything, or health ≥ 0 at conservative prices, or the payment was the owner's own deposit of a mint that is not allowlisted (worth 0 as collateral anyway) |
| **G4** | Tighten now, loosen later | A change that tightens every field applies instantly. Any other change waits ≥ 72 hours (a constant), is public, any guardian can veto it, and it expires 7 days after becoming executable. With its guardian quorum, a protocol may **abdicate** loosening a change kind forever; tightening it stays instant. |
| **G5** | Guardians can stop, never steal | No guardian instruction transfers tokens or chooses a recipient. Only live guardians (heart-beat within their interval) can act; unfreezing needs a live quorum. |
| **G6** | Emergencies can't become exits | The admin can move funds instantly only into the Bulkhead-held lifeboat. Leaving the lifeboat waits ≥ 72 hours and goes only to a destination committed ≥ 72 hours earlier. |
| **G7** | Fail closed | A missing, stale or wide price, an unknown asset, or an arithmetic overflow can only reduce the backed amount, never increase it |
| **G8** | (Floor) The upgrade key can't act quickly or alone | A new binary deploys only after ≥ 72h without veto, or with a live guardian quorum's approval of that exact frozen buffer while the program is stopped. Any live guardian can stop the program instantly; a live quorum restores the snapshot, verified byte-identical to the stopped code. |
| **G9** | Bulkhead itself can't be changed | On mainnet, Bulkhead's and Floor's own upgrade authorities are burned after audit. On devnet they are a team key, disclosed in `SECURITY.md`. |

What an attacker who fully controls a Vault-protected protocol can take:
- whatever they deposited themselves;
- plus the unbacked budget until a guardian freezes.

That budget is 2.07% of the vault if the freeze lands in 2 minutes, 4% in 1 hour, and 10% in 24 hours.

## 4. UX principles

1. **Invisible when things are fine.** Deposits, withdrawals of own funds and ordinary borrows never touch the limiter. Calibration (`07 §4`) checks this on the protocol's own history.
2. **One line of worst case.** Every status page leads with: "Worst case right now: **$X** instantly, at most **$Y** in 1 hour, **$Z** in 24 hours."
3. **Queued is visible, not lost.** A ticket shows its amount, reason (unbacked, over the limit), ETA and status. The protocol shows "arriving at ETA" in its own UI.
4. **Every loosening has a countdown.** Pending changes show time left and who can veto.
5. **Numbers are real or labelled.** Replays show signatures. Models say "model" and list their assumptions next to the number.
6. **Calm tone.** No fear marketing. The data does the scaring.

## 5. The worst-case attestation

For each vault, computed from on-chain state (`03 §7`):
- `available_now`, from both buckets, capped at the vault's token balance.
- `worst_1h` = `min_k C_k·(W_k + 1 hour)/W_k`.
- `worst_24h` = `min_k C_k·(W_k + 24 hours)/W_k`.

Summed across vaults at display prices. Display prices are **never** used on-chain.
When frozen: "Frozen: $0 can leave unbacked until {time}."

## 6. Non-goals (and where to go instead)

| We don't | Why | Instead |
|---|---|---|
| Detect attacks | Detection is a crowded, different skill | Range, Hypernative, solgov alerts feed our guardians |
| Protect user wallets | Different threat | Wallet vendors |
| Protect AMM pools | Every swap output is unbacked | — |
| Run an oracle | Different company | Pyth; SVI-style on-chain valuations |
| Underwrite insurance | Capital business | Cover partners price our published bound |
| Stop a patient insider forever | A rate limit buys time; people must use it | Guardians, alerts, the lifeboat |

## 7. Glossary

| Term | Meaning |
|---|---|
| **Vault** | A token account for one mint, owned by a Bulkhead PDA |
| **Mint gate** | A Bulkhead PDA holding a mint's authority; unbacked minting is rate-limited like unbacked outflow |
| **Owner** | The wallet or PDA whose tokens actually arrived in a deposit; backing belongs to it and pays only to it |
| **Backing / ledger** | Up to 8 positions `(mint, net)` per owner; positive = deposited, negative = backed borrowing |
| **Backed / unbacked** | Whether a payout is supported by the owner's ledger (G3) or must use the limiter (G1) |
| **Burst, daily cap** | The two GCRA buckets: default 2%/1h and 5%/24h of the lower of the reference and the live balance, optionally capped in tokens |
| **Reference balance** | A slow (24h) average of the vault balance. Capacities come from the lower of it and the live balance |
| **Ticket** | A queued unbacked payout with an ETA; guardians may cancel or extend it |
| **Freeze** | Guardian action: the unbacked lane queues everything and tickets cannot settle, ≤ 24h per call |
| **Lifeboat** | Bulkhead-held holding account for emergency moves; exits wait 72h to a pre-committed destination |
| **Guardian** | A key that can stop things (freeze, cancel, extend, veto, abort) but never move funds |
| **Floor** | Tier 0 program that holds upgrade authorities |
| **Abort binary** | A two-instruction sBPF v3 program that makes every call fail |
| **Seal** | The end of genesis: before it, releases are disabled and configuration applies instantly |
