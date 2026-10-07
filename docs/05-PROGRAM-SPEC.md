# 05 — Vault program specification (`programs/vault`)

This is the contract between the program, its integrators, the tests and auditors. All rules are computed by `bulkhead-core`. The program only:
- loads and checks accounts;
- calls the core;
- moves tokens;
- emits events.

Status: built (Pinocchio 0.11, one dependency: `bulkhead-core`), sBPF v3. Tested with scenario and negative tests plus a program-vs-model differential on the real runtime (`09 §7`), and exercised end-to-end on `solana-test-validator` (`cloud/e2e`). Deployed on devnet on 28 Sep 2026 (`HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b`); the bytes on devnet are the 29 Sep upgrade, not this tree (`08`, `SECURITY.md`). Unaudited.

Conventions:
- `now` = `Clock::unix_timestamp` (seconds); limiter math uses `now_ms = now × 1000`.
- **Admin** = `protocol.admin`. **Guardian** = a key in `protocol.guardians`. **Live** = heart-beat within `heartbeat_interval_s`. **Quorum** = `threshold` (≥ 2) distinct live guardians signing the same instruction.
- **Caller** = the protocol's PDA `["bulkhead-caller"]` under its own program id. Only the protocol program can sign as it, so only the protocol can `deposit` and `release`.
- Instruction data = one tag byte, then little-endian arguments. Account lists are documented above each handler in `programs/vault/src/*.rs`.
- Every state change emits a structured event with `sol_log_data` (`Program data: …`, the channel Anchor events use): `vault:released`, `vault:frozen`, `vault:change_proposed`, and so on. The Cloud guardian and the status page parse them.

## 1. Constants (compile-time; changing one means a different program)

| Name | Value | Meaning |
|---|---|---|
| `MIN_LOOSEN_DELAY_S` | 259 200 | 72h floor for any loosening, including the seal |
| `MAX_LOOSEN_DELAY_S` | 2 592 000 | 30-day cap. A raise applies at once, so an uncapped delay could push later governance out of reach. Floor's upgrade delay uses the same cap |
| `MAX_FREEZE_S` | 86 400 | Longest single freeze (re-freezable) |
| `MAX_TICKET_EXTENSION_S` / `_TOTAL_S` | 86 400 / 604 800 | Guardian extension limits |
| `QUEUE_HORIZON_S` | 604 800 | Requests whose ETA would be further out are refused |
| `CHANGE_EXPIRY_S` | 604 800 | A loosening not executed within 7 days of becoming executable expires |
| `MAX_GUARDIANS` / `MIN_GUARDIAN_THRESHOLD` | 8 / 2 | Guardian bitmaps are one byte; one key can never undo a stop |
| `MAX_SLOTS` | 8 | Positions per owner ledger |
| bps bounds | ≤ 10 000 | Limits and haircuts; liability weight ≥ 10 000 |

## 2. Accounts (PDAs of the Vault program)

| Account | Seeds | Size | Key fields |
|---|---|---|---|
| `Protocol` | `["protocol", protocol_program]` | 597 B | admin, caller, guardians + heartbeats, threshold, sealed, freeze, abdications, vault count, ticket and change counters, lifeboat destination (+ when set), seal schedule |
| `Vault` | `["vault", protocol, mint]` | 433 B | mint, token program, token account, `LimitConfig`, two TATs, EMA reference, pending tickets, queued amount, freeze, imported backing, counters (in, backed out, unbacked out, settled, cancelled), lifeboat and pending exit |
| Vault token account | `["vault-tokens", protocol, mint]` | 165 B + extensions | A token account whose authority is the `Vault` PDA. The protocol can't transfer, close or delegate it. |
| `Asset` | `["asset", protocol, mint]` | 159 B | `AssetConfig` (allowlisted, haircut, liability weight, confidence multiple, max age, max confidence, Pyth feed id) + decimals |
| `Backing` | `["backing", protocol, owner]` | 464 B | Up to 8 `(mint, net: i128)` positions: the owner's shadow ledger |
| `Ticket` | `["ticket", protocol, payer, nonce]` (the payer picks the nonce; the id inside is the protocol counter) | 216 B | vault, recipient token account and owner, amount, created, ETA, extension, payer; closed on settle or cancel |
| `Change` | `["change", protocol, id]` | 448 B | kind, target, payload, proposer, executable, expiry, vetoed, executed |
| Lifeboat token account | `["lifeboat-tokens", protocol, mint]` | 165 B + ext. | Authority = the `Vault` PDA |

Every account has an 8-byte discriminator and a fixed layout, read field by field (`state.rs`). Loading checks the owner program, the discriminator, the length and the re-derived PDA address. Tickets and changes use monotonic ids, so a closed id is never reused.

## 3. Lifecycle

```
register_protocol → create_vault / upsert_asset / import_backing        (genesis: configuration is instant)
                  → propose_seal ──72h, vetoable──► execute_seal         (sealed: releases enabled)
                  → deposit / release / settle_ticket                     (runtime; deposit and release only via the caller PDA)
                  → propose_change (tighten: now; loosen: 72h + veto) / freeze / cancel / lifeboat …
```

The seal waits 72h so anyone can compare the imported backing (public events) with the protocol's own books before money can leave (T19). While the seal is under review (proposed, not vetoed, not expired), no loosening applies: a new vault, an import, a looser asset, limits, guardians, admin, destination or delay are refused with `SealUnderReview`. Tightenings still apply at once. A guardian's veto ends the review; the next proposal waits a full 72h.

## 4. Instructions

| Tag | Instruction | Signer | Checks | Effect |
|---|---|---|---|---|
| 0 | `register_protocol` | the protocol's upgrade authority, **or** its caller PDA via CPI | delay ≥ 72h; 2 ≤ threshold ≤ count ≤ 8; guardians unique, ≠ admin; interval 1–30 days; destination ≠ admin | Creates `Protocol` (survives a pre-funded address) |
| 1 | `create_vault(limits)` | admin | limits valid (bps ≤ 10 000, windows > 0); mint passes the Token-2022 policy (§7); not while the seal is under review; after the seal, the limits must keep the unbacked lane closed (one bucket with no bps and no floor), and opening it is a 72h change | Creates `Vault` and its token account (size from `GetAccountDataSize`) |
| 2 | `upsert_asset(config)` | admin | genesis only (afterwards: `propose_change`) | Creates or updates `Asset` |
| 3 | `import_backing(amount)` | admin | genesis only | Credits `Backing[owner]`; `vault.imported += amount` |
| 4 / 6 / 5 | `propose_seal` / `veto_seal` / `execute_seal` | admin / live guardian / anyone | execute: after the delay, not vetoed, not expired; every vault, vault token account, and lifeboat token PDA passed exactly once; `imported + total_in ≤ vault balance + actual spendable lifeboat balance` | `sealed = true` |
| 7 | `deposit(amount)` | caller + source authority | accounts match the vault; source ≠ vault account | EMA update; `transfer_checked`; credits the amount actually **received** (transfer fees) to `Backing[source authority]`; returns `received` |
| 8 | `release(amount, nonce)` | caller | sealed; the recipient's mint matches; `(Asset PDA, price)` pairs for the released mint and every mint in the recipient owner's ledger, in ledger order | Backed part `b` from the ledger (§5), unbacked `u = amount − b` through the limiter: instant, or a `Ticket`, or the **whole instruction fails** (`LaneClosed`, `QueueFull`). Pays `b + instant`. |
| 23 | `quote_release(amount)` | none | as `release` | The same outcome as return data, no writes (for `simulateTransaction`) |
| 9 | `settle_ticket` | anyone | `now ≥ ETA`; not frozen (protocol or vault); the stored recipient and payer | Pays the ticket; closes it (rent to its payer) |
| 10 | `cancel_ticket` | live guardian (not the admin: a stolen admin key could cancel every queued withdrawal, A4) | ticket of this vault | Closes it; **no refund** of the reservation (G1 depends on it) |
| 11 | `extend_ticket(secs)` | live guardian | ≤ 24h per call, ≤ 7 days in total | ETA later |
| 12 | `freeze(scope, secs)` | live guardian or admin | ≤ 24h; never shortens | Protocol or vault `frozen_until` |
| 13 | `unfreeze(scope)` | live quorum | — | Freeze ends now (the admin can't unfreeze) |
| 14 | `heartbeat` | live guardian | a dead guardian can't revive itself | — |
| 15 | `eject(target)` | live quorum of the *other* guardians | stays ≥ threshold | Removes the guardian at once |
| 16 | `reset_backlog` | admin or live guardian | zero pending tickets | Each bucket clamped to "just emptied" |
| 17 | `abdicate(kind)` | admin + live guardian quorum | — | Loosening that change kind is gone forever (Morpho V2); tightening it stays instant |
| 18 | `propose_change(kind, target, payload)` | admin | valid; core classification; a loosening of an abdicated kind is refused | Tighten (or genesis) → applied now. Loosen → `Change` executable after ≥ 72h, expiring 7 days later. |
| 19 / 21 / 20 | `veto_change` / `cancel_change` / `execute_change` | live guardian / admin / anyone | execute: executable, not vetoed, not expired, not abdicated; payload re-validated | Applies the change |
| 22 | `attest` | none | — | Returns the live worst case (§6) |
| 24 / 25 | `lifeboat_move` / `lifeboat_return` | admin / admin or live quorum | — | Vault ↔ lifeboat (a Bulkhead-held account) |
| 26 / 28 / 27 | `propose_lifeboat_exit` / `veto_lifeboat_exit` / `execute_lifeboat_exit` | admin / live guardian / anyone | destination set ≥ 72h before the proposal; exit waits ≥ 72h; destination account owned by the committed destination | Lifeboat → the committed destination |
| 29 | `replace_recovery(key)` | admin + live guardian quorum | the new key is not the admin (all zero: none) | Replaces the recovery key at once; what the old key proposed (and any pending `SetRecovery`) goes stale (`09`, finding 62) |

Change kinds: `SetLimits(vault)`, `UpsertAsset(mint)`, `SetGuardians`, `SetAdmin`, `SetLifeboatDestination`, `SetLoosenDelay`, `SetRecovery`. The optional **recovery key** (set at registration, or later by the admin while none exists) may propose only `SetAdmin` and `SetRecovery`; the admin cannot cancel those, but the admin with a live guardian quorum replaces the key at once (`replace_recovery`), each key cancels only what it proposed, and a recovery `SetAdmin` makes every earlier admin rotation stale. A change records the version of what it replaces (the vault's limits, the asset record, or the protocol-level value) and executes only if that version has not moved: any change to the same thing since the proposal, an ejection included, makes it `ChangeStale`, and it must be proposed again. Guardians, admin and destination changes are always loosenings; a delay below 72h is refused even before the seal.

**Return data of `release`** (40 bytes, little-endian): `backed u64 | instant u64 | queued u64 | ticket_id u64 | eta_s i64`.
- It is set after the last CPI, because every CPI clears return data.
- The integrating protocol books the full amount against the user. If `queued > 0`, it records the ticket (`07 §3`).
- `eta_s` rounds the millisecond ETA **up**, so a ticket is never early.

## 5. Pricing and the backed amount

- Price accounts are Pyth `PriceUpdateV2`:
  - owned by the Pyth receiver (`rec5EKMG…`) or its Pyth Pro-compatible deployment (`rec2HHDD…`);
  - `Full` verification only;
  - the feed id must match the asset.
- **The allowlist can't be dodged.** For every mint in the owner's ledger, the program derives the `Asset` PDA and requires exactly that account. If no asset record exists there, the mint is truly "not allowlisted". Only the *price* may be omitted, and then the asset is `Unpriced`, which fails closed (collateral counts 0; a liability makes health unknown). A wrong feed or a partial verification is refused outright (`BadPriceAccount`).
- Stale or wide prices (per asset: max age, max confidence) are `Unpriced`.
- Bounds: `lo = min(spot, EMA) − k`, `hi = max(spot, EMA) + k`, `k = ⌈conf · mult⌉` (`03 §4.2`).
- The backed amount is `Ledger::backed_amount` (`03 §4.4`), with two exact early exits:
  - an owner with no collateral gets 0;
  - a fully payable amount is paid in full.

## 6. `attest`: the worst case, readable by any program

Return data (64 bytes): `available_now`, `worst_1h`, `worst_24h`, `balance`, `frozen_until`, `queued`, `loosen_delay_s`, `pending u32`, `live guardians u8`, `guardian count u8`, `sealed u8`.

- `worst_T` is the G1 bound over `T` if nobody freezes.
- `available_now` is exact: that amount would be instant; one unit more would not.

Any program can CPI into it. A router or curator can read a venue's live worst case **on-chain** and refuse to route funds when it's too large.

This matters in practice. A lender that accepts positions in other venues as collateral inherits their losses: Project 0 ships an instruction to claim from Drift's bad-debt portal (`01 §9`). The status page computes the same figures from raw account data, and the end-to-end test checks the two are identical.

## 7. Token-2022 extension policy (`create_vault`)

An **allowlist** of extension types (`ExtensionType` numbers from `spl-token-2022`); anything else, including types not known today, is refused:

| Extension | Policy | Reason |
|---|---|---|
| TransferFeeConfig (1) | Allowed | Deposits credit what was actually received |
| MintCloseAuthority (3) | Allowed only when the close authority is unset (32 zero bytes) | A set authority can close the mint at supply 0 and recreate the address with a refused extension |
| InterestBearing (10), MetadataPointer / TokenMetadata (18, 19), group pointers and members (20–23), ScaledUiAmount (25), PermissionedBurn (28) | Allowed | No custody effect |
| DefaultAccountState (6) | Allowed unless Frozen | A frozen default would trap the vault account |
| PermanentDelegate (12) | **Refused** | The delegate could move vault tokens outside Bulkhead (tested) |
| TransferHook (14) | **Refused** | Arbitrary code in the custody path |
| Confidential transfers (4, 16, 24) | **Refused** | Balances must be measurable |
| NonTransferable (9), Pausable (26) | **Refused** | Custody would be stuck or controlled elsewhere |
| Any mint's freeze authority | Disclosed | The issuer can freeze any holder; nobody can prevent that |

## 8. Errors

Codes from 8000 (`error.rs`), disjoint from Floor (7000+), Anchor (6000+) and the abort code:

`InvalidInstruction` 8000, `WrongAccountType`, `WrongAddress`, `AlreadyInitialized`, `NotRegistrar`, `NotAdmin`, `NotGuardian`, `NoQuorum`, `MissingSignature`, `WrongCaller`, `WrongVault`, `WrongMint`, `WrongTokenProgram`, `ExtensionNotAllowed`, `RecipientOwnerMismatch`, `BadPriceAccount`, `NotSealed`, `AlreadySealed`, `SealNotExecutable`, `ImportExceedsBalance`, `VaultCountMismatch`, `InvalidLimits`, `InvalidAsset`, `InvalidGuardians`, `DelayBelowMinimum`, `LaneClosed`, `QueueFull`, `Frozen`, `FreezeTooLong`, `TicketNotDue`, `TicketNotPending`, `ExtensionTooLong`, `TicketsPending`, `ChangeNotExecutable`, `ChangeVetoed`, `ChangeExpired`, `ChangeExecuted`, `Abdicated`, `LedgerUnsound`, `LedgerCorrupt`, `NoSlot`, `DuplicateAccount`, `CannotEject`, `GenesisOnly`, `DestinationNotSettled`, `NothingToExit`, `ZeroAmount`, `Overflow` (8047), `DelayAboveMaximum` (8048), `InsufficientBalance` (8049), `SealUnderReview` (8050), `ChangeStale` (8051).

## 9. The Solana attack classes (`sealevel-attacks`)

| # | Class | Check | Tested by |
|---|---|---|---|
| 0 | Signer authorization | admin, guardians, caller PDA, source authority | `only_the_protocol_itself_can_release`, `freezes_are_short…` |
| 1 | Account data matching | vault ↔ protocol ↔ mint ↔ token account; ticket ↔ vault; backing ↔ recipient owner | `a_ticket_settles…only`, differential |
| 2 | Owner checks | program-owned state; token accounts owned by a token program; prices owned by the Pyth receiver | `a_price_for_the_wrong_feed_is_refused` |
| 3 | Type cosplay | 8-byte discriminators + exact lengths | unit `every_layout_round_trips` (a `Change` never reads as a `Ticket`) |
| 4 | Initialization | creation only on an empty, system-owned PDA; pre-funding handled | `registration_survives_a_prefunded_config_address` (Floor) |
| 5 | Arbitrary CPI | token CPIs only to the vault's stored token program (SPL Token or Token-2022) | account matching |
| 6 | Duplicate mutable accounts | source ≠ vault account; recipient ≠ vault account; seal: each vault once | explicit `DuplicateAccount` checks |
| 7 | Bump canonicalization | canonical bumps found at creation and stored; later re-derived | load helpers |
| 8 | PDA sharing | distinct seeds per role | layout |
| 9 | Closing accounts | tickets closed (rent to their payer); monotonic ids never reused | `a_ticket_settles…` |
| 10 | Sysvar spoofing | `Clock::get()` / `Rent::get()` syscalls; no sysvar accounts trusted | code |

## 10. Compute (measured on the real runtime, through Harbor's CPI)

| Path | Compute units | Target |
|---|---|---|
| `deposit` | 9,848 (a first deposit, which creates the ledger: ~14–18k) | ≤ 25k |
| `release`, own deposit (G2 path) | 12,775 | ≤ 35k |
| `release`, priced borrow with two price pairs | 17,468 | ≤ 90k |
| `release` that becomes a ticket | 17,843 | — |
| `settle_ticket` | 4,882 | ≤ 20k |
| `attest` | 4,977 | — |
| Ten payouts in one transaction (S8) | < 1.4M (the transaction limit) | — |

Framework decision (D13, revised 27 Sep): **Pinocchio for both programs.** Floor showed the approach works: 56 KB, a 10k-CU stop, zero framework code. Both programs share one dependency (the verified core) and one test harness. The cost is manual account checks, and each has a negative test.
