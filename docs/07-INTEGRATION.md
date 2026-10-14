# 07 — Integration guide (and Harbor, the reference integration)

Exact account lists and data layouts are documented above each handler in `programs/floor/src/*.rs` and `programs/vault/src/*.rs`. Working instruction builders (Rust) are in `programs/tests/tests/common/`, and the zero-dependency JavaScript client is in `cloud/lib/`.

## 1. Floor (Tier 0): one instruction, zero code changes

```
bulkhead_floor::register(owner, guardians, threshold, heartbeat_interval, delay, recovery?)
  signed by your program's CURRENT upgrade authority
```

- `recovery` is optional: absent or all zero means none; a cut-off key is refused. It may later propose only a new owner or a new recovery key (`06 §6`), and is never a guardian or the owner.
- The instruction creates Floor's config and **moves the upgrade authority to Floor's PDA itself** (a CPI `SetAuthority`), in one step. There is never a moment when Floor holds your key but someone else chose your guardians.
- If your upgrade authority is a Squads vault, execute `register` as a vault transaction.
- Then:
  1. Stage the stop button: write the canonical abort binary (`bulkhead_core::floor::ABORT_ELF`) to a buffer, set that buffer's authority to Floor's PDA, and call `stage_abort`.
  2. Pin a snapshot: write your live binary to a buffer, hand its authority to Floor, and call `pin_snapshot`. Floor verifies it byte-for-byte on-chain.

  Anyone can do both, including the Bulkhead Cloud bot.
- From then on your owner key *proposes* upgrades, and they execute after the delay (72h through 30 days; **7 days recommended**) unless a guardian vetoes. Any live guardian can stop the program in one instruction.
- Read `elf_is_v3` in the config, or run `python3 tools/floor_check.py <program-id>`. If it's false, build and test an sBPF v3 version now (`06 §8`).

## 2. Vault (Tier 1) checklist

1. **Derive your caller PDA:** `["bulkhead-caller"]` under your own program id. Only your program can sign as it, so only your program can deposit and release. **Check the Vault program id before signing.** The caller PDA is the signature the Vault trusts as "this protocol", and signer privileges carry into nested calls. Harbor refuses any program id other than the one it was built for (`BULKHEAD_VAULT_ID`). Copy that check. Do not forward the signature to a program id the caller supplied.
2. **Register** (`register_protocol`), signed by your upgrade authority or by the caller PDA through a CPI. Prefer the upgrade authority: registration is one-shot, and a CPI path anyone can call (like Harbor's REGISTER) lets whoever calls first choose the admin and guardians. If you register through a CPI, gate it on your upgrade authority or a compiled-in key (`09`, finding 87):
   - admin = your Squads vault;
   - 3–8 guardians (ops key, the Bulkhead Cloud bot, a security partner) and a threshold of at least 2 and below the guardian count, so the others can always eject a rogue (finding 96; plan for `threshold + 2`, §6);
   - a heartbeat interval (7 days default);
   - loosen delay from 72h through 30 days (a raise applies at once, so a longer one is refused);
   - `lifeboat_destination` = a *different* cold multisig.
3. **Create one vault per custody mint** (`create_vault` with your limits). The mint must pass the Token-2022 policy (`05 §7`). A mint with InterestBearing (10) or ScaledUiAmount (25) may be held, but is never priced: an asset record that allowlists it is refused (`ExtensionNotAllowed`).
4. **Allowlist valued assets** during genesis (`upsert_asset`: Pyth feed id, haircut ≥ your max LTV + 5 points, liability weight, confidence multiple, max age, max confidence). Use feeds for deep assets only.
5. **Migrate:**
   1. `import_backing` for every existing depositor, from a published snapshot;
   2. move the tokens from your old accounts into the vault token accounts;
   3. `propose_seal`. The seal executes after 72h; meanwhile anyone can compare the imports (public events) with your books.
6. **Replace every token movement:**
   - transfer in → CPI `deposit(amount)`, signed by the caller PDA plus the user;
   - transfer out → CPI `release(amount, nonce)`, signed by the caller PDA. Pass the ticket account `["ticket", protocol, payer, nonce]` with a nonce the payer has not used (a counter or random u64): it is created only if part of the amount is queued, and two users' releases never compete for it.
7. **Read the outcome** of each `release` from return data: `backed | instant | queued | ticket_id | eta_s` (40 bytes, `05 §4`). Book the full amount against the user. If `queued > 0`, record `(ticket_id, queued, eta_s)` so your UI shows "arriving at ETA"; anyone can call `settle_ticket` once it's due.
8. **A cancelled ticket** is a governance matter. The tokens stay in the vault. Never re-release automatically: cancellation usually means an incident.
9. **Calibrate** (§4) before the seal. Tightening later is instant; loosening takes 72h.
10. **Run a guardian** (Bulkhead Cloud or your own `cloud/guardian`) and publish the status page. It vetoes every loosening, lifeboat exit and Floor proposal you have not pre-approved, and it is also your **keeper**: a change you did approve (`approvedChanges`, `approvedFloorProposals`, `approvedUpgradeBuffers`, each by what it does) is executed by it as soon as its delay ends. Solana programs never run on their own, so after a delay someone must send `execute`; anyone may, and the keeper makes sure someone does, before the 7-day expiry. It never executes the release of Floor's upgrade authority, which closes Floor's config.

**Before the seal, the admin key is trusted completely** (`04`, T19b). Configuration is instant then: guardians, limits, assets, imported backing. Nothing can be paid out, not even a depositor's own deposit, and the lifeboat is shut until the seal (finding 86). So:

- **Admin.** Make it a multisig (a Squads vault, at least 2-of-3, hardware keys) from registration. Set the recovery key at registration, a separate cold key.
- **Guardians.** Use independent operators, each running a guardian from registration.
- **A short, public genesis.** Register, create the vaults, add the assets, import and `propose_seal` on the same day. Publish the snapshot of imported balances with the seal proposal, so anyone can compare it during the 72h review.
- **No deposits before the seal.** Open deposits in your UI only once the status page (or `attest`) shows the protocol sealed. Before that, a deposit cannot be withdrawn.
- **After the seal**, check that the guardian set, the admin, the recovery key and the lifeboat destination are the ones you published, then announce.

**Hard rules.** Each one is a way to lose the guarantee without a bug in Bulkhead:

- **Pin the Vault program id** in every CPI that carries the caller PDA's signature (step 1; `15`, A11). Compare it with a constant, never with an account the transaction supplies.
- **Deposit credits the signing source authority**, not the token account's owner. Have the user sign as the authority of their own token account. Never pull tokens through a delegate PDA that you also release to: every deposit would credit that PDA, and a release to an account it owns would be backed by everyone's deposits.
- **A recipient can stall its own ticket.** `settle_ticket` pays the token account stored in the ticket. If its owner closes it, freezes it or enables `MemoTransfer` (the Vault's transfer carries no memo), settling fails and the ticket stays pending, with its reservation, until a guardian cancels it (`cancel_ticket`). While it is pending, `reset_backlog` is refused. Watch for tickets past their ETA that do not settle.
- **You trust the mint's issuer.** For a `TransferFeeConfig` mint, the fee authority can raise the fee up to its configured maximum: deposits credit what arrived, but every release then delivers less. A mint's freeze authority can freeze the vault token account and stop custody entirely. Bulkhead discloses both (`05 §7`); it cannot prevent either. Prefer mints with no freeze authority and no fee authority.
- **No lifeboat for a fee-bearing mint.** Each lifeboat move would pay the mint's transfer fee, so a stolen admin key moving a vault in and out repeatedly in one transaction would burn value as withheld fees (`09`, finding 97). `lifeboat_move` refuses a mint with a non-zero transfer fee or a fee config authority (`FeeBearingMint`); `lifeboat_return` always works. Plan your emergency path accordingly if you custody such a mint.
- **Use v0 transactions with a lookup table for users with many mints.** A `release` names 11 fixed Vault accounts, then an (asset, price) pair for the paid mint and every other mint in the owner's ledger. Size is the limit: through Harbor (14 fixed keys: the Vault's 11, the Harbor and Vault programs, and the user) a borrow against a full ledger of 8 is 1,176 of 1,232 bytes with a relayer paying, and paying a ninth mint is 1,242 bytes, which does not fit (finding 104). Put the accounts that are the same on every release in an address lookup table: the Vault program, your caller PDA (it signs only through your CPI), the protocol, the vault and its token account, the mint, the token and system programs, and the asset PDAs and price accounts. The per-user and per-release accounts (the recipient, the backing PDA, the ticket PDA), the transaction's signers and the program you invoke stay in the message.
- **Set the compute limit from a simulation.** A release's compute is not fixed. The test measured about 77k CU through Harbor for a full ledger and a 200,000-token over-ask, with Harbor's overhead, Harbor's caller-PDA search and the Vault's ticket search at their cheapest (both bumps at 255); the same test cost 90,387 on CI, where those bumps sat 3 and 6 steps lower. Compute grows with the backed-amount search (about log₂ of the amount requested, up to 64 steps), and each PDA the program has to find costs 1,500 CU plus 1,500 per step its bump sits below 255: the ticket when part of the payout queues; the owner's backing PDA on every release to an owner with no ledger yet; the asset PDA of the paid mint and of each ledger mint that has no asset record; and your program's own (Harbor derives its caller PDA on every call). Simulate each release and set its limit from the result, with a margin.
- **Placeholder price accounts, only where no price can change the outcome.** Every release takes a price account per mint, and a placeholder (the system program) is read as "no price". The test and the code show three cases where that changes nothing: an own-deposit exit with no loan open (at most the owner's balance of the paid mint, G2); a mint outside a full ledger (no slot, so nothing can be backed; paying a ninth mint that way is 954 bytes); and the owner's own balance of a mint with no asset record. In other releases a placeholder can take the backing away: a borrow with placeholders is never backed, and with a loan open neither is the owner's own balance of an allowlisted mint; the amount then goes to the limited lane, where it is paid, queued, or refused (`LaneClosed`, `QueueFull`) like any unbacked payout. Unless your release is one of the three, pass the real price accounts. The asset PDAs are always required.
- **Deposit with the user as the authority.** The caller PDA signs every release, so its signature never counts as a borrower's consent (`09`, finding 98): a ledger the caller PDA owns gets its own balance back, but never a backed loan. Each user's deposit must be signed by that user, never by any PDA of your program: your program can sign as any of its PDAs (a pool, an escrow), the Vault cannot tell those from a user's key, and a compromised program would then consent to loans against them.

## 3. The pattern, from Harbor (`programs/harbor`)

Harbor forwards to Bulkhead, signing as its caller PDA:

```rust
// accounts: [vault program, caller PDA, …harbor accounts, …Vault instruction accounts from index 1]
let seeds = [Seed::from(b"bulkhead-caller".as_ref()), Seed::from(&[bump])];
invoke_signed_with_bounds::<MAX, &AccountView>(&release_ix, &accounts, &[Signer::from(&seeds)])?;
// then read the outcome with get_return_data(): backed, instant, queued, ticket_id, eta_s
```

- **Your own checks come first.** Harbor's `WITHDRAW` requires the user to own the recipient token account. A real protocol also checks the user's claim, LTV and so on. Bulkhead is not your risk engine; it bounds what happens when that engine is wrong or compromised.
- **Pin the Vault program id.** Harbor compares account 0 with a build-time constant and returns `IncorrectProgramId` otherwise. An integration that signs for whatever program the transaction names hands the caller PDA to that program.
- **Price pairs.** For a `release`, pass `(Asset PDA, Pyth price account)` pairs for the released mint and then for every other mint in the recipient's ledger, in ledger order. For an owner who owes nothing and takes back their own deposit (G2), pass the asset PDA and any non-Pyth account as the price: no prices are needed.
- **Borrowers sign the release.** A backed release beyond the recipient owner's own balance of that mint is a loan in that owner's name, and the Vault backs it only if the owner signed: append the user's account, as a signer, after the price pairs (Harbor forwards signer flags, so the user's signature on your transaction reaches the Vault). Without it the excess goes to the unbacked lane: a compromised caller can no longer create loans in other people's names through the unfreezable backed lane (finding 74). Own-deposit withdrawals need no signature; a liquidator signs its own liquidation.
- **Liquidations:** take the liquidator's repayment first (a `deposit`, which creates backing), then `release` the seized collateral. More than the bonus is unbacked: the repayment backs collateral only at the conservative *high* price times the liability weight, and in a falling market Pyth's EMA sits above spot. In the crash scenario (`08` S11) 14–17% of every liquidation is unbacked with a 5% bonus. Size the buckets for cascades (§4, step 5).

## 4. Calibration (how to set the limits for a real protocol)

Inputs: the last 90 days of the protocol's outflows per vault (from its events or an indexer), vault balances, and historical Pyth prices.

1. Replay each historical outflow through `bulkhead-core` (the backed amount at the prices of that moment); the rest is the unbacked part.
2. For each vault, compute the maximum unbacked sum over any 1-hour window and any 24-hour window, as a fraction of the capacity base at that time (the least of the reference, the live balance and the low-water balance, `03 §3`).
3. Set `short_bps ≥ 1.5 × max hourly` and `long_bps ≥ 1.5 × max daily`, never below the defaults (2%, 5%) unless the history is flat.
4. Set absolute caps (`short_cap`, `long_cap`, in tokens) at the same percentages of the vault's honest size, for example its 30-day median balance. Without caps, an attacker who parks their own capital in the vault raises the base while it is there (`15`, A1b). Lowering a cap is instant; raising one waits 72h, so review caps as the vault grows. The demo setup creates its vault with calibrated caps; `cloud/deploy/market.mjs caps` applies them to an existing demo market.
5. **Lending markets: size for a crash, not only for history.** A quiet 90 days says nothing about a cascade. Run `crates/bulkhead-core/tests/cascade.rs` with the market's own weights, bonus and collateral share. With the defaults, a 10-minute −20% crash that liquidates 17% of a vault already queues some liquidations for 6 hours; 4%/h and 10%/day absorb a 30% cascade (`08` S11). Looser limits also double what a thief can take, so this is a trade-off to publish, not hide.
6. Report how many historical requests *would have queued* under the chosen values. The target is zero.
7. Publish the report. It is the evidence that honest users never notice.

Harbor is calibrated synthetically. Real calibration happens with the first design partner.

**Which protocols fit.** Backing belongs to whoever deposited. Protocols whose positions are **not transferable** (lending accounts, perps margin, vaults without a share token) fit well: withdrawals are backed and never queue. Protocols whose positions **are** transferable (LP tokens, cTokens, liquid-staking tokens) do not fit as they are: a buyer on the secondary market redeems with no backing, so ordinary redemptions go through the limited lane, calibration pushes the limits up, and the bound weakens. They need a backing-transfer hook, which is not in this build (§6).

## 5. Harbor, the reference integration

Harbor is deliberately naive, so the scenarios can play a compromised protocol:

| Tag | Instruction | Who | What it does |
|---|---|---|---|
| 0 | `REGISTER` | anyone (first caller) | Registers Harbor with Bulkhead, the caller PDA acting as registrar |
| 1 | `DEPOSIT(amount)` | a user | Forwards to `deposit` |
| 2 | `WITHDRAW(amount)` | a user who owns the recipient account | Forwards to `release`, any amount (a "buggy" protocol) |
| 3 | `ADMIN_PAYOUT(amount)` | the admin recorded in Harbor's Bulkhead protocol account | Forwards to `release` for anyone: the Drift path |

A protocol whose admin can pay anyone anything is the worst case. Harbor shows that even then, Bulkhead bounds the outflow (`08` S1, S8).

## 6. Running a guardian

The guardian (`cloud/guardian/main.mjs`, Node 20+, no dependencies) is what turns G1's bound into a freeze within seconds. Each guardian key should run on its own host, under its own operator.

**Stopping a program under Floor is a person's decision; the bot never does it.** In an incident, a guardian runs `node cloud/guardian/stop.mjs <guardian-config.json> <program>`. It reads Floor's config fresh before each attempt (the abort buffer and the current snapshot pin, which anyone may move), sizes the compute budget to the program, prices from recent fees (never below 10,000 µL/CU), sends to every endpoint each slot until Floor shows the program stopped, then checks that calls fail. Measured on a local validator: **4.1 s (8 slots) every time** with no interference; **15–44 s** while an attacker extended the program every slot to block it (finding 77: `ExtendProgram` is permissionless and an upgrade is refused in a slot with an extension); the old code never ran meanwhile, and calls in a slot with an extension fail with `UnsupportedProgramId`, the attacker's own included. The Floor demo in the deploy rehearsal stops its program with this tool, so CI exercises it.

**After a stop, a restore or an upgrade, re-arm, then take the old buffers' rent back.** Stage a new abort buffer and pin a new snapshot (A5). Then the owner runs `node cloud/deploy/floor-buffers.mjs <rpc> <floor-program> <program>`. It lists every buffer Floor holds for the program as `abort`, `pin`, `pending`, `spare` (identical to the live code: a stop may name it, so it stays until the code changes or the program is stopped) or `orphan`: a cleared pin, or a withdrawn or stopped proposal's buffer. With `--close <owner.json>` it closes the orphans and returns their rent to the owner (about 1.04 SOL per 200 KB; `09`, finding 78). Floor refuses to close the other three whatever the tool says. The deploy rehearsal closes the buffer of the upgrade its demo withdraws, so CI exercises this too.

```json
{ "cluster": "mainnet-beta",
  "rpc": "https://your-primary-rpc", "rpcs": ["https://a-second-provider", "https://a-third"],
  "vaultProgram": "...", "protocolProgram": "...", "mints": ["..."],
  "guardianKey": "/etc/bulkhead/keys/guardian.json",
  "stateFile": "/var/lib/bulkhead/<name>.state.json",
  "alert": { "url": "https://hooks.slack.com/services/...", "format": "slack" },
  "liveness": { "url": "https://hc-ping.com/<uuid>", "everyS": 60 },
  "minBalanceSol": 0.1,
  "policy": { "approvedChanges": [] } }
```

**The config is checked before anything runs** (`checkConfig`, `checkPolicy`; `09`, finding 83). An unknown setting (a typo), a wrong type or an out-of-range number stops the start with its name. Fractions are fractions (0.5, not 50), and seconds are whole numbers. With `"cluster": "mainnet-beta"` the guardian refuses to start without backup endpoints and an alert webhook. It also checks the RPC's genesis hash, so a devnet endpoint cannot pass for mainnet, and warns when `liveness` is missing.

**Before launch, for each guardian key:**
- **Its own host, cloud account and RPC providers.** Run at least two more keys than the quorum (3-of-5, or 2-of-4 at the least). With only one more, one lost key and one rogue guardian leave no quorum that can replace either, and governance is locked for good (`16` §4.4, AUD-2). The guardian logs this at start, and on mainnet it alerts.
- **Caps set.** The guardian alerts once for each watched vault without absolute caps: without them, capital an attacker parks first widens the worst case it freezes against (§4; `15`, A1b). The status page shows such a vault as UNCAPPED.
- **A dead-man's switch.** Set `liveness` to a service such as healthchecks.io or a pager's heartbeat URL, which pages when the pings stop. The bot's own alerts stop with its process or host; the on-chain heartbeat shows a dead guardian only a day later.
- **Funds.** About 0.5 SOL. The guardian alerts below `minBalanceSol` (default 0.05). A freeze costs at most 55,000 lamports and heartbeats about 0.002 SOL a month, but a freeze retried under congestion pays up to 1,000,000 µL/CU (`maxPriorityMicroLamports`).
- **Permissions.** The key file is 0600, owned by the service user, and so is the config: it holds the webhook URL and RPC keys. Use a system Node 20+ (`ProtectHome` hides nvm installs), with NTP running (the unit waits for `time-sync.target`).
- **Approvals.** Pin Vault approvals to their base version, and write the mainnet config by hand and have it reviewed.
- **Practice.** Once a week, stop one guardian on purpose and check that the pager fires.

- **Endpoints from different providers.** With `rpcs`, reads and sends move to the next endpoint when one fails, and every transaction also goes to all of them (`09`, findings 49 and 51). Prefer endpoints that keep transaction history.
- **RPC requirements.** Every endpoint must allow `getProgramAccounts` on the Vault and Floor programs (the ticket, change and keeper scans use it; a node answering -32010 or -32601 is now skipped for a backup), answer with low latency (measured on a local validator: a freeze 5.4–5.6 s after the first payout and 2–3 s after the payout that crosses the threshold; 13–20 s with every RPC call delayed 1.5 s; `09`, finding 82), and there must be **at least one backup** in `rpcs`. With backups, the guardian also cross-checks them every `freshnessCheckS` (60 s): a primary more than 150 slots behind the best, or missing a transaction a backup has had for over 30 s, is switched away from with an urgent alert (`09`, finding 76).
- **Spam slows ingestion.** Anyone can send cheap transactions that list the protocol account (for example `attest`), and the guardian reads every one. A pass now ingests for at most `ingestBudgetMs` (3 s), fetching `ingestConcurrency` (8) transactions at a time, and carries the rest to the next pass, so the chain sync, freeze retry, ticket scan, vetoes and heartbeats keep running; ingestion more than `lagAlertS` (60 s) behind the chain raises an urgent "ingest lagging" alert. Under heavy spam a freeze still comes as late as that lag: a faster endpoint is the fix.
- **Outflow alerts.** Unbacked outflow under the freeze thresholds still alerts once it passes half the 24-hour threshold, and as a "sustained drip" when it does on 2 of 3 days (`alertFractionOfThreshold`, `sustainedDays`). Those are for people: the bot does not freeze a drip under the honest ceiling (`15`, A2).
- **Alerts.** Freezes, failures and lifeboat moves need people: only a guardian quorum unfreezes or returns the lifeboat. Set `alert`, and keep its URL secret. A delivery that fails is retried three times (1, 3, 9 s); one never delivered is reported in the log and is not muted.
- **How a freeze is sent.** The freeze has its own sending loop. It goes out without preflight to every endpoint, rebroadcast every 400 ms, at no less than `freezeMinPriorityMicroLamports` (100,000 µL/CU, i.e. 5,000 lamports). After each 6 s without confirmation it is signed again with a fresh blockhash at twice the price, up to `maxPriorityMicroLamports`, until the chain shows the protocol frozen or `freezeDeadlineS` (90 s) passes; then the next loop pass tries again and the failure alerts. A freeze's priority price no longer comes only from recent fees on the protocol account: a quiet account shows 0 (`09`, finding 82).
- **Supervision.** The guardian exits on anything it cannot recover from, after logging and alerting it. Run it under `cloud/guardian/bulkhead-guardian@.service` (systemd: restarts it, never gives up, read-only filesystem except its state directory). The incident hold is kept across restarts in `stateFile` (under the unit, its state directory by default; `09`, findings 48 and 54).
- **Liveness.** It heartbeats every 24h; a key that misses its on-chain interval stops counting toward the quorum. The status page shows each guardian's standing.
- **Approvals are explicit, and name what is approved.** It vetoes every loosening, lifeboat exit and Floor proposal not listed in its policy, as soon as it is proposed. Approve a change by what it does, never by its id: `approvedChanges` takes `"kind:target:payloadHex"`, `approvedFloorProposals` takes `"program:kind:target:payloadHex"` (code by buffer, in `approvedUpgradeBuffers`), and `approvedExits` takes `"mint:amount"`. An id is only the next counter, so a stolen key that proposes first would take an id approved in advance; the guardian refuses to start with `approvedChangeIds`. Add the approval and restart the guardian *before* proposing, so it never vetoes the change; `node cloud/deploy/approvals.mjs <rpc> <vault-program> <protocol> [floor-program protected-program]` prints the approval of each change already pending (`09`, finding 61).
- **Approval expiry reads the guardian host's clock.** An `@expiry` and the keeper's due check use the host's time; a clock running behind keeps an expired approval live a little longer (an early execute only fails on chain). Run NTP; the unit waits for `time-sync.target`.
- **Pin Vault approvals to the base version.** Content alone can be proposed again by anyone holding the proposing key. Prefer `"kind:target:payloadHex#<baseVersion>"`: `baseVersion` is the version of the target that the change account records when proposed (the vault's limits version for limits, the asset record's version for an asset (0 if none yet), otherwise the protocol's version for that kind). The change executes only while the target is still at that version, and every execution moves it on, so a pinned approval can never match a replay, whatever the guardian remembers. Proposing does not move the version, so you can read it beforehand; `approvals.mjs` prints the pinned form of every open change. A live proposal event names no version, so the guardian reads the change account by id before it decides. Floor approvals have no version.
- **Unpinned approvals are spent.** An approval without `#<baseVersion>` still works, but the guardian logs a warning at startup. Once a matching change executes, one approval of that content is spent: the live one that expires first (one with no expiry last; an expired one is never spent). The state file records this (`stateFile`), and so does the list of executions already seen: a guardian with no such record treats every change that has already executed as old and spends nothing on it. To approve the same content again, add it again with an expiry, `"...@<unix seconds>"`, so it is a different entry (`09`, finding 71).

## 7. Not in this build

- **Mint gates** (a Bulkhead-held mint authority with the same limiter on supply) and **flash loans** (`flash_release` with an introspected top-level `flash_repay`) are specified in `03 §4.8`.
- They are not implemented in this build. A protocol that needs them waits, rather than routing around custody.
- **A backing-transfer hook** (moving backing with a transferable position, §4) is not designed yet.
