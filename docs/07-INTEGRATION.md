# 07 — Integration guide (and Harbor, the reference integration)

Exact account lists and data layouts are documented above each handler in `programs/floor/src/lib.rs` and `programs/vault/src/*.rs`. Working instruction builders (Rust) are in `programs/tests/tests/common/`, and the zero-dependency JavaScript client is in `cloud/lib/`.

## 1. Floor (Tier 0): one instruction, zero code changes

```
bulkhead_floor::register(owner, guardians, threshold, heartbeat_interval, delay)
  signed by your program's CURRENT upgrade authority
```

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
2. **Register** (`register_protocol`), signed by your upgrade authority or by the caller PDA through a CPI:
   - admin = your Squads vault;
   - 2–8 guardians (ops key, the Bulkhead Cloud bot, a security partner) and a threshold ≥ 2;
   - a heartbeat interval (7 days default);
   - loosen delay from 72h through 30 days (a raise applies at once, so a longer one is refused);
   - `lifeboat_destination` = a *different* cold multisig.
3. **Create one vault per custody mint** (`create_vault` with your limits). The mint must pass the Token-2022 policy (`05 §7`).
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
- **Liquidations:** take the liquidator's repayment first (a `deposit`, which creates backing), then `release` the seized collateral. More than the bonus is unbacked: the repayment backs collateral only at the conservative *high* price times the liability weight, and in a falling market Pyth's EMA sits above spot. In the crash scenario (`08` S11) 14–17% of every liquidation is unbacked with a 5% bonus. Size the buckets for cascades (§4, step 5).

## 4. Calibration (how to set the limits for a real protocol)

Inputs: the last 90 days of the protocol's outflows per vault (from its events or an indexer), vault balances, and historical Pyth prices.

1. Replay each historical outflow through `bulkhead-core` (the backed amount at the prices of that moment); the rest is the unbacked part.
2. For each vault, compute the maximum unbacked sum over any 1-hour window and any 24-hour window, as a fraction of the capacity base at that time (the lower of the reference and the live balance, `03 §3`).
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

```json
{ "rpc": "https://your-primary-rpc", "rpcs": ["https://a-second-provider", "https://a-third"],
  "vaultProgram": "...", "protocolProgram": "...", "mints": ["..."],
  "guardianKey": "/etc/bulkhead/keys/guardian.json",
  "stateFile": "/var/lib/bulkhead/<name>.state.json",
  "alert": { "url": "https://hooks.slack.com/services/...", "format": "slack" },
  "policy": { "approvedChanges": [] } }
```

- **Endpoints from different providers.** With `rpcs`, reads and sends move to the next endpoint when one fails, and every transaction also goes to all of them (`09`, findings 49 and 51). Prefer endpoints that keep transaction history.
- **Alerts.** Freezes, failures and lifeboat moves need people: only a guardian quorum unfreezes or returns the lifeboat. Set `alert`, and keep its URL secret.
- **Supervision.** The guardian exits on anything it cannot recover from, after logging and alerting it. Run it under `cloud/guardian/bulkhead-guardian@.service` (systemd: restarts it, never gives up, read-only filesystem except its state directory). The incident hold is kept across restarts in `stateFile` (under the unit, its state directory by default; `09`, findings 48 and 54).
- **Liveness.** It heartbeats every 24h; a key that misses its on-chain interval stops counting toward the quorum. The status page shows each guardian's standing.
- **Approvals are explicit, and name what is approved.** It vetoes every loosening, lifeboat exit and Floor proposal not listed in its policy, as soon as it is proposed. Approve a change by what it does, never by its id: `approvedChanges` takes `"kind:target:payloadHex"`, `approvedFloorProposals` takes `"program:kind:target:payloadHex"` (code by buffer, in `approvedUpgradeBuffers`), and `approvedExits` takes `"mint:amount"`. An id is only the next counter, so a stolen key that proposes first would take an id approved in advance; the guardian refuses to start with `approvedChangeIds`. Add the approval and restart the guardian *before* proposing, so it never vetoes the change; `node cloud/deploy/approvals.mjs <rpc> <vault-program> <protocol> [floor-program protected-program]` prints the approval of each change already pending (`09`, finding 61).

## 7. Not in this build

- **Mint gates** (a Bulkhead-held mint authority with the same limiter on supply) and **flash loans** (`flash_release` with an introspected top-level `flash_repay`) are specified in `03 §4.8`.
- They are not implemented in this build. A protocol that needs them waits, rather than routing around custody.
- **A backing-transfer hook** (moving backing with a transferable position, §4) is not designed yet.
