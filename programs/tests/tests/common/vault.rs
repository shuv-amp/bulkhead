//! Vault harness: SPL mints and token accounts, Pyth `PriceUpdateV2` accounts,
//! and builders for Bulkhead Vault instructions sent through Harbor (the demo
//! protocol that signs as its caller PDA), exactly as an integrator would.
#![allow(dead_code)]

use super::*;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;

pub fn token_program() -> Address {
    Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}
pub fn token_2022() -> Address {
    Address::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}
pub fn pyth_receiver() -> Address {
    Address::from_str_const("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ")
}

/// Vault error codes (programs/vault/src/error.rs).
pub mod verr {
    pub const WRONG_ADDRESS: u32 = 8002;
    pub const NOT_ADMIN: u32 = 8005;
    pub const NOT_GUARDIAN: u32 = 8006;
    pub const NO_QUORUM: u32 = 8007;
    pub const WRONG_CALLER: u32 = 8009;
    pub const EXTENSION_NOT_ALLOWED: u32 = 8013;
    pub const BAD_PRICE_ACCOUNT: u32 = 8015;
    pub const NOT_SEALED: u32 = 8016;
    pub const SEAL_NOT_EXECUTABLE: u32 = 8018;
    pub const IMPORT_EXCEEDS_BALANCE: u32 = 8019;
    pub const DELAY_BELOW_MINIMUM: u32 = 8024;
    pub const LANE_CLOSED: u32 = 8025;
    pub const QUEUE_FULL: u32 = 8026;
    pub const FROZEN: u32 = 8027;
    pub const FREEZE_TOO_LONG: u32 = 8028;
    pub const TICKET_NOT_DUE: u32 = 8029;
    pub const EXTENSION_TOO_LONG: u32 = 8031;
    pub const TICKETS_PENDING: u32 = 8032;
    pub const CHANGE_NOT_EXECUTABLE: u32 = 8033;
    pub const CHANGE_VETOED: u32 = 8034;
    pub const ABDICATED: u32 = 8037;
    pub const CANNOT_EJECT: u32 = 8042;
    pub const GENESIS_ONLY: u32 = 8043;
    pub const DESTINATION_NOT_SETTLED: u32 = 8044;
}

pub fn so(name: &str) -> Vec<u8> {
    let path = format!("{}/../../target/deploy/{name}.so", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|_| panic!("build programs first: scripts/build-programs.sh ({path})"))
}

// ---------------------------------------------------------------------------
// SPL Token
// ---------------------------------------------------------------------------

impl Env {
    pub fn create_mint(&mut self, decimals: u8, program: &Address) -> (Address, Keypair) {
        let mint = Keypair::new();
        let authority = Keypair::new();
        let lamports = self.svm.minimum_balance_for_rent_exemption(82);
        let create = solana_system_interface::instruction::create_account(
            &self.payer.pubkey(),
            &mint.pubkey(),
            lamports,
            82,
            program,
        );
        let mut d = vec![20u8, decimals]; // InitializeMint2
        d.extend_from_slice(authority.pubkey().as_ref());
        d.push(0); // no freeze authority
        let init = Instruction { program_id: *program, accounts: vec![AccountMeta::new(mint.pubkey(), false)], data: d };
        self.ok(&[create, init], &[&mint]);
        (mint.pubkey(), authority)
    }

    pub fn token_account(&mut self, mint: &Address, owner: &Address, program: &Address) -> Address {
        let acc = Keypair::new();
        let size = 165; // no extensions: the same base layout in both token programs
        let _ = program;
        let lamports = self.svm.minimum_balance_for_rent_exemption(size);
        let create = solana_system_interface::instruction::create_account(
            &self.payer.pubkey(),
            &acc.pubkey(),
            lamports,
            size as u64,
            program,
        );
        let mut d = vec![18u8]; // InitializeAccount3
        d.extend_from_slice(owner.as_ref());
        let init = Instruction {
            program_id: *program,
            accounts: vec![AccountMeta::new(acc.pubkey(), false), AccountMeta::new_readonly(*mint, false)],
            data: d,
        };
        self.ok(&[create, init], &[&acc]);
        acc.pubkey()
    }

    pub fn mint_to(&mut self, mint: &Address, authority: &Keypair, to: &Address, amount: u64, program: &Address) {
        let mut d = vec![7u8];
        d.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: *program,
            accounts: vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new(*to, false),
                AccountMeta::new_readonly(authority.pubkey(), true),
            ],
            data: d,
        };
        self.ok(&[ix], &[authority]);
    }

    pub fn balance(&self, token_account: &Address) -> u64 {
        let d = self.account(token_account).data;
        u64::from_le_bytes(d[64..72].try_into().unwrap())
    }

    /// Writes a fully verified Pyth `PriceUpdateV2` account.
    #[allow(clippy::too_many_arguments)]
    pub fn set_price(&mut self, at: &Address, feed: [u8; 32], price: i64, conf: u64, expo: i32, ema: i64, publish_time: i64) {
        let mut d = vec![34, 241, 35, 99, 157, 126, 244, 205];
        d.extend_from_slice(&[7; 32]); // write authority
        d.push(1); // Full
        d.extend_from_slice(&feed);
        d.extend_from_slice(&price.to_le_bytes());
        d.extend_from_slice(&conf.to_le_bytes());
        d.extend_from_slice(&expo.to_le_bytes());
        d.extend_from_slice(&publish_time.to_le_bytes());
        d.extend_from_slice(&(publish_time - 1).to_le_bytes());
        d.extend_from_slice(&ema.to_le_bytes());
        d.extend_from_slice(&conf.to_le_bytes());
        d.extend_from_slice(&self.slot.to_le_bytes());
        d.push(0); // pad to the allocated size of a Partial-level account
        let lamports = self.svm.minimum_balance_for_rent_exemption(d.len());
        self.svm
            .set_account(*at, Account { lamports, data: d, owner: pyth_receiver(), executable: false, rent_epoch: 0 })
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// Bulkhead Vault through Harbor
// ---------------------------------------------------------------------------

pub struct Market {
    pub vault_program: Address,
    pub harbor: Address,
    pub caller: Address,
    pub protocol: Address,
    pub admin: Keypair,
    pub g: [Keypair; 3],
    pub destination: Keypair,
}

pub struct VaultRef {
    pub mint: Address,
    pub mint_authority: Keypair,
    pub token_program: Address,
    pub vault: Address,
    pub vault_tokens: Address,
    pub asset: Address,
    pub price: Address,
    pub feed: [u8; 32],
    pub decimals: u8,
}

pub fn pda(seeds: &[&[u8]], program: &Address) -> Address {
    Address::find_program_address(seeds, program).0
}

/// Limits as stored (seconds): short bps, short window, long bps, long window,
/// min queue delay, floors, caps.
#[derive(Clone, Copy)]
pub struct Limits {
    pub short_bps: u16,
    pub short_window_s: u32,
    pub long_bps: u16,
    pub long_window_s: u32,
    pub min_queue_delay_s: u32,
    pub short_floor: u64,
    pub long_floor: u64,
    pub short_cap: u64,
    pub long_cap: u64,
}

impl Limits {
    /// The defaults in docs/03 §1: 2%/hour, 5%/day, 6h minimum queue delay.
    pub fn default_limits() -> Limits {
        Limits {
            short_bps: 200,
            short_window_s: 3_600,
            long_bps: 500,
            long_window_s: 86_400,
            min_queue_delay_s: 21_600,
            short_floor: 0,
            long_floor: 0,
            short_cap: 0,
            long_cap: 0,
        }
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&self.short_bps.to_le_bytes());
        d.extend_from_slice(&self.short_window_s.to_le_bytes());
        d.extend_from_slice(&self.long_bps.to_le_bytes());
        d.extend_from_slice(&self.long_window_s.to_le_bytes());
        d.extend_from_slice(&self.min_queue_delay_s.to_le_bytes());
        for v in [self.short_floor, self.long_floor, self.short_cap, self.long_cap] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d
    }
}

/// Asset config bytes: allowlisted, haircut, liability, conf_mult, max_age, max_conf, feed.
pub fn asset_bytes(allowlisted: bool, haircut: u32, liability: u32, conf_mult: u32, max_age: u32, max_conf: u32, feed: [u8; 32]) -> Vec<u8> {
    let mut d = vec![allowlisted as u8];
    for v in [haircut, liability, conf_mult, max_age, max_conf] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(&feed);
    d
}

impl Market {
    pub fn new(env: &mut Env) -> Market {
        Market::with_ids(env, Address::new_unique(), Address::new_unique())
    }

    /// Like `new`, with fixed program ids (the E2E world uses the ids of the
    /// locally built program keypairs, so a validator can load the same state).
    pub fn with_ids(env: &mut Env, vault_program: Address, harbor: Address) -> Market {
        env.svm.add_program(vault_program, &so("bulkhead_vault")).unwrap();
        env.svm.add_program(harbor, &so("bulkhead_harbor")).unwrap();
        let caller = pda(&[b"bulkhead-caller"], &harbor);
        let protocol = pda(&[b"protocol", harbor.as_ref()], &vault_program);
        let admin = Keypair::new();
        let g = [Keypair::new(), Keypair::new(), Keypair::new()];
        let destination = Keypair::new();
        env.fund(&admin);
        for k in &g {
            env.fund(k);
        }
        let m = Market { vault_program, harbor, caller, protocol, admin, g, destination };
        // Register through Harbor: the caller PDA is the registrar.
        let mut args = Vec::new();
        args.extend_from_slice(m.admin.pubkey().as_ref());
        args.push(3);
        for k in &m.g {
            args.extend_from_slice(k.pubkey().as_ref());
        }
        args.push(2);
        args.extend_from_slice(&(7 * DAY).to_le_bytes());
        args.extend_from_slice(&(3 * DAY).to_le_bytes());
        args.extend_from_slice(m.destination.pubkey().as_ref());
        let accounts = vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(m.protocol, false),
            AccountMeta::new_readonly(m.harbor, false),
            AccountMeta::new_readonly(m.harbor, false), // programdata: unused with a caller registrar
            AccountMeta::new_readonly(m.caller, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        let ix = m.harbor_ix(0, &args, vec![], accounts);
        env.ok(&[ix], &[]);
        m
    }

    pub fn harbor_ix(&self, tag: u8, args: &[u8], harbor_accounts: Vec<AccountMeta>, vault_accounts: Vec<AccountMeta>) -> Instruction {
        let mut data = vec![tag];
        data.extend_from_slice(args);
        let mut accounts = vec![
            AccountMeta::new_readonly(self.vault_program, false),
            AccountMeta::new_readonly(self.caller, false),
        ];
        accounts.extend(harbor_accounts);
        accounts.extend(vault_accounts);
        Instruction { program_id: self.harbor, accounts, data }
    }

    pub fn vault_ix(&self, tag: u8, args: &[u8], accounts: Vec<AccountMeta>) -> Instruction {
        let mut data = vec![tag];
        data.extend_from_slice(args);
        Instruction { program_id: self.vault_program, accounts, data }
    }

    pub fn create_vault(&self, env: &mut Env, decimals: u8, limits: Limits, feed: [u8; 32], program: Option<Address>) -> VaultRef {
        let token_program = program.unwrap_or_else(token_program);
        let (mint, mint_authority) = env.create_mint(decimals, &token_program);
        self.create_vault_for(env, mint, mint_authority, decimals, limits, feed, token_program)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_vault_for(&self, env: &mut Env, mint: Address, mint_authority: Keypair, decimals: u8, limits: Limits, feed: [u8; 32], token_program: Address) -> VaultRef {
        let vault = pda(&[b"vault", self.protocol.as_ref(), mint.as_ref()], &self.vault_program);
        let vault_tokens = pda(&[b"vault-tokens", self.protocol.as_ref(), mint.as_ref()], &self.vault_program);
        let ix = self.vault_ix(
            1,
            &limits.bytes(),
            vec![
                AccountMeta::new(env.payer.pubkey(), true),
                AccountMeta::new_readonly(self.admin.pubkey(), true),
                AccountMeta::new(self.protocol, false),
                AccountMeta::new(vault, false),
                AccountMeta::new(vault_tokens, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        );
        env.ok(&[ix], &[&self.admin]);
        let asset = pda(&[b"asset", self.protocol.as_ref(), mint.as_ref()], &self.vault_program);
        VaultRef { mint, mint_authority, token_program, vault, vault_tokens, asset, price: Address::new_unique(), feed, decimals }
    }

    pub fn upsert_asset_ix(&self, env: &Env, v: &VaultRef, cfg: &[u8]) -> Instruction {
        self.vault_ix(
            2,
            cfg,
            vec![
                AccountMeta::new(env.payer.pubkey(), true),
                AccountMeta::new_readonly(self.admin.pubkey(), true),
                AccountMeta::new_readonly(self.protocol, false),
                AccountMeta::new(v.asset, false),
                AccountMeta::new_readonly(v.mint, false),
                AccountMeta::new_readonly(v.token_program, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        )
    }

    pub fn backing(&self, owner: &Address) -> Address {
        pda(&[b"backing", self.protocol.as_ref(), owner.as_ref()], &self.vault_program)
    }

    /// A user deposits `amount` from their token account through Harbor.
    pub fn deposit_ix(&self, env: &Env, v: &VaultRef, user: &Address, from: &Address, amount: u64) -> Instruction {
        self.harbor_ix(
            1,
            &amount.to_le_bytes(),
            vec![AccountMeta::new_readonly(*user, true)],
            vec![
                AccountMeta::new_readonly(self.protocol, false),
                AccountMeta::new(v.vault, false),
                AccountMeta::new(v.vault_tokens, false),
                AccountMeta::new_readonly(v.mint, false),
                AccountMeta::new(*from, false),
                AccountMeta::new_readonly(*user, true),
                AccountMeta::new(self.backing(user), false),
                AccountMeta::new(env.payer.pubkey(), true),
                AccountMeta::new_readonly(v.token_program, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
        )
    }

    pub fn next_ticket(&self, env: &Env) -> (u64, Address) {
        let d = env.account(&self.protocol).data;
        // next_ticket_id: after disc 8, keys 96, guardians 256, heartbeats 64,
        // 4 bytes, 3 × i64, abdications u32, vault_count u32.
        let o = 8 + 96 + 256 + 64 + 4 + 24 + 8;
        let id = u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        (id, pda(&[b"ticket", self.protocol.as_ref(), &id.to_le_bytes()], &self.vault_program))
    }

    /// The release accounts after the caller (Vault indices 1..).
    /// `prices`: (asset PDA, price account) for the released mint and every
    /// other mint in the recipient's ledger, in ledger order.
    pub fn release_accounts(&self, env: &Env, v: &VaultRef, recipient: &Address, owner: &Address, prices: &[(Address, Address)]) -> Vec<AccountMeta> {
        let (_, ticket) = self.next_ticket(env);
        let mut a = vec![
            AccountMeta::new(self.protocol, false),
            AccountMeta::new(v.vault, false),
            AccountMeta::new(v.vault_tokens, false),
            AccountMeta::new_readonly(v.mint, false),
            AccountMeta::new(*recipient, false),
            AccountMeta::new(self.backing(owner), false),
            AccountMeta::new_readonly(v.token_program, false),
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(ticket, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        for (asset, price) in prices {
            a.push(AccountMeta::new_readonly(*asset, false));
            a.push(AccountMeta::new_readonly(*price, false));
        }
        a
    }

    /// A user withdraws `amount` to their own token account through Harbor.
    pub fn withdraw_ix(&self, env: &Env, v: &VaultRef, user: &Address, to: &Address, amount: u64, prices: &[(Address, Address)]) -> Instruction {
        self.harbor_ix(2, &amount.to_le_bytes(), vec![AccountMeta::new_readonly(*user, true)], self.release_accounts(env, v, to, user, prices))
    }

    /// Harbor's admin orders a payout to anyone (the Drift path).
    pub fn admin_payout_ix(&self, env: &Env, v: &VaultRef, to: &Address, to_owner: &Address, amount: u64, prices: &[(Address, Address)]) -> Instruction {
        self.harbor_ix(3, &amount.to_le_bytes(), vec![AccountMeta::new_readonly(self.admin.pubkey(), true)], self.release_accounts(env, v, to, to_owner, prices))
    }

    pub fn propose_seal_ix(&self) -> Instruction {
        self.vault_ix(4, &[], vec![AccountMeta::new(self.protocol, false), AccountMeta::new_readonly(self.admin.pubkey(), true)])
    }

    pub fn execute_seal_ix(&self, vaults: &[&VaultRef]) -> Instruction {
        let mut a = vec![AccountMeta::new(self.protocol, false)];
        for v in vaults {
            a.push(AccountMeta::new_readonly(v.vault, false));
            a.push(AccountMeta::new_readonly(v.vault_tokens, false));
        }
        self.vault_ix(5, &[], a)
    }

    pub fn settle_ix(&self, v: &VaultRef, ticket: &Address, recipient: &Address, payer: &Address) -> Instruction {
        self.vault_ix(
            9,
            &[],
            vec![
                AccountMeta::new_readonly(self.protocol, false),
                AccountMeta::new(v.vault, false),
                AccountMeta::new(v.vault_tokens, false),
                AccountMeta::new_readonly(v.mint, false),
                AccountMeta::new(*ticket, false),
                AccountMeta::new(*recipient, false),
                AccountMeta::new(*payer, false),
                AccountMeta::new_readonly(v.token_program, false),
            ],
        )
    }

    pub fn cancel_ix(&self, v: &VaultRef, ticket: &Address, signer: &Address, payer: &Address) -> Instruction {
        self.vault_ix(
            10,
            &[],
            vec![
                AccountMeta::new_readonly(self.protocol, false),
                AccountMeta::new(v.vault, false),
                AccountMeta::new(*ticket, false),
                AccountMeta::new_readonly(*signer, true),
                AccountMeta::new(*payer, false),
            ],
        )
    }

    pub fn freeze_ix(&self, signer: &Address, scope_vault: Option<&VaultRef>, secs: i64) -> Instruction {
        let mut args = vec![scope_vault.is_some() as u8];
        args.extend_from_slice(&secs.to_le_bytes());
        let mut a = vec![AccountMeta::new(self.protocol, false), AccountMeta::new_readonly(*signer, true)];
        if let Some(v) = scope_vault {
            a.push(AccountMeta::new(v.vault, false));
        }
        self.vault_ix(12, &args, a)
    }

    pub fn unfreeze_ix(&self, scope_vault: Option<&VaultRef>, guardians: &[Address]) -> Instruction {
        let mut a = vec![AccountMeta::new(self.protocol, false)];
        a.push(match scope_vault {
            Some(v) => AccountMeta::new(v.vault, false),
            None => AccountMeta::new_readonly(self.protocol, false),
        });
        a.extend(guardians.iter().map(|g| AccountMeta::new_readonly(*g, true)));
        self.vault_ix(13, &[scope_vault.is_some() as u8], a)
    }

    pub fn attest(&self, env: &mut Env, v: &VaultRef) -> Attestation {
        let ix = self.vault_ix(
            22,
            &[],
            vec![
                AccountMeta::new_readonly(self.protocol, false),
                AccountMeta::new_readonly(v.vault, false),
                AccountMeta::new_readonly(v.vault_tokens, false),
            ],
        );
        let m = env.ok(&[ix], &[]);
        let d = m.return_data.data;
        let u = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        Attestation {
            available_now: u(0),
            worst_1h: u(8),
            worst_24h: u(16),
            balance: u(24),
            frozen_until: u(32) as i64,
            queued: u(40),
            pending: u32::from_le_bytes(d[56..60].try_into().unwrap()),
            live_guardians: d[60],
            sealed: d[62] == 1,
        }
    }

    pub fn propose_change_ix(&self, env: &Env, kind: u8, target: &Address, payload: &[u8], target_account: Option<&Address>) -> Instruction {
        let d = env.account(&self.protocol).data;
        let o = 8 + 96 + 256 + 64 + 4 + 24 + 8 + 8;
        let id = u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        let change = pda(&[b"change", self.protocol.as_ref(), &id.to_le_bytes()], &self.vault_program);
        let mut args = vec![kind];
        args.extend_from_slice(target.as_ref());
        args.extend_from_slice(payload);
        let mut a = vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new_readonly(self.admin.pubkey(), true),
            AccountMeta::new(self.protocol, false),
            AccountMeta::new(change, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ];
        if let Some(t) = target_account {
            a.push(AccountMeta::new(*t, false));
        }
        self.vault_ix(18, &args, a)
    }

    pub fn change_address(&self, id: u64) -> Address {
        pda(&[b"change", self.protocol.as_ref(), &id.to_le_bytes()], &self.vault_program)
    }
}

pub struct Attestation {
    pub available_now: u64,
    pub worst_1h: u64,
    pub worst_24h: u64,
    pub balance: u64,
    pub frozen_until: i64,
    pub queued: u64,
    pub pending: u32,
    pub live_guardians: u8,
    pub sealed: bool,
}

/// Parsed `ReleaseOutcome` return data.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub backed: u64,
    pub instant: u64,
    pub queued: u64,
    pub ticket_id: u64,
    pub eta_s: i64,
}

pub fn outcome(m: &litesvm::types::TransactionMetadata) -> Outcome {
    let d = &m.return_data.data;
    let u = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
    Outcome { backed: u(0), instant: u(8), queued: u(16), ticket_id: u(24), eta_s: u(32) as i64 }
}
