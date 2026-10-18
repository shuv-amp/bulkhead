//! Shared harness: a LiteSVM instance with mainnet features (the real agave
//! loader and runtime), programs deployed through genuine loader-v3
//! instructions, and builders for every Floor instruction.
#![allow(dead_code)]
#![allow(clippy::result_large_err)] // LiteSVM's failure type carries full logs

pub mod sweep;
pub mod vault;

use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_loader_v3_interface::{get_program_data_address, instruction as lv3};
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

pub const LOADER_V3: Address = solana_sdk_ids::bpf_loader_upgradeable::ID;
pub const SYSTEM: Address = solana_sdk_ids::system_program::ID;
pub const RENT: Address = solana_sdk_ids::sysvar::rent::ID;
pub const CLOCK: Address = solana_sdk_ids::sysvar::clock::ID;

pub const DAY: i64 = 86_400;
pub const T0: i64 = 1_790_000_000; // a fixed start time (Sep 2026)

/// Floor error codes (programs/floor/src/error.rs), checked by the tests.
pub mod err {
    pub const INVALID_INSTRUCTION: u32 = 7000;
    pub const NOT_A_FLOOR_CONFIG: u32 = 7001;
    pub const WRONG_CONFIG_ADDRESS: u32 = 7002;
    pub const WRONG_AUTHORITY_ADDRESS: u32 = 7003;
    pub const NOT_LOADER_V3: u32 = 7005;
    pub const PROGRAM_MISMATCH: u32 = 7006;
    pub const NOT_CURRENT_AUTHORITY: u32 = 7007;
    pub const INVALID_GUARDIANS: u32 = 7008;
    pub const INVALID_THRESHOLD: u32 = 7009;
    pub const INVALID_INTERVAL: u32 = 7010;
    pub const INVALID_DELAY: u32 = 7011;
    pub const MISSING_SIGNATURE: u32 = 7012;
    pub const NOT_OWNER: u32 = 7013;
    pub const NOT_LIVE_GUARDIAN: u32 = 7014;
    pub const NO_QUORUM: u32 = 7015;
    pub const NOT_LIVE: u32 = 7016;
    pub const NOT_ABORTED: u32 = 7017;
    pub const NOT_CANONICAL_ABORT: u32 = 7018;
    pub const NO_ABORT_BUFFER: u32 = 7019;
    pub const ABORT_ALREADY_STAGED: u32 = 7020;
    pub const WRONG_BUFFER: u32 = 7021;
    pub const BUFFER_NOT_FROZEN: u32 = 7022;
    pub const SNAPSHOT_MISMATCH: u32 = 7023;
    pub const NO_VALID_SNAPSHOT: u32 = 7024;
    pub const PROPOSAL_PENDING: u32 = 7025;
    pub const NO_PROPOSAL: u32 = 7026;
    pub const WRONG_PROPOSAL_KIND: u32 = 7027;
    pub const NOT_EXECUTABLE: u32 = 7028;
    pub const VETOED: u32 = 7029;
    pub const EXPIRED: u32 = 7030;
    pub const CANNOT_EJECT: u32 = 7031;
    pub const WRONG_SYSVAR: u32 = 7032;
    pub const WRONG_PROGRAM: u32 = 7033;
    pub const ABORT_DOES_NOT_FIT: u32 = 7035;
    pub const BUFFER_IN_USE: u32 = 7036;
    pub const WRONG_ACCOUNT: u32 = 7037;
}

// ---------------------------------------------------------------------------
// Tiny sBPF v3 programs: stand-ins for a protected protocol
// ---------------------------------------------------------------------------

/// One instruction: opcode, dst, src, imm.
pub fn insn(opc: u8, dst: u8, src: u8, imm: i32) -> [u8; 8] {
    let i = imm.to_le_bytes();
    [opc, (src << 4) | dst, 0, 0, i[0], i[1], i[2], i[3]]
}

/// A strict-layout sBPF v3 ELF with one executable segment.
pub fn tiny_elf(text: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    e.extend_from_slice(&3u16.to_le_bytes()); // ET_DYN
    e.extend_from_slice(&0xF7u16.to_le_bytes());
    e.extend_from_slice(&1u32.to_le_bytes());
    e.extend_from_slice(&(1u64 << 32).to_le_bytes()); // entry
    e.extend_from_slice(&64u64.to_le_bytes()); // phoff
    e.extend_from_slice(&0u64.to_le_bytes()); // shoff
    e.extend_from_slice(&3u32.to_le_bytes()); // e_flags: v3
    e.extend_from_slice(&64u16.to_le_bytes());
    e.extend_from_slice(&56u16.to_le_bytes());
    e.extend_from_slice(&1u16.to_le_bytes()); // phnum
    e.extend_from_slice(&64u16.to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes());
    e.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    e.extend_from_slice(&1u32.to_le_bytes()); // PF_X
    e.extend_from_slice(&120u64.to_le_bytes()); // offset
    e.extend_from_slice(&(1u64 << 32).to_le_bytes());
    e.extend_from_slice(&(1u64 << 32).to_le_bytes());
    e.extend_from_slice(&(text.len() as u64).to_le_bytes());
    e.extend_from_slice(&(text.len() as u64).to_le_bytes());
    e.extend_from_slice(&0u64.to_le_bytes());
    e.extend_from_slice(text);
    e
}

/// Returns `code` from every call (0 = success). `pad` extra no-op
/// instructions make distinct binaries with the same behavior.
pub fn program_returning(code: i32, pad: usize) -> Vec<u8> {
    let mut text = Vec::new();
    for _ in 0..pad {
        text.extend_from_slice(&insn(0xb7, 1, 0, 0)); // mov64 r1, 0
    }
    text.extend_from_slice(&insn(0xb7, 0, 0, code)); // mov64 r0, code
    text.extend_from_slice(&insn(0x95, 0, 0, 0)); // exit
    tiny_elf(&text)
}

/// The honest protocol (v1), its fixed version, and an attacker's drainer.
pub fn honest_v1() -> Vec<u8> {
    program_returning(0, 0)
}
pub fn honest_fix() -> Vec<u8> {
    program_returning(0, 3)
}
pub fn drainer() -> Vec<u8> {
    program_returning(0xBAD, 0)
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

pub struct Env {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub floor: Address,
    pub slot: u64,
    pub time: i64,
}

/// The mainnet binaries LiteSVM 0.16.0 ships, in the cargo registry
/// (`$CARGO_HOME`, by default `~/.cargo`).
pub fn litesvm_elf_dir() -> std::path::PathBuf {
    let home = std::env::var("CARGO_HOME").unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap()));
    std::fs::read_dir(format!("{home}/registry/src"))
        .unwrap()
        .map(|d| d.unwrap().path().join("litesvm-0.16.0/src/programs/elf"))
        .find(|d| d.is_dir())
        .expect("litesvm 0.16.0 sources in the cargo registry")
}

pub fn floor_so() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/deploy/bulkhead_floor.so"
    );
    std::fs::read(path).expect("build Floor first: scripts/build-programs.sh")
}

impl Env {
    pub fn new() -> Env {
        let mut svm = LiteSVM::new();
        let floor = Address::new_unique();
        svm.add_program(floor, &floor_so()).expect("load Floor");
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        let mut env = Env {
            svm,
            payer,
            floor,
            slot: 1_000,
            time: T0,
        };
        env.sync_clock();
        env
    }

    pub fn sync_clock(&mut self) {
        let mut c: Clock = self.svm.get_sysvar();
        c.slot = self.slot;
        c.unix_timestamp = self.time;
        self.svm.set_sysvar(&c);
    }

    /// Move to a later slot (and time).
    pub fn advance(&mut self, secs: i64) {
        self.slot += 1 + (secs.max(0) as u64) * 5 / 2; // ~400 ms slots
        self.time += secs;
        self.sync_clock();
        self.svm.expire_blockhash();
    }

    pub fn next_slot(&mut self) {
        self.advance(0);
    }

    pub fn fund(&mut self, k: &Keypair) {
        self.svm.airdrop(&k.pubkey(), 100_000_000_000).unwrap();
    }

    pub fn send(
        &mut self,
        ixs: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let mut all: Vec<&Keypair> = vec![&self.payer];
        all.extend_from_slice(signers);
        let msg = Message::new(ixs, Some(&self.payer.pubkey()));
        let tx = Transaction::new(&all, msg, self.svm.latest_blockhash());
        let r = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        r
    }

    pub fn ok(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> TransactionMetadata {
        match self.send(ixs, signers) {
            Ok(m) => m,
            Err(e) => panic!(
                "transaction failed: {:?}\n{}",
                e.err,
                e.meta.logs.join("\n")
            ),
        }
    }

    /// The custom error code of a failing transaction.
    pub fn fails(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> u32 {
        match self.send(ixs, signers) {
            Ok(m) => panic!("expected failure, got success:\n{}", m.logs.join("\n")),
            Err(e) => custom_code(&e).unwrap_or_else(|| {
                panic!(
                    "not a custom error: {:?}\n{}",
                    e.err,
                    e.meta.logs.join("\n")
                )
            }),
        }
    }

    pub fn account(&self, a: &Address) -> Account {
        self.svm.get_account(a).expect("account exists")
    }

    // --- loader-v3 ---------------------------------------------------------

    /// A buffer holding `bytes`, written in chunks, authority `authority`.
    pub fn write_buffer(&mut self, bytes: &[u8], authority: &Keypair) -> Address {
        let buffer = Keypair::new();
        let lamports = self.svm.minimum_balance_for_rent_exemption(
            bulkhead_core::floor::BUFFER_DATA_OFFSET + bytes.len(),
        );
        let ixs = lv3::create_buffer(
            &self.payer.pubkey(),
            &buffer.pubkey(),
            &authority.pubkey(),
            lamports,
            bytes.len(),
        )
        .unwrap();
        self.ok(&ixs, &[&buffer]);
        for (i, chunk) in bytes.chunks(900).enumerate() {
            let ix = lv3::write(
                &buffer.pubkey(),
                &authority.pubkey(),
                (i * 900) as u32,
                chunk.to_vec(),
            );
            self.ok(&[ix], &[authority]);
        }
        buffer.pubkey()
    }

    /// Hand a buffer to `new_authority` (e.g. Floor's PDA), freezing its bytes.
    pub fn set_buffer_authority(
        &mut self,
        buffer: &Address,
        current: &Keypair,
        new_authority: &Address,
    ) {
        let ix = lv3::set_buffer_authority(buffer, &current.pubkey(), new_authority);
        self.ok(&[ix], &[current]);
    }

    /// Deploy `elf` as an upgradeable program with `authority`; returns
    /// (program id, programdata address).
    pub fn deploy(
        &mut self,
        elf: &[u8],
        authority: &Keypair,
        max_len: usize,
    ) -> (Address, Address) {
        let buffer = self.write_buffer(elf, authority);
        let program = Keypair::new();
        let lamports = self.svm.minimum_balance_for_rent_exemption(36);
        let ixs = lv3::deploy_with_max_program_len(
            &self.payer.pubkey(),
            &program.pubkey(),
            &buffer,
            &authority.pubkey(),
            lamports,
            max_len,
            true,
        )
        .unwrap();
        self.ok(&ixs, &[&program, authority]);
        self.next_slot();
        (
            program.pubkey(),
            get_program_data_address(&program.pubkey()),
        )
    }

    /// Call a program with no accounts; returns its outcome.
    pub fn call(
        &mut self,
        program: &Address,
    ) -> Result<TransactionMetadata, FailedTransactionMetadata> {
        let ix = Instruction::new_with_bytes(*program, &[], vec![]);
        self.send(&[ix], &[])
    }

    pub fn programdata_bytes(&self, programdata: &Address) -> Vec<u8> {
        self.account(programdata).data[bulkhead_core::floor::PROGRAMDATA_DATA_OFFSET..].to_vec()
    }

    pub fn upgrade_authority(&self, programdata: &Address) -> Option<[u8; 32]> {
        bulkhead_core::floor::programdata_header(&self.account(programdata).data)
            .unwrap()
            .upgrade_authority
    }
}

pub fn custom_code(e: &FailedTransactionMetadata) -> Option<u32> {
    match &e.err {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(*c),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Floor client
// ---------------------------------------------------------------------------

pub struct Floor {
    pub id: Address,
    pub program: Address,
    pub programdata: Address,
    pub config: Address,
    pub authority: Address,
}

impl Floor {
    pub fn new(floor_id: Address, program: Address) -> Floor {
        let (config, _) = Address::find_program_address(&[b"floor", program.as_ref()], &floor_id);
        let (authority, _) =
            Address::find_program_address(&[b"authority", program.as_ref()], &floor_id);
        Floor {
            id: floor_id,
            program,
            programdata: get_program_data_address(&program),
            config,
            authority,
        }
    }

    fn ix(&self, data: Vec<u8>, accounts: Vec<AccountMeta>) -> Instruction {
        Instruction {
            program_id: self.id,
            accounts,
            data,
        }
    }

    pub fn guardian_set(guardians: &[Address], threshold: u8, interval: i64) -> Vec<u8> {
        let mut d = vec![guardians.len() as u8];
        for g in guardians {
            d.extend_from_slice(g.as_ref());
        }
        d.push(threshold);
        d.extend_from_slice(&interval.to_le_bytes());
        d
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &self,
        payer: &Address,
        current_authority: &Address,
        owner: &Address,
        guardians: &[Address],
        threshold: u8,
        interval: i64,
        delay: i64,
    ) -> Instruction {
        let mut d = vec![0u8];
        d.extend_from_slice(owner.as_ref());
        d.extend(Self::guardian_set(guardians, threshold, interval));
        d.extend_from_slice(&delay.to_le_bytes());
        self.ix(
            d,
            vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(self.config, false),
                AccountMeta::new_readonly(self.authority, false),
                AccountMeta::new_readonly(self.program, false),
                AccountMeta::new(self.programdata, false),
                AccountMeta::new_readonly(*current_authority, true),
                AccountMeta::new_readonly(SYSTEM, false),
                AccountMeta::new_readonly(LOADER_V3, false),
            ],
        )
    }

    pub fn stage_abort(&self, buffer: &Address) -> Instruction {
        self.stage_abort_by(buffer, &[])
    }

    /// Replacing a staged abort buffer takes a live guardian quorum (finding 88).
    pub fn stage_abort_by(&self, buffer: &Address, guardians: &[Address]) -> Instruction {
        let mut a = vec![
            AccountMeta::new(self.config, false),
            AccountMeta::new_readonly(*buffer, false),
            AccountMeta::new_readonly(self.programdata, false),
        ];
        a.extend(guardians.iter().map(|g| AccountMeta::new_readonly(*g, true)));
        self.ix(vec![1], a)
    }

    pub fn pin_snapshot(&self, buffer: &Address) -> Instruction {
        self.ix(
            vec![2],
            vec![
                AccountMeta::new(self.config, false),
                AccountMeta::new_readonly(self.programdata, false),
                AccountMeta::new_readonly(*buffer, false),
            ],
        )
    }

    fn upgrade_accounts(&self, buffer: &Address, spill: &Address) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.programdata, false),
            AccountMeta::new(self.program, false),
            AccountMeta::new(*buffer, false),
            AccountMeta::new(*spill, false),
            AccountMeta::new_readonly(RENT, false),
            AccountMeta::new_readonly(CLOCK, false),
            AccountMeta::new_readonly(self.authority, false),
            AccountMeta::new_readonly(LOADER_V3, false),
        ]
    }

    pub fn abort(
        &self,
        signer: &Address,
        abort_buffer: &Address,
        snapshot: Option<&Address>,
    ) -> Instruction {
        let mut a = vec![
            AccountMeta::new(self.config, false),
            AccountMeta::new_readonly(*signer, true),
        ];
        // The spill is the config itself (finding 88).
        a.extend(self.upgrade_accounts(abort_buffer, &self.config));
        if let Some(s) = snapshot {
            a.push(AccountMeta::new_readonly(*s, false));
        }
        self.ix(vec![3], a)
    }

    pub fn propose(
        &self,
        owner: &Address,
        kind: u8,
        target: &Address,
        payload: &[u8],
        buffer: Option<&Address>,
    ) -> Instruction {
        let mut d = vec![4, kind];
        d.extend_from_slice(target.as_ref());
        d.extend_from_slice(payload);
        let mut a = vec![
            AccountMeta::new(self.config, false),
            AccountMeta::new_readonly(*owner, true),
        ];
        if let Some(b) = buffer {
            a.push(AccountMeta::new_readonly(*b, false));
        }
        self.ix(d, a)
    }

    pub fn veto(&self, guardian: &Address) -> Instruction {
        self.veto_id(guardian, None)
    }

    pub fn veto_id(&self, guardian: &Address, id: Option<u64>) -> Instruction {
        let mut d = vec![5];
        if let Some(id) = id {
            d.extend_from_slice(&id.to_le_bytes());
        }
        self.ix(
            d,
            vec![
                AccountMeta::new(self.config, false),
                AccountMeta::new_readonly(*guardian, true),
            ],
        )
    }

    /// Approve the pending restore `id` (Floor refuses another id).
    pub fn approve(&self, id: u64, guardians: &[Address]) -> Instruction {
        let mut a = vec![AccountMeta::new(self.config, false)];
        a.extend(
            guardians
                .iter()
                .map(|g| AccountMeta::new_readonly(*g, true)),
        );
        let mut d = vec![6];
        d.extend_from_slice(&id.to_le_bytes());
        self.ix(d, a)
    }

    pub fn execute_code(&self, buffer: &Address, spill: &Address) -> Instruction {
        let mut a = vec![AccountMeta::new(self.config, false)];
        a.extend(self.upgrade_accounts(buffer, spill));
        self.ix(vec![7], a)
    }

    pub fn execute_config(&self) -> Instruction {
        self.ix(vec![7], vec![AccountMeta::new(self.config, false)])
    }

    /// The new authority signs (issue #39); `held` are the staged abort buffer
    /// and the pinned snapshot, which the release closes (issue #37).
    pub fn execute_release(&self, owner: &Address, new_authority: Option<&Address>, held: &[Address]) -> Instruction {
        let mut a = vec![
            AccountMeta::new(self.config, false),
            AccountMeta::new(self.programdata, false),
            AccountMeta::new_readonly(self.authority, false),
            AccountMeta::new_readonly(LOADER_V3, false),
            AccountMeta::new(*owner, new_authority.is_none()),
        ];
        if let Some(n) = new_authority {
            a.push(AccountMeta::new_readonly(*n, true));
        }
        a.extend(held.iter().map(|b| AccountMeta::new(*b, false)));
        self.ix(vec![7], a)
    }

    /// The owner closes a buffer Floor holds that nothing refers to (issue #37).
    pub fn close_buffer(&self, owner: &Address, buffer: &Address) -> Instruction {
        self.ix(
            vec![13],
            vec![
                AccountMeta::new_readonly(self.config, false),
                AccountMeta::new(*owner, true),
                AccountMeta::new(*buffer, false),
                AccountMeta::new_readonly(self.authority, false),
                AccountMeta::new_readonly(LOADER_V3, false),
                AccountMeta::new_readonly(self.programdata, false),
            ],
        )
    }

    pub fn restore_snapshot(
        &self,
        snapshot: &Address,
        spill: &Address,
        guardians: &[Address],
    ) -> Instruction {
        let mut a = vec![AccountMeta::new(self.config, false)];
        a.extend(self.upgrade_accounts(snapshot, spill));
        a.extend(
            guardians
                .iter()
                .map(|g| AccountMeta::new_readonly(*g, true)),
        );
        self.ix(vec![8], a)
    }

    pub fn heartbeat(&self, guardian: &Address) -> Instruction {
        self.ix(
            vec![9],
            vec![
                AccountMeta::new(self.config, false),
                AccountMeta::new_readonly(*guardian, true),
            ],
        )
    }

    pub fn eject(&self, target: u8, guardians: &[Address]) -> Instruction {
        let mut a = vec![AccountMeta::new(self.config, false)];
        a.extend(
            guardians
                .iter()
                .map(|g| AccountMeta::new_readonly(*g, true)),
        );
        self.ix(vec![10, target], a)
    }

    pub fn cancel(&self, owner: &Address) -> Instruction {
        self.ix(
            vec![11],
            vec![
                AccountMeta::new(self.config, false),
                AccountMeta::new_readonly(*owner, true),
            ],
        )
    }

    /// The owner with a live guardian quorum replaces the recovery key.
    pub fn replace_recovery(&self, owner: &Address, recovery: &Address, guardians: &[Address]) -> Instruction {
        let mut d = vec![12];
        d.extend_from_slice(recovery.as_ref());
        let mut a = vec![
            AccountMeta::new(self.config, false),
            AccountMeta::new_readonly(*owner, true),
        ];
        a.extend(guardians.iter().map(|g| AccountMeta::new_readonly(*g, true)));
        self.ix(d, a)
    }
}

/// Floor's config, decoded by Floor's own `Config::load`.
pub fn read_config(env: &Env, f: &Floor) -> bulkhead_floor::Config {
    bulkhead_floor::Config::load(&env.account(&f.config).data).expect("a Floor config")
}

/// `len` bytes starting with `disc`, then a pattern in which no field-sized
/// window repeats nearby (byte i is `i mod 251 + 1`, never zero), so a field
/// read even one byte off decodes to a different value. Layout tests decode it
/// with a program's `load` and compare every field with the offsets the
/// off-chain readers use.
pub fn patterned(len: usize, disc: &[u8; 8]) -> Vec<u8> {
    let mut d: Vec<u8> = (0..len).map(|i| (i % 251) as u8 + 1).collect();
    d[..8].copy_from_slice(disc);
    d
}

/// A protected program with Floor registered: 4 guardians, threshold 2,
/// 7-day heartbeats, 72h delay, an abort buffer staged, a snapshot pinned.
pub struct Protected {
    pub f: Floor,
    pub team: Keypair,
    pub owner: Keypair,
    pub g: [Keypair; 4],
    pub abort_buffer: Address,
    pub snapshot: Address,
    pub original: Vec<u8>,
}

impl Protected {
    pub fn guardians(&self) -> Vec<Address> {
        self.g.iter().map(|k| k.pubkey()).collect()
    }
}

pub fn protect(env: &mut Env, elf: &[u8]) -> Protected {
    let team = Keypair::new();
    env.fund(&team);
    let (program, _) = env.deploy(elf, &team, elf.len().max(2048) * 2); // 2x headroom, like real deploys
    let f = Floor::new(env.floor, program);
    let owner = Keypair::new();
    let g = [Keypair::new(), Keypair::new(), Keypair::new(), Keypair::new()];
    for k in &g {
        env.fund(k);
    }
    env.fund(&owner);
    let gs: Vec<Address> = g.iter().map(|k| k.pubkey()).collect();
    let ix = f.register(
        &env.payer.pubkey(),
        &team.pubkey(),
        &owner.pubkey(),
        &gs,
        2,
        7 * DAY,
        3 * DAY,
    );
    env.ok(&[ix], &[&team]);
    // Anyone stages the canonical abort binary and a snapshot of the live code.
    let stager = Keypair::new();
    env.fund(&stager);
    let abort_buffer = env.write_buffer(&bulkhead_core::floor::ABORT_ELF, &stager);
    env.set_buffer_authority(&abort_buffer, &stager, &f.authority);
    env.ok(&[f.stage_abort(&abort_buffer)], &[]);
    let original = env.programdata_bytes(&f.programdata);
    let live_elf = elf.to_vec();
    let snapshot = env.write_buffer(&live_elf, &stager);
    env.set_buffer_authority(&snapshot, &stager, &f.authority);
    env.ok(&[f.pin_snapshot(&snapshot)], &[]);
    env.next_slot();
    Protected {
        f,
        team,
        owner,
        g,
        abort_buffer,
        snapshot,
        original,
    }
}
