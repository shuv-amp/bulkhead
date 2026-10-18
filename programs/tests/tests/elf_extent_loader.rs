//! Finding 88's rule against the real agave loader (LiteSVM).
//!
//! A pinned snapshot is the buffer a restore hands to the loader's `Upgrade`.
//! So Floor's test of a snapshot, `snapshot_restorable` (identical to the live
//! code, and at least `elf_extent` long), must never pass a buffer the loader
//! then refuses: that is the restore failing when it is needed. The core's
//! unit tests and the `loader_parsers` fuzz target check `elf_extent` against
//! our own statement of what the loader reads. Here the judge is the loader
//! itself, over real binaries and mutated ones, both sBPF v0 (the lenient
//! parser, which reads the section headers) and v3 (the strict one, which
//! does not).
//!
//! The rule may be stricter than the loader; that costs only a refused pin.
//! Each test prints how often it is (docs/09, finding 88's coverage row).

mod common;

use bulkhead_core::floor::{elf_extent, snapshot_restorable, ABORT_ELF, ABORT_ELF_MINIMAL, BUFFER_DATA_OFFSET};
use common::*;
use solana_account::Account;
use solana_address::Address;
use solana_instruction_error::InstructionError;
use solana_keypair::Keypair;
use solana_loader_v3_interface::instruction as lv3;
use solana_signer::Signer;
use solana_transaction_error::TransactionError;

/// Loader-v3 `Upgrade`'s own `InvalidAccountData` refusals, of its accounts.
const NOT_THE_ELF: [&str; 3] = ["Invalid Program account", "Buffer account too small", "Invalid ProgramData account"];

/// Whether the logs of an `InvalidAccountData` refusal give the ELF as the
/// reason. The loader logs an ELF or verifier error on its own line
/// (solana-program-runtime 4.2.2 deploy.rs:85-120), never with the
/// runtime's "Program " prefix; an account that does not decode fails with
/// the same error and no line at all.
fn refused_the_elf(logs: &[String]) -> bool {
    let reasons: Vec<&String> = logs.iter().filter(|l| !l.starts_with("Program ")).collect();
    !reasons.is_empty() && !reasons.iter().any(|l| NOT_THE_ELF.iter().any(|m| l.contains(m)))
}

/// Zeros after the binary: the programdata beyond a binary is zero-filled,
/// so this is what a copy of the live code may be cut from.
const TAIL: usize = 512;

/// A loader-v3 buffer holding `bytes` (set directly: the bytes are the
/// subject here, not the `Write` instruction).
fn buffer(env: &mut Env, bytes: &[u8], authority: &Address) -> Address {
    let mut data = vec![0u8; BUFFER_DATA_OFFSET + bytes.len()];
    data[0] = 1; // UpgradeableLoaderState::Buffer
    data[4] = 1; // Some(authority)
    data[5..BUFFER_DATA_OFFSET].copy_from_slice(authority.as_ref());
    data[BUFFER_DATA_OFFSET..].copy_from_slice(bytes);
    let a = Address::new_unique();
    let lamports = env.svm.minimum_balance_for_rent_exemption(data.len());
    let owner = solana_sdk_ids::bpf_loader_upgradeable::id();
    env.svm.set_account(a, Account { lamports, data, owner, executable: false, rent_epoch: 0 }).unwrap();
    a
}

/// A deployed program with room for `max_len` bytes, and `upgrade(bytes)`:
/// whether the loader takes `bytes` in a real `Upgrade`, as at a restore.
struct Live {
    program: Keypair,
    authority: Keypair,
}

impl Live {
    fn deploy(env: &mut Env, elf: &[u8], max_len: usize) -> Option<Live> {
        let (program, authority) = (Keypair::new(), Keypair::new());
        env.fund(&authority);
        let buf = buffer(env, elf, &authority.pubkey());
        let lamports = env.svm.minimum_balance_for_rent_exemption(36);
        let ixs = lv3::deploy_with_max_program_len(&env.payer.pubkey(), &program.pubkey(), &buf, &authority.pubkey(), lamports, max_len, true).unwrap();
        let ok = env.send(&ixs, &[&program, &authority]).is_ok();
        env.next_slot();
        ok.then_some(Live { program, authority })
    }

    /// A refusal must be the loader's refusal of the ELF: `InvalidAccountData`
    /// with the ELF as its logged reason, not one of the messages with which
    /// loader-v3's `Upgrade` refuses its accounts with that same error
    /// (solana-bpf-loader-program 4.2.2 lib.rs:398-483). A refusal for any
    /// other reason would make a refusal here mean nothing, so it fails the
    /// test.
    fn upgrade(&self, env: &mut Env, bytes: &[u8]) -> bool {
        let b = buffer(env, bytes, &self.authority.pubkey());
        let ix = lv3::upgrade(&self.program.pubkey(), &b, &self.authority.pubkey(), &env.payer.pubkey(), true);
        let result = env.send(&[ix], &[&self.authority]);
        env.next_slot();
        match result {
            Ok(_) => true,
            Err(e) if e.err == TransactionError::InstructionError(0, InstructionError::InvalidAccountData) && refused_the_elf(&e.meta.logs) => false,
            Err(e) => panic!("the upgrade failed, not on its ELF: {:?}\n{}", e.err, e.meta.logs.join("\n")),
        }
    }
}

/// Floor's three programs (sBPF v3), the two abort binaries (v3, no section
/// headers), and the mainnet binaries LiteSVM ships (v0).
fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut v = vec![
        ("ABORT_ELF".to_string(), ABORT_ELF.to_vec()),
        ("ABORT_ELF_MINIMAL".to_string(), ABORT_ELF_MINIMAL.to_vec()),
    ];
    for p in ["floor", "vault", "harbor"] {
        let path = format!("{}/../../target/deploy/bulkhead_{p}.so", env!("CARGO_MANIFEST_DIR"));
        v.push((p.to_string(), std::fs::read(path).expect("build the programs first: scripts/build-programs.sh")));
    }
    let mut shipped: Vec<_> = std::fs::read_dir(litesvm_elf_dir()).unwrap().map(|f| f.unwrap().path()).collect();
    shipped.sort();
    for f in shipped {
        v.push((f.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read(&f).unwrap()));
    }
    assert_eq!(v.len(), 14, "the corpus changed: review the counts below");
    v
}

fn sbpf_v0(elf: &[u8]) -> bool {
    elf[48..52] == [0, 0, 0, 0]
}

/// Every real binary: a copy of the live code is restorable exactly from its
/// extent on, and the loader redeploys every restorable copy. Cut one byte
/// short, a v0 binary is refused by the loader too (finding 88's premise).
#[test]
fn every_restorable_copy_of_a_real_binary_redeploys() {
    let mut env = Env::new();
    let (mut checked, mut stricter) = (0, vec![]);
    for (name, elf) in corpus() {
        let Some(live) = Live::deploy(&mut env, &elf, elf.len() + TAIL) else {
            // Built for the deprecated loader: no deploy, nothing to restore.
            assert_eq!(name, "spl_memo-1.0.0.so", "the loader refused {name} whole");
            continue;
        };
        let mut programdata = elf.clone();
        programdata.resize(elf.len() + TAIL, 0);
        let extent = elf_extent(&programdata).unwrap_or_else(|| panic!("{name}: no extent"));
        assert_eq!(extent, elf.len(), "{name}: a real binary ends where its ELF says");
        for cut in [extent - 64, extent - 8, extent - 1, extent, extent + 1, extent + TAIL / 2, extent + TAIL] {
            let copy = &programdata[..cut];
            let restorable = snapshot_restorable(copy, &programdata);
            assert_eq!(restorable, cut >= extent, "{name}: cut at {cut}, extent {extent}");
            let redeploys = live.upgrade(&mut env, copy);
            if restorable {
                assert!(redeploys, "{name}: restorable from {cut} bytes, but the loader refuses them");
                checked += 1;
            } else if redeploys {
                stricter.push(format!("{name}@{}", extent - cut));
            }
            if cut == extent - 1 && sbpf_v0(&elf) {
                assert!(!redeploys, "{name}: v0, one byte short of its extent, yet the loader takes it");
            }
        }
    }
    println!("{checked} restorable copies of 13 binaries redeploy; the loader also took {} cuts the rule refuses: {}", stricter.len(), stricter.join(" "));
    assert_eq!(checked, 13 * 4);
}

/// SPL Memo 4.0.0 (v0) laid out three more ways, each of which puts a
/// different term of `elf_extent` last: its last section moved after the
/// section table, its program header table moved to the end, and a `NOBITS`
/// section over zeros at the end. In each the loader takes the copy cut at
/// the extent and refuses the copy one byte shorter. The `NOBITS` section
/// holds no file bytes, yet the loader bounds its range (finding 115).
#[test]
fn each_term_of_the_extent_is_what_the_loader_reads() {
    let memo = std::fs::read(litesvm_elf_dir().join("spl_memo-4.0.0.so")).unwrap();
    let at = |b: &[u8], i: usize| read(b, i, 8) as usize;
    let put = |b: &mut Vec<u8>, i: usize, v: usize| b[i..i + 8].copy_from_slice(&(v as u64).to_le_bytes());
    let (phoff, shoff, shnum) = (at(&memo, 0x20), at(&memo, 0x28), read(&memo, 0x3c, 2) as usize);
    assert_eq!((memo.len(), shoff + 64 * shnum), (2304, 2304), "the section table ends the file");
    let last = shoff + 64 * (shnum - 1); // .shstrtab, the last section
    let (off, size) = (at(&memo, last + 24), at(&memo, last + 32));
    // The last section's bytes after the section table.
    let mut section_last = memo.clone();
    section_last.extend_from_slice(&memo[off..off + size]);
    put(&mut section_last, last + 24, memo.len());
    // The program header table at the end.
    let mut table_last = memo.clone();
    table_last.extend_from_slice(&memo[phoff..phoff + 56 * read(&memo, 0x38, 2) as usize]);
    put(&mut table_last, 0x20, memo.len());
    // One more section header: NOBITS, over 64 zeros after the table.
    let mut nobits = memo.clone();
    let mut header = [0u8; 64];
    header[4] = 8;
    header[24..32].copy_from_slice(&(memo.len() as u64 + 64).to_le_bytes());
    header[32..40].copy_from_slice(&64u64.to_le_bytes());
    nobits.extend_from_slice(&header);
    nobits.extend_from_slice(&[0; 64]);
    nobits[0x3c..0x3e].copy_from_slice(&(shnum as u16 + 1).to_le_bytes());
    let mut env = Env::new();
    for (name, elf) in [("section last", section_last), ("table last", table_last), ("NOBITS last", nobits)] {
        let live = Live::deploy(&mut env, &elf, elf.len() + TAIL).unwrap_or_else(|| panic!("{name}: the loader refuses it whole"));
        let mut programdata = elf.clone();
        programdata.resize(elf.len() + TAIL, 0);
        let extent = elf_extent(&programdata).unwrap_or_else(|| panic!("{name}: no extent"));
        assert_eq!(extent, elf.len(), "{name}");
        assert!(snapshot_restorable(&programdata[..extent], &programdata), "{name}");
        assert!(live.upgrade(&mut env, &programdata[..extent]), "{name}: the loader refuses the copy cut at the extent");
        assert!(!snapshot_restorable(&programdata[..extent - 1], &programdata), "{name}");
        assert!(!live.upgrade(&mut env, &programdata[..extent - 1]), "{name}: the loader takes the copy one byte short");
    }
}

/// xorshift64: the search is the same on every run.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

fn read(b: &[u8], at: usize, width: usize) -> u64 {
    let mut le = [0u8; 8];
    le[..width].copy_from_slice(&b[at..at + width]);
    u64::from_le_bytes(le)
}

/// `elf` with `TAIL` zeros after it and one to three header fields rewritten:
/// the section table's offset or count, a program header's type, offset,
/// file size or memory size, or a section's type, offset or size. The new
/// values aim at the edges: the old one nudged, zero, the tail, the extent.
fn mutate(r: &mut Rng, elf: &[u8]) -> Vec<u8> {
    let mut b = elf.to_vec();
    b.resize(elf.len() + TAIL, 0);
    let (len, ext) = (elf.len() as u64, elf_extent(elf).unwrap() as u64);
    let (phoff, phnum) = (read(&b, 0x20, 8) as usize, read(&b, 0x38, 2));
    let (shoff, shnum) = (read(&b, 0x28, 8) as usize, read(&b, 0x3c, 2));
    for _ in 0..1 + r.below(3) {
        let (at, width) = match r.below(6) {
            0 => (0x28, 8),
            1 => (0x3c, 2),
            2 if phnum > 0 => (phoff + 56 * r.below(phnum) as usize + [8, 32, 40][r.below(3) as usize], 8),
            3 if phnum > 0 => (phoff + 56 * r.below(phnum) as usize, 4),
            4 if shnum > 0 => (shoff + 64 * r.below(shnum) as usize + [24, 32][r.below(2) as usize], 8),
            5 if shnum > 0 => (shoff + 64 * r.below(shnum) as usize + 4, 4),
            _ => continue,
        };
        if at + width > b.len() {
            continue;
        }
        let old = read(&b, at, width);
        let new = match r.below(8) {
            0 => 0,
            1 => old.wrapping_add(1 + r.below(16)),
            2 => old.wrapping_sub(1 + r.below(16)),
            3 => len + r.below(TAIL as u64),
            4 => ext.wrapping_sub(r.below(64)),
            5 => old.wrapping_add(r.below(TAIL as u64)),
            6 => [1, 2, 3, 6, 8, 0x6000_0000][r.below(6) as usize], // PT_/SHT_ types
            _ => r.below(len + TAIL as u64),
        };
        b[at..at + width].copy_from_slice(&new.to_le_bytes()[..width]);
    }
    b
}

/// Mutated binaries: whenever the loader takes one whole, the loader takes
/// every copy of it `snapshot_restorable` passes (cut at its extent, and at a
/// point in the zeros after it). 1,000 mutants of each small binary by
/// default; BULKHEAD_ELF_MUTANTS sets the number.
#[test]
fn no_restorable_copy_of_a_mutated_binary_is_refused_by_the_loader() {
    let n: usize = std::env::var("BULKHEAD_ELF_MUTANTS").ok().map(|s| s.parse().unwrap()).unwrap_or(1_000);
    let mut env = Env::new();
    for (name, elf) in corpus().into_iter().filter(|(_, e)| e.len() <= 10_000) {
        let live = Live::deploy(&mut env, &elf, elf.len() + TAIL).unwrap();
        let mut r = Rng(0x9e37_79b9_7f4a_7c15 ^ elf.len() as u64);
        // whole, no extent, restorable copies, refused restorable copies,
        // cuts one byte short of the extent that the loader still takes
        let mut c = [0usize; 5];
        for _ in 0..n {
            let m = mutate(&mut r, &elf);
            if !live.upgrade(&mut env, &m) {
                continue;
            }
            c[0] += 1;
            let Some(extent) = elf_extent(&m) else {
                c[1] += 1;
                continue;
            };
            let past = extent + r.below((m.len() - extent) as u64 + 1) as usize;
            for &cut in &[extent, past][..1 + (past > extent) as usize] {
                if snapshot_restorable(&m[..cut], &m) {
                    c[2] += 1;
                    if !live.upgrade(&mut env, &m[..cut]) {
                        c[3] += 1;
                        println!("{name}: restorable from {cut} bytes (extent {extent}), the loader refuses them");
                    }
                }
            }
            if extent > 64 && live.upgrade(&mut env, &m[..extent - 1]) {
                c[4] += 1;
            }
        }
        println!("{name}: {n} mutants, {} taken whole, {} with no extent, {} restorable copies, {} refused, {} taken one byte short", c[0], c[1], c[2], c[3], c[4]);
        // The search reaches what it is for in each binary: copies of
        // mutants the loader takes that the rule calls restorable.
        assert!(c[2] >= n / 5, "{name}: only {} restorable copies", c[2]);
        assert_eq!(c[3], 0, "{name}: a restorable copy the loader refuses");
    }
}
