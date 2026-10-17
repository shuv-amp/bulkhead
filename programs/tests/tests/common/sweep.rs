//! Account-substitution sweep: the commonest critical Solana bug is an
//! instruction that does not fully check an account it is given (owner, PDA,
//! signer, which protocol or vault it belongs to). For each instruction this
//! takes a transaction that succeeds and swaps one account at a time for a
//! fresh address, every other account in the transaction, a second market's
//! accounts, the other vault, programs and sysvars, and, for a signer, every
//! other known key; then, per key that signs at any slot (a free one
//! included) and stands at a checked slot, the key unsigned at every
//! checked slot (a free slot where it signed gets the payer; not for the
//! fee payer). Every swap must fail, except at positions the program
//! deliberately leaves free (each listed with its reason), and fail with
//! the swept program's own error code: a refusal that only a CPI or the
//! runtime makes would hide that program's check being deleted. A slot
//! where another program or the runtime refuses by design is listed as a
//! backstop, with the errors it refuses with and who refuses; a backstop
//! whose errors never occur fails the sweep. The sweep cannot tell there
//! whether the program's own check exists. Nor can it tell which of the
//! program's checks refused: one deleted where a later check returns a
//! code of the same program passes, so such checks need their own tests.
#![allow(dead_code)]

use super::vault::*;
use super::*;
use litesvm::LiteSVM;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_instruction_error::InstructionError;
use solana_transaction_error::TransactionError;
use std::collections::HashSet;
use std::ops::Range;

/// What one tampered transaction came to.
enum Outcome {
    /// A required signer is not a key we hold.
    Unsignable,
    /// Sent; a success or a refusal not by the program is already reported.
    Sent,
    /// Refused with this error a backstop names.
    Backstopped(InstructionError),
}

/// A program's error codes: each program numbers its own from its first,
/// InvalidInstruction (Floor 7000, the Vault 8000), fewer than 1000 of
/// them; the programs they call (token, system, loader) use codes below 100.
fn codes(first: u32) -> Range<u32> {
    first..first + 1000
}

fn short(a: &Address) -> String {
    a.to_string()[..8].to_string()
}

/// A substitution the program accepts on purpose, or (`backstop`) a slot
/// where something else refuses swaps first.
#[derive(Clone)]
pub struct Allow {
    pub at: usize,
    /// None: any account. Some: these addresses (the same role).
    /// (Some and empty for a backstop: nothing else may stand there.)
    pub who: Option<Vec<Address>>,
    pub why: &'static str,
    /// A backstop's errors: the slot is swept as usual (every swap must
    /// fail), but a refusal with one of these, from another program or the
    /// runtime, stands for the program's own code. Empty otherwise.
    pub refusals: Vec<InstructionError>,
}
pub fn any(at: usize, why: &'static str) -> Allow {
    Allow {
        at,
        who: None,
        why,
        refusals: vec![],
    }
}
pub fn role(at: usize, who: Vec<Address>, why: &'static str) -> Allow {
    Allow {
        at,
        who: Some(who),
        why,
        refusals: vec![],
    }
}
/// Swaps at `at` are refused with one of `refusals` before the swept
/// program can refuse them; `why` names who refuses.
pub fn backstop(at: usize, refusals: &[InstructionError], why: &'static str) -> Allow {
    assert!(!refusals.is_empty(), "a backstop names the errors it refuses with");
    Allow {
        at,
        who: Some(vec![]),
        why,
        refusals: refusals.to_vec(),
    }
}

pub struct Sweep {
    /// The swept program's error codes (`codes`).
    own: Range<u32>,
    decoys: Vec<(String, Address)>,
    keys: Vec<Keypair>,
    pub unexpected: Vec<String>,
    pub attempts: usize,
    pub unsignable: usize,
    /// Swaps refused at a backstop slot by something other than the
    /// program's own code.
    pub backstopped: usize,
    /// Transactions swept (each `run`).
    pub runs: usize,
    /// (run name, key) for every key sent unsigned at all its checked
    /// slots (the payer standing in at free slots where it signed).
    pub unsigned: Vec<(String, Address)>,
}

impl Sweep {
    pub fn for_market(
        env: &Env,
        m: &Market,
        sol: &VaultRef,
        other: &Market,
        other_vault: &VaultRef,
    ) -> Sweep {
        let mut decoys = vec![
            ("system".into(), SYSTEM),
            ("token program".into(), token_program()),
            ("token-2022".into(), token_2022()),
            ("vault program".into(), m.vault_program),
            ("harbor".into(), m.harbor),
            (
                "clock sysvar".into(),
                Address::from_str_const("SysvarC1ock11111111111111111111111111111111"),
            ),
        ];
        for (tag, v) in [("sol", sol), ("other market's", other_vault)] {
            decoys.push((format!("{tag} vault"), v.vault));
            decoys.push((format!("{tag} vault tokens"), v.vault_tokens));
            decoys.push((format!("{tag} mint"), v.mint));
            decoys.push((format!("{tag} asset"), v.asset));
            decoys.push((format!("{tag} price"), v.price));
        }
        decoys.push(("other market's protocol".into(), other.protocol));
        decoys.push(("other market's caller".into(), other.caller));
        decoys.push(("other harbor".into(), other.harbor));
        let mut keys = vec![
            env.payer.insecure_clone(),
            m.admin.insecure_clone(),
            other.admin.insecure_clone(),
        ];
        keys.extend(m.g.iter().map(|k| k.insecure_clone()));
        keys.extend(other.g.iter().map(|k| k.insecure_clone()));
        Sweep {
            own: codes(verr::INVALID_INSTRUCTION),
            decoys,
            keys,
            unexpected: vec![],
            attempts: 0,
            unsignable: 0,
            backstopped: 0,
            runs: 0,
            unsigned: vec![],
        }
    }

    /// A sweep with only the basic decoys and these keys, of a program whose
    /// error codes start at `first_code`.
    pub fn new(
        env: &Env,
        first_code: u32,
        decoys: Vec<(String, Address)>,
        keys: &[&Keypair],
    ) -> Sweep {
        let mut d = vec![
            ("system".into(), SYSTEM),
            ("token program".into(), token_program()),
            (
                "loader-v3".into(),
                Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111"),
            ),
            (
                "clock sysvar".into(),
                Address::from_str_const("SysvarC1ock11111111111111111111111111111111"),
            ),
        ];
        d.extend(decoys);
        let mut k = vec![env.payer.insecure_clone()];
        k.extend(keys.iter().map(|x| x.insecure_clone()));
        Sweep {
            own: codes(first_code),
            decoys: d,
            keys: k,
            unexpected: vec![],
            attempts: 0,
            unsignable: 0,
            backstopped: 0,
            runs: 0,
            unsigned: vec![],
        }
    }

    /// Another key an attacker might hold or name.
    pub fn key(&mut self, k: &Keypair) {
        if !self.keys.iter().any(|x| x.pubkey() == k.pubkey()) {
            self.keys.push(k.insecure_clone());
        }
    }

    /// Another account a careless check would accept here.
    pub fn decoy(&mut self, name: &str, a: Address) {
        self.decoys.push((name.into(), a));
    }

    /// Sends `ix` signed by whichever known keys it needs (plus `extra`);
    /// None when a required signer is not a key we hold.
    fn send(
        &self,
        env: &mut Env,
        ix: Instruction,
        extra: Option<&Keypair>,
    ) -> Option<Result<(), FailedTransactionMetadata>> {
        let msg = Message::new(&[ix], Some(&env.payer.pubkey()));
        let n = msg.header.num_required_signatures as usize;
        let mut signers: Vec<&Keypair> = vec![];
        for k in &msg.account_keys[..n] {
            let found = self.keys.iter().chain(extra).find(|kp| kp.pubkey() == *k)?;
            signers.push(found);
        }
        let tx = Transaction::new(&signers, msg, env.svm.latest_blockhash());
        let r = env.svm.send_transaction(tx).map(|_| ());
        env.svm.expire_blockhash();
        Some(r)
    }

    /// Sends one tampered transaction from `base`; a success is reported,
    /// and so is a refusal by anything but the program's own code or one of
    /// `refusals` (with the log line of the program that failed first).
    fn attempt(
        &mut self,
        env: &mut Env,
        base: &LiteSVM,
        tampered: Instruction,
        key: Option<&Keypair>,
        refusals: &[InstructionError],
        report: String,
    ) -> Outcome {
        env.svm = base.clone();
        if let Some(k) = key {
            env.fund(k);
        }
        self.attempts += 1;
        let Some(sent) = self.send(env, tampered, key) else {
            self.unsignable += 1;
            return Outcome::Unsignable;
        };
        let Err(failed) = sent else {
            self.unexpected.push(report);
            return Outcome::Sent;
        };
        if custom_code(&failed).is_some_and(|c| self.own.contains(&c)) {
            return Outcome::Sent;
        }
        if let TransactionError::InstructionError(_, e) = &failed.err {
            if refusals.contains(e) {
                self.backstopped += 1;
                return Outcome::Backstopped(e.clone());
            }
        }
        let by = failed.meta.logs.iter().find(|l| l.contains(" failed: "));
        self.unexpected.push(format!(
            "{report}: refused by {:?}, not the program's own code ({})",
            failed.err,
            by.map_or("no failure logged", |l| l.as_str())
        ));
        Outcome::Sent
    }

    /// `ok`: what the program deliberately accepts, as (position, the
    /// addresses that may stand there, or None for any, and why).
    pub fn run(
        &mut self,
        env: &mut Env,
        name: &str,
        ix: Instruction,
        extra_keys: &[&Keypair],
        ok: &[Allow],
    ) {
        self.runs += 1;
        let free: Vec<usize> = ok
            .iter()
            .filter(|a| a.who.is_none())
            .map(|a| a.at)
            .collect();
        let backstops: Vec<&Allow> = ok.iter().filter(|a| !a.refusals.is_empty()).collect();
        // Per slot, the errors its backstops name.
        let mut refusals_at: Vec<Vec<InstructionError>> = vec![vec![]; ix.accounts.len()];
        for a in &backstops {
            refusals_at[a.at].extend(a.refusals.iter().cloned());
        }
        // (slot, error) of every backstop refusal a swap produced in this run.
        let mut seen_refusals: Vec<(usize, InstructionError)> = vec![];
        for k in extra_keys {
            if !self.keys.iter().any(|x| x.pubkey() == k.pubkey()) {
                self.keys.push(k.insecure_clone());
            }
        }
        let base = env.svm.clone();
        assert_eq!(
            self.send(env, ix.clone(), None),
            Some(Ok(())),
            "{name}: the unmodified transaction must succeed"
        );
        for (i, orig) in ix.accounts.iter().enumerate() {
            if free.contains(&i) {
                continue;
            }
            let same_role: Vec<Address> = ok
                .iter()
                .filter(|a| a.at == i)
                .flat_map(|a| a.who.clone().unwrap_or_default())
                .collect();
            let mut tries: Vec<(String, AccountMeta, Option<Keypair>)> = vec![];
            if orig.is_signer {
                let k = Keypair::new();
                tries.push((
                    "a fresh key".into(),
                    AccountMeta {
                        pubkey: k.pubkey(),
                        ..orig.clone()
                    },
                    Some(k),
                ));
                for k in &self.keys {
                    if k.pubkey() != orig.pubkey {
                        tries.push((
                            format!("key {}", short(&k.pubkey())),
                            AccountMeta {
                                pubkey: k.pubkey(),
                                ..orig.clone()
                            },
                            None,
                        ));
                    }
                }
            } else {
                tries.push((
                    "a fresh address".into(),
                    AccountMeta {
                        pubkey: Address::new_unique(),
                        ..orig.clone()
                    },
                    None,
                ));
                let mut seen = HashSet::new();
                let inner: Vec<(String, Address)> = ix
                    .accounts
                    .iter()
                    .enumerate()
                    .map(|(j, a)| (format!("account {j}"), a.pubkey))
                    .collect();
                for (what, d) in inner.iter().chain(self.decoys.iter()) {
                    if *d != orig.pubkey && seen.insert(*d) {
                        tries.push((
                            what.clone(),
                            AccountMeta {
                                pubkey: *d,
                                ..orig.clone()
                            },
                            None,
                        ));
                    }
                }
            }
            for (what, meta, key) in tries {
                if same_role.contains(&meta.pubkey) && meta.is_signer == orig.is_signer {
                    continue;
                }
                let mut tampered = ix.clone();
                tampered.accounts[i] = meta;
                let report = format!(
                    "{name}: account {i} ({}) replaced by {what}",
                    short(&orig.pubkey)
                );
                if let Outcome::Backstopped(e) =
                    self.attempt(env, &base, tampered, key.as_ref(), &refusals_at[i], report)
                {
                    if !seen_refusals.contains(&(i, e.clone())) {
                        seen_refusals.push((i, e));
                    }
                }
            }
        }
        // Signing is per key, not per slot: unsigning one slot changes
        // nothing while another slot signs for the same key. So, once per
        // key that signs at some slot and stands at a checked one, reported
        // at its first checked slot: the key unsigned at every checked slot,
        // with the payer standing in at free slots where it signed (they
        // take any account; a control first checks the payer is accepted
        // there with the key signed at its checked slots, so the refusal
        // is the missing signature's); not for the fee payer, which signs
        // the transaction anyway.
        let payer = env.payer.pubkey();
        let mut done = HashSet::new();
        for (i, orig) in ix.accounts.iter().enumerate() {
            if free.contains(&i) || orig.pubkey == payer || !done.insert(orig.pubkey) {
                continue;
            }
            let slots: Vec<usize> = (0..ix.accounts.len())
                .filter(|&j| ix.accounts[j].pubkey == orig.pubkey)
                .collect();
            if !slots.iter().any(|&j| ix.accounts[j].is_signer) {
                continue;
            }
            let mut unsigned = ix.clone();
            let mut control = ix.clone();
            let mut stand_in = vec![];
            for &j in &slots {
                let a = &mut unsigned.accounts[j];
                if free.contains(&j) && a.is_signer {
                    a.pubkey = payer;
                    control.accounts[j].pubkey = payer;
                    stand_in.push(j);
                } else {
                    a.is_signer = false;
                    control.accounts[j].is_signer = !free.contains(&j);
                }
            }
            if !stand_in.is_empty() {
                env.svm = base.clone();
                assert_eq!(
                    self.send(env, control, None),
                    Some(Ok(())),
                    "{name}: the payer must be accepted at {stand_in:?}"
                );
            }
            let mut report = format!("{name}: account {i} ({}) unsigned", short(&orig.pubkey));
            if !stand_in.is_empty() {
                report += &format!(", the payer at {stand_in:?}");
            }
            // Excused only by a missing-signature refusal one of the key's
            // backstop slots names (not counted as seen there: which slot
            // refused is unknown, so only account swaps keep a backstop).
            let refusals: Vec<InstructionError> = slots
                .iter()
                .flat_map(|&j| refusals_at[j].iter().cloned())
                .filter(|e| *e == InstructionError::MissingRequiredSignature)
                .collect();
            if !matches!(
                self.attempt(env, &base, unsigned, None, &refusals, report),
                Outcome::Unsignable
            ) {
                self.unsigned.push((name.into(), orig.pubkey));
            }
        }
        // A backstop error no swap produced is stale: the program now
        // refuses there itself, or the slot moved.
        for a in &backstops {
            for e in &a.refusals {
                if !seen_refusals.contains(&(a.at, e.clone())) {
                    self.unexpected.push(format!(
                        "{name}: backstop at account {} ({}) never refused with {e:?}",
                        a.at, a.why
                    ));
                }
            }
        }
        // Continue from the state after the real transaction.
        env.svm = base;
        assert_eq!(self.send(env, ix, None), Some(Ok(())));
    }
}
