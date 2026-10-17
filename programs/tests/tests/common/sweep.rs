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
//! deliberately leaves free (each listed with its reason).
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
use std::collections::HashSet;

fn short(a: &Address) -> String {
    a.to_string()[..8].to_string()
}

/// A substitution the program accepts on purpose.
pub struct Allow {
    pub at: usize,
    /// None: any account. Some: these addresses (the same role).
    pub who: Option<Vec<Address>>,
    #[allow(dead_code)]
    pub why: &'static str,
}
pub fn any(at: usize, why: &'static str) -> Allow {
    Allow { at, who: None, why }
}
pub fn role(at: usize, who: Vec<Address>, why: &'static str) -> Allow {
    Allow {
        at,
        who: Some(who),
        why,
    }
}

pub struct Sweep {
    decoys: Vec<(String, Address)>,
    keys: Vec<Keypair>,
    pub unexpected: Vec<String>,
    pub attempts: usize,
    pub unsignable: usize,
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
            decoys,
            keys,
            unexpected: vec![],
            attempts: 0,
            unsignable: 0,
            runs: 0,
            unsigned: vec![],
        }
    }

    /// A sweep with only the basic decoys and these keys.
    pub fn new(env: &Env, decoys: Vec<(String, Address)>, keys: &[&Keypair]) -> Sweep {
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
            decoys: d,
            keys: k,
            unexpected: vec![],
            attempts: 0,
            unsignable: 0,
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
    fn send(&self, env: &mut Env, ix: Instruction, extra: Option<&Keypair>) -> Option<bool> {
        let msg = Message::new(&[ix], Some(&env.payer.pubkey()));
        let n = msg.header.num_required_signatures as usize;
        let mut signers: Vec<&Keypair> = vec![];
        for k in &msg.account_keys[..n] {
            let found = self.keys.iter().chain(extra).find(|kp| kp.pubkey() == *k)?;
            signers.push(found);
        }
        let tx = Transaction::new(&signers, msg, env.svm.latest_blockhash());
        let ok = env.svm.send_transaction(tx).is_ok();
        env.svm.expire_blockhash();
        Some(ok)
    }

    /// Sends one tampered transaction from `base`; a success is reported.
    /// False when it could not be signed.
    fn attempt(
        &mut self,
        env: &mut Env,
        base: &LiteSVM,
        tampered: Instruction,
        key: Option<&Keypair>,
        report: String,
    ) -> bool {
        env.svm = base.clone();
        if let Some(k) = key {
            env.fund(k);
        }
        self.attempts += 1;
        let sent = self.send(env, tampered, key);
        match sent {
            None => self.unsignable += 1,
            Some(true) => self.unexpected.push(report),
            Some(false) => {}
        }
        sent.is_some()
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
        for k in extra_keys {
            if !self.keys.iter().any(|x| x.pubkey() == k.pubkey()) {
                self.keys.push(k.insecure_clone());
            }
        }
        let base = env.svm.clone();
        assert_eq!(
            self.send(env, ix.clone(), None),
            Some(true),
            "{name}: the unmodified transaction must succeed"
        );
        for i in 0..ix.accounts.len() {
            if free.contains(&i) {
                continue;
            }
            let same_role: Vec<Address> = ok
                .iter()
                .filter(|a| a.at == i)
                .flat_map(|a| a.who.clone().unwrap_or_default())
                .collect();
            let orig = ix.accounts[i].clone();
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
                self.attempt(env, &base, tampered, key.as_ref(), report);
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
                    Some(true),
                    "{name}: the payer must be accepted at {stand_in:?}"
                );
            }
            let mut report = format!("{name}: account {i} ({}) unsigned", short(&orig.pubkey));
            if !stand_in.is_empty() {
                report += &format!(", the payer at {stand_in:?}");
            }
            if self.attempt(env, &base, unsigned, None, report) {
                self.unsigned.push((name.into(), orig.pubkey));
            }
        }
        // Continue from the state after the real transaction.
        env.svm = base;
        assert_eq!(self.send(env, ix, None), Some(true));
    }
}
