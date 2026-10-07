//! Account-substitution sweep: the commonest critical Solana bug is an
//! instruction that does not fully check an account it is given (owner, PDA,
//! signer, which protocol or vault it belongs to). For each instruction this
//! takes a transaction that succeeds and swaps one account at a time for a
//! fresh address, every other account in the transaction, a second market's
//! accounts, the other vault, programs and sysvars, and, for a signer, every
//! other known key and the same key unsigned. Every swap must fail, except at
//! positions the program deliberately leaves free (each listed with its
//! reason).
#![allow(dead_code)]

use super::vault::*;
use super::*;
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
            // Signing is per key, not per slot: only try the key unsigned
            // where nothing else in the transaction makes it sign.
            let signs_elsewhere = orig.pubkey == env.payer.pubkey()
                || ix
                    .accounts
                    .iter()
                    .enumerate()
                    .any(|(j, a)| j != i && a.pubkey == orig.pubkey && a.is_signer);
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
                if !signs_elsewhere {
                    tries.push((
                        "the same key, unsigned".into(),
                        AccountMeta {
                            is_signer: false,
                            ..orig.clone()
                        },
                        None,
                    ));
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
                env.svm = base.clone();
                if let Some(k) = &key {
                    env.fund(k);
                }
                let mut tampered = ix.clone();
                tampered.accounts[i] = meta;
                self.attempts += 1;
                match self.send(env, tampered, key.as_ref()) {
                    None => self.unsignable += 1,
                    Some(true) => self.unexpected.push(format!(
                        "{name}: account {i} ({}) replaced by {what}",
                        short(&orig.pubkey)
                    )),
                    Some(false) => {}
                }
            }
        }
        // Continue from the state after the real transaction.
        env.svm = base;
        assert_eq!(self.send(env, ix, None), Some(true));
    }
}
