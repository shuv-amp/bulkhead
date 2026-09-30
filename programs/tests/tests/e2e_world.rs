//! Builds the end-to-end world for `cloud/e2e/run.sh`: a sealed Bulkhead
//! market (Harbor + one USDC vault holding 10,000,000 USDC) created on LiteSVM
//! with the ids of the locally built programs and back-dated clocks, then
//! dumps every account and key so `solana-test-validator` can boot with the
//! same state. (A real validator can't skip the 72h seal; the seal flow itself
//! is tested in tests/vault.rs.)
//!
//!     cargo test --release --test e2e_world -- --ignored

mod common;

use common::vault::*;
use common::*;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::fs;

fn program_id(name: &str) -> Address {
    let path = format!("{}/../../target/deploy/{name}-keypair.json", env!("CARGO_MANIFEST_DIR"));
    let bytes: Vec<u8> = serde_like_parse(&fs::read_to_string(path).expect("build programs first"));
    Address::new_from_array(bytes[32..64].try_into().unwrap())
}

/// Parses "[1,2,3]" without a JSON dependency.
fn serde_like_parse(s: &str) -> Vec<u8> {
    s.trim().trim_start_matches('[').trim_end_matches(']').split(',').map(|x| x.trim().parse().unwrap()).collect()
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn dump_account(env: &Env, dir: &str, name: &str, address: &Address) {
    let a = env.account(address);
    let json = format!(
        "{{\"pubkey\":\"{}\",\"account\":{{\"lamports\":{},\"data\":[\"{}\",\"base64\"],\"owner\":\"{}\",\"executable\":false,\"rentEpoch\":0,\"space\":{}}}}}\n",
        address, a.lamports, b64(&a.data), a.owner, a.data.len()
    );
    fs::write(format!("{dir}/accounts/{name}.json"), json).unwrap();
}

fn save_key(dir: &str, name: &str, k: &Keypair) {
    let bytes = k.to_bytes();
    let list: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    fs::write(format!("{dir}/keys/{name}.json"), format!("[{}]", list.join(","))).unwrap();
}

#[test]
#[ignore]
fn build_world() {
    let dir = format!("{}/../../target/e2e", env!("CARGO_MANIFEST_DIR"));
    fs::create_dir_all(format!("{dir}/accounts")).unwrap();
    fs::create_dir_all(format!("{dir}/keys")).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    let mut env = Env::new();
    env.time = now - 80 * 3_600; // genesis 80h ago; the seal executes 8h ago
    env.sync_clock();
    // The Vault at the id Harbor is built for; the validator loads it there.
    let (vault_program, harbor) = (harbor_vault_id(), program_id("bulkhead_harbor"));
    let m = Market::with_ids(&mut env, vault_program, harbor);
    let usdc = m.create_vault(&mut env, 6, Limits::default_limits(), [1; 32], None);
    let whale = Keypair::new();
    env.fund(&whale);
    let whale_acc = env.token_account(&usdc.mint, &whale.pubkey(), &usdc.token_program);
    env.mint_to(&usdc.mint, &usdc.mint_authority, &whale_acc, 10_000_000_000_000, &usdc.token_program);
    let ix = m.deposit_ix(&env, &usdc, &whale.pubkey(), &whale_acc, 10_000_000_000_000);
    env.ok(&[ix], &[&whale]);
    env.ok(&[m.propose_seal_ix()], &[&m.admin]);
    env.advance(72 * 3_600);
    env.ok(&[m.execute_seal_ix(&[&usdc])], &[]);
    for g in &m.g {
        let hb = m.vault_ix(14, &[], vec![
            solana_instruction::AccountMeta::new(m.protocol, false),
            solana_instruction::AccountMeta::new_readonly(g.pubkey(), true),
        ]);
        env.ok(&[hb], &[g]);
    }
    let attacker = Keypair::new();
    let loot = env.token_account(&usdc.mint, &attacker.pubkey(), &usdc.token_program);

    dump_account(&env, &dir, "protocol", &m.protocol);
    dump_account(&env, &dir, "vault", &usdc.vault);
    dump_account(&env, &dir, "vault_tokens", &usdc.vault_tokens);
    dump_account(&env, &dir, "mint", &usdc.mint);
    dump_account(&env, &dir, "loot", &loot);
    dump_account(&env, &dir, "whale_backing", &m.backing(&whale.pubkey()));
    save_key(&dir, "admin", &m.admin);
    for (i, g) in m.g.iter().enumerate() {
        save_key(&dir, &format!("guardian{i}"), g);
    }
    save_key(&dir, "attacker", &attacker);
    let world = format!(
        "{{\n  \"vaultProgram\": \"{vault_program}\",\n  \"harbor\": \"{harbor}\",\n  \"protocol\": \"{}\",\n  \"caller\": \"{}\",\n  \"mint\": \"{}\",\n  \"vault\": \"{}\",\n  \"vaultTokens\": \"{}\",\n  \"attackerTokens\": \"{loot}\",\n  \"attacker\": \"{}\",\n  \"tokenProgram\": \"{}\"\n}}\n",
        m.protocol, m.caller, usdc.mint, usdc.vault, usdc.vault_tokens, attacker.pubkey(), usdc.token_program
    );
    fs::write(format!("{dir}/world.json"), world).unwrap();
    println!("E2E world written to {dir}");
}
