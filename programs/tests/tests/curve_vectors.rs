//! Generates tools/testdata/curve25519_vectors.json: PDA candidate addresses
//! (real `derive_address` outputs, on and off the curve) with Solana's own
//! verdict (`Address::is_on_curve`, curve25519-dalek). `tools/floor_check.py
//! --self-test` must agree on every one. Run to regenerate:
//!     cargo test --test curve_vectors -- --ignored

use solana_address::Address;

#[test]
#[ignore]
fn generate() {
    let program = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
    let mut out = String::from("[\n");
    let (mut on, mut off) = (0, 0);
    for i in 0u32..64 {
        for bump in [255u8, 254, 253, 252] {
            let a = Address::derive_address(&[b"vector".as_ref(), &i.to_le_bytes()], Some(bump), &program);
            let c = a.is_on_curve();
            if c { on += 1 } else { off += 1 }
            let hex: String = a.as_ref().iter().map(|b| format!("{b:02x}")).collect();
            out += &format!("  [\"{hex}\", {c}],\n");
        }
    }
    out.truncate(out.len() - 2);
    out += "\n]\n";
    assert!(on > 50 && off > 50, "both kinds: {on} on-curve, {off} off-curve");
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tools/testdata/curve25519_vectors.json");
    std::fs::write(path, out).unwrap();
    println!("wrote {on} on-curve and {off} off-curve vectors");
}
