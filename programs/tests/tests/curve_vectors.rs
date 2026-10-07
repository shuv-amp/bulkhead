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
    // Edge encodings PDA candidates almost never hit: y of 0, 1, p - 1, and p or
    // more (Solana takes y mod p; p + 1 is the identity point), each with and
    // without the sign bit. Solana's verdict is the reference.
    let p_minus = |d: u8| {
        let mut b = [0xffu8; 32];
        b[31] = 0x7f;
        b[0] = 0xed - d;
        b
    };
    let p_plus = |d: u8| {
        let mut b = [0xffu8; 32];
        b[31] = 0x7f;
        b[0] = 0xed + d;
        b
    };
    let small = |v: u8| {
        let mut b = [0u8; 32];
        b[0] = v;
        b
    };
    for base in [small(0), small(1), p_minus(1), p_plus(0), p_plus(1), p_plus(18)] {
        for sign in [false, true] {
            let mut b = base;
            if sign {
                b[31] |= 0x80;
            }
            let c = Address::new_from_array(b).is_on_curve();
            if c { on += 1 } else { off += 1 }
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
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
