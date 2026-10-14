//! `GuardianSet::parse`, the one guardian-set parser Floor and the Vault
//! share, against an independent statement of the rules: the same outcome on
//! every input, never a panic, and whatever it accepts obeys every rule.
#![no_main]
use bulkhead_core::governance::{GuardianSet, GuardianSetError};
use libfuzzer_sys::fuzz_target;

const DAY: i64 = 86_400;

/// The rules, stated again: a count byte; 2..=8 guardians; the whole encoding
/// present; keys not zero, not forbidden, not repeated; 2 <= threshold <
/// count; an interval of 1-30 days.
fn reference(b: &[u8], forbidden: [&[u8; 32]; 2]) -> Result<(usize, u8, i64, usize), GuardianSetError> {
    let count = *b.first().ok_or(GuardianSetError::Truncated)? as usize;
    if !(2..=8).contains(&count) {
        return Err(GuardianSetError::BadCount);
    }
    let used = 1 + 32 * count + 1 + 8;
    if b.len() < used {
        return Err(GuardianSetError::Truncated);
    }
    let keys: Vec<&[u8]> = (0..count).map(|i| &b[1 + 32 * i..33 + 32 * i]).collect();
    for (i, k) in keys.iter().enumerate() {
        if k.iter().all(|x| *x == 0)
            || forbidden.iter().any(|f| f[..] == k[..])
            || keys[..i].contains(k)
        {
            return Err(GuardianSetError::BadKey);
        }
    }
    let threshold = b[1 + 32 * count];
    if !(2 <= threshold as usize && (threshold as usize) < count) {
        return Err(GuardianSetError::BadThreshold);
    }
    let interval = i64::from_le_bytes(b[2 + 32 * count..used].try_into().unwrap());
    if !(DAY..=30 * DAY).contains(&interval) {
        return Err(GuardianSetError::BadInterval);
    }
    Ok((count, threshold, interval, used))
}

// Raw bytes: [flags][forbidden 1: 32][forbidden 2: 32][the set...]. Flag bit 0
// shapes the set into one that can be accepted (count, threshold, interval
// in range), so the accept path is reached; bit 1 makes the second forbidden
// key one of the set's keys.
fuzz_target!(|data: &[u8]| {
    if data.len() < 66 {
        return;
    }
    let flags = data[0];
    let f1: [u8; 32] = data[1..33].try_into().unwrap();
    let mut f2: [u8; 32] = data[33..65].try_into().unwrap();
    let mut b = data[65..].to_vec();
    if flags & 1 == 1 {
        let count = 3 + b[0] % 6;
        b[0] = count;
        let n = count as usize;
        b.resize(GuardianSet::encoded_len(n), 1);
        b[1 + 32 * n] = 2 + b[1 + 32 * n] % (count - 2);
        let raw = u64::from_le_bytes(b[2 + 32 * n..10 + 32 * n].try_into().unwrap());
        let interval = DAY + (raw % (29 * DAY as u64 + 1)) as i64;
        b[2 + 32 * n..10 + 32 * n].copy_from_slice(&interval.to_le_bytes());
    }
    if flags & 2 == 2 && b.len() >= 33 {
        f2.copy_from_slice(&b[1..33]);
    }
    let got = GuardianSet::parse(&b, [&f1, &f2]);
    let want = reference(&b, [&f1, &f2]);
    assert_eq!(
        got.map(|(s, used)| (s.count as usize, s.threshold, s.interval_s, used)),
        want
    );
    if let Ok((s, used)) = got {
        let n = s.count as usize;
        assert_eq!(&s.keys[..n].concat()[..], &b[1..1 + 32 * n]);
        assert!(s.keys[n..].iter().all(|k| *k == [0; 32]));
        assert!(used <= b.len());
    }
});
