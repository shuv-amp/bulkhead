//! The one runtime syscall Vault calls directly: structured events
//! ("Program data: <base64>", the channel Anchor events use), parsed by the
//! Cloud guardian and the status page. The only `unsafe` in this program.
#![allow(unsafe_code)]

///
/// Every event ends with the protocol PDA it concerns: one Vault program
/// serves every protocol, and a transaction can list one protocol's account
/// while acting on another's, so a reader must not attribute an event by the
/// account list (docs/09, finding 64).
pub fn event(protocol: &[u8; 32], fields: &[&[u8]]) {
    let mut all: [&[u8]; 8] = [&[]; 8];
    let n = fields.len().min(all.len() - 1);
    all[..n].copy_from_slice(&fields[..n]);
    all[n] = protocol;
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_log_data(all.as_ptr() as *const u8, (n + 1) as u64);
    }
    #[cfg(not(target_os = "solana"))]
    let _ = all;
}
