//! The one runtime syscall Vault calls directly: structured events
//! ("Program data: <base64>", the channel Anchor events use), parsed by the
//! Cloud guardian and the status page. The only `unsafe` in this program.
#![allow(unsafe_code)]

pub fn event(fields: &[&[u8]]) {
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_log_data(fields.as_ptr() as *const u8, fields.len() as u64);
    }
    #[cfg(not(target_os = "solana"))]
    let _ = fields;
}
