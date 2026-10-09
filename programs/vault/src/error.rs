//! Vault errors (`docs/05-PROGRAM-SPEC.md §5`). Codes start at 8000: disjoint
//! from Floor (7000+), Anchor (6000+) and the abort code `0x464C4F52`.

use pinocchio::error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VaultError {
    InvalidInstruction = 8000,
    WrongAccountType,
    WrongAddress,
    AlreadyInitialized,
    NotRegistrar,
    NotAdmin,
    NotGuardian,
    NoQuorum,
    MissingSignature,
    WrongCaller,
    WrongVault,
    WrongMint,
    WrongTokenProgram,
    ExtensionNotAllowed,
    RecipientOwnerMismatch,
    BadPriceAccount,
    NotSealed,
    AlreadySealed,
    SealNotExecutable,
    ImportExceedsBalance,
    VaultCountMismatch,
    InvalidLimits,
    InvalidAsset,
    InvalidGuardians,
    DelayBelowMinimum,
    LaneClosed,
    QueueFull,
    Frozen,
    FreezeTooLong,
    TicketNotDue,
    TicketNotPending,
    ExtensionTooLong,
    TicketsPending,
    ChangeNotExecutable,
    ChangeVetoed,
    ChangeExpired,
    ChangeExecuted,
    Abdicated,
    LedgerUnsound,
    LedgerCorrupt,
    NoSlot,
    DuplicateAccount,
    CannotEject,
    GenesisOnly,
    DestinationNotSettled,
    NothingToExit,
    ZeroAmount,
    Overflow,
    /// Loosen or upgrade delay above `MAX_LOOSEN_DELAY_S` (30 days).
    DelayAboveMaximum,
    /// `backed + instant` is larger than the vault token account's balance.
    InsufficientBalance,
    /// A loosening while the seal is under its 72h review.
    SealUnderReview,
    /// The change's target changed after it was proposed.
    ChangeStale,
    /// The ticket at this address is not the one the instruction names: a
    /// closed ticket's address is reused by its payer's next one.
    WrongTicket,
    /// A lifeboat exit to a destination this program owns, which could never
    /// move the tokens on (issue #38).
    StrandedDestination,
}

impl From<VaultError> for ProgramError {
    fn from(e: VaultError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
