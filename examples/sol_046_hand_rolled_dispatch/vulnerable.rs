//! SOL-046 vulnerable - hand-rolled dispatch bypasses Anchor's account guards.
//! Routing on raw data[0] skips the 8-byte discriminator AND every #[account(...)]
//! constraint - accounts arrive unvalidated as a bare &[AccountInfo].
use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
use solana_program::program_error::ProgramError;

pub fn process_instruction(_program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    // BUG: no Anchor dispatch - no discriminator, no constraint checks run.
    match data[0] {
        0 => initialize(accounts),
        1 => set_admin(accounts), // privileged, yet no signer/owner check runs
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn initialize(_accounts: &[AccountInfo]) -> ProgramResult { Ok(()) }
fn set_admin(_accounts: &[AccountInfo]) -> ProgramResult { Ok(()) }
