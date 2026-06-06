//! SOL-016 fixed — Anchor `seeds + bump` constraint enforces the canonical bump.
//!
//! The bare `bump` constraint makes Anchor derive the CANONICAL bump via
//! `find_program_address` and require the account to match it. No stored bump is
//! read in handler code and fed to `create_program_address`, so a non-canonical
//! PDA cannot pass validation. The `.bump` field read is gone.

use anchor_lang::prelude::*;

#[account]
pub struct Vault {
    pub bump: u8,
}

#[derive(Accounts)]
pub struct UseVault<'info> {
    // Anchor re-derives the canonical bump and checks the account matches.
    #[account(seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

pub fn use_vault(_ctx: Context<UseVault>) -> Result<()> {
    Ok(())
}
