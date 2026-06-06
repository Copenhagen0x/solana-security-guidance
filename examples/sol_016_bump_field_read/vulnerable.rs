//! SOL-016 vulnerable — stored bump used without canonical validation.
//!
//! The handler reads a `bump` stored in account data and feeds it straight to
//! `create_program_address`, which accepts ANY valid off-curve bump — not just
//! the canonical one. An attacker who initialized the account with a
//! non-canonical bump can make a second, different PDA validate against the
//! same seeds, enabling account substitution.
//!
//! Bug class: non-canonical bump (missing find_program_address comparison).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey::Pubkey;

#[account]
pub struct Vault {
    pub bump: u8,
}

#[derive(Accounts)]
pub struct UseVault<'info> {
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

pub fn use_vault(ctx: Context<UseVault>) -> Result<()> {
    // BUG: trusts the stored bump; create_program_address accepts a
    // non-canonical bump, so a crafted PDA passes this derivation.
    let stored = ctx.accounts.vault.bump;
    let user_key = ctx.accounts.user.key();
    let seeds: &[&[u8]] = &[b"vault", user_key.as_ref(), &[stored]];
    let _derived = Pubkey::create_program_address(seeds, ctx.program_id)
        .map_err(|_| ErrorCode::BadPda)?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("bad pda")]
    BadPda,
}
