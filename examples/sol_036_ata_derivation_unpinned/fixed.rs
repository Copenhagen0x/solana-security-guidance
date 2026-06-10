// SOL-036 (fixed): Anchor's `associated_token::mint` + `associated_token::authority`
// constraints re-derive the canonical ATA for (user, mint) and reject anything
// else — the attacker can no longer substitute a token account they control.
use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{Mint, Token, TokenAccount};

pub fn record_deposit(ctx: Context<RecordDeposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.last_credited = ctx.accounts.user_token.key();
    vault.credited = vault.credited.checked_add(amount).ok_or(error!(VaultError::Overflow))?;
    Ok(())
}

#[derive(Accounts)]
pub struct RecordDeposit<'info> {
    #[account(mut, has_one = user)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
    pub mint: Account<'info, Mint>,
    // FIX: pinned to the canonical ATA for (user, mint).
    #[account(
        associated_token::mint = mint,
        associated_token::authority = user,
    )]
    pub user_token: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[account]
pub struct Vault {
    pub user: Pubkey,
    pub last_credited: Pubkey,
    pub credited: u64,
}

#[error_code]
pub enum VaultError {
    Overflow,
}
