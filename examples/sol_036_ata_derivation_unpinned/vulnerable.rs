// SOL-036 (vulnerable): the program credits a deposit to "the user's token account"
// but never checks that the passed account is the canonical ATA for (user, mint).
// An attacker passes a token account they control for a DIFFERENT user/mint and
// redirects the payout. Review-only: the absence of a derivation check has no
// single syntactic marker, so this class is caught in review (see the exclusions).
use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};

pub fn record_deposit(ctx: Context<RecordDeposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    // BUG: `user_token` is trusted as the user's ATA, but nothing ties it to
    // (user, mint). The attacker supplies any TokenAccount they own.
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
    // No associated_token constraints — unpinned.
    pub user_token: Account<'info, TokenAccount>,
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
