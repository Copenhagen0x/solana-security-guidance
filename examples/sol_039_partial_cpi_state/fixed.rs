//! SOL-039 fixed - the CPI Result is propagated with `?`, so the whole instruction
//! reverts atomically with the balance debit if the transfer fails. The debit itself
//! also returns a clean error on underflow rather than panicking.
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[error_code]
pub enum WithdrawError { #[msg("insufficient balance")] Insufficient }

#[account]
pub struct Position { pub owner: Pubkey, pub balance: u64 }

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = owner)]
    pub position: Account<'info, Position>,
    pub owner: Signer<'info>,
    #[account(mut)] pub vault: Account<'info, TokenAccount>,
    #[account(mut)] pub user_ata: Account<'info, TokenAccount>,
    /// CHECK: vault PDA authority
    pub vault_authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    ctx.accounts.position.balance = ctx.accounts.position.balance
        .checked_sub(amount)
        .ok_or(error!(WithdrawError::Insufficient))?;
    let cpi = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.user_ata.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        },
    );
    // FIX: propagate with `?` - if the transfer fails, the balance debit reverts too.
    token::transfer(cpi, amount)?;
    Ok(())
}
