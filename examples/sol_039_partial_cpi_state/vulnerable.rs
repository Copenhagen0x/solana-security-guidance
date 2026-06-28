//! SOL-039 vulnerable - a fund-moving CPI's Result is swallowed after a state debit.
//! `withdraw` DEBITS the recorded balance, then transfers tokens out - but the
//! transfer Result is discarded with `let _ =`. On Solana only an Err RETURNED from
//! the top-level instruction reverts writes, so a swallowed inner-CPI failure leaves
//! `balance` debited while no tokens moved; the attacker forces the transfer to fail.
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

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
    // self-mutation committed BEFORE the CPI:
    ctx.accounts.position.balance = ctx.accounts.position.balance.checked_sub(amount).unwrap();
    let cpi = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.user_ata.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        },
    );
    // BUG: transfer Result discarded - a failed transfer leaves balance debited, no tokens moved.
    let _ = token::transfer(cpi, amount);
    Ok(())
}
