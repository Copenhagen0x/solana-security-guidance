// SOL-033 (fixed): `reload()` between the CPI and the read re-deserializes the
// account from its AccountInfo, so the solvency gate sees the POST-transfer
// balance. The scanner (CPI-then-read proximity tripwire) still fires here by
// design — RE2 can't see the reload — the fix satisfies the rule's exclusion #1.
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

pub fn distribute(ctx: Context<Distribute>, payout: u64) -> Result<()> {
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_token.to_account_info(),
                to: ctx.accounts.recipient.to_account_info(),
                authority: ctx.accounts.vault_signer.to_account_info(),
            },
            &[&[b"vault", &[ctx.accounts.pool.vault_bump]]],
        ),
        payout,
    )?;

    // FIX: refresh the cached deserialization — the CPI mutated this account.
    ctx.accounts.vault_token.reload()?;
    let remaining = ctx.accounts.vault_token.amount;
    require!(remaining >= ctx.accounts.pool.reserved, PoolError::Insolvent);
    Ok(())
}

#[derive(Accounts)]
pub struct Distribute<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub recipient: Account<'info, TokenAccount>,
    /// CHECK: PDA signer for the vault, validated by seeds on the CPI.
    pub vault_signer: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Pool {
    pub reserved: u64,
    pub vault_bump: u8,
}

#[error_code]
pub enum PoolError {
    Insolvent,
}
