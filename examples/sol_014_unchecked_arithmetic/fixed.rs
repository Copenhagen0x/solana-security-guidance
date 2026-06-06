//! SOL-014 fixed — `checked_sub` with explicit error handling.
//!
//! The subtraction uses `checked_sub`, which returns `None` on underflow; the
//! handler maps that to a domain error and aborts. A withdrawal larger than the
//! balance is rejected instead of wrapping. No bare `a - b` on the financial
//! path remains for the scanner to flag.

use anchor_lang::prelude::*;

#[account]
pub struct Account_ {
    pub balance: u64,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub acct: Account<'info, Account_>,
    pub owner: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let balance = ctx.accounts.acct.balance;
    let new_balance = balance.checked_sub(amount).ok_or(ErrorCode::Underflow)?;
    ctx.accounts.acct.balance = new_balance;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("withdrawal exceeds balance")]
    Underflow,
}
