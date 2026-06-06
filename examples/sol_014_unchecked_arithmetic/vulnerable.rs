//! SOL-014 vulnerable — unchecked arithmetic on a balance.
//!
//! `balance - amount` uses native subtraction. In release builds (no overflow
//! checks) a withdrawal larger than the balance wraps around u64, crediting the
//! attacker an enormous balance instead of failing. The same applies to `+`
//! (overflow) on deposits/fees.
//!
//! Bug class: integer overflow/underflow on financial values.

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
    // BUG: underflows and wraps when amount > balance (release builds).
    let new_balance: u64 = balance - amount;
    ctx.accounts.acct.balance = new_balance;
    Ok(())
}
