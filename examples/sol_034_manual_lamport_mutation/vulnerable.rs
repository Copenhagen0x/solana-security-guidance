// SOL-034 (vulnerable): lamports move, the ledger doesn't. The treasury pays
// the user with a direct lamport write, but `treasury.recorded_balance` — the
// program's own accounting of what the treasury holds — is never decremented.
// Withdraw-limit checks keyed on recorded_balance now pass against funds that
// are already gone: the next withdrawals over-distribute until the account is
// drained below rent exemption and gets purged.
use anchor_lang::prelude::*;

pub fn pay_out(ctx: Context<PayOut>, amount: u64) -> Result<()> {
    let treasury_info = ctx.accounts.treasury.to_account_info();
    let user_info = ctx.accounts.user.to_account_info();

    require!(
        ctx.accounts.treasury.recorded_balance >= amount,
        PayError::InsufficientRecorded
    );

    // Manual lamport mutation: debit the treasury, credit the user.
    **treasury_info.try_borrow_mut_lamports()? -= amount;
    **user_info.try_borrow_mut_lamports()? += amount;

    // BUG: recorded_balance is never decremented — the program's internal
    // ledger now says the treasury still holds `amount` it no longer has.
    Ok(())
}

#[derive(Accounts)]
pub struct PayOut<'info> {
    #[account(mut, has_one = authority)]
    pub treasury: Account<'info, Treasury>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub user: SystemAccount<'info>,
}

#[account]
pub struct Treasury {
    pub authority: Pubkey,
    pub recorded_balance: u64,
}

#[error_code]
pub enum PayError {
    InsufficientRecorded,
}
