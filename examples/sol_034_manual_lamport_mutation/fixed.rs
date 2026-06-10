// SOL-034 (fixed): every lamport debit updates the matching ledger field in
// the same instruction, and the treasury is verified to stay rent-exempt after
// the debit. The scanner (substring tripwire on manual lamport mutation) still
// fires here by design — the fix satisfies the rule's exclusion #1.
use anchor_lang::prelude::*;

pub fn pay_out(ctx: Context<PayOut>, amount: u64) -> Result<()> {
    let treasury_info = ctx.accounts.treasury.to_account_info();
    let user_info = ctx.accounts.user.to_account_info();

    require!(
        ctx.accounts.treasury.recorded_balance >= amount,
        PayError::InsufficientRecorded
    );

    // FIX (1/2): the internal ledger moves WITH the lamports, same instruction.
    ctx.accounts.treasury.recorded_balance = ctx
        .accounts
        .treasury
        .recorded_balance
        .checked_sub(amount)
        .ok_or(error!(PayError::InsufficientRecorded))?;

    // FIX (2/2): the debited account must remain rent-exempt after the debit.
    let rent = Rent::get()?;
    let post = treasury_info
        .lamports()
        .checked_sub(amount)
        .ok_or(error!(PayError::InsufficientRecorded))?;
    require!(
        post >= rent.minimum_balance(treasury_info.data_len()),
        PayError::WouldBreakRentExemption
    );

    **treasury_info.try_borrow_mut_lamports()? -= amount;
    **user_info.try_borrow_mut_lamports()? += amount;
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
    WouldBreakRentExemption,
}
