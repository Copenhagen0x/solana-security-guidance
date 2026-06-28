//! SOL-044 vulnerable - interest accrued from a hardcoded slot->time rate.
//! SLOTS_PER_YEAR assumes a fixed ~400ms slot time; real slot time drifts, so the
//! accrual silently diverges from wall-clock time (over/under-payment that compounds).
use anchor_lang::prelude::*;

const SLOTS_PER_YEAR: u64 = 78_840_000; // BUG: hardcoded slot->time conversion

pub fn accrue(ctx: Context<Accrue>) -> Result<()> {
    let now_slot = Clock::get()?.slot;
    let elapsed_slots = now_slot - ctx.accounts.loan.last_slot;
    let interest = ctx.accounts.loan.principal
        .checked_mul(elapsed_slots).unwrap()
        / SLOTS_PER_YEAR;
    ctx.accounts.loan.owed = ctx.accounts.loan.owed.checked_add(interest).unwrap();
    ctx.accounts.loan.last_slot = now_slot;
    Ok(())
}

#[account]
pub struct Loan { pub principal: u64, pub owed: u64, pub last_slot: u64 }

#[derive(Accounts)]
pub struct Accrue<'info> { #[account(mut)] pub loan: Account<'info, Loan> }
