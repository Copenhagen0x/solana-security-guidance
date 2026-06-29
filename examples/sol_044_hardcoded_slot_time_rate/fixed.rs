//! SOL-044 fixed - accrue on Clock unix_timestamp deltas, not a hardcoded slot rate.
//! Note the three completeness pieces a real fix needs (the "use unix_timestamp"
//! direction alone is not enough): (a) `last_ts` is initialized to now at loan open,
//! (b) a non-monotonic clock is rejected (no `.unwrap()` panic), (c) the per-call
//! elapsed is capped so an uninitialized/forward last_ts can't book years of interest.
use anchor_lang::prelude::*;

const SECONDS_PER_YEAR: u64 = 31_536_000; // real seconds, not slots
const MAX_ELAPSED: i64 = 7 * 24 * 60 * 60; // cap one accrual to a week

#[error_code]
pub enum AccrueError { #[msg("clock went backwards")] ClockRegressed }

pub fn open_loan(ctx: Context<OpenLoan>, principal: u64) -> Result<()> {
    let loan = &mut ctx.accounts.loan;
    loan.principal = principal;
    loan.owed = 0;
    loan.last_ts = Clock::get()?.unix_timestamp; // (a) seed last_ts, never leave it zero
    Ok(())
}

pub fn accrue(ctx: Context<Accrue>) -> Result<()> {
    let now_ts = Clock::get()?.unix_timestamp;
    let last_ts = ctx.accounts.loan.last_ts;
    // (b) reject a backwards clock instead of panicking on checked_sub().unwrap()
    require!(now_ts >= last_ts, AccrueError::ClockRegressed);
    // (c) cap the charged interval; advance the cursor by only what was charged
    let elapsed = (now_ts - last_ts).min(MAX_ELAPSED);
    let interest = ctx.accounts.loan.principal
        .checked_mul(elapsed as u64).unwrap_or(0)
        / SECONDS_PER_YEAR;
    ctx.accounts.loan.owed = ctx.accounts.loan.owed.saturating_add(interest);
    ctx.accounts.loan.last_ts = last_ts + elapsed;
    Ok(())
}

#[account]
pub struct Loan { pub principal: u64, pub owed: u64, pub last_ts: i64 }

#[derive(Accounts)]
pub struct OpenLoan<'info> {
    #[account(init, payer = user, space = 8 + 8 + 8 + 8)]
    pub loan: Account<'info, Loan>,
    #[account(mut)] pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Accrue<'info> { #[account(mut)] pub loan: Account<'info, Loan> }
