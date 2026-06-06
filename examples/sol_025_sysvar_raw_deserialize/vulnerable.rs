//! SOL-025 vulnerable — `bincode::deserialize::<Clock>` from a passed account.
//!
//! The handler deserializes a `Clock` out of a caller-supplied account's data
//! without verifying the account is the real Clock sysvar. An attacker passes a
//! look-alike account carrying an arbitrary `unix_timestamp`/`slot`, spoofing
//! "time" to bypass a vesting cliff or expiry.
//!
//! Bug class: raw sysvar deserialize instead of Clock::get() / Sysvar<>.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::clock::Clock;

#[derive(Accounts)]
pub struct Claim<'info> {
    /// CHECK: BUG — never verified to be the Clock sysvar.
    pub clock_account: AccountInfo<'info>,
    pub user: Signer<'info>,
}

pub fn claim(ctx: Context<Claim>) -> Result<()> {
    let data = ctx.accounts.clock_account.try_borrow_data()?;
    // BUG: deserializes "time" from an unverified account.
    let clock: Clock = bincode::deserialize::<Clock>(&data)
        .map_err(|_| ErrorCode::BadClock)?;
    msg!("now = {}", clock.unix_timestamp);
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("bad clock")]
    BadClock,
}
