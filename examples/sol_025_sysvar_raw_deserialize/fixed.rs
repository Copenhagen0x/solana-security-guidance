//! SOL-025 fixed — `Clock::get()` reads the authentic runtime sysvar.
//!
//! `Clock::get()` returns the runtime's authoritative clock; there is no
//! caller-supplied account to spoof. (Equivalently, an Anchor `Sysvar<Clock>`
//! field has its key checked by the framework.) The raw sysvar deserialize is gone.

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Claim<'info> {
    pub user: Signer<'info>,
}

pub fn claim(_ctx: Context<Claim>) -> Result<()> {
    // Authentic clock — cannot be substituted by the caller.
    let clock = Clock::get()?;
    msg!("now = {}", clock.unix_timestamp);
    Ok(())
}
