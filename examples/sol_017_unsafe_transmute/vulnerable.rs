//! SOL-017 vulnerable — `unsafe { transmute }` over raw account bytes.
//!
//! The handler transmutes a borrowed byte slice into a typed struct reference
//! with no length check and no layout validation. A short or malformed account
//! reads out of bounds / interprets attacker bytes as a `Pubkey` + `u64`,
//! corrupting every downstream decision.
//!
//! Bug class: unchecked transmute (no deserialize-then-validate).

use anchor_lang::prelude::*;
use core::mem::transmute;

#[repr(C)]
pub struct Header {
    pub authority: Pubkey,
    pub amount: u64,
}

#[derive(Accounts)]
pub struct Read<'info> {
    /// CHECK: raw bytes, transmuted below (the bug).
    pub blob: AccountInfo<'info>,
}

pub fn read(ctx: Context<Read>) -> Result<()> {
    let data = ctx.accounts.blob.try_borrow_data()?;
    // BUG: no length/owner/layout check before reinterpreting the bytes.
    let header: &Header = unsafe { transmute(data.as_ptr()) };
    msg!("amount = {}", header.amount);
    Ok(())
}
