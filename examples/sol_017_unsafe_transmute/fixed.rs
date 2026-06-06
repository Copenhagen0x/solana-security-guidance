//! SOL-017 fixed — typed deserialize with length + discriminator validation.
//!
//! `blob` is an Anchor `Account<'info, Header>`: Anchor checks the owner and the
//! 8-byte discriminator and deserializes safely (length-validated) before the
//! handler runs. No `unsafe`/`transmute` and no raw pointer cast remain.

use anchor_lang::prelude::*;

#[account]
pub struct Header {
    pub authority: Pubkey,
    pub amount: u64,
}

#[derive(Accounts)]
pub struct Read<'info> {
    pub blob: Account<'info, Header>,
}

pub fn read(ctx: Context<Read>) -> Result<()> {
    msg!("amount = {}", ctx.accounts.blob.amount);
    Ok(())
}
