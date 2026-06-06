//! SOL-007 fixed — typed `Account<>` enforces the owner before any field use.
//!
//! `vault` is an Anchor `Account<'info, Vault>`. Anchor checks the account is
//! owned by this program AND validates the 8-byte discriminator before the
//! handler body runs, so a foreign look-alike account is rejected at
//! deserialization. No raw data-borrow cast over an unverified-owner account remains.

use anchor_lang::prelude::*;

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Anchor enforces: owner == program_id AND discriminator matches.
    #[account(has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // `vault.authority` is trustworthy: the account was owner-checked.
    let _ = ctx.accounts.vault.balance;
    Ok(())
}
