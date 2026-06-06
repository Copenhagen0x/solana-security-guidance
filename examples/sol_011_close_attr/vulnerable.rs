//! SOL-011 vulnerable — `close =` to a caller-chosen destination.
//!
//! The account is closed with its lamports swept to `destination`, an
//! attacker-supplied `AccountInfo`. The caller closes someone else's escrow
//! and redirects the reclaimed rent (and any residual balance) to themselves.
//! There is also no check that token balances were drained first.
//!
//! Bug class: account-close with attacker-controlled lamport destination.

use anchor_lang::prelude::*;

#[account]
pub struct Escrow {
    pub owner: Pubkey,
    pub amount: u64,
}

#[derive(Accounts)]
pub struct CloseEscrow<'info> {
    // BUG: lamports go to a caller-supplied account, and `escrow` is not bound
    // to the signer (no has_one), so anyone can close anyone's escrow.
    #[account(mut, close = destination)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: BUG — attacker-chosen lamport sink.
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub caller: Signer<'info>,
}

pub fn close_escrow(_ctx: Context<CloseEscrow>) -> Result<()> {
    Ok(())
}
