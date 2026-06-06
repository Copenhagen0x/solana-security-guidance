//! SOL-011 fixed — close only the owner's escrow, lamports to the owner.
//!
//! `has_one = owner` binds the SIGNING `owner` to this escrow, so only the real
//! owner can close it. `close = owner` sends the reclaimed lamports back to that
//! signer, not to a caller-chosen sink. (A token balance, if any, would be
//! transferred out in a prior step — the struct here holds only lamports.)
//!
//! The `close =` attribute is still present — it is the correct Anchor close
//! mechanism. The fix is the `has_one` binding + a trusted destination, which
//! is what the SOL-011 exclusions require; the scanner tripwire is cleared by
//! exclusion, not by removing the close.

use anchor_lang::prelude::*;

#[account]
pub struct Escrow {
    pub owner: Pubkey,
    pub amount: u64,
}

#[derive(Accounts)]
pub struct CloseEscrow<'info> {
    // Bound to the signer; lamports returned to the owner, not an attacker.
    #[account(mut, has_one = owner, close = owner)]
    pub escrow: Account<'info, Escrow>,
    pub owner: Signer<'info>,
}

pub fn close_escrow(_ctx: Context<CloseEscrow>) -> Result<()> {
    Ok(())
}
