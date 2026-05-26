//! SOL-005 vulnerable — Anchor account `realloc()` without guards.
//!
//! The handler calls `realloc()` based on caller-supplied size with no
//! upper bound, no rent-exemption check after the resize, and no
//! verification that the account belongs to this program.
//!
//! Real-world disclosure: Bounty 5 F12 (percolator-cli#78) — anchor
//! resize call without guards.

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ResizePortfolio<'info> {
    /// CHECK: vulnerable code reads `data_len` without verifying ownership.
    #[account(mut)]
    pub portfolio: AccountInfo<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn resize(
    ctx: Context<ResizePortfolio>,
    new_size: u64,            // ← caller-controlled
) -> Result<()> {
    // BUGS:
    //   1. no upper bound on `new_size` — caller passes u32::MAX, allocator
    //      blows out (compute-units exhausted / heap fragmentation)
    //   2. no `account.owner == program_id` check — could be wrong account
    //   3. no rent-exemption check after resize — account becomes purgeable
    ctx.accounts.portfolio.realloc(new_size as usize, true)?;
    Ok(())
}
