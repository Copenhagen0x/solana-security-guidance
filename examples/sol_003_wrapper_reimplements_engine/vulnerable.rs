//! SOL-003 vulnerable — wrapper handler re-implements engine logic.
//!
//! The Solana program wrapper duplicates close/settle/accrue logic that
//! the engine library already exposes as a single call. Re-implementation
//! drifts from the engine, skips lifecycle hooks, and silently diverges
//! when the engine adds new spec terms.
//!
//! Real-world disclosure: Bounty 5 F1 (Critical, percolator-cli#78) —
//! wrapper's `handle_close_resolved` re-implemented close inline instead
//! of delegating to engine; positive-PnL stuck, hooks skipped, bankruptcy
//! unsettled.

use anchor_lang::prelude::*;

#[account]
pub struct Position {
    pub size: i64,
    pub pnl: i64,
    pub status: u8,
    pub owner: Pubkey,
}

#[derive(Accounts)]
pub struct HandleCloseResolved<'info> {
    #[account(mut)]
    pub position: Account<'info, Position>,
    pub authority: Signer<'info>,
}

pub fn handle_close_resolved(ctx: Context<HandleCloseResolved>) -> Result<()> {
    let pos = &mut ctx.accounts.position;
    // BUG: re-implements close logic inline.
    //   - misses the engine's `on_close` lifecycle hook
    //   - doesn't settle negative-PnL via the bankruptcy path
    //   - if the engine adds new fields, this drifts silently
    if pos.size == 0 {
        pos.status = 2; // "closed"
        pos.pnl = 0;
    }
    Ok(())
}
