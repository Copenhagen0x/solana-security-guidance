//! SOL-003 fixed — wrapper delegates to engine.
//!
//! The wrapper's job is to marshal accounts. The engine's job is to make
//! the state transitions. Delegation keeps the two in sync: when the engine
//! adds a new lifecycle term, every wrapper picks it up automatically.

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

// Engine entry point — the canonical close path. Wrappers MUST go through it.
mod engine {
    use super::Position;
    pub fn close(pos: &mut Position) -> Result<(), &'static str> {
        // [engine logic: on_close hooks, bankruptcy settlement, fee accrual,
        //  rebate distribution, ... — all the terms the wrapper would miss]
        if pos.size != 0 {
            return Err("cannot close — open size remains");
        }
        // [hook: notify subscribers]
        // [settlement: route negative PnL to insurance, positive PnL to claim queue]
        pos.status = 2;
        Ok(())
    }
}

pub fn handle_close_resolved(ctx: Context<HandleCloseResolved>) -> Result<()> {
    // FIX: wrapper just marshals + calls engine. Single source of truth.
    engine::close(&mut ctx.accounts.position)
        .map_err(|_| error!(ErrorCode::EngineRefused))?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("engine refused the close")]
    EngineRefused,
}
