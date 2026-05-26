//! SOL-002 vulnerable — cross-market state asymmetry.
//!
//! Multiple markets share a single aggregate counter (e.g. an insurance
//! fund pool, a cross-market PnL bound). Each market's handler can write
//! to the shared field without verifying the write is gated by per-market
//! authority. A permissionless caller on Market A can inflate the counter
//! used by Market B, draining the shared pool.
//!
//! Real-world disclosure class: the `pnl_pos_bound_tot` inflation pattern
//! used to win Bounty 5 primary (insurance fund 50025 → 25 atoms).

use anchor_lang::prelude::*;

#[account]
pub struct SharedPool {
    pub insurance_fund: u64,         // shared across ALL markets
    pub pnl_pos_bound_tot: u64,      // ← the cross-market counter
    pub authority: Pubkey,
}

#[derive(Accounts)]
pub struct UpdateCrossMarket<'info> {
    #[account(mut)]
    pub pool: Account<'info, SharedPool>,
    /// Market that's reporting — no constraint linking it to `pool.authority`
    /// or any per-market allowlist.
    pub market: AccountInfo<'info>,
    pub caller: Signer<'info>,       // anyone can sign here
}

pub fn report_pnl_increment(
    ctx: Context<UpdateCrossMarket>,
    delta: u64,
) -> Result<()> {
    // BUG: anyone holding any market account can inflate the shared counter.
    // No check that `market` is on an allowlist, no check that the caller
    // is the market's authority, no per-market scoping at all.
    ctx.accounts.pool.pnl_pos_bound_tot =
        ctx.accounts.pool.pnl_pos_bound_tot
            .checked_add(delta)
            .ok_or(ErrorCode::Overflow)?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("overflow")]
    Overflow,
}
