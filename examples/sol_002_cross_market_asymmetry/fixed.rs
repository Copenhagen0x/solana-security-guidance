//! SOL-002 fixed — per-market authority gates the shared counter write.
//!
//! Each market has its own PDA-derived authority. Writes to the shared
//! aggregate counter require (1) the caller is the market's signer-authority
//! AND (2) the market is on the pool's allowlist. Both checks together
//! eliminate the cross-market asymmetry.

use anchor_lang::prelude::*;

#[account]
pub struct SharedPool {
    pub insurance_fund: u64,
    pub pnl_pos_bound_tot: u64,
    pub market_allowlist: [Pubkey; 16],  // markets allowed to write
}

#[account]
pub struct Market {
    pub market_id: u32,
    pub authority: Pubkey,
}

#[derive(Accounts)]
pub struct UpdateCrossMarket<'info> {
    #[account(mut)]
    pub pool: Account<'info, SharedPool>,
    /// Anchor constraint enforces the market's authority IS the signer below.
    #[account(has_one = authority)]
    pub market: Account<'info, Market>,
    pub authority: Signer<'info>,
}

pub fn report_pnl_increment(
    ctx: Context<UpdateCrossMarket>,
    delta: u64,
) -> Result<()> {
    // Per-market authorization: only allowlisted markets may write.
    let market_key = ctx.accounts.market.key();
    if !ctx.accounts.pool.market_allowlist.contains(&market_key) {
        return err!(ErrorCode::MarketNotAllowed);
    }
    // The `has_one = authority` constraint already proved `market.authority`
    // matches the signer. Both checks together = per-market authorization.

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
    #[msg("market not on the allowlist for the shared pool")]
    MarketNotAllowed,
}
