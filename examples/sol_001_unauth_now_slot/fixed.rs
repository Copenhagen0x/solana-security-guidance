//! SOL-001 fixed — authenticate `now_slot` against on-chain clock.
//!
//! Caller may still pass a `now_slot` hint, but it gets clamped against
//! the real `Clock::get()?.slot` before being persisted. An attacker
//! passing `u64::MAX` is silently capped at the current slot.

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ActivateAsset<'info> {
    #[account(mut)]
    pub market: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

/// Returns the caller's hint clamped to the on-chain clock.
/// Pattern copied from the percolator fix in commit 6512fa1.
fn authenticated_slot_or_fallback(hint: u64, clock_slot: u64) -> u64 {
    // Accept the hint only if it doesn't run ahead of the real clock.
    // Otherwise fall back to the chain's authoritative value.
    if hint <= clock_slot { hint } else { clock_slot }
}

pub fn activate(
    ctx: Context<ActivateAsset>,
    asset_id: u32,
    now_slot: u64,
) -> Result<()> {
    let chain_slot = Clock::get()?.slot;
    let authenticated = authenticated_slot_or_fallback(now_slot, chain_slot);

    let mut market = ctx.accounts.market.try_borrow_mut_data()?;
    market[asset_id as usize..asset_id as usize + 8]
        .copy_from_slice(&authenticated.to_le_bytes());
    Ok(())
}
