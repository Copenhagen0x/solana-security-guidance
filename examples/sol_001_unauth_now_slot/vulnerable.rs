//! SOL-001 vulnerable — caller-controlled `now_slot`.
//!
//! The handler accepts `now_slot` as an instruction-data argument and stamps
//! it directly into market state. A permissionless caller can pass
//! `u64::MAX` and freeze the market: subsequent permissionless cranks see
//! `current_slot > now()` and reject as "not yet matured" — permanent DoS.
//!
//! Real-world disclosure: percolator-prog#107 (Bounty 6 H2, closed/fixed).

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct ActivateAsset<'info> {
    #[account(mut)]
    pub market: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub fn activate(
    ctx: Context<ActivateAsset>,
    asset_id: u32,
    now_slot: u64,            // ← attacker-controlled
) -> Result<()> {
    let mut market = ctx.accounts.market.try_borrow_mut_data()?;
    // BUG: caller-supplied `now_slot` written into trusted state.
    market[asset_id as usize..asset_id as usize + 8]
        .copy_from_slice(&now_slot.to_le_bytes());
    Ok(())
}
