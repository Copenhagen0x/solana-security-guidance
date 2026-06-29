//! SOL-042 vulnerable - unbounded loop over caller-controlled remaining_accounts.
//! With no per-call cap, an attacker pads remaining_accounts until the tx exceeds
//! the ~1.4M compute-unit limit and EVERY call reverts (permanent DoS).
use anchor_lang::prelude::*;

pub fn settle(ctx: Context<Settle>) -> Result<()> {
    // BUG: no length cap - the trip count is attacker-controlled.
    for acc in ctx.remaining_accounts {
        let data = acc.try_borrow_data()?;
        msg!("processed {}", data.len());
    }
    Ok(())
}

#[derive(Accounts)]
pub struct Settle<'info> { pub authority: Signer<'info> }
