//! SOL-024 vulnerable — oracle price read with no staleness/confidence check.
//!
//! `get_price_unchecked` returns the last posted price regardless of how old it
//! is or how wide its confidence interval is. During congestion or a feed
//! outage the price can be stale; an attacker times a borrow/liquidation around
//! the stale value to extract funds.
//!
//! Bug class: stale / over-confident oracle price — an unchecked read acts on a
//! price that may be far older, or wider-confidence, than the protocol tolerates.
//! (Distinct from oracle *manipulation* — e.g. Mango Markets ~$116M and Loopscale
//! ~$5.8M both moved the *reported* price via thin-market / flash-loan trades — a
//! staleness/confidence check does NOT stop manipulation; that needs a TWAP /
//! circuit-breaker.)

use anchor_lang::prelude::*;
use pyth_sdk_solana::state::SolanaPriceAccount;

#[derive(Accounts)]
pub struct Borrow<'info> {
    /// CHECK: pyth price account.
    pub price_feed: AccountInfo<'info>,
    pub user: Signer<'info>,
}

pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let feed = SolanaPriceAccount::account_info_to_feed(&ctx.accounts.price_feed)
        .map_err(|_| ErrorCode::BadFeed)?;
    // BUG: unchecked — ignores publish-slot age and confidence interval.
    let price = feed.get_price_unchecked();
    let collateral_value = (price.price as u64).saturating_mul(amount);
    msg!("collateral value = {}", collateral_value);
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("bad feed")]
    BadFeed,
}
