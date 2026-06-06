//! SOL-024 fixed — staleness window + confidence bound, with a safe price cast.
//!
//! `get_price_no_older_than` rejects a price older than a bounded staleness
//! window (here 60s — a real tolerance, not u64::MAX). The price is verified
//! POSITIVE before any cast (a negative `i64` must never be reinterpreted as
//! `u64`), and the confidence interval is checked with a cross-multiplied bound
//! so a small price cannot round the bound down to zero. No unchecked read remains.
//!
//! NOTE: staleness + confidence guard against a STALE or UNCERTAIN feed — they
//! do NOT defend against oracle *manipulation* (e.g. pumping a thin spot market,
//! as in Mango Markets). That needs a TWAP / circuit-breaker, out of scope here.
//! Real code must also verify `price_feed.key()` equals the expected feed pubkey.

use anchor_lang::prelude::*;
use pyth_sdk_solana::state::SolanaPriceAccount;

// Real staleness tolerance for the protocol — not an unbounded value.
const MAX_PRICE_AGE_SECS: u64 = 60;
// Reject if the confidence interval exceeds 1% (100 bps) of the price.
const MAX_CONF_BPS: u128 = 100;

#[derive(Accounts)]
pub struct Borrow<'info> {
    /// CHECK: pyth price account (real code must also verify this key == expected feed).
    pub price_feed: AccountInfo<'info>,
    pub user: Signer<'info>,
}

pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let feed = SolanaPriceAccount::account_info_to_feed(&ctx.accounts.price_feed)
        .map_err(|_| ErrorCode::BadFeed)?;
    let now = Clock::get()?.unix_timestamp;
    // Staleness: bounded age window.
    let price = feed
        .get_price_no_older_than(now, MAX_PRICE_AGE_SECS)
        .ok_or(ErrorCode::StalePrice)?;
    // Never reinterpret a negative i64 price as u64 — reject non-positive prices.
    let price_mag = u64::try_from(price.price).map_err(|_| ErrorCode::NonPositivePrice)?;
    require!(price_mag > 0, ErrorCode::NonPositivePrice);
    // Confidence: reject if conf exceeds MAX_CONF_BPS of the price. Cross-multiply
    // in u128 so a small price can't round the bound down to zero.
    require!(
        (price.conf as u128) * 10_000 <= (price_mag as u128) * MAX_CONF_BPS,
        ErrorCode::PriceTooUncertain
    );

    // checked_mul (not saturating) on the financial path — abort on overflow
    // rather than silently capping the collateral value at u64::MAX.
    let collateral_value = price_mag.checked_mul(amount).ok_or(ErrorCode::Overflow)?;
    msg!("collateral value = {}", collateral_value);
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("bad feed")]
    BadFeed,
    #[msg("oracle price is stale")]
    StalePrice,
    #[msg("oracle price is non-positive")]
    NonPositivePrice,
    #[msg("oracle price confidence too wide")]
    PriceTooUncertain,
    #[msg("arithmetic overflow")]
    Overflow,
}
