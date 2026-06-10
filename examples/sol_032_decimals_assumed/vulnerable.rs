// SOL-032 (vulnerable): the price math assumes every mint has 6 decimals.
// Quote a 9-decimals token through this and the value is off by 1000x —
// deposits credited 1000x high, or collateral valued 1000x low (drain class).
// Review-only rule: the scanner cannot tell a token scale from any other
// constant, so this class is caught in review — see the rule's exclusions.
use anchor_lang::prelude::*;

const ASSUMED_SCALE: u64 = 1_000_000; // "all our tokens are 6 decimals"... until one isn't

pub fn quote_collateral(ctx: Context<Quote>, raw_amount: u64, price_usd_6: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    // BUG: raw_amount is in the deposit mint's native units. If that mint has
    // 9 decimals (SOL-wrapped, many LSTs), this values it 1000x off.
    let value_usd_6 = raw_amount
        .checked_mul(price_usd_6)
        .ok_or(error!(QuoteError::Overflow))?
        / ASSUMED_SCALE;
    vault.credited_usd_6 = vault
        .credited_usd_6
        .checked_add(value_usd_6)
        .ok_or(error!(QuoteError::Overflow))?;
    Ok(())
}

#[derive(Accounts)]
pub struct Quote<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    // The deposit mint is RIGHT THERE — its decimals are never read.
    pub deposit_mint: Account<'info, anchor_spl::token::Mint>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub credited_usd_6: u64,
}

#[error_code]
pub enum QuoteError {
    Overflow,
}
