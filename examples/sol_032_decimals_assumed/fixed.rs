// SOL-032 (fixed): read the scale from the mint itself — `mint.decimals` is
// fixed at initializeMint and cannot change, so normalizing against it is
// always correct regardless of which mint the caller deposits.
use anchor_lang::prelude::*;

pub fn quote_collateral(ctx: Context<Quote>, raw_amount: u64, price_usd_6: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    // FIX: derive the scale from the deposit mint's own on-chain decimals.
    let scale = 10u64
        .checked_pow(ctx.accounts.deposit_mint.decimals as u32)
        .ok_or(error!(QuoteError::Overflow))?;
    let value_usd_6 = raw_amount
        .checked_mul(price_usd_6)
        .ok_or(error!(QuoteError::Overflow))?
        / scale;
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
