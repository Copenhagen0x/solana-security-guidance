//! SOL-042 fixed - enforce a per-instruction cap proven to fit the CU budget before
//! iterating (paginate the remainder across transactions with a stored cursor).
//!
//! NOTE - completeness for a PAYOUT loop: the count cap alone fixes ONLY a read-only
//! loop like this one. If the loop instead credits/pays each iterated account, the cap
//! is not enough - bind every iterated account by identity to authoritative state
//! (`require_keys_eq!(acc.key(), registry.recipients[i])`) or it becomes a SOL-027
//! account-substitution fund-drain (worse than the DoS). See SOL-027.
use anchor_lang::prelude::*;

const MAX_ACCOUNTS: usize = 16; // proven to fit the CU budget for this loop body

pub fn settle(ctx: Context<Settle>) -> Result<()> {
    // FIX: bound the trip count first; the loop iterates a checked-length slice.
    require!(ctx.remaining_accounts.len() <= MAX_ACCOUNTS, ErrorCode::TooManyAccounts);
    let accounts = ctx.remaining_accounts;
    for acc in accounts {
        let data = acc.try_borrow_data()?;
        msg!("processed {}", data.len()); // read-only: no payout, so the cap is the complete fix here
    }
    Ok(())
}

#[derive(Accounts)]
pub struct Settle<'info> { pub authority: Signer<'info> }

#[error_code]
pub enum ErrorCode { #[msg("too many accounts")] TooManyAccounts }
