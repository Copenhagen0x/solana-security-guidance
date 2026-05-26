//! SOL-005 fixed — owner check + size bound + rent-exemption guard.

use anchor_lang::prelude::*;

const MAX_PORTFOLIO_SIZE: u64 = 10_240; // 10 KB hard cap

#[derive(Accounts)]
pub struct ResizePortfolio<'info> {
    /// CHECK: verified manually below.
    #[account(mut)]
    pub portfolio: AccountInfo<'info>,
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn resize(
    ctx: Context<ResizePortfolio>,
    new_size: u64,
) -> Result<()> {
    // 1. Owner check — account must belong to this program.
    require_keys_eq!(
        *ctx.accounts.portfolio.owner,
        *ctx.program_id,
        ErrorCode::WrongOwner
    );

    // 2. Size bound — refuse caller-supplied sizes above the program cap.
    require!(new_size <= MAX_PORTFOLIO_SIZE, ErrorCode::SizeExceedsCap);

    // 3. Rent-exemption check — refuse if the post-resize lamports are
    //    below the rent floor (account would be purged by the runtime).
    let rent = Rent::get()?;
    let required_lamports = rent.minimum_balance(new_size as usize);
    require!(
        ctx.accounts.portfolio.lamports() >= required_lamports,
        ErrorCode::RentExemptionLost
    );

    ctx.accounts.portfolio.realloc(new_size as usize, true)?;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("portfolio account is owned by the wrong program")]
    WrongOwner,
    #[msg("requested size exceeds the per-program cap")]
    SizeExceedsCap,
    #[msg("rent-exemption invariant would be violated by this resize")]
    RentExemptionLost,
}
