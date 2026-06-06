//! SOL-020 vulnerable — `set_authority` CPI with no current-authority check.
//!
//! The handler reassigns a token account's authority via a `set_authority` CPI
//! but never verifies the caller is the CURRENT authority. Any caller passes
//! the victim's token account and a `new_authority` of their choosing, seizing
//! control of the account.
//!
//! Bug class: authority transfer without verifying the existing authority.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, SetAuthority, Token, TokenAccount};
use anchor_spl::token::spl_token::instruction::AuthorityType;

#[derive(Accounts)]
pub struct Reassign<'info> {
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
    /// CHECK: BUG — used as the SetAuthority `current_authority` but never
    /// verified to equal token_account.owner.
    pub current: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}

pub fn reassign(ctx: Context<Reassign>, new_authority: Pubkey) -> Result<()> {
    // BUG: no check that `current` is the token account's existing authority.
    let cpi = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        SetAuthority {
            account_or_mint: ctx.accounts.token_account.to_account_info(),
            current_authority: ctx.accounts.current.clone(),
        },
    );
    token::set_authority(cpi, AuthorityType::AccountOwner, Some(new_authority))?;
    Ok(())
}
