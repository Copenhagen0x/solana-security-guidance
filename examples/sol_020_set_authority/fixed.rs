//! SOL-020 fixed — bind the signing authority to the account's current owner.
//!
//! `current` is now a `Signer<'info>`, and a `constraint = token_account.owner
//! == current.key()` binds that signer to the account's CURRENT authority. A
//! caller who is not the present owner cannot satisfy the constraint, so the
//! `set_authority` CPI only runs for the legitimate authority.
//!
//! The `set_authority` call remains — it is the legitimate operation. The fix is
//! the current-authority binding the SOL-020 exclusion #2 requires (a Signer<>
//! bound to the stored authority, not a bare/unbound account).

use anchor_lang::prelude::*;
use anchor_spl::token::{self, SetAuthority, Token, TokenAccount};
use anchor_spl::token::spl_token::instruction::AuthorityType;

#[derive(Accounts)]
pub struct Reassign<'info> {
    #[account(mut, constraint = token_account.owner == current.key())]
    pub token_account: Account<'info, TokenAccount>,
    // Must SIGN and be the account's current authority.
    pub current: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

pub fn reassign(ctx: Context<Reassign>, new_authority: Pubkey) -> Result<()> {
    let cpi = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        SetAuthority {
            account_or_mint: ctx.accounts.token_account.to_account_info(),
            current_authority: ctx.accounts.current.to_account_info(),
        },
    );
    token::set_authority(cpi, AuthorityType::AccountOwner, Some(new_authority))?;
    Ok(())
}
