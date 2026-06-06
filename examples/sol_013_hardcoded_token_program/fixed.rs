//! SOL-013 fixed — typed `Program<Token>` account, no raw literal.
//!
//! Declaring `token_program: Program<'info, Token>` makes Anchor enforce the
//! account's key equals the canonical `anchor_spl::token::ID` at validation
//! time — type-safe, no stringly-typed comparison, and trivially switchable to
//! `Token2022` where required. The base-58 literal is gone.

use anchor_lang::prelude::*;
use anchor_spl::token::Token;

#[derive(Accounts)]
pub struct Transfer<'info> {
    // Anchor checks token_program.key() == anchor_spl::token::ID.
    pub token_program: Program<'info, Token>,
    pub authority: Signer<'info>,
}

pub fn transfer(_ctx: Context<Transfer>) -> Result<()> {
    Ok(())
}
