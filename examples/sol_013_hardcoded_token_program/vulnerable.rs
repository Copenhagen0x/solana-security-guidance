//! SOL-013 vulnerable — hardcoded SPL Token program id as a raw string.
//!
//! The handler "validates" the token program by comparing its key to a raw
//! base-58 literal. A typo, a Token-2022 mint, or an attacker-supplied program
//! that the string check is bypassed for all slip through — and the literal
//! pins the program to legacy SPL Token even when the mint requires token-2022.
//!
//! Bug class: unverified / hardcoded program id instead of the typed constant.

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Transfer<'info> {
    /// CHECK: compared to a raw literal below (the bug).
    pub token_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub fn transfer(ctx: Context<Transfer>) -> Result<()> {
    // BUG: raw-literal program-id check instead of anchor_spl::token::ID.
    let expected = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    require!(
        ctx.accounts.token_program.key().to_string() == expected,
        ErrorCode::WrongProgram
    );
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("wrong token program")]
    WrongProgram,
}
