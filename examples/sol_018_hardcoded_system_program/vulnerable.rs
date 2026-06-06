//! SOL-018 vulnerable — System Program id as a raw all-ones string literal.
//!
//! The handler compares the system program account to the literal
//! "11111111111111111111111111111111" instead of the typed
//! `system_program::ID`. A typo silently disables the check, and the
//! stringly-typed comparison is brittle and easy to get subtly wrong.
//!
//! Bug class: hardcoded program id (hygiene; low severity).

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Init<'info> {
    /// CHECK: compared to a raw literal below (the bug).
    pub system_program: AccountInfo<'info>,
    pub payer: Signer<'info>,
}

pub fn init(ctx: Context<Init>) -> Result<()> {
    // BUG: raw-literal comparison instead of system_program::ID.
    require!(
        ctx.accounts.system_program.key().to_string()
            == "11111111111111111111111111111111",
        ErrorCode::WrongProgram
    );
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("wrong system program")]
    WrongProgram,
}
