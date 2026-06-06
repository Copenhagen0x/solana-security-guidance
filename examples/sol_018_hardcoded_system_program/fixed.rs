//! SOL-018 fixed — typed `Program<System>`, no raw literal.
//!
//! Declaring `system_program: Program<'info, System>` makes Anchor enforce the
//! key equals the canonical `system_program::ID`. The all-ones string literal
//! is gone.

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Init<'info> {
    pub system_program: Program<'info, System>,
    pub payer: Signer<'info>,
}

pub fn init(_ctx: Context<Init>) -> Result<()> {
    Ok(())
}
