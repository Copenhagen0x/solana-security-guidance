//! SOL-010 fixed — one-time `init`, so a second call fails instead of resetting.
//!
//! `position` is declared with Anchor `init` (not the re-init variant). A second
//! call on the same PDA fails at account creation ("already in use"), so the
//! balance/owner can never be silently reset. The re-init smell is gone.
//!
//! If a create-or-update flow genuinely needs both paths, split them into two
//! instructions: `init` once, and a separate `update` that loads the existing
//! `Account<>` (which carries an owner check) and mutates it.

use anchor_lang::prelude::*;

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub balance: u64,
}

#[derive(Accounts)]
pub struct OpenPosition<'info> {
    // init (one-time): a second call on the same PDA aborts, never resets.
    #[account(init, payer = user, space = 8 + 32 + 8, seeds = [b"pos", user.key().as_ref()], bump)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn open_position(ctx: Context<OpenPosition>) -> Result<()> {
    ctx.accounts.position.owner = ctx.accounts.user.key();
    ctx.accounts.position.balance = 0;
    Ok(())
}
