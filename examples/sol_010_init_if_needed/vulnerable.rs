//! SOL-010 vulnerable — `init_if_needed` on a value-bearing account.
//!
//! The `position` PDA holds a token `balance` and an `owner`. Because it is
//! declared `init_if_needed`, calling the handler a second time on an existing
//! position silently RE-RUNS initialization, resetting `balance`/`owner` to the
//! handler's defaults — wiping the prior owner's accounting or re-opening a
//! closed position an attacker can re-seed.
//!
//! Bug class: re-initialization / state reset (the init_if_needed footgun).

use anchor_lang::prelude::*;

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub balance: u64,
}

#[derive(Accounts)]
pub struct OpenPosition<'info> {
    // BUG: init_if_needed re-runs on an already-initialized account; a second
    // call resets balance/owner with no already-initialized guard.
    #[account(init_if_needed, payer = user, space = 8 + 32 + 8, seeds = [b"pos", user.key().as_ref()], bump)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn open_position(ctx: Context<OpenPosition>) -> Result<()> {
    ctx.accounts.position.owner = ctx.accounts.user.key();
    ctx.accounts.position.balance = 0; // BUG: clobbers an existing balance
    Ok(())
}
