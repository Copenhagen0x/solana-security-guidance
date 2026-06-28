//! SOL-051 vulnerable - lottery winner seeded from on-chain unix_timestamp.
//! unix_timestamp is public + leader-steerable: the submitter simulates and only
//! sends when they win, so the prize is deterministically claimable.
use anchor_lang::prelude::*;

pub fn draw(ctx: Context<Draw>) -> Result<()> {
    let players = &ctx.accounts.pool.players;
    // BUG: on-chain value used as randomness - not secret.
    let winner = Clock::get()?.unix_timestamp as usize % players.len();
    ctx.accounts.pool.winner = players[winner];
    Ok(())
}

#[account]
pub struct Pool { pub players: Vec<Pubkey>, pub winner: Pubkey }

#[derive(Accounts)]
pub struct Draw<'info> { #[account(mut)] pub pool: Account<'info, Pool> }
