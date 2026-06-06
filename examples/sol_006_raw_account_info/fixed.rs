//! SOL-006 fixed — bind a real `Signer<>` to the stored admin key.
//!
//! `admin` is now a `Signer<'info>` (the runtime enforces the signature) AND
//! an Anchor `has_one = admin` constraint binds that signer to the key stored
//! in `config`. A caller who is not the current admin cannot satisfy both.
//!
//! Note: no raw account-info type for the privileged caller — the scanner smell
//! is gone because the typed Signer now carries the authorization guarantee.

use anchor_lang::prelude::*;

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub paused: bool,
}

#[derive(Accounts)]
pub struct SetPaused<'info> {
    #[account(mut, has_one = admin)]
    pub config: Account<'info, Config>,
    // Must SIGN, and `has_one = admin` binds this signer to config.admin.
    pub admin: Signer<'info>,
}

pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
    ctx.accounts.config.paused = paused;
    Ok(())
}
