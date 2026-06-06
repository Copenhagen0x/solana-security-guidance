//! SOL-006 vulnerable — privileged handler trusts a raw `AccountInfo` caller.
//!
//! `admin` is a bare `AccountInfo<'info>`: the handler never checks
//! `admin.is_signer`, so ANY account passed in that slot is accepted as the
//! admin. A permissionless caller hands in the real admin's pubkey (public
//! information) without its signature and flips the protocol's pause flag.
//!
//! Bug class: missing signer authorization — the same omission behind a long
//! line of Solana account-validation exploits (e.g. Cashio, $52M).

use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SetPaused<'info> {
    #[account(mut)]
    pub config: AccountInfo<'info>,
    /// CHECK: BUG — never verified as a signer or against a stored admin key.
    pub admin: AccountInfo<'info>,
}

pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
    // BUG: no `ctx.accounts.admin.is_signer` assertion and no key binding.
    // The caller supplies any `admin` account; authorization is a no-op.
    let mut data = ctx.accounts.config.try_borrow_mut_data()?;
    data[0] = paused as u8;
    Ok(())
}
