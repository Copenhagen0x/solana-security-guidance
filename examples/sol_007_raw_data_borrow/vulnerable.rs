//! SOL-007 vulnerable — deserialize raw account bytes with no owner check.
//!
//! The handler casts `&*vault.data.borrow()` straight into a typed view and
//! trusts the `authority` field — without ever checking that `vault` is owned
//! by this program. An attacker passes a look-alike account they fully control
//! (owned by a program they wrote), sets `authority` to themselves, and drains.
//!
//! Bug class: missing account-owner validation — the Cashio infinite-mint
//! root cause ($52M): a fake collateral account passed the type checks.

use anchor_lang::prelude::*;

#[repr(C)]
pub struct VaultView {
    pub authority: Pubkey,
    pub balance: u64,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: BUG — owner is never compared to program_id before the cast.
    pub vault: AccountInfo<'info>,
    pub caller: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    let raw = &*ctx.accounts.vault.data.borrow();
    // BUG: raw bytes from an unverified-owner account, trusted as state.
    let view = unsafe { &*(raw.as_ptr() as *const VaultView) };
    require_keys_eq!(view.authority, ctx.accounts.caller.key());
    Ok(())
}
