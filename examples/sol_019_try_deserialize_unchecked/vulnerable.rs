//! SOL-019 vulnerable — `try_deserialize_unchecked` skips the discriminator.
//!
//! The handler manually deserializes the account with
//! `try_deserialize_unchecked`, which does NOT verify the 8-byte Anchor
//! discriminator. An attacker passes a different account type whose bytes
//! happen to fit `Order`'s layout (type confusion), and the program treats it
//! as a valid order.
//!
//! Bug class: missing discriminator check (account type confusion).

use anchor_lang::prelude::*;

#[account]
pub struct Order {
    pub maker: Pubkey,
    pub price: u64,
}

#[derive(Accounts)]
pub struct Fill<'info> {
    /// CHECK: deserialized unchecked below (the bug).
    pub order: AccountInfo<'info>,
    pub taker: Signer<'info>,
}

pub fn fill(ctx: Context<Fill>) -> Result<()> {
    let data = ctx.accounts.order.try_borrow_data()?;
    // BUG: no discriminator check — any same-size account is accepted.
    let order = Order::try_deserialize_unchecked(&mut &data[..])?;
    msg!("price = {}", order.price);
    Ok(())
}
