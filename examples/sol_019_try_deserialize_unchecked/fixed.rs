//! SOL-019 fixed — typed `Account<>` (or `try_deserialize`) checks the discriminator.
//!
//! `order` is an Anchor `Account<'info, Order>`, which verifies the 8-byte
//! discriminator (and the owner) before the handler runs — a foreign account
//! type is rejected. The unchecked deserialize call is gone; if a manual
//! deserialize were needed, `Order::try_deserialize` (with the discriminator
//! check) would be used instead.

use anchor_lang::prelude::*;

#[account]
pub struct Order {
    pub maker: Pubkey,
    pub price: u64,
}

#[derive(Accounts)]
pub struct Fill<'info> {
    pub order: Account<'info, Order>,
    pub taker: Signer<'info>,
}

pub fn fill(ctx: Context<Fill>) -> Result<()> {
    msg!("price = {}", ctx.accounts.order.price);
    Ok(())
}
