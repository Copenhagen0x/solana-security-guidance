use anchor_lang::prelude::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Flags {
    pub is_admin: bool,   // 1 byte + 7 bytes implicit padding before the u64
    pub epoch: u64,
}

// BUG: hand-written Pod over a layout with a bool + padding. The real derive would
// reject the bool field; this hand impl silently asserts the type is Pod.
unsafe impl bytemuck::Zeroable for Flags {}
unsafe impl bytemuck::Pod for Flags {}

#[derive(Accounts)]
pub struct Gate<'info> {
    /// CHECK: raw config buffer, reinterpreted below (the bug).
    pub config: AccountInfo<'info>,
    pub caller: Signer<'info>,
}

pub fn privileged(ctx: Context<Gate>) -> Result<()> {
    let data = ctx.accounts.config.try_borrow_data()?;
    // BUG: typed cast with no canonical-value check; ANY non-zero byte reads admin.
    let flags: &Flags = bytemuck::from_bytes(&data[..core::mem::size_of::<Flags>()]);
    if flags.is_admin {
        msg!("admin path entered");
    }
    Ok(())
}
