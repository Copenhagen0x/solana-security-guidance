use anchor_lang::prelude::*;

#[account(zero_copy)]
#[repr(C)]
pub struct Flags {
    pub is_admin: u8,        // canonical 0/1, validated on every load
    pub _reserved: [u8; 7],  // named padding, zero-checked on load
    pub epoch: u64,
}

#[derive(Accounts)]
pub struct Gate<'info> {
    #[account(owner = crate::ID)]
    pub config: AccountLoader<'info, Flags>,
    pub caller: Signer<'info>,
}

pub fn privileged(ctx: Context<Gate>) -> Result<()> {
    // AccountLoader::load validates owner + discriminator (typed, length-checked).
    let flags = ctx.accounts.config.load()?;
    // Canonicalize on EVERY load: reject any non-{0,1} flag byte and any non-zero
    // reserved byte, then branch on the EXACT value (== 1), never != 0.
    require!(flags.is_admin <= 1, ErrorCode::NonCanonicalFlag);
    require!(flags._reserved == [0u8; 7], ErrorCode::NonCanonicalFlag);
    if flags.is_admin == 1 {
        msg!("admin path entered");
    }
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("non-canonical flag or reserved byte")]
    NonCanonicalFlag,
}
