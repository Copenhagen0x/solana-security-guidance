//! SOL-046 fixed - dispatch via Anchor's #[program] macro, so every account is
//! validated by the generated discriminator + #[account(...)] constraints. The full
//! pattern includes the `initialize` that CREATES `config` and sets `admin` at init,
//! so `set_admin`'s `has_one = admin` guard is satisfiable (avoiding the SOL-048
//! zero-default-admin trap a bare example would invite).
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>, admin: Pubkey) -> Result<()> {
        ctx.accounts.config.admin = admin; // set at init - never left as Pubkey::default()
        Ok(())
    }
    // FIX: set_admin runs through #[derive(Accounts)] - the has_one + Signer guards
    // are enforced before the body, so no unvalidated account can reach it.
    pub fn set_admin(ctx: Context<SetAdmin>, new_admin: Pubkey) -> Result<()> {
        ctx.accounts.config.admin = new_admin;
        Ok(())
    }
}

#[account]
pub struct Config { pub admin: Pubkey }

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8 + 32, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(mut)] pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetAdmin<'info> {
    #[account(mut, seeds = [b"config"], bump, has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}
