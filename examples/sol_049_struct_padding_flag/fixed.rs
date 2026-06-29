use anchor_lang::prelude::*;

// crate::ID is your program's declared ID (from declare_id!); the owner constraint
// pins each buffer to THIS program. (No declare_id! literal — use your real ID.)

#[account(zero_copy)]
#[repr(C)]
pub struct Flags {
    pub is_admin: u8,        // canonical 0/1, validated on every load
    pub _reserved: [u8; 7],  // named padding, zeroed on init/write, zero-checked on load
    pub authority: Pubkey,   // the ONLY key allowed to flip is_admin (bound via has_one)
    pub epoch: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8 + core::mem::size_of::<Flags>())]
    pub config: AccountLoader<'info, Flags>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    let mut flags = ctx.accounts.config.load_init()?;
    flags.is_admin = 0;          // canonical
    flags._reserved = [0u8; 7];  // padding zeroed at creation
    // MUST set authority — else it stays Pubkey::default() and set_admin is uncallable.
    // Production: use a durable authority (multisig / upgrade authority) and add a
    // transfer_authority instruction; authority is otherwise locked to this payer.
    flags.authority = ctx.accounts.payer.key();
    Ok(())
}

// Decommission: a real program adds a CloseConfig instruction whose `config` carries
// Anchor's close + has_one constraints (drain, then close to a controlled authority) to
// reclaim rent; a zero_copy account with no close path is un-closeable without manual
// lamport draining (SOL-011).

#[derive(Accounts)]
pub struct SetAdmin<'info> {
    // has_one = authority binds config.authority == authority.key(): ONLY the stored
    // admin authority (a signer) can flip is_admin. Without this binding ANY signer
    // could grant themselves admin — the access-control gap this example must not teach.
    #[account(mut, owner = crate::ID, has_one = authority)]
    pub config: AccountLoader<'info, Flags>,
    pub authority: Signer<'info>,
}

pub fn set_admin(ctx: Context<SetAdmin>, new_is_admin: u8) -> Result<()> {
    // Write-side canonicalization: never store a byte the load check would reject.
    require!(new_is_admin <= 1, ErrorCode::NonCanonicalFlag);
    let mut flags = ctx.accounts.config.load_mut()?;
    flags.is_admin = new_is_admin;
    Ok(())
}

#[derive(Accounts)]
pub struct Gate<'info> {
    // Owner check + the canonical check below are JOINTLY required — canonicalization
    // alone is bypassable if an attacker supplies a foreign account whose byte[0] is
    // already 0x01. AccountLoader::load also validates the 8-byte discriminator.
    // SCOPE NOTE: this minimal example does not pin `config` to a canonical address, so a
    // caller can pass any program-owned Flags account they control (bring-your-own-
    // config, SOL-048) — `caller` is NOT a present guard. A real privileged path should
    // pin config by address (or bind `caller` to a stored authority); here the focus is
    // flag canonicalization.
    #[account(owner = crate::ID)]
    pub config: AccountLoader<'info, Flags>,
    pub caller: Signer<'info>,
}

pub fn privileged(ctx: Context<Gate>) -> Result<()> {
    let flags = ctx.accounts.config.load()?;
    // Canonicalize on EVERY load: reject any non-{0,1} flag and any non-zero reserved
    // byte, then branch on the EXACT value (== 1), never != 0.
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
