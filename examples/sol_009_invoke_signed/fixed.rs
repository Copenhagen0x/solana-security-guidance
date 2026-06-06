//! SOL-009 fixed — verify the caller's authority for THIS vault, then sign.
//!
//! Before the `invoke_signed`, an Anchor `has_one = authority` constraint binds
//! the signing `caller` to the authority stored in this specific `vault`. A
//! caller who is not this vault's authority is rejected at account validation,
//! so the program's PDA signature is only ever applied on the owner's behalf.
//!
//! `invoke_signed` is still present (it is the legitimate mechanism) — the fix
//! is the authorization gate in front of it, which the SOL-009 exclusion #1
//! requires ("Signer + has_one/constraint binding the caller to the target").

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_spl::token::Token;

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct Drain<'info> {
    // has_one binds the SIGNING caller to THIS vault's stored authority.
    #[account(mut, has_one = authority, seeds = [b"vault", authority.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: destination, validated by program policy elsewhere.
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub authority: Signer<'info>,
    // Typed program account — Anchor enforces the key == the SPL Token program id.
    pub token_program: Program<'info, Token>,
}

pub fn drain(ctx: Context<Drain>, amount: u64) -> Result<()> {
    let authority_key = ctx.accounts.authority.key();
    let seeds: &[&[u8]] = &[b"vault", authority_key.as_ref(), &[ctx.accounts.vault.bump]];
    let ix = Instruction { program_id: ctx.accounts.token_program.key(), accounts: vec![], data: amount.to_le_bytes().to_vec() };
    invoke_signed(&ix, &[ctx.accounts.vault.to_account_info(), ctx.accounts.destination.clone()], &[seeds])?;
    Ok(())
}
