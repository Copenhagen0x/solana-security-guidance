//! SOL-009 vulnerable — `invoke_signed` with no caller-authority check.
//!
//! The handler signs a token transfer out of a program-owned vault PDA using
//! `invoke_signed`, but never verifies the caller is authorized for THIS vault.
//! Any caller invokes it and the program's own PDA signature moves someone
//! else's funds.
//!
//! Bug class: confused-deputy CPI — the program's signing authority is applied
//! without binding the caller to the resource being acted on.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::solana_program::instruction::Instruction;

#[derive(Accounts)]
pub struct Drain<'info> {
    /// CHECK: vault PDA, signed for below.
    #[account(mut)]
    pub vault: AccountInfo<'info>,
    /// CHECK: destination chosen by the caller.
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub caller: Signer<'info>,
    /// CHECK: token program.
    pub token_program: AccountInfo<'info>,
}

pub fn drain(ctx: Context<Drain>, amount: u64, bump: u8) -> Result<()> {
    // BUG: no Signer + has_one/constraint binding `caller` to this vault's
    // stored authority BEFORE we sign. The PDA seed is unconditional.
    let ix = Instruction { program_id: *ctx.accounts.token_program.key, accounts: vec![], data: amount.to_le_bytes().to_vec() };
    let seeds: &[&[u8]] = &[b"vault", &[bump]];
    invoke_signed(&ix, &[ctx.accounts.vault.clone(), ctx.accounts.destination.clone()], &[seeds])?;
    Ok(())
}
