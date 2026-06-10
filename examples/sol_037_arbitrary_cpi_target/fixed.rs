// SOL-037 (fixed): pin BOTH the callee program AND the accounts it's handed.
// (1) the target program id is asserted == the expected, program-stored constant,
// so an attacker-supplied program is rejected (equivalently: a typed Anchor
// `Program<'info, ThatProgram>`). (2) the destination account in the CPI metas is
// validated against stored state — pinning the program alone is NOT enough: a CPI
// to the RIGHT program with an attacker-substituted `to` account (especially under
// invoke_signed carrying this program's PDA authority) is still a confused-deputy
// drain (see SOL-027 for the account validation).
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke,
};

pub fn forward(ctx: Context<Forward>, data: Vec<u8>) -> Result<()> {
    // (1) pin the callee program to the expected one.
    require_keys_eq!(
        *ctx.accounts.target_program.key,
        ctx.accounts.config.expected_program,
        ForwardError::WrongCallee
    );
    // (2) pin the accounts handed to the callee — the destination must be the
    // program-recorded payout account, not whatever the caller passed.
    require_keys_eq!(
        ctx.accounts.destination.key(),
        ctx.accounts.config.expected_destination,
        ForwardError::WrongDestination
    );

    let ix = Instruction {
        program_id: *ctx.accounts.target_program.key,
        accounts: vec![AccountMeta::new(ctx.accounts.destination.key(), false)],
        data,
    };
    invoke(
        &ix,
        &[
            ctx.accounts.target_program.clone(),
            ctx.accounts.destination.to_account_info(),
        ],
    )?;
    Ok(())
}

#[derive(Accounts)]
pub struct Forward<'info> {
    pub authority: Signer<'info>,
    pub config: Account<'info, Config>,
    /// CHECK: validated against config.expected_program above before the CPI.
    pub target_program: AccountInfo<'info>,
    /// CHECK: validated against config.expected_destination above before the CPI.
    pub destination: AccountInfo<'info>,
}

#[account]
pub struct Config {
    pub expected_program: Pubkey,
    pub expected_destination: Pubkey,
}

#[error_code]
pub enum ForwardError {
    WrongCallee,
    WrongDestination,
}
