// SOL-035 (vulnerable): the handler introspects the instructions sysvar to confirm
// an Ed25519 signature-verify ran in the same transaction — but it reads from a
// raw AccountInfo whose key is NEVER pinned to the real instructions sysvar. An
// attacker passes a forged "instructions" account they control, stuffed with a
// fake Ed25519 instruction, and the signature gate passes without a real signature.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked;

pub fn verify_and_act(ctx: Context<VerifyAndAct>) -> Result<()> {
    // BUG: ix_sysvar is an unchecked AccountInfo — its key is never compared to
    // solana_program::sysvar::instructions::ID, so it can be any account.
    let ix = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;
    require!(
        ix.program_id == anchor_lang::solana_program::ed25519_program::ID,
        AuthError::MissingSignature
    );
    // ... trusts the "verified" signature and moves on ...
    Ok(())
}

#[derive(Accounts)]
pub struct VerifyAndAct<'info> {
    pub authority: Signer<'info>,
    /// CHECK: read as the instructions sysvar — but its key is never pinned (the bug).
    pub ix_sysvar: AccountInfo<'info>,
}

#[error_code]
pub enum AuthError {
    MissingSignature,
}
