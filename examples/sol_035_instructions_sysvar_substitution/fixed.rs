// SOL-035 (fixed): BOTH halves of the fix. (1) the instructions sysvar is a typed,
// key-pinned `Sysvar<Instructions>`, so a forged account is rejected; AND (2) the
// introspected Ed25519 precompile instruction's contents are validated — its
// program id, the signer PUBKEY, and the signed MESSAGE are all compared to the
// expected values. Pinning alone is NOT enough: an attacker can include a real
// Ed25519 ix over THEIR OWN keypair/message, so a bare "did an ed25519 ix run?"
// check is bypassable. The scanner (substring tripwire on load_instruction_at_checked)
// still fires here by design; the fix satisfies the rule's exclusion #1.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::ed25519_program;
use anchor_lang::solana_program::sysvar::instructions::{load_instruction_at_checked, Instructions};

pub fn verify_and_act(ctx: Context<VerifyAndAct>, expected_msg: Vec<u8>) -> Result<()> {
    // (1) read from the typed, key-pinned sysvar account.
    let ix = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar.to_account_info())?;

    // (2) validate the precompile instruction's CONTENTS, not just that it ran.
    require!(ix.program_id == ed25519_program::ID, AuthError::NotEd25519);
    // The Ed25519 precompile ix lays out, for a single signature in the same ix:
    //   [0]=num_signatures, [1]=padding, then a 14-byte offsets struct, then
    //   pubkey(32) | signature(64) | message(..). Parse the pubkey + message and
    //   bind them to who/what THIS program expects — otherwise any valid signature
    //   over an attacker message passes.
    let data = &ix.data;
    require!(data.len() >= 14 && data[0] == 1, AuthError::MalformedPrecompile);
    let pubkey_off = u16::from_le_bytes([data[6], data[7]]) as usize;
    let msg_off = u16::from_le_bytes([data[10], data[11]]) as usize;
    let msg_size = u16::from_le_bytes([data[12], data[13]]) as usize;
    require!(data.len() >= pubkey_off + 32, AuthError::MalformedPrecompile);
    require!(data.len() >= msg_off + msg_size, AuthError::MalformedPrecompile);

    let signer_pubkey = &data[pubkey_off..pubkey_off + 32];
    let signed_msg = &data[msg_off..msg_off + msg_size];
    require!(signer_pubkey == ctx.accounts.config.expected_signer.as_ref(), AuthError::WrongSigner);
    require!(signed_msg == expected_msg.as_slice(), AuthError::WrongMessage);
    // ...only now is the precompile-verified signature trustworthy.
    Ok(())
}

#[derive(Accounts)]
pub struct VerifyAndAct<'info> {
    pub authority: Signer<'info>,
    pub config: Account<'info, Config>,
    // Anchor enforces this account's key == sysvar::instructions::ID.
    pub ix_sysvar: Sysvar<'info, Instructions>,
}

#[account]
pub struct Config {
    pub expected_signer: Pubkey,
}

#[error_code]
pub enum AuthError {
    NotEd25519,
    MalformedPrecompile,
    WrongSigner,
    WrongMessage,
}
