// SOL-037 (vulnerable): the handler CPIs into a program whose id is taken from a
// caller-supplied account and never checked against the expected program. The
// attacker passes their OWN program as `target_program`, so `invoke` runs
// attacker code with this program's accounts. (SOL-009 is about the CALLER's
// authority; SOL-037 is the unpinned CALLEE.) Review-only: an unpinned program
// id has no single syntactic marker — caught in review (see the exclusions).
use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke};

pub fn forward(ctx: Context<Forward>, data: Vec<u8>) -> Result<()> {
    // BUG: target_program is whatever the caller passed — never compared to an
    // expected program id. The CPI dispatches to attacker-controlled code.
    let ix = Instruction {
        program_id: *ctx.accounts.target_program.key,
        accounts: vec![],
        data,
    };
    invoke(&ix, &[ctx.accounts.target_program.clone()])?;
    Ok(())
}

#[derive(Accounts)]
pub struct Forward<'info> {
    pub authority: Signer<'info>,
    /// CHECK: invoked as a program — but its id is never pinned (the bug).
    pub target_program: AccountInfo<'info>,
}
