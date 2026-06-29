// SOL-038 (vulnerable): two caller-controlled variable-length seeds (`org`, `name`)
// sit ADJACENT in the PDA scheme with no fixed-width separator. Solana flattens
// seeds=[...] into one buffer, so the org|name boundary is unpinned: an attacker
// registers (org="ab", name="cd") to alias the PDA of victim (org="a", name="bcd")
// — same flat bytes b"member"||"ab"||"cd" == b"member"||"a"||"bcd" — and overwrites it.
use anchor_lang::prelude::*;

pub fn create_member(ctx: Context<CreateMember>, _org: String, _name: String) -> Result<()> {
    ctx.accounts.member.owner = ctx.accounts.payer.key();
    Ok(())
}

#[derive(Accounts)]
#[instruction(org: String, name: String)]
pub struct CreateMember<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + 32,
        // BUG: two adjacent variable-length seeds, boundary not pinned.
        seeds = [b"member", org.as_bytes(), name.as_bytes()],
        bump
    )]
    pub member: Account<'info, Member>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Member { pub owner: Pubkey }
