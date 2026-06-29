// SOL-038 (fixed): every variable element is hashed to a FIXED 32 bytes before it
// enters the seeds, and the scheme leads with a fixed-width per-type tag from one
// program-wide registry. Element boundaries are now unambiguous regardless of
// content, so b"member"||tag||keccak(org)||keccak(name) cannot be shifted to alias
// another (org,name) pair — the org/name split is fully pinned. Complete fix: this
// is the program's only var-ending scheme AND the per-type tag is a CONSISTENT 4-byte
// width across the whole registry (all u32 here — never mixed widths, since a narrower
// tag can prefix a wider one) plus 32-byte-wide elements remove both intra-scheme
// shifting and cross-scheme aliasing.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;

#[repr(u32)]
pub enum PdaTag { Member = 1 } // 4-byte tag from one program-wide registry; never a per-file const

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
        // FIX: fixed-width tag + each variable element hashed to a constant 32 bytes.
        seeds = [
            &(PdaTag::Member as u32).to_le_bytes(),
            keccak::hash(org.as_bytes()).as_ref(),
            keccak::hash(name.as_bytes()).as_ref(),
        ],
        bump
    )]
    pub member: Account<'info, Member>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Member { pub owner: Pubkey }
