//! SOL-051 fixed - randomness from an owner-verified, draw-bound VRF result account.
//! The result account is (1) owned by the trusted oracle program, (2) the EXACT
//! account committed for THIS draw (key stored at request time), and (3) read via a
//! parser that REJECTS an unfulfilled (zeroed) round - and the randomness is read
//! from that SAME owner-checked account, not a decoupled local one. So the outcome
//! cannot be grinded, account-substituted, or replayed.
use anchor_lang::prelude::*;

#[error_code]
pub enum DrawError {
    #[msg("VRF account is not owned by the oracle program")] WrongOracleOwner,
    #[msg("VRF account is not the one bound to this draw")] UnboundVrf,
    #[msg("VRF round not yet fulfilled")] NotFulfilled,
}

pub fn draw(ctx: Context<Draw>) -> Result<()> {
    let players = &ctx.accounts.pool.players;
    let vrf = &ctx.accounts.vrf;
    // (1) the result account is owned by the trusted oracle program
    require_keys_eq!(*vrf.owner, ctx.accounts.pool.oracle_program, DrawError::WrongOracleOwner);
    // (2) it is the exact account committed for THIS draw, stored at request time
    require_keys_eq!(vrf.key(), ctx.accounts.pool.vrf_account, DrawError::UnboundVrf);
    // (3) parse the oracle's value FROM THE OWNER-CHECKED ACCOUNT and reject a zeroed/unfulfilled round
    let value = parse_oracle_result(&vrf.try_borrow_data()?)?;
    require!(value != [0u8; 32], DrawError::NotFulfilled);
    let n = u64::from_le_bytes(value[..8].try_into().unwrap());
    let idx = (n % players.len() as u64) as usize;
    ctx.accounts.pool.winner = players[idx];
    Ok(())
}

// In production this is the oracle SDK's typed parser (e.g. Switchboard
// `RandomnessAccountData::parse` / `get_value(&clock)`), which enforces the account
// layout AND returns the revealed value only when the round is resolved. Shown inline
// only to keep the example self-contained - the security comes from the three checks
// above, performed on the single owner-checked, draw-bound `vrf` account.
fn parse_oracle_result(data: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[8..40]);
    Ok(out)
}

#[account]
pub struct Pool { pub players: Vec<Pubkey>, pub winner: Pubkey, pub oracle_program: Pubkey, pub vrf_account: Pubkey }

#[derive(Accounts)]
pub struct Draw<'info> {
    #[account(mut)] pub pool: Account<'info, Pool>,
    /// CHECK: owner-verified against pool.oracle_program AND key-bound to pool.vrf_account before any read
    pub vrf: AccountInfo<'info>,
}
