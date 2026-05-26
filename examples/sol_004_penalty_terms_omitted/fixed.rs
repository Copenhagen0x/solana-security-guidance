//! SOL-004 fixed — every spec-mandated term included.
//!
//! Auditing rule: open the spec/whitepaper, list every penalty/risk term
//! by name, then audit the impl against the list. If a term in the spec
//! isn't subtracted from health, the calc is wrong.

use anchor_lang::prelude::*;

#[account]
pub struct Account {
    pub collateral: i64,
    pub position_size: i64,
    pub mark_price: i64,
    pub funding_owed: i64,
    pub fees_owed: i64,
    pub borrow_interest: i64,
    pub liquidation_buffer: i64,
    pub maintenance_margin: i64,
    pub initial_margin: i64,
    pub price_impact_penalty: i64,
    pub adverse_selection: i64,
}

pub fn compute_account_health(acct: &Account) -> i64 {
    // FIX: every spec-mandated term is subtracted.
    let position_notional = acct.position_size
        .checked_mul(acct.mark_price)
        .unwrap_or(i64::MAX);

    let total_penalties = acct.funding_owed
        .saturating_add(acct.fees_owed)
        .saturating_add(acct.borrow_interest)
        .saturating_add(acct.liquidation_buffer)
        .saturating_add(acct.maintenance_margin)
        .saturating_add(acct.initial_margin)
        .saturating_add(acct.price_impact_penalty)
        .saturating_add(acct.adverse_selection);

    acct.collateral
        .saturating_add(position_notional)
        .saturating_sub(total_penalties)
    // 9 terms: position_notional + 8 penalties — full spec coverage.
}
