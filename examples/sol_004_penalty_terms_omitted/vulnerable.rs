//! SOL-004 vulnerable — penalty/health terms omitted from calculation.
//!
//! The health certificate's `compute_account_health` only includes a
//! SUBSET of the penalty terms named in the spec. Missing terms understate
//! risk, allowing under-collateralized positions to look healthy. Margin
//! calls and liquidations fail to trigger.
//!
//! Real-world disclosure: Bounty 5 F2 (Critical, percolator-cli#78) —
//! `compute_account_health_cert_with_price_override` omitted all 9
//! spec-mandated penalty terms.

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
    // BUG: only 2 of the 9 spec-mandated terms.
    // Spec requires: funding_owed, fees_owed, borrow_interest,
    //                liquidation_buffer, maintenance_margin, initial_margin,
    //                price_impact_penalty, adverse_selection,
    //                position_size * mark_price.
    // Caller sees inflated health → under-collateralized account looks safe.
    let position_notional = acct.position_size
        .checked_mul(acct.mark_price)
        .unwrap_or(i64::MAX); // BUG: i64::MAX on overflow masks insolvency — see fixed.rs
    acct.collateral
        .saturating_add(position_notional)
        .saturating_sub(acct.funding_owed)
    // 7 more terms missing
}
