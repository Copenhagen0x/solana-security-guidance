# Solana Security Guidance — by Jelleo

> Real-world rules drawn from 38+ disclosed Solana bounty findings.
> Maintained: github.com/Copenhagen0x/solana-security-guidance · Audits: jelleo.com

This file extends Claude Code's security-guidance plugin with Solana-specific
review rules. Each rule traces to a real bug class we've disclosed.

## Threat model

Solana programs are stateless executables anyone can invoke. Assume every caller is hostile until proven otherwise via cryptographic verification. Dominant bug classes: trust-boundary breaks (instruction-data flowing into trusted state), authority confusion (wrong signer/PDA/owner), state integrity (cross-account/market leaks), time/sequence (caller-supplied clock or lifecycle field), and Anchor framework gaps (missing constraints, unsafe `init_if_needed`, bump skipped).

## Review checklist

When reviewing a Solana-program diff, verify each rule below. Critical priorities: no instruction-data `now_slot`/clock value persisted without `Clock::get()` authentication (SOL-001); wrapper handlers delegate to engine instead of reimplementing (SOL-003); health/penalty calculations include every spec term (SOL-004); Anchor `Account<>` cross-references carry `has_one`/`constraint=`/`seeds=` (SOL-015); every privileged handler verifies its signer (SOL-006) and account owner (SOL-007); integer arithmetic uses `checked_*` (SOL-014); discriminator checked on every deserialize (SOL-019).

## Detailed rules

### SOL-001 · Unauthenticated `now_slot`
Caller-controlled clock value flowing into market/asset state. Attacker passes `u64::MAX`, stamps state ahead of real chain time; real cranks then reject as stale — permanent DoS.
**Fix:** `let now_slot = authenticated_slot_or_fallback(now_slot, Clock::get()?.slot);`
**References (two confirmed-exploitable bounty wins, same class):**
- ACTIVATE branch — `aeyakovenko/percolator-prog#107`, fixed in `6512fa1`
- RETIRE branch — `aeyakovenko/percolator-cli#78` F33, fixed in `3fd9b1d`

### SOL-002 · Cross-market state asymmetry
Counter or aggregate written by one market read by another with no per-market scoping. Permissionless caller inflates a cross-market counter → drains the shared pool (e.g. insurance fund).
**Reference:** Documented cross-market exploitation class (the `pnl_pos_bound_tot` insurance-drain pattern publicly disclosed in `aeyakovenko/percolator-prog#104`). Not our finding — included because the pattern is reproducible across perp-DEX programs.

### SOL-003 · Wrapper re-implements engine
Wrapper handler reimplements logic the engine already provides (close, settle, accrue). Reimplementation drifts, skips hooks/side-effects, silently diverges.
**Fix:** Delegate to engine; wrapper marshals accounts and calls the engine method.
**Reference:** Pattern documented in our bounty 5 disclosure (`aeyakovenko/percolator-cli#78` F1). Maintainer independently fixed in `0925ed4` before triage.

### SOL-004 · Penalty/health terms omitted
Health, margin, or penalty calculations omit spec-mandated terms. Result understates risk, allowing under-collateralized positions.
**Reference:** Pattern documented in our bounty 5 disclosure (`aeyakovenko/percolator-cli#78` F2). Engine-side per maintainer triage; separate disclosure pending at `aeyakovenko/percolator`.

### SOL-005 · Anchor resize without checks
`AccountInfo.realloc()` without owner verification, size bounds, or rent-exemption invariant.
**Look for:** `.realloc(` without preceding owner + size guards.
**Reference:** Latent pattern documented in our bounty 5 disclosure (`aeyakovenko/percolator-cli#78` F12). Reachable when the 14-asset cap is lifted.

### SOL-006 · Missing signer check
Privileged handler mutates state without verifying signer. Permissionless caller spoofs identity.
**Look for:** Handler mutating state without `account.is_signer` check or Anchor `Signer<>` typed account.

### SOL-007 · Missing owner verification
`AccountInfo` read without `account.owner == program_id` check. Attacker passes different-owner account whose layout matches.
**Look for:** Manual deserialization from `AccountInfo` without prior owner check.

### SOL-008 · Unverified PDA
PDA derived from instruction data without canonical `find_program_address` validation. Attacker passes any account, claims it's the PDA.

### SOL-009 · CPI without authority check
Cross-program invocation executes without verifying caller authority. `invoke_signed` just signs with a PDA — doesn't validate upstream authority.

### SOL-010 · Reinit attack
`init_if_needed` on accounts that hold value or grant authority. Second call re-initializes state, dropping balances/ownership.
**Fix:** Plain `init` with explicit existence guards unless reinit is truly required.

### SOL-011 · Lamport drain via close
`close = receiver` on accounts not fully drained; OR closure that doesn't zero data — attacker reads residual fields.

### SOL-012 · Rent exemption check missing
Account funded but not verified rent-exempt. Balance below rent floor → account purged by runtime → state lost.

### SOL-013 · Token Program ID confusion
Token Program ID hardcoded as legacy SPL Token, but account is Token-2022 (or vice versa). Wrong program receives the invocation.
**Fix:** `anchor_spl::token::ID` via typed accounts; never hardcode `Tokenkeg...`.

### SOL-014 · Unchecked integer arithmetic
`+`, `-`, `*` on `u64`/`i64` without `checked_*`. Release builds wrap silently — silent wrap is the financial bug.
**Fix:** `a.checked_add(b).ok_or(ErrorCode::Overflow)?`

### SOL-015 · Anchor constraints missing
`Account<'info, T>` cross-references another account without `has_one =` / `constraint =`.
**Look for:** `#[derive(Accounts)]` structs with multiple accounts and no constraints tying them together.

### SOL-016 · Bump seed unvalidated
PDA derived with `bump` stored on the account, but the bump isn't checked against `find_program_address` canonical bump on the first read.

### SOL-017 · Raw AccountInfo without typed deserialize
Handler casts the data buffer to a struct without deserialize-then-validate.
**Look for:** `&*account.data.borrow()`; `unsafe { transmute }` on account data.

### SOL-018 · Hardcoded System Program ID
System Program ID as a literal string rather than imported constant.
**Fix:** `solana_program::system_program::ID`, not `"11111111111111111111111111111111"`.

### SOL-019 · Missing discriminator check
Account deserialize without verifying the 8-byte Anchor discriminator. Attacker passes wrong-type account with matching length.
**Look for:** `try_deserialize_unchecked`; manual `bytemuck::cast` without discriminator check.

### SOL-020 · SetAuthority without verification
Token `SetAuthority` invoked without verifying current authority matches the expected key. Attacker hijacks ownership.

## References

- **Bounty 6 H2** (`percolator-prog#107`, fixed `6512fa1`) → jelleo.com/cycles/20260526-bounty6-h2-activate-future-slot-dos
- **Bounty 5 disclosure** (`percolator-cli#78`, F33 fixed `3fd9b1d`) → jelleo.com/cycles/20260526-bounty5-final-36findings
- **All cycles** → jelleo.com/cycles

**Honest provenance:** SOL-001 covers two confirmed-exploitable maintainer-fixed bounty wins (ACTIVATE + RETIRE). SOL-002 is a documented public class disclosed by a separate researcher. SOL-003 / SOL-004 / SOL-005 are real Solana patterns surfaced in our bounty 5 disclosure; the maintainer's triage classified F1 as already-fixed in-flight, F2 as engine-side (pending separate disclosure), and F12 as latent. The remaining 15 rules (SOL-006 through SOL-020) are documented Solana hygiene patterns.

Maintained by [Jelleo](https://jelleo.com). MIT licensed. PRs welcome.
