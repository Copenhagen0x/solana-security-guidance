# Solana Security Guidance — by Jelleo

> Real-world rules drawn from 38+ disclosed Solana bounty findings.
> Maintained: github.com/Copenhagen0x/solana-security-guidance · Audits: jelleo.com

This file extends Claude Code's security-guidance plugin with Solana-specific
review rules. Each rule traces to a real bug class we've disclosed.

## Threat model (Solana programs)

Solana programs are stateless executables anyone can invoke with arbitrary
instruction data. Assume every caller is hostile until proven otherwise via
cryptographic verification. The dominant bug classes in our published audits:

1. **Trust boundary breaks** — instruction-data values flowing into trusted state without authentication
2. **Authority confusion** — wrong signer accepted, wrong PDA derived, wrong owner trusted
3. **State integrity** — partial updates, cross-account/cross-market leaks, lifecycle stage skips
4. **Time/sequence** — slot, clock, lifecycle field controlled by caller instead of authenticated
5. **Anchor framework gaps** — missing `has_one`/`constraint=`, unsafe `init_if_needed`, bump skipped

## Review checklist

When reviewing a Solana-program diff, verify:

- Every privileged handler verifies the expected signer(s)
- Every account read verifies `account.owner == program_id`
- PDA-derived accounts verify bump via canonical `find_program_address`
- Anchor constraints (`has_one`, `constraint=`, `seeds=`, `bump=`) present on every cross-referenced account
- No `now_slot` / clock value comes from instruction data without being authenticated against `Clock::get()`
- Wrapper handlers delegate to engine logic; never re-implement (drifts, skips spec terms)
- Health, penalty, fee, PnL calculations include every spec-mandated term — sample the spec, then audit the impl
- CPI calls verify invocation authority BEFORE executing
- Account closure sweeps lamports to a known destination and zeroes data
- Token Program ID is the imported `anchor_spl::token::ID` (or Token-2022 equivalent), not a hardcoded literal
- Integer arithmetic uses `checked_*`, not raw operators (release builds wrap silently)
- Discriminator checked on every account deserialize — never trust the layout from raw `AccountInfo`
- `SetAuthority` calls verify the prior authority matches the expected key

## Detailed rules

### SOL-001 · Unauthenticated `now_slot`
Caller-controlled clock value flowing into market/asset state. Attacker passes `u64::MAX`, stamps state ahead of real chain time; real cranks then reject as stale — permanent DoS.
**Fix:** `let now_slot = authenticated_slot_or_fallback(now_slot, Clock::get()?.slot);`
**Reference:** Bounty 6 H2, percolator-prog#107 (closed/fixed 2026-05-26).

### SOL-002 · Cross-market state asymmetry
Counter or aggregate written by one market read by another with no per-market scoping. Permissionless caller inflates a cross-market counter → drains the shared pool (e.g. insurance fund).
**Reference:** Bounty 5 primary class (`pnl_pos_bound_tot` insurance drain pattern).

### SOL-003 · Wrapper re-implements engine
Wrapper handler reimplements logic the engine already provides (close, settle, accrue). Reimplementation drifts, skips hooks/side-effects, silently diverges.
**Fix:** Delegate to engine; wrapper marshals accounts and calls the engine method.
**Reference:** Bounty 5 F1 (Critical), percolator-cli#78.

### SOL-004 · Penalty/health terms omitted
Health, margin, or penalty calculations omit spec-mandated terms. Result understates risk, allowing under-collateralized positions.
**Reference:** Bounty 5 F2 (Critical, 9 missing penalty terms), percolator-cli#78.

### SOL-005 · Anchor resize without checks
`AccountInfo.realloc()` without owner verification, size bounds, or rent-exemption invariant.
**Look for:** `.realloc(` without preceding owner + size guards.

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

Headline rules trace to published Jelleo audit cycles:

- **Bounty 6 H2** → jelleo.com/cycles/20260526-bounty6-h2-activate-future-slot-dos
- **Bounty 5 final (36 findings)** → jelleo.com/cycles/20260526-bounty5-final-36findings
- **All cycles** → jelleo.com/cycles

Maintained by [Jelleo](https://jelleo.com). MIT licensed. PRs welcome.
