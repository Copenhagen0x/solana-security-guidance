# AGENTS.md

## Solana Security Standard (SOL-0XX)

When you write, edit, or review Solana code in this project — on-chain Anchor/Rust programs AND the TypeScript/JavaScript that builds and sends transactions (bots, keepers, integrators) — apply the Solana Security Standard (SOL-0XX) below. Solana programs are stateless: treat every caller as hostile until cryptographically proven otherwise. For each rule, flag the pattern, fix it as described, and cite the SOL-0XX id in your explanation. Off-chain code (client / cli / offchain / sdk / tests) is generally exempt from the on-chain (Rust) rules, EXCEPT the integrator rules SOL-029..031, which apply specifically to that transaction-sending TypeScript/JavaScript. Full catalog: https://github.com/Copenhagen0x/solana-security-standard . Audits: jelleo.com .

## Threat model

Solana programs are stateless — assume every caller is hostile until cryptographically proven otherwise. Dominant classes: trust-boundary breaks (instruction data → trusted state), authority confusion (wrong signer/PDA/owner), state integrity (cross-account/market leaks), time & lifecycle (caller clock, terminal guards that never clear), oracle trust (stale/unchecked prices), Anchor gaps (missing constraints, unsafe `init_if_needed`, skipped bump). Integrator layer (SOL-029-031): off-chain TS/JS that builds and sends txs (preflight, priority fees, stale routes), flagged on `.ts`/`.js`.

## Review checklist — critical priorities

Caller clock auth (SOL-001); wrapper delegation (SOL-003); complete risk math (SOL-004); terminal not live-gated (SOL-021); fees round vs user (SOL-023); oracle staleness+confidence (SOL-024); Anchor constraints (SOL-015); signer+owner (SOL-006/007); `checked_*` math (SOL-014); discriminator on deserialize (SOL-019).

## Rules

### SOL-001 · Unauthenticated now_slot
Caller-controlled clock into state (pass `u64::MAX`, real cranks then reject as stale → permanent DoS). Fix: `authenticated_slot_or_fallback(now_slot, Clock::get()?.slot)`. *(2 confirmed wins: prog#107, cli#78 F33)*

### SOL-002 · Cross-market state asymmetry
Counter written by one market and read by another with no per-market scoping → permissionless cross-market inflation drains a shared pool. Fix: gate every write by per-market authorization. *(public class)*

### SOL-003 · Wrapper re-implements engine
Wrapper redoes engine logic (close/settle/accrue), drifts, skips side-effects. Fix: delegate to the engine; the wrapper only marshals accounts.

### SOL-004 · Penalty/health terms omitted
Risk/margin math drops a spec-mandated term → under-collateralized positions allowed. Fix: include every term the spec lists.

### SOL-005 · Anchor resize without checks
`realloc()` with no owner / size-bound / rent-exemption guard. Fix: verify all three before resizing.

### SOL-006 · Missing signer check
Privileged handler mutates state without verifying the signer. Fix: Anchor `Signer<>` typed account, or check `is_signer`.

### SOL-007 · Missing owner verification
`AccountInfo` deserialized without `owner == program_id` → attacker passes a same-layout account from another program. Fix: check owner first.

### SOL-008 · Unverified PDA
PDA used without `find_program_address` validation → attacker passes any account as the PDA. Fix: derive and compare.

### SOL-009 · CPI without authority check
`invoke_signed` without verifying the caller's authority (signing with a PDA ≠ authorization). Fix: check authority before the CPI.

### SOL-010 · Reinit attack
`init_if_needed` on accounts holding value/authority → a 2nd call reinits, dropping balances. Fix: plain `init` + explicit existence guard.

### SOL-011 · Lamport drain via close
`close =` on an account not fully drained, or a close that doesn't zero data (residual reads). Fix: drain + zero + controlled destination.

### SOL-012 · Rent exemption check missing
Funded account not verified rent-exempt → runtime purges it, state lost. Fix: assert rent-exempt.

### SOL-013 · Token Program ID confusion
Hardcoded SPL Token ID but the account is Token-2022 (or vice versa). Fix: `anchor_spl::token::ID` via typed accounts; never hardcode.

### SOL-014 · Unchecked integer arithmetic
`+ - *` on ints without `checked_*` → release builds wrap silently, and the wrap IS the bug. Fix: `a.checked_add(b).ok_or(Overflow)?`.

### SOL-015 · Anchor constraints missing
`Account<'info, T>` cross-references another account with no `has_one =` / `constraint =`. Fix: tie related accounts together with constraints.

### SOL-016 · Bump seed unvalidated
A stored `.bump` isn't checked against the canonical bump on first read → attacker pre-creates a non-canonical PDA. Fix: compare to the `find_program_address` bump once.

### SOL-017 · Raw AccountInfo without typed deserialize
Data buffer cast to a struct with no deserialize-then-validate (`&*account.data.borrow()`, `transmute`). Fix: typed deserialize + length/field checks.

### SOL-018 · Hardcoded System Program ID
`"111…"` literal instead of the imported constant. Fix: `solana_program::system_program::ID`.

### SOL-019 · Missing discriminator check
Deserialize without the 8-byte Anchor discriminator (`try_deserialize_unchecked`) → wrong-type account of matching length accepted. Fix: `try_deserialize`.

### SOL-020 · SetAuthority without verification
`SetAuthority` without checking the current authority matches the expected key → ownership hijack. Fix: verify current authority first.

### SOL-021 · Terminal op gated on a live-only condition
A close/resolve reuses a guard (`status==Fresh`, `expiry>now`) that can't hold once status is **terminal** → reverts forever, funds lock. Fix: a terminal release that ignores freshness/expiry. *(v16 audit F1)*

### SOL-022 · Write-only "impaired" counter
A counter bumped when state degrades (valid→impaired), never decremented → funds encumbered forever, slot never reusable. Fix: add the inverse settlement. *(v16 audit F2)*

### SOL-023 · Fee/penalty rounds toward the user
Fee/penalty uses integer `/` (rounds down) → user underpays, dust → 0 (evasion + leakage). Fix: `u64::div_ceil` what the user **owes**; round against the less-trusted party (fee UP, payout DOWN). *(v16 audit F3, Low)*

### SOL-024 · Stale / unchecked oracle price
A Pyth/Switchboard price with no staleness (publish-slot age) or confidence check → attacker trades/liquidates at a mispriced value. Fix: `get_price_no_older_than(...)`; reject wide-confidence.

### SOL-025 · Sysvar read by raw deserialize
A sysvar (Clock/Rent) read by **raw-deserializing** account data (`bincode::deserialize::<Clock>`) instead of `Clock::get()` / `Sysvar::from_account_info` (which key-check) → attacker passes a look-alike. Fix: `Clock::get()` / Anchor `Sysvar<>`; never hand-deserialize a sysvar.

### SOL-026 · Duplicate mutable account (native programs)
Two accounts that must differ aren't checked → attacker passes one twice, collapsing a delta check. Fix: `require_keys_neq!`. *(Anchor rejects dupe-mutable `Account<>` (err 2040); NOT `AccountLoader`/`UncheckedAccount`/remaining_accounts.)*

### SOL-027 · Unvalidated remaining_accounts
`ctx.remaining_accounts` read/written/invoked without checking each one's owner/key/signer — fully attacker-controlled. Fix: validate every account like a declared one.

### SOL-028 · Missing slippage / min-out bound
A swap/withdraw/settle derives an output with no caller min-out/max-in → no protection from an adverse move or sandwich. Fix: take + enforce a caller bound.

### SOL-029 · Preflight simulation disabled
`skipPreflight: true` (or no `simulateTransaction`) before a mainnet send → reverts are paid, not caught; a live bot desyncs. Fix: keep preflight on, or simulate and assert `err === null` first.

### SOL-030 · Static priority fee
Hardcoded `microLamports` priority fee → underpays in congestion (tx never lands) or overpays when idle. Fix: derive from `getRecentPrioritizationFees()` and clamp.

### SOL-031 · Stale Jupiter quote
Jupiter quote swapped without a `quoteResponse.contextSlot` freshness check → stale route = worse fill + sandwich/MEV. Fix: refetch/reject when `contextSlot` lags the current slot.

## Provenance

Honest origins (full table in README): SOL-001 = 2 confirmed bounty wins; SOL-002 = a public class (another researcher); SOL-003/004/005 = our bounty-5 patterns; SOL-021/022/023 = our v16 audit; SOL-029-031 = a live integrator report; the rest = documented Solana/DeFi hygiene. We never claim credit we didn't earn.

Maintained by [Jelleo](https://jelleo.com). MIT.
