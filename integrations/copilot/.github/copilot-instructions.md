# Copilot instructions: Solana Security Standard (SOL-0XX)

When you write, edit, or review Solana code in this project — on-chain Anchor/Rust programs AND the TypeScript/JavaScript that builds and sends transactions (bots, keepers, integrators) — apply the Solana Security Standard (SOL-0XX) below. Solana programs are stateless: treat every caller as hostile until cryptographically proven otherwise. For each rule, flag the pattern, fix it as described, and cite the SOL-0XX id in your explanation. Off-chain code (client / cli / offchain / sdk / tests) is generally exempt from the on-chain (Rust) rules, EXCEPT the integrator rules SOL-029..031, which apply specifically to that transaction-sending TypeScript/JavaScript. Full catalog: https://github.com/Copenhagen0x/solana-security-guidance . Audits: jelleo.com .

## Threat model

Solana programs are stateless — assume every caller is hostile until cryptographically proven otherwise. Dominant classes: trust-boundary breaks (instruction data → trusted state), authority confusion (wrong signer/PDA/owner), state integrity (cross-account/market leaks), time & lifecycle (caller clock, terminal guards that never clear), oracle trust (stale/unchecked prices), Anchor gaps (missing constraints, unsafe `init_if_needed`, skipped bump). **Integrator layer (SOL-029..031):** the off-chain TS/JS that builds and sends transactions (bots, keepers, workers, integrators) has its own footguns — disabled preflight, static priority fees, stale routes — flagged on `.ts`/`.js`, not `.rs`.

## Review checklist — critical priorities

Caller `now_slot`/clock authenticated via `Clock::get()` (SOL-001); wrappers delegate to the engine (SOL-003); risk math includes every spec term (SOL-004); terminal/close paths not gated on live-only conditions (SOL-021); fees round against the user (SOL-023); oracle prices checked for staleness+confidence (SOL-024); Anchor cross-refs carry constraints (SOL-015); privileged handlers verify signer (SOL-006) + owner (SOL-007); `checked_*` arithmetic (SOL-014); discriminator checked on deserialize (SOL-019).

## Rules

### SOL-001 · Unauthenticated now_slot
Caller-controlled clock into market/asset state (pass `u64::MAX`, real cranks then reject as stale → permanent DoS). Fix: `authenticated_slot_or_fallback(now_slot, Clock::get()?.slot)`. *(two confirmed wins: percolator-prog#107, -cli#78 F33)*

### SOL-002 · Cross-market state asymmetry
Counter written by one market and read by another with no per-market scoping → permissionless cross-market inflation drains a shared pool. Fix: gate every write by per-market authorization. *(public class, percolator-prog#104)*

### SOL-003 · Wrapper re-implements engine
Wrapper handler redoes engine logic (close/settle/accrue), drifts, skips side-effects. Fix: delegate to the engine; the wrapper only marshals accounts.

### SOL-004 · Penalty/health terms omitted
Risk/margin math drops a spec-mandated term → under-collateralized positions allowed. Fix: include every term the spec lists.

### SOL-005 · Anchor resize without checks
`realloc()` with no owner / size-bound / rent-exemption guard. Fix: verify all three before resizing.

### SOL-006 · Missing signer check
Privileged handler mutates state without verifying the signer. Fix: Anchor `Signer<>` typed account, or check `is_signer`.

### SOL-007 · Missing owner verification
`AccountInfo` deserialized without `owner == program_id` → attacker passes a same-layout account from another program. Fix: check owner first.

### SOL-008 · Unverified PDA
PDA used without `find_program_address` validation → attacker passes any account and claims it's the PDA. Fix: derive and compare.

### SOL-009 · CPI without authority check
`invoke_signed` runs without verifying the caller's authority (signing with a PDA ≠ authorization). Fix: check authority before the CPI.

### SOL-010 · Reinit attack
`init_if_needed` on accounts holding value/authority → a second call re-initializes, dropping balances. Fix: plain `init` + explicit existence guard.

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
`SetAuthority` invoked without checking the current authority matches the expected key → ownership hijack. Fix: verify current authority first.

### SOL-021 · Terminal op gated on a live-only condition
A close/resolve path reuses a guard (`status==Fresh`, `expiry>now`) that can't hold once the program's status is **terminal** → the call reverts forever, funds lock. Fix: a terminal release that ignores freshness/expiry. *(v16 audit F1; maintainer fixed as "Finding C")*

### SOL-022 · Write-only "impaired" counter
A counter incremented when state migrates to a degraded bucket (valid→impaired) but never decremented → those funds are encumbered forever, slot never reusable. Fix: add the inverse settlement (release/write-off). *(v16 audit F2; percolator#74, code-confirmed)*

### SOL-023 · Fee/penalty rounds toward the user
Fee/penalty/debt uses integer `/` (rounds down), so the user underpays and dust rounds to 0 → evasion + leakage. Fix: `u64::div_ceil` what the user **owes** — round against the less-trusted party (fee/penalty UP, payout DOWN). *(v16 audit F3, Low)*

### SOL-024 · Stale / unchecked oracle price
A Pyth/Switchboard price used with no staleness (publish-slot age) or confidence-interval check → attacker trades/liquidates at a mispriced value. Fix: `get_price_no_older_than(...)` and reject wide-confidence prices.

### SOL-025 · Sysvar read by raw deserialize
A sysvar (Clock/Rent) read by **raw-deserializing account data** (`bincode::deserialize::<Clock>`, raw cast) instead of `Clock::get()` / `Sysvar::from_account_info` (which key-check) → attacker passes a look-alike account. Fix: use `Clock::get()` / Anchor `Sysvar<>`; never hand-deserialize a sysvar.

### SOL-026 · Duplicate mutable account (native programs)
Two accounts that must differ aren't checked → attacker passes one twice, collapsing a delta check. Fix: `require_keys_neq!`. *(Anchor auto-rejects dupe-mutable `Account<>` via err 2040 — but NOT `AccountLoader` (zero-copy, still aliases memory), `UncheckedAccount`, or remaining_accounts.)*

### SOL-027 · Unvalidated remaining_accounts
`ctx.remaining_accounts` are read/written/invoked without checking each one's owner/key/signer — the list is fully attacker-controlled. Fix: validate every account before trusting it, exactly as a declared account.

### SOL-028 · Missing slippage / min-out bound
A swap/withdraw/settle derives an output amount with no caller-supplied min-out / max-in → no protection from an adverse price move or sandwich. Fix: take and enforce a caller-supplied bound.

### SOL-029 · Preflight simulation disabled
Client sends a transaction with `skipPreflight: true` (or never `simulateTransaction`s) → reverts are paid for, not caught, and a live bot/keeper desyncs. Fix: keep preflight on, or `simulateTransaction` and assert `err === null` before the mainnet send. *(integrator layer — TS/JS)*

### SOL-030 · Static priority fee
Hardcoded `microLamports` compute-unit price → underpays in congestion (tx never lands) or overpays when idle. Fix: derive from `getRecentPrioritizationFees()` / a fee oracle and clamp to a max. *(integrator layer — TS/JS)*

### SOL-031 · Stale Jupiter quote
A Jupiter quote is swapped without checking `quoteResponse.contextSlot` freshness → an old route means a worse fill and sandwich/MEV exposure. Fix: reject/refetch when `contextSlot` lags the current slot before executing. *(integrator layer — TS/JS)*

## Provenance

Honest origins (full table in README): SOL-001 = two confirmed maintainer-fixed bounty wins; SOL-002 = a public class from another researcher; SOL-003/004/005 = our bounty-5 patterns; SOL-021/022/023 = our v16 audit (F1 = "Finding C"; F2 = percolator#74; F3 Low); the rest = documented Solana/DeFi hygiene. We never claim credit we didn't earn.

Maintained by [Jelleo](https://jelleo.com). MIT. Full catalog → README.
