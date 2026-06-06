# Examples

Paired vulnerable/fixed Solana snippets, one per rule. Read the `vulnerable.*`
first, then compare against `fixed.*`.

These are **self-testing fixtures**: `cli/test/examples.test.js` runs the real
scanner over every pair and asserts each `vulnerable.*` still fires its rule (an
anti-rot guard — if a matcher regresses, the test fails) and each `fixed.*` is
either scanner-clean or a documented *exclusion-cleared* example. See the note
below the table.

| Directory | Rule | Bug class |
|---|---|---|
| [`sol_001_unauth_now_slot/`](sol_001_unauth_now_slot/) | SOL-001 | Caller-controlled `now_slot` |
| [`sol_002_cross_market_asymmetry/`](sol_002_cross_market_asymmetry/) | SOL-002 | Cross-market counter inflation |
| [`sol_003_wrapper_reimplements_engine/`](sol_003_wrapper_reimplements_engine/) | SOL-003 | Wrapper re-implements engine logic |
| [`sol_004_penalty_terms_omitted/`](sol_004_penalty_terms_omitted/) | SOL-004 | Penalty/health terms omitted |
| [`sol_005_realloc_no_guard/`](sol_005_realloc_no_guard/) | SOL-005 | Anchor `realloc()` without guards |
| [`sol_006_raw_account_info/`](sol_006_raw_account_info/) | SOL-006 | Privileged raw `AccountInfo` (no signer check) |
| [`sol_007_raw_data_borrow/`](sol_007_raw_data_borrow/) | SOL-007 | Deserialize without an owner check |
| [`sol_009_invoke_signed/`](sol_009_invoke_signed/) | SOL-009 | `invoke_signed` without caller authority |
| [`sol_010_init_if_needed/`](sol_010_init_if_needed/) | SOL-010 | `init_if_needed` re-init reset |
| [`sol_011_close_attr/`](sol_011_close_attr/) | SOL-011 | `close =` to an attacker destination |
| [`sol_013_hardcoded_token_program/`](sol_013_hardcoded_token_program/) | SOL-013 | Hardcoded token-program id literal |
| [`sol_014_unchecked_arithmetic/`](sol_014_unchecked_arithmetic/) | SOL-014 | Unchecked arithmetic on a balance |
| [`sol_016_bump_field_read/`](sol_016_bump_field_read/) | SOL-016 | Non-canonical PDA bump |
| [`sol_017_unsafe_transmute/`](sol_017_unsafe_transmute/) | SOL-017 | `unsafe { transmute }` over account bytes |
| [`sol_018_hardcoded_system_program/`](sol_018_hardcoded_system_program/) | SOL-018 | Hardcoded System Program literal |
| [`sol_019_try_deserialize_unchecked/`](sol_019_try_deserialize_unchecked/) | SOL-019 | Missing discriminator check |
| [`sol_020_set_authority/`](sol_020_set_authority/) | SOL-020 | `set_authority` without current-authority check |
| [`sol_024_oracle_price_unchecked/`](sol_024_oracle_price_unchecked/) | SOL-024 | Oracle price with no staleness/confidence |
| [`sol_025_sysvar_raw_deserialize/`](sol_025_sysvar_raw_deserialize/) | SOL-025 | Raw sysvar deserialize vs `Clock::get()` |
| [`sol_029_skip_preflight/`](sol_029_skip_preflight/) | SOL-029 | `skipPreflight: true` on a mainnet send (TS) |
| [`sol_030_static_priority_fee/`](sol_030_static_priority_fee/) | SOL-030 | Static priority fee (TS) |
| [`sol_031_jupiter_quote_freshness/`](sol_031_jupiter_quote_freshness/) | SOL-031 | Stale Jupiter quote (TS) |

Each example is illustrative — minimal Solana program code focused on the specific bug class. Real-world variants have more context but the same shape.

**Why some `fixed.*` still trip the scanner.** The scanner is a fail-open
tripwire: it flags a *pattern*, not a *verdict*. For fixes that are runtime or
structural (the syntactic pattern legitimately stays — e.g. `.realloc()` with
guards added, `invoke_signed` with an authority check in front, `set_authority`
constrained to the current authority), the scanner still fires and the fix
clears the rule's **exclusion** rather than the regex. The self-test tracks
those in a documented allowlist; all other fixes are scanner-clean.

Full bug case studies (with PoCs, LiteSVM tests, suggested patches, audit trail): [jelleo.com/cycles](https://jelleo.com/cycles).
