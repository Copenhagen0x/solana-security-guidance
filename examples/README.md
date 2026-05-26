# Examples

Paired vulnerable/fixed Solana snippets, one per headline rule. Read the `vulnerable.rs` first, then compare against `fixed.rs`.

| Directory | Rule | Bug class |
|---|---|---|
| [`sol_001_unauth_now_slot/`](sol_001_unauth_now_slot/) | SOL-001 | Caller-controlled `now_slot` |
| [`sol_002_cross_market_asymmetry/`](sol_002_cross_market_asymmetry/) | SOL-002 | Cross-market counter inflation |
| [`sol_003_wrapper_reimplements_engine/`](sol_003_wrapper_reimplements_engine/) | SOL-003 | Wrapper re-implements engine logic |
| [`sol_004_penalty_terms_omitted/`](sol_004_penalty_terms_omitted/) | SOL-004 | Penalty/health terms omitted |
| [`sol_005_realloc_no_guard/`](sol_005_realloc_no_guard/) | SOL-005 | Anchor `realloc()` without guards |

Each example is illustrative — minimal Solana program code focused on the specific bug class. Real-world variants have more context but the same shape.

Full bug case studies (with PoCs, LiteSVM tests, suggested patches, audit trail): [jelleo.com/cycles](https://jelleo.com/cycles).
