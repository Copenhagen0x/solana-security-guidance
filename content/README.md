# Rule content — all 52 SOL-0XX explainers

> One page per rule: what it catches, the fix, whether it is machine-checkable, the real exploits in that class, and a code example where one exists. Generated from the standard + patterns + the [Hacks Database](../hacks/) + examples by [`scripts/sync-content.js`](./scripts/sync-content.js) — do not hand-edit.

**30 of 52** rules are machine-checkable (deterministic pattern); the rest are review-only. **8** map to a catalogued real-world exploit.

| Rule | Title | Tier | Severity | Enforcement | Real exploits | Example |
| --- | --- | --- | --- | --- | --- | --- |
| [SOL-001](./rules/SOL-001.md) | Unauthenticated now_slot | high | high | pattern | — | ✓ |
| [SOL-002](./rules/SOL-002.md) | Cross-market state asymmetry | high | high | pattern | — | ✓ |
| [SOL-003](./rules/SOL-003.md) | Wrapper re-implements engine | low | medium | review | — | ✓ |
| [SOL-004](./rules/SOL-004.md) | Penalty/health terms omitted | high | high | review | Cypher Protocol | ✓ |
| [SOL-005](./rules/SOL-005.md) | Anchor resize without checks | high | medium | pattern | — | ✓ |
| [SOL-006](./rules/SOL-006.md) | Missing signer check | high | high | pattern | Solend | ✓ |
| [SOL-007](./rules/SOL-007.md) | Missing owner verification | high | high | pattern | Crema Finance, Cashio, Wormhole, Solend | ✓ |
| [SOL-008](./rules/SOL-008.md) | Unverified PDA | high | high | review | — | — |
| [SOL-009](./rules/SOL-009.md) | CPI without authority check | high | high | pattern | — | ✓ |
| [SOL-010](./rules/SOL-010.md) | Reinit attack | high | high | pattern | — | ✓ |
| [SOL-011](./rules/SOL-011.md) | Lamport drain via close | high | high | pattern | — | ✓ |
| [SOL-012](./rules/SOL-012.md) | Rent exemption check missing | high | medium | review | — | — |
| [SOL-013](./rules/SOL-013.md) | Token Program ID confusion | high | high | pattern | — | ✓ |
| [SOL-014](./rules/SOL-014.md) | Unchecked integer arithmetic | high | high | pattern | — | ✓ |
| [SOL-015](./rules/SOL-015.md) | Anchor constraints missing | high | high | review | Cashio | — |
| [SOL-016](./rules/SOL-016.md) | Bump seed unvalidated | high | high | pattern | — | ✓ |
| [SOL-017](./rules/SOL-017.md) | Raw AccountInfo without typed deserialize | high | high | pattern | Crema Finance | ✓ |
| [SOL-018](./rules/SOL-018.md) | Hardcoded System Program ID | low | low | pattern | — | ✓ |
| [SOL-019](./rules/SOL-019.md) | Missing discriminator check | high | high | pattern | — | ✓ |
| [SOL-020](./rules/SOL-020.md) | SetAuthority without verification | high | high | pattern | — | ✓ |
| [SOL-021](./rules/SOL-021.md) | Terminal op gated on a live-only condition | high | high | review | — | — |
| [SOL-022](./rules/SOL-022.md) | Write-only "impaired" counter | low | medium | review | — | — |
| [SOL-023](./rules/SOL-023.md) | Fee/penalty rounds toward the user | low | low | review | — | — |
| [SOL-024](./rules/SOL-024.md) | Stale / unchecked oracle price | high | high | pattern | Loopscale, Mango Markets, Nirvana Finance | ✓ |
| [SOL-025](./rules/SOL-025.md) | Sysvar read by raw deserialize | high | high | pattern | Wormhole | ✓ |
| [SOL-026](./rules/SOL-026.md) | Duplicate mutable account (native programs) | high | high | review | — | — |
| [SOL-027](./rules/SOL-027.md) | Unvalidated remaining_accounts | high | high | review | — | — |
| [SOL-028](./rules/SOL-028.md) | Missing slippage / min-out bound | high | high | review | Loopscale, Nirvana Finance | — |
| [SOL-029](./rules/SOL-029.md) | Preflight simulation disabled | high | medium | pattern | — | ✓ |
| [SOL-030](./rules/SOL-030.md) | Static priority fee | low | low | pattern | — | ✓ |
| [SOL-031](./rules/SOL-031.md) | Stale Jupiter quote | high | medium | pattern | — | ✓ |
| [SOL-032](./rules/SOL-032.md) | Decimals assumed, not read | high | high | review | — | ✓ |
| [SOL-033](./rules/SOL-033.md) | Stale account read after CPI | high | high | pattern | — | ✓ |
| [SOL-034](./rules/SOL-034.md) | Manual lamport mutation | high | high | pattern | — | ✓ |
| [SOL-035](./rules/SOL-035.md) | Instructions sysvar substitution | high | high | pattern | — | ✓ |
| [SOL-036](./rules/SOL-036.md) | ATA derivation unpinned | high | high | review | — | ✓ |
| [SOL-037](./rules/SOL-037.md) | Arbitrary CPI target | high | high | review | — | ✓ |
| [SOL-038](./rules/SOL-038.md) | PDA seed collision | high | high | pattern | — | ✓ |
| [SOL-039](./rules/SOL-039.md) | Asymmetric partial-CPI state | high | high | pattern | — | ✓ |
| [SOL-040](./rules/SOL-040.md) | Credit from requested, not measured (Token-2022) | high | high | review | — | — |
| [SOL-041](./rules/SOL-041.md) | Forced-balance / supply desync | high | high | review | — | — |
| [SOL-042](./rules/SOL-042.md) | Unbounded account-iteration compute DoS | high | medium | pattern | — | ✓ |
| [SOL-043](./rules/SOL-043.md) | Unbounded storage / slot-exhaustion griefing | high | high | review | — | — |
| [SOL-044](./rules/SOL-044.md) | Hardcoded slot-time rate | high | medium | pattern | — | ✓ |
| [SOL-045](./rules/SOL-045.md) | Incremental Merkle insertion error | high | high | review | — | — |
| [SOL-046](./rules/SOL-046.md) | Hand-rolled dispatch bypasses framework guards | high | high | pattern | — | ✓ |
| [SOL-047](./rules/SOL-047.md) | Forged receipt token / mint | high | high | review | — | — |
| [SOL-048](./rules/SOL-048.md) | Default/zero value accepted as valid | high | high | review | — | — |
| [SOL-049](./rules/SOL-049.md) | Struct-padding / non-canonical flag read | high | high | pattern | — | ✓ |
| [SOL-050](./rules/SOL-050.md) | Serialization symmetry mismatch | high | high | review | — | — |
| [SOL-051](./rules/SOL-051.md) | Predictable on-chain entropy | high | high | pattern | — | ✓ |
| [SOL-052](./rules/SOL-052.md) | Token-2022 semantics assumed | high | high | review | — | — |

Maintained by [Jelleo](https://jelleo.com). MIT.
