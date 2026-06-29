# Hacks Database — schema

[`hacks.json`](./hacks.json) is the source of truth. [`README.md`](./README.md) is generated from it by [`scripts/sync-hacks.js`](./scripts/sync-hacks.js) — never edit the README by hand.

## Top level

```json
{
  "version": "1.0.0",
  "description": "…",
  "hacks": [ /* entries */ ]
}
```

## Entry fields

| Field | Type | Rule |
| --- | --- | --- |
| `id` | string | Unique lowercase slug `[a-z0-9-]+`, e.g. `mango-markets-2022-10`. Used as the README anchor. |
| `name` | string | Short human title of the bug. |
| `protocol` | string | Protocol/product name. |
| `date` | string | `YYYY-MM-DD` of the exploit. Must be a real date, not in the future. |
| `loss_usd` | integer | Best-estimate USD lost (≥ 0). Approximate figures are fine; cite the source. |
| `category` | string | One of: `oracle-manipulation`, `account-validation`, `missing-authority`, `accounting`, `key-compromise`, `off-chain-wallet`. |
| `code_preventable` | boolean | `true` if an on-chain code rule could have flagged the root cause; `false` for stolen-key / off-chain / insider failures. |
| `sol_rules` | string[] | The `SOL-0XX` rule class(es) this exploit falls under. Each ID must exist in [`claude-security-guidance.md`](../claude-security-guidance.md). |
| `root_cause` | string | 2–3 sentences, technical, on what actually went wrong. |
| `rule_link` | string | One sentence on *why* the listed rule(s) map — or, for out-of-scope entries, why no code rule applies. |
| `sources` | string[] | ≥ 1 `https://` URL to a credible post-mortem / report. |

## Honesty invariants (enforced by the validator)

- `code_preventable: true` ⟺ `sol_rules` is non-empty. A mapped exploit must name its rule class; an out-of-scope incident must **not** claim one.
- Every `sol_rules` ID is cross-checked against the 52 rules in `claude-security-guidance.md`. A typo or a non-existent rule fails CI.
- A mapping means "this is the rule class that flags this bug," **not** that any tool would have auto-fixed it. We never claim credit a rule did not earn — the same standard the rest of this repo holds itself to.
- The free-text fields (`name`, `protocol`, `root_cause`, `rule_link`) render **verbatim** into the public README, so the validator rejects `<`, `>`, `|`, `](`, newlines, and bare `http(s)://` URLs in them (they'd become live links, broken tables, or raw HTML). Put every URL in `sources` — that's the linked field; don't inline links in prose.

## Regenerate / validate

```bash
node scripts/sync-hacks.js          # validate hacks.json + rewrite README.md
node scripts/sync-hacks.js --check  # validate + fail if README.md is stale (CI)
node --test                          # run the test suite
```
