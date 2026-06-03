# Solana Security Standard — Semgrep ruleset

A [Semgrep](https://semgrep.dev) port of the Solana Security Standard (SOL-0XX) — the same
SOL-0XX bug-class rules that power the [CLI, GitHub Action](../cli), the
[VS Code extension](../extensions/vscode), and the Claude Code plugin, expressed as Semgrep
`pattern-regex` rules so you can run them in any Semgrep-based pipeline.

## Use it

```bash
# from a checkout of this repo
semgrep --config semgrep/solana-security-standard.yaml path/to/program

# or straight from GitHub, no clone needed
semgrep --config https://raw.githubusercontent.com/Copenhagen0x/solana-security-guidance/main/semgrep/solana-security-standard.yaml path/to/program
```

Every rule is scoped to Rust (`languages: [rust]`) and matches with a raw regex, so it needs no
working Rust parse — it still fires on Anchor macro code that Semgrep's grammar can't fully parse.
Findings are `WARNING` / `confidence: LOW`: a hit means **"look here,"** not "definitely a bug."
Off-chain directories (`client/`, `cli/`, `offchain/`, `sdk/`, `tests/`) are excluded per rule
where the on-chain pattern is harmless there — matching the scanner exactly.

## Generated — do not edit by hand

`solana-security-standard.yaml` is compiled from the single source of truth,
[`../security-patterns.yaml`](../security-patterns.yaml), by
[`../cli/scripts/sync-semgrep.js`](../cli/scripts/sync-semgrep.js):

```
security-patterns.yaml  (source of truth)
   ├──> cli/rules.json                       → the zero-dependency scanner (CLI/Action/editor)
   └──> semgrep/solana-security-standard.yaml → this ruleset
```

Regenerate after editing the YAML: `npm --prefix cli run sync:semgrep`. CI fails if the committed
file drifts (`sync-semgrep.js --check`) and runs `semgrep --validate` so a rule that Semgrep's
RE2 engine can't compile is caught on every change.

### One documented divergence (SOL-011)

The scanner's SOL-011 regex balances nested parens in `#[account(...)]`. Semgrep's RE2 engine
expands bounded repetitions and rejects that pattern as *"regular expression is too large,"* so the
Semgrep rule uses a delimiter-bounded window instead. It flags the same real
`#[account(close = …)]` attributes (including long multi-line ones), trading the scanner's exact
paren-balancing for slightly broader matching. The reason is recorded in that rule's
`metadata.note`.

## How it fits

- **In your editor** — the [VS Code extension](../extensions/vscode) (live squiggles, also Cursor/Windsurf).
- **In Claude Code** — the security-guidance plugin (semantic review).
- **In CI** — this ruleset, the [GitHub Action](../cli), or `npx @jelleo/solana-security-standard`.
- **A full audit** — [jelleo.com](https://jelleo.com).

100% local — Semgrep runs the rules on your machine. MIT · [Jelleo](https://jelleo.com)
