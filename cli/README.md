# solana-security-standard (CLI)

Scan Solana / Anchor Rust code against the **[Solana Security Standard](https://github.com/Copenhagen0x/solana-security-standard)** (SOL-0XX) — the deterministic per-edit rules, run from your terminal or CI. Zero runtime dependencies.

```bash
# one-off, no install
npx @jelleo/solana-security-standard scan ./programs

# or install
npm i -g @jelleo/solana-security-standard
solana-security-standard scan ./programs
```

## Usage

```
solana-security-standard scan [paths...] [options]

  -f, --format <text|json|sarif>  output format (default: text)
  -o, --output <file>             write to a file instead of stdout
  -p, --patterns <rules.json>     custom rules file (default: bundled)
      --no-fail                   always exit 0 (report only)
  -q, --quiet                     text mode: findings only, no banner
      --no-color                  disable ANSI color
  -v, --version                   print version
  -h, --help                      show help
```

**Exit codes:** `0` no findings (or `--no-fail`) · `1` findings present · `2` usage/error.

## Examples

```bash
solana-security-standard scan ./programs              # human-readable
solana-security-standard scan . -f json -o report.json
solana-security-standard scan . -f sarif -o results.sarif   # for GitHub code scanning
solana-security-standard scan . --no-fail             # report without failing CI
```

## What it flags

The 20 deterministic SOL-0XX patterns — 17 on-chain Rust checks (caller-controlled `now_slot`, missing signer/owner checks, unchecked arithmetic, `init_if_needed` reinit, raw sysvar deserialize, and more) plus 3 integrator checks for the transaction-sending TypeScript/JS (preflight disabled, static priority fee, stale Jupiter quote). These are **fast, advisory tripwires** — a finding means "look here," not "definitely a bug." The on-chain patterns skip off-chain code (`client/`, `cli/`, `offchain/`, `sdk/`, `tests/`) where they're harmless; the integrator patterns target the TS/JS that builds and sends transactions. The full semantic review lives in the [Claude Code plugin](https://github.com/Copenhagen0x/solana-security-standard) and in a [Jelleo audit](https://jelleo.com).

## Rules source of truth

The patterns come from [`security-patterns.yaml`](../security-patterns.yaml) (the same file the Claude Code plugin uses). `rules.json` is the pre-parsed form this scanner reads at runtime; regenerate it with `npm run sync` after editing the YAML. CI verifies the two stay in sync.

## GitHub Action

The same engine ships as a drop-in CI check — see the repo README for the **Solana Security Standard ✓** badge setup.

MIT · [Jelleo](https://jelleo.com)
