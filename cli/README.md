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
  -r, --root <dir>                base for reported paths
      --no-fail                   always exit 0 (report only)
      --min-tier <high|low>       noise floor: high drops LOW-tier findings
      --baseline <file>           report only findings NOT in this baseline
                                  (suppressed count always shown; a bad
                                  baseline exits 2, never scans without it)
      --write-baseline <file>     record current findings as a baseline
  -q, --quiet                     text mode: findings only, no banner
      --no-color                  disable ANSI color
  -v, --version                   print version
  -h, --help                      show help
```

**Exit codes:** `0` no findings (or `--no-fail`) · `1` findings present · `2` usage/error, or an INCOMPLETE scan (finding cap hit).

## Examples

```bash
solana-security-standard scan ./programs              # human-readable
solana-security-standard scan . -f json -o report.json
solana-security-standard scan . -f sarif -o results.sarif   # for GitHub code scanning
solana-security-standard scan . --no-fail             # report without failing CI
```

## Adopting on an existing codebase — baseline

Day one on a repo with existing findings, without a red gate — and without hiding anything:

```bash
# 1. Record what exists today (reviewable file; commit it)
solana-security-standard scan . --write-baseline .sss-baseline.json --no-fail

# 2. From now on, gate only on NEW findings
solana-security-standard scan . --baseline .sss-baseline.json
```

Findings are matched by their stable 128-bit `fingerprint` (rule + file + normalized matched code), so moving or reformatting code does **not** re-alert an acknowledged finding — only genuinely new ones gate. The baseline file holds a human-readable snapshot per entry (rule, file, line, match) — **enforced at load: an entry stripped of its snapshot is rejected** — so **review baseline diffs in PRs like code**: an entry added to hide a new bug is visible as exactly what it suppresses. Suppression is never silent — every format reports how many findings the baseline removed, and entries that no longer match anything are flagged stale so the file doesn't rot. Refresh with both flags together: `--baseline old.json --write-baseline new.json` keeps prior acknowledgments and adds current findings.

Use the **same scan path and `-r` root** when writing and applying a baseline: fingerprints include the reported file path, so a different root changes every path and the baseline reads as all-stale (everything looks new — a loud false red, never a silent miss). A baseline cannot be written from an INCOMPLETE scan (finding cap hit) — that exits 2 rather than recording a partial picture.

In CI, treat the baseline file like a security control: add it to `CODEOWNERS` so a change to it always requires a designated reviewer — the file lives in the scanned checkout, so a PR can edit it in the same diff that adds code.

## What it flags

The 30 deterministic SOL-0XX patterns — 27 on-chain Rust checks (caller-controlled `now_slot`, missing signer/owner checks, unchecked arithmetic, `init_if_needed` reinit, raw sysvar deserialize, and more) plus 3 integrator checks for the transaction-sending TypeScript/JS (preflight disabled, static priority fee, stale Jupiter quote). These are **fast, advisory tripwires** — a finding means "look here," not "definitely a bug." The on-chain patterns skip off-chain code (`client/`, `cli/`, `offchain/`, `sdk/`, `tests/`) where they're harmless; the integrator patterns target the TS/JS that builds and sends transactions. The full semantic review lives in the [Claude Code plugin](https://github.com/Copenhagen0x/solana-security-standard) and in a [Jelleo audit](https://jelleo.com).

## Rules source of truth

The patterns come from [`security-patterns.yaml`](../security-patterns.yaml) (the same file the Claude Code plugin uses). `rules.json` is the pre-parsed form this scanner reads at runtime; regenerate it with `npm run sync` after editing the YAML. CI verifies the two stay in sync.

## GitHub Action

The same engine ships as a drop-in CI check — see the repo README for the **Solana Security Standard ✓** badge setup.

MIT · [Jelleo](https://jelleo.com)
