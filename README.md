# Solana Security Standard

> The **Solana Security Standard** — `SOL-0XX` rules distilled from $514M of real exploits, firing as you code in every AI tool (Claude Code, Codex, Cursor, Windsurf…), your editor, and CI. By the auditors who find them.

![SOL-001 firing on a vulnerable Solana program — Bounty 6 H2 case study](assets/sol-001-demo.png)

[![Solana Security Standard](https://img.shields.io/badge/Solana%20Security%20Standard-SOL--0XX-a855f7?labelColor=6d28d9)](https://github.com/Copenhagen0x/solana-security-standard)
[![CI](https://github.com/Copenhagen0x/solana-security-standard/actions/workflows/validate.yml/badge.svg)](https://github.com/Copenhagen0x/solana-security-standard/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.12.0-blue.svg)](CHANGELOG.md)
[![Bounty wins](https://img.shields.io/badge/bounty_wins-2_confirmed_(SOL--001)-orange)](https://jelleo.com/cycles)

The same SOL-0XX rules flag Solana-specific bugs while you code — caller-controlled clock values, cross-market state asymmetry, wrapper handlers that drift from engine logic, missing Anchor constraints, and **52 bug classes in all**, drawn from real audits.

**Works in:** Claude Code · Codex · Copilot · Cursor · Windsurf · Cline · Aider · any MCP client · the VS Code extension (Open VSX) · the CLI · Semgrep · GitHub Actions. Pick your surface below.

## Use it in Claude Code (30 seconds)

```bash
mkdir -p .claude && \
  curl -sL https://raw.githubusercontent.com/Copenhagen0x/solana-security-standard/main/plugin-guidance.md \
       -o .claude/claude-security-guidance.md && \
  curl -sL https://raw.githubusercontent.com/Copenhagen0x/solana-security-standard/main/security-patterns.yaml \
       -o .claude/security-patterns.yaml
```

`plugin-guidance.md` is the compact ≤8 KB plugin digest (every rule as a one-line cue, generated from the full [`claude-security-guidance.md`](claude-security-guidance.md)); it lands as the plugin's `.claude/claude-security-guidance.md`. Full per-rule detail is one MCP call (`list_solana_security_rules`) or one click (the master on GitHub) away.

Then make sure you have Anthropic's security-guidance plugin installed:

```text
/plugin install security-guidance@claude-plugins-official
/reload-plugins
```

Done. Open a Solana program file in Claude Code and the plugin will catch issues as you write.

*(This pulls from `main` with no integrity check. For supply-chain-sensitive use, see **Verified install** below.)*

Or install the whole standard as a **Claude Code plugin** (the MCP scan tool + a `/scan` command, auto-wired):

```text
/plugin marketplace add Copenhagen0x/solana-security-standard
/plugin install solana-security-standard@solana-security-standard
```

## Verified install (pin + checksum)

For CI or supply-chain-sensitive setups, **pin to a release tag and verify the download** against the published `CHECKSUMS.txt` instead of pulling `main`:

> **Note:** the `plugin-guidance.md` digest ships from **v1.11.0** onward. Pin the latest release tag in the flow below.

```bash
TAG=v1.12.0   # the digest ships from v1.11.0 on; older tags use claude-security-guidance.md directly
BASE="https://raw.githubusercontent.com/Copenhagen0x/solana-security-standard/$TAG"
tmp=$(mktemp -d) && cd "$tmp" && mkdir -p semgrep
curl -fsSL "$BASE/CHECKSUMS.txt"                          -o CHECKSUMS.txt
curl -fsSL "$BASE/plugin-guidance.md"                     -o plugin-guidance.md
curl -fsSL "$BASE/security-patterns.yaml"                 -o security-patterns.yaml
curl -fsSL "$BASE/semgrep/solana-security-standard.yaml"  -o semgrep/solana-security-standard.yaml
sha256sum -c CHECKSUMS.txt          # Linux — all three must print "OK"; aborts on any mismatch
# macOS (no sha256sum): shasum -a 256 -c CHECKSUMS.txt
mkdir -p "$OLDPWD/.claude"
cp security-patterns.yaml "$OLDPWD/.claude/"
cp plugin-guidance.md "$OLDPWD/.claude/claude-security-guidance.md"   # rename to the plugin's expected filename
# the verified semgrep ruleset stays in $tmp/semgrep/ — point `semgrep --config` at it or copy where you need it
```

Pinning to a tag freezes you to a known release (a tampered `main` can't reach you); the checksum confirms nothing was altered in transit. (Hashes are over the LF bytes GitHub serves — verify the *downloaded* files, not a CRLF local checkout.) Tags from `v1.9.1` on are SSH-signed — verify origin with `git verify-tag v1.12.0` (key + steps in [`SECURITY.md`](SECURITY.md)). *(Checksums and the in-repo allowed-signers can't defend against a full account compromise that rewrites both — the signed tag, verified out of band, is the origin check for that.)*

## Run it in CI — GitHub Action

Gate every pull request on the standard. The same SOL-0XX patterns run as a check, with inline annotations on the diff:

```yaml
# .github/workflows/solana-security.yml
name: Solana Security Standard
on: [pull_request]
permissions:
  contents: read
  security-events: write   # optional — enables inline PR annotations
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Copenhagen0x/solana-security-standard@v1
        with:
          paths: ./programs        # what to scan (default: .)
          # fail-on-findings: true # red X on findings (default)
          # upload-sarif: true     # GitHub code scanning (default)
          # min-tier: high         # noise floor: drop LOW-tier hygiene findings
          # baseline: .sss-baseline.json  # gate only on NEW findings (see cli/README)
```

Then show the world you adopt it — drop this badge in your README:

```md
[![Solana Security Standard](https://img.shields.io/badge/Solana%20Security%20Standard-SOL--0XX-a855f7?labelColor=6d28d9)](https://github.com/Copenhagen0x/solana-security-standard)
```

[![Solana Security Standard](https://img.shields.io/badge/Solana%20Security%20Standard-SOL--0XX-a855f7?labelColor=6d28d9)](https://github.com/Copenhagen0x/solana-security-standard)

## Run it from the CLI

```bash
npx @jelleo/solana-security-standard scan ./programs
```

Human, JSON, or SARIF output; exits non-zero on findings (so it gates any CI). Zero dependencies. Details in [`cli/`](cli/).

Every machine rule is scored against its canonical vulnerable/fixed example pair on every change — see [`BENCHMARK.md`](BENCHMARK.md) (generated, CI-enforced: a rule that stops detecting its bug, or starts flagging its fix, cannot merge).

## Run it in your editor — VS Code / Cursor / Windsurf

The [VS Code extension](extensions/vscode) shows SOL-0XX findings as inline warning squiggles as you
type, in Rust **and TypeScript/JS** files. Same engine as the CLI, 100% local (no telemetry). Install it
from **[Open VSX](https://open-vsx.org/extension/jelleo/solana-security-standard)** — works in Cursor,
Windsurf, and VSCodium; on stock VS Code, sideload the `.vsix` from [`extensions/vscode/`](extensions/vscode/)
(the Microsoft Marketplace listing is pending publisher verification). Details in [`extensions/vscode/`](extensions/vscode/).

## Run it with Semgrep

Already have a Semgrep pipeline? Point it at the [ported ruleset](semgrep):

```bash
semgrep --config https://raw.githubusercontent.com/Copenhagen0x/solana-security-standard/main/semgrep/solana-security-standard.yaml ./programs
```

The same SOL-0XX rules as `pattern-regex` rules. Details in [`semgrep/`](semgrep/).

## Use it in your AI coding agent — Codex · Copilot · Cursor · Windsurf · Cline · Aider

Most AI coding tools read a rules/instructions file. [`integrations/`](integrations/) ships the SOL-0XX
standard in each tool's native format — all generated from the one source — so your assistant writes
**and reviews** Solana/Anchor code against the rules. Copy the file for your tool (full matrix in
[`integrations/README.md`](integrations/README.md)):

| Tool | Copy into your repo |
| --- | --- |
| Codex / any `AGENTS.md` agent | `integrations/codex/AGENTS.md` |
| GitHub Copilot | `integrations/copilot/.github/copilot-instructions.md` |
| Cursor | `integrations/cursor/.cursor/` |
| Windsurf | `integrations/windsurf/.windsurf/` |
| Cline | `integrations/cline/.clinerules` |
| Aider | `integrations/aider/` (with an optional scanner lint command) |

## Use it via MCP — any MCP client

Prefer the [Model Context Protocol](mcp/)? The [MCP server](mcp/) gives any MCP client (Cline, Copilot,
Cursor, Claude, Windsurf) a `scan_solana_code` tool plus the full rule set — no file to copy:

```json
{ "mcpServers": { "solana-security-standard": { "command": "npx", "args": ["-y", "@jelleo/solana-security-mcp"] } } }
```

100% local, same scanner as the CLI. Details in [`mcp/`](mcp/).

## Learn from real exploits — the Solana Hacks Database

[`hacks/`](hacks/) maps real, disclosed Solana exploits to the SOL-0XX rule class each one falls under —
Wormhole, Mango Markets, Cashio, Crema, Nirvana, Cypher, Loopscale, and more (**$514M+** in documented
losses). Every entry is cited, and incidents no code rule can prevent (stolen keys, off-chain wallets)
are flagged as such rather than misattributed — the same honesty the rest of this repo holds itself to.
Browse the [database →](hacks/README.md).

## Every rule, explained — [`content/`](content/)

[`content/`](content/) is a standalone explainer for **all 52 rules**: what each catches, the fix, whether
it is machine-checkable or review-only, the real exploits in that class (cross-linked to the Hacks
Database), and a code example where one exists. One page per rule — all generated from the standard +
patterns + hacks + examples, so nothing drifts.

## Grow it — the [`disclosures/`](disclosures/) feed

The standard is a living one. [`disclosures/`](disclosures/) ingests a new Solana disclosure — a GitHub
Security Advisory, an Immunefi report, or a security-fix PR — and **proposes a candidate** Hacks-Database
entry with suggested SOL-0XX mappings for a human to verify. It never auto-writes (a cited DB only takes
reviewed entries). As an internal sanity check, the keyword classifier surfaces a labeled rule among its
ranked suggestions for every exploit already catalogued — self-consistency on our own root-cause text,
not a blind-accuracy or top-1 claim.

## What you get

52 rules: **49 on-chain** Solana program bug classes, plus **3 integrator / client-side rules (SOL-029–031)** for the TypeScript/web3.js that builds and sends transactions (bots, keepers, integrators). **SOL-001 covers two confirmed-exploitable bounty wins (the same caller-controlled `now_slot` class fixed in both the ACTIVATE and RETIRE branches of percolator).** Most of the rest are drawn from documented Solana audit patterns — some from our published disclosures (with maintainer triage classifications noted in the Source column), some from public bug-class taxonomy; the integrator trio came from a live buyback-worker report.

| Rule | Catches | Source |
|---|---|---|
| [SOL-001](claude-security-guidance.md#sol-001--unauthenticated-now_slot) | Unauthenticated `now_slot` / clock spoofing | **Bounty wins (2):** [percolator-prog#107](https://github.com/aeyakovenko/percolator-prog/issues/107) ACTIVATE + [percolator-cli#78](https://github.com/aeyakovenko/percolator-cli/issues/78) F33 RETIRE |
| [SOL-002](claude-security-guidance.md#sol-002--cross-market-state-asymmetry) | Cross-market state asymmetry → counter inflation | Documented public class ([percolator-prog#104](https://github.com/aeyakovenko/percolator-prog/issues/104)) — not our bounty |
| [SOL-003](claude-security-guidance.md#sol-003--wrapper-re-implements-engine) | Wrapper handler re-implements engine logic | Pattern from our [#78](https://github.com/aeyakovenko/percolator-cli/issues/78) F1 — maintainer fixed in-flight, not bountied |
| [SOL-004](claude-security-guidance.md#sol-004--penaltyhealth-terms-omitted) | Health/penalty terms omitted from calc | Pattern from our [#78](https://github.com/aeyakovenko/percolator-cli/issues/78) F2 — engine-side, separate disclosure pending |
| [SOL-005](claude-security-guidance.md#sol-005--anchor-resize-without-checks) | Anchor `realloc()` without guards | Latent pattern from our [#78](https://github.com/aeyakovenko/percolator-cli/issues/78) F12 — reachable when 14-asset cap lifted |
| [SOL-006](claude-security-guidance.md#sol-006--missing-signer-check) | Missing signer check on privileged handler | Generic Solana |
| [SOL-007](claude-security-guidance.md#sol-007--missing-owner-verification) | Missing `account.owner == program_id` | Generic Solana |
| [SOL-008](claude-security-guidance.md#sol-008--unverified-pda) | Unverified PDA derivation | Generic Solana |
| [SOL-009](claude-security-guidance.md#sol-009--cpi-without-authority-check) | CPI without authority check | Generic Solana |
| [SOL-010](claude-security-guidance.md#sol-010--reinit-attack) | Reinit attack via `init_if_needed` | Generic Solana |
| [SOL-011](claude-security-guidance.md#sol-011--lamport-drain-via-close) | Lamport drain via account closure | Generic Solana |
| [SOL-012](claude-security-guidance.md#sol-012--rent-exemption-check-missing) | Rent exemption check missing | Generic Solana |
| [SOL-013](claude-security-guidance.md#sol-013--token-program-id-confusion) | Token Program ID confusion (Token vs Token-2022) | Generic Solana |
| [SOL-014](claude-security-guidance.md#sol-014--unchecked-integer-arithmetic) | Unchecked integer arithmetic | Generic Solana |
| [SOL-015](claude-security-guidance.md#sol-015--anchor-constraints-missing) | Anchor `has_one`/`constraint=` missing | Generic Anchor |
| [SOL-016](claude-security-guidance.md#sol-016--bump-seed-unvalidated) | Bump seed not validated against canonical bump | Generic Solana |
| [SOL-017](claude-security-guidance.md#sol-017--raw-accountinfo-without-typed-deserialize) | Raw `AccountInfo` without typed deserialize | Generic Solana |
| [SOL-018](claude-security-guidance.md#sol-018--hardcoded-system-program-id) | Hardcoded System Program ID literal | Generic Solana |
| [SOL-019](claude-security-guidance.md#sol-019--missing-discriminator-check) | Missing discriminator check on deserialize | Generic Solana |
| [SOL-020](claude-security-guidance.md#sol-020--setauthority-without-verification) | `SetAuthority` without prior verification | Generic Solana |
| [SOL-021](claude-security-guidance.md#sol-021--terminal-op-gated-on-a-live-only-condition) | Terminal/close op gated on a live-only condition → funds lock | **Jelleo v16 audit F1** — maintainer fixed as "Finding C" |
| [SOL-022](claude-security-guidance.md#sol-022--write-only-impaired-counter) | Write-only "impaired" counter never decremented → funds encumbered | **Jelleo v16 audit F2** — [percolator#74](https://github.com/aeyakovenko/percolator/issues/74), code-confirmed |
| [SOL-023](claude-security-guidance.md#sol-023--feepenalty-rounds-toward-the-user) | Fee/penalty rounds toward the user → evasion + leakage | **Jelleo v16 audit F3** (Low) |
| [SOL-024](claude-security-guidance.md#sol-024--stale--unchecked-oracle-price) | Stale / unchecked Pyth/Switchboard oracle price | Generic Solana DeFi |
| [SOL-025](claude-security-guidance.md#sol-025--sysvar-read-by-raw-deserialize) | Sysvar read by raw deserialize (not `Clock::get()`) | Generic Solana |
| [SOL-026](claude-security-guidance.md#sol-026--duplicate-mutable-account-native-programs) | Duplicate mutable account unchecked (native + Anchor `AccountLoader`/`remaining_accounts`) | Generic Solana |
| [SOL-027](claude-security-guidance.md#sol-027--unvalidated-remaining_accounts) | Unvalidated `remaining_accounts` | Generic Solana |
| [SOL-028](claude-security-guidance.md#sol-028--missing-slippage--min-out-bound) | Missing slippage / min-out bound | Generic Solana DeFi |
| [SOL-029](claude-security-guidance.md#sol-029--preflight-simulation-disabled) | Preflight simulation disabled (`skipPreflight: true`) on a mainnet send | **Integrator** — live buyback-worker report (TS/web3.js) |
| [SOL-030](claude-security-guidance.md#sol-030--static-priority-fee) | Hardcoded priority fee — no congestion awareness | **Integrator** — live buyback-worker report (TS/web3.js) |
| [SOL-031](claude-security-guidance.md#sol-031--stale-jupiter-quote) | Jupiter quote consumed without `contextSlot` freshness | **Integrator** — live buyback-worker report (TS/web3.js) |
| [SOL-032](claude-security-guidance.md#sol-032--decimals-assumed-not-read) | Decimals assumed (hardcoded scale) instead of read from the mint | Jelleo audit pattern — the decimals/accounting loss-of-funds class (review-only: a scale literal isn't machine-distinguishable) |
| [SOL-033](claude-security-guidance.md#sol-033--stale-account-read-after-cpi) | Account field read after a CPI without `reload()` — stale-state decisions | Generic Anchor (documented reload footgun) |
| [SOL-034](claude-security-guidance.md#sol-034--manual-lamport-mutation) | Manual lamport mutation desyncs the program's internal ledger | Generic Solana |
| [SOL-035](claude-security-guidance.md#sol-035--instructions-sysvar-substitution) | Instructions sysvar read unpinned — forged introspection spoofs a precompile/CPI-origin check | Generic Solana (known precompile-bypass class) |
| [SOL-036](claude-security-guidance.md#sol-036--ata-derivation-unpinned) | Token account trusted as an ATA without canonical (owner, mint) derivation | Generic Solana SPL (review-only) |
| [SOL-037](claude-security-guidance.md#sol-037--arbitrary-cpi-target) | CPI callee program id unpinned — call redirected to an attacker program | Generic Solana (review-only; the callee-side gap SOL-009 doesn't cover) |
| [SOL-038](claude-security-guidance.md#sol-038--pda-seed-collision) | Unpinned PDA seed boundaries — two distinct accounts derive the same address | Public Solana bug-class taxonomy (machine) |
| [SOL-039](claude-security-guidance.md#sol-039--asymmetric-partial-cpi-state) | Swallowed fund-moving CPI `Result` leaves half-applied state | Public Solana bug-class taxonomy (machine) |
| [SOL-040](claude-security-guidance.md#sol-040--credit-from-requested-not-measured-token-2022) | Crediting the requested amount, not the measured balance delta (Token-2022 fee/hook) | Public Solana bug-class taxonomy (review-only) |
| [SOL-041](claude-security-guidance.md#sol-041--forced-balance--supply-desync) | Forced token balance / supply desyncs internal accounting | Public Solana bug-class taxonomy (review-only) |
| [SOL-042](claude-security-guidance.md#sol-042--unbounded-account-iteration-compute-dos) | Unbounded loop over caller-controlled `remaining_accounts` — CU-limit DoS | Public Solana bug-class taxonomy (machine) |
| [SOL-043](claude-security-guidance.md#sol-043--unbounded-storage--slot-exhaustion-griefing) | Attacker-grown storage / slot exhaustion bricks an instruction | Public Solana bug-class taxonomy (review-only) |
| [SOL-044](claude-security-guidance.md#sol-044--hardcoded-slot-time-rate) | Hardcoded ~400ms slot time — interest/vesting drifts from wall-clock | Public Solana bug-class taxonomy (machine) |
| [SOL-045](claude-security-guidance.md#sol-045--incremental-merkle-insertion-error) | Off-by-one in incremental Merkle tree insertion | Public Solana bug-class taxonomy (review-only) |
| [SOL-046](claude-security-guidance.md#sol-046--hand-rolled-dispatch-bypasses-framework-guards) | Raw-byte instruction dispatcher skips Anchor's account guards | Public Solana bug-class taxonomy (machine) |
| [SOL-047](claude-security-guidance.md#sol-047--forged-receipt-token--mint) | Receipt token/mint not pinned — forged redemption | Public Solana bug-class taxonomy (review-only) |
| [SOL-048](claude-security-guidance.md#sol-048--defaultzero-value-accepted-as-valid) | Zeroed/default pubkey or value accepted as authorized | Public Solana bug-class taxonomy (review-only) |
| [SOL-049](claude-security-guidance.md#sol-049--struct-padding--non-canonical-flag-read) | Hand-rolled zero-copy reads a non-canonical flag / padding byte | Public Solana bug-class taxonomy (machine) |
| [SOL-050](claude-security-guidance.md#sol-050--serialization-symmetry-mismatch) | serialize/deserialize asymmetry corrupts or forges state | Public Solana bug-class taxonomy (review-only) |
| [SOL-051](claude-security-guidance.md#sol-051--predictable-on-chain-entropy) | On-chain-observable value seeds a draw — grindable / leader-steerable | Public Solana bug-class taxonomy (machine) |
| [SOL-052](claude-security-guidance.md#sol-052--token-2022-semantics-assumed) | Token-2022 extensions (transfer hook / fee / freeze) assumed absent | Public Solana bug-class taxonomy (review-only) |

## Why these rules — honest provenance

We disclose exactly where each rule came from. Some are confirmed-exploitable bounty wins; some are documented patterns we surfaced but the maintainer classified differently in triage. We list both kinds because all of them are real Solana attack surfaces worth flagging — but we don't claim bounty credit we didn't earn.

- **SOL-001 — TWO confirmed-exploitable bounty wins (same class, two code paths).** ACTIVATE branch: [percolator-prog#107](https://github.com/aeyakovenko/percolator-prog/issues/107), fixed in `6512fa1`. RETIRE branch: [percolator-cli#78 F33](https://github.com/aeyakovenko/percolator-cli/issues/78), fixed in `3fd9b1d`. Both maintainer-acknowledged via Lean theorem-prover models. Our suggested `authenticated_slot_or_fallback` patch shipped verbatim.
- **SOL-002 — public class, not our bounty.** The cross-market `pnl_pos_bound_tot` inflation class was publicly disclosed at [percolator-prog#104](https://github.com/aeyakovenko/percolator-prog/issues/104) by another researcher. Included because the pattern is reproducible across perp-DEX programs.
- **SOL-003, SOL-004, SOL-005 — patterns from our bounty 5 disclosure.** All three were in our [#78](https://github.com/aeyakovenko/percolator-cli/issues/78) submission (36 findings total). Maintainer triage outcomes: F1 already fixed in `0925ed4` before triage; F2 engine-side (separate disclosure pending at `aeyakovenko/percolator`); F12 latent (reachable when the 14-asset cap is lifted). Real Solana patterns worth flagging in future code, none paid as new bounties.

- **SOL-021, SOL-022, SOL-023 — patterns from our percolator v16 engine audit.** F1 (terminal-close deadlock) was fixed by the maintainer as "Finding C". F2 (write-only impaired insurance counter) is disclosed at [percolator#74](https://github.com/aeyakovenko/percolator/issues/74) — code-confirmed, not yet reproduced on-chain. F3 (fee rounding) is Low. Code-analysis patterns, not claimed as paid bounties.

The remaining rules (SOL-006 through SOL-020, plus SOL-024 through SOL-028) cover documented Solana / DeFi audit patterns — signer/owner/PDA verification, Anchor constraints, CPI authority, lamport drains, Token Program ID confusion, integer overflow, oracle staleness, slippage bounds, etc. Standard auditor checklist territory.

All published cycle reports: [jelleo.com/cycles](https://jelleo.com/cycles)

## How it works

The standard is two source files — a YAML of deterministic patterns and a Markdown threat-model + rule catalog — plus a self-contained scanner. **Every surface runs the same rules:** the CLI, GitHub Action, editor extension, MCP server, and Semgrep apply them directly. In **Claude Code** specifically, Anthropic's [security-guidance plugin](https://code.claude.com/docs/en/security-guidance) reads the two files and reviews edits at three layers:

1. **On each file edit** — fast pattern match (no model call). Reads `.claude/security-patterns.yaml` for regex/substring rules. **Our file provides 30 deterministic patterns.**
2. **At the end of each turn** — background model review of the full diff. Reads `.claude/claude-security-guidance.md` for semantic guidance. **Our file provides the Solana threat model + 52-rule catalog + review checklist.**
3. **On each commit Claude makes** — deeper agentic review that reads surrounding code. Uses the same guidance file.

Every time a rule fires, the reminder text includes the rule ID (e.g. `Jelleo SOL-001:`) and a link back to this repo so you can see the underlying bounty case study.

## Examples

The [`examples/`](examples/) directory contains **30 paired vulnerable/fixed snippets — one for every machine-checkable rule** (Rust on-chain; TypeScript for the integrator rules). They're self-tested: the scanner must fire on each `vulnerable` file and clear on each `fixed` one, so they can't drift from the rules. Useful for understanding a bug class before reading the rule definition.

## Contributing

PRs welcome — especially:
- New rules drawn from your own audits (please include a reference to the disclosed finding)
- Tightened regexes that reduce false positives
- Additional vulnerable/fixed example pairs

Open an issue first if you're proposing a new rule category. Keep rules focused: each one should catch a single bug class with a low false-positive rate. Quality over quantity.

## Versioning

This repo follows [Semantic Versioning](https://semver.org/). Pin a tagged release rather than `main` (the `plugin-guidance.md` digest ships from **v1.11.0** onward):

```bash
curl -sL https://raw.githubusercontent.com/Copenhagen0x/solana-security-standard/v1.12.0/plugin-guidance.md \
     -o .claude/claude-security-guidance.md
```

A bare `curl` like this has no integrity check — for checksum + signed-tag verification use the [**Verified install**](#verified-install-pin--checksum) flow above.

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

## License

[MIT](LICENSE) — use anywhere, attribution appreciated.

## Maintained by

[**Jelleo**](https://jelleo.com) — continuous Solana program audits. Every cycle is Ed25519-signed and Merkle-rooted; all artifacts public at [jelleo.com/cycles](https://jelleo.com/cycles).

Each new bounty cycle we publish adds rules to this guidance. If you want a deeper audit of your Solana program, see [jelleo.com](https://jelleo.com).
