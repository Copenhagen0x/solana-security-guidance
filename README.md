# Solana Security Guidance

> Solana security rules for Anthropic's Claude Code security-guidance plugin. By the team that finds the bugs.

![SOL-001 firing on a vulnerable Solana program — Bounty 6 H2 case study](assets/sol-001-demo.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG.md)
[![Powered by](https://img.shields.io/badge/powered_by-38_bounty_findings-orange)](https://jelleo.com/cycles)

Drop these two files into your Solana project's `.claude/` directory and your IDE will flag Solana-specific bugs while you code — caller-controlled clock values, cross-market state asymmetry, wrapper handlers that drift from engine logic, missing Anchor constraints, and 16 more bug classes drawn from real audits.

## Install (30 seconds)

```bash
mkdir -p .claude && \
  curl -sL https://raw.githubusercontent.com/Copenhagen0x/solana-security-guidance/main/claude-security-guidance.md \
       -o .claude/claude-security-guidance.md && \
  curl -sL https://raw.githubusercontent.com/Copenhagen0x/solana-security-guidance/main/security-patterns.yaml \
       -o .claude/security-patterns.yaml
```

Then make sure you have Anthropic's security-guidance plugin installed:

```text
/plugin install security-guidance@claude-plugins-official
/reload-plugins
```

Done. Open a Solana program file in Claude Code and the plugin will catch issues as you write.

## What you get

20 rules covering the dominant Solana program bug classes. The 5 headline rules trace to real published bounty findings; the remaining 15 cover the rest of the Solana attack surface (Anchor constraints, signer checks, PDA verification, CPI authority, lamport drains, etc.).

| Rule | Catches | Source |
|---|---|---|
| [SOL-001](claude-security-guidance.md#sol-001--unauthenticated-now_slot) | Unauthenticated `now_slot` / clock spoofing | Bounty 6 H2 ([percolator-prog#107](https://github.com/aeyakovenko/percolator-prog/issues/107)) |
| [SOL-002](claude-security-guidance.md#sol-002--cross-market-state-asymmetry) | Cross-market state asymmetry → counter inflation | Bounty 5 primary class |
| [SOL-003](claude-security-guidance.md#sol-003--wrapper-re-implements-engine) | Wrapper handler re-implements engine logic | Bounty 5 F1 ([percolator-cli#78](https://github.com/aeyakovenko/percolator-cli/issues/78)) |
| [SOL-004](claude-security-guidance.md#sol-004--penaltyhealth-terms-omitted) | Health/penalty terms omitted from calc | Bounty 5 F2 (percolator-cli#78) |
| [SOL-005](claude-security-guidance.md#sol-005--anchor-resize-without-checks) | Anchor `realloc()` without guards | Bounty 5 F12 |
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

## Why these rules

Each headline rule traces to a real bug we found and disclosed:

- **SOL-001** → Bounty 6 H2, accepted + fixed by Toly at [percolator-prog#107](https://github.com/aeyakovenko/percolator-prog/issues/107). Our suggested patch (`authenticated_slot_or_fallback`) shipped verbatim.
- **SOL-002** → The cross-market `pnl_pos_bound_tot` inflation class that drained `header.insurance`. We documented this surface in our percolator audits.
- **SOL-003, SOL-004, SOL-005** → 3 of the 36 findings in our Bounty 5 final disclosure at [percolator-cli#78](https://github.com/aeyakovenko/percolator-cli/issues/78) (2 Critical + 17 High + 12 Medium + 5 Low).

The 15 generic rules cover the rest of the Solana attack surface — every common bug class an auditor checks for. Together they give the Claude Code plugin enough Solana-specific context to catch issues before they reach a pull request.

All published cycle reports: [jelleo.com/cycles](https://jelleo.com/cycles)

## How it works

Anthropic's [security-guidance plugin](https://code.claude.com/docs/en/security-guidance) reviews Claude's code edits at three layers:

1. **On each file edit** — fast pattern match (no model call). Reads `.claude/security-patterns.yaml` for regex/substring rules. **Our file provides 15 deterministic patterns.**
2. **At the end of each turn** — background model review of the full diff. Reads `.claude/claude-security-guidance.md` for semantic guidance. **Our file provides the Solana threat model + 20-item review checklist.**
3. **On each commit Claude makes** — deeper agentic review that reads surrounding code. Uses the same guidance file.

Every time a rule fires, the reminder text includes the rule ID (e.g. `Jelleo SOL-001:`) and a link back to this repo so you can see the underlying bounty case study.

## Examples

The [`examples/`](examples/) directory contains 5 paired vulnerable/fixed Solana snippets — one per headline rule. Useful for understanding the bug class before reading the rule definition.

## Contributing

PRs welcome — especially:
- New rules drawn from your own audits (please include a reference to the disclosed finding)
- Tightened regexes that reduce false positives
- Additional vulnerable/fixed example pairs

Open an issue first if you're proposing a new rule category. Keep rules focused: each one should catch a single bug class with a low false-positive rate. Quality over quantity.

## Versioning

This repo follows [Semantic Versioning](https://semver.org/). Tagged releases are safe to pin in your `.claude/` directory:

```bash
curl -sL https://raw.githubusercontent.com/Copenhagen0x/solana-security-guidance/v1.0.0/claude-security-guidance.md \
     -o .claude/claude-security-guidance.md
```

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

## License

[MIT](LICENSE) — use anywhere, attribution appreciated.

## Maintained by

[**Jelleo**](https://jelleo.com) — continuous Solana program audits. Every cycle is Ed25519-signed and Merkle-rooted; all artifacts public at [jelleo.com/cycles](https://jelleo.com/cycles).

Each new bounty cycle we publish adds rules to this guidance. If you want a deeper audit of your Solana program, see [jelleo.com](https://jelleo.com).
