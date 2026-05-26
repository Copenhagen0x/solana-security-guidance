# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-26

### Added
- Initial release with 20 Solana security rules (SOL-001 through SOL-020)
- 15 deterministic patterns in `security-patterns.yaml` (regex/substring matchers for the per-edit check)
- 8KB threat model + review checklist + detailed rules in `claude-security-guidance.md`
- 5 headline rules backed by published bounty findings:
  - SOL-001: Unauthenticated `now_slot` (Bounty 6 H2, percolator-prog#107)
  - SOL-002: Cross-market state asymmetry (Bounty 5 primary class)
  - SOL-003: Wrapper re-implements engine (Bounty 5 F1, percolator-cli#78)
  - SOL-004: Penalty/health terms omitted (Bounty 5 F2, percolator-cli#78)
  - SOL-005: Anchor resize without checks (Bounty 5 F12, percolator-cli#78)
- 15 generic Solana hygiene rules covering signer checks, owner verification, PDA validation, CPI authority, reinit attacks, lamport drains, Token Program ID confusion, integer overflow, Anchor constraints, bump validation, discriminator checks, and `SetAuthority` verification
- 5 paired vulnerable/fixed example snippets under `examples/`
- CI workflow validating YAML parse, MD ≤8KB, regex compilation, and reminder ≤1KB
- MIT license

[1.0.0]: https://github.com/Copenhagen0x/solana-security-guidance/releases/tag/v1.0.0
