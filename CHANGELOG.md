# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-05-26

### Changed (honest-provenance correction)

After the maintainer (Anatoly Yakovenko) triaged our bounty 5 submission at `percolator-cli#78` on 2026-05-26T01:24Z, his disposition of the 36 findings was substantially different from how v1.0.0 cited them. v1.0.0 implicitly claimed bounty credit for findings the maintainer classified as already-fixed-in-flight, engine-side (not reproduced at the wrapper layer), or latent (not currently exploitable). This release corrects the record.

- **SOL-001:** added the second confirmed-exploitable bounty win. The maintainer's triage confirmed bounty 5 F33 (RETIRE branch `now_slot` poison, fixed in `3fd9b1d`) is the sibling of `percolator-prog#107` (ACTIVATE branch, fixed in `6512fa1`). Same caller-controlled clock class, two code paths, both maintainer-acknowledged via Lean theorem-prover models. SOL-001 now correctly cites TWO bounty wins.
- **SOL-002:** corrected attribution. Originally framed as "Bounty 5 primary class" implying our credit. The `pnl_pos_bound_tot` insurance-drain pattern was publicly disclosed at `percolator-prog#104` by another researcher (not us). Reframed honestly — the pattern is real, included for cross-protocol relevance, but not a Jelleo bounty.
- **SOL-003:** removed F1 win-claim. Maintainer's triage: F1 was independently fixed in `0925ed4` before our submission was triaged. Rule retained — the pattern is real — but provenance reframed.
- **SOL-004:** removed F2 win-claim. Maintainer classified F2 as engine-side, not reproduced at the wrapper layer; recommended separate disclosure at `aeyakovenko/percolator`. Rule retained as engine-pattern guidance; separate disclosure pending.
- **SOL-005:** removed F12 win-claim. Maintainer classified F12 as latent — reachable only when the per-program 14-asset cap is lifted. Rule retained as forward-looking guidance.
- **README headline + badge:** "5 backed by real bounty wins" / "38 bounty findings" → accurate framing reflecting 2 confirmed wins (both under SOL-001) plus documented patterns for the remaining rules.
- **Claude-security-guidance.md:** "Honest provenance" paragraph added to the references section explaining what each rule cites and what it doesn't claim.

### Why this matters
The original v1.0.0 framing was wrong about which findings translated to paid bounty credit. The bug-class rules themselves remain — every one is a real Solana attack surface worth flagging — but provenance now matches what's actually paid + confirmed. Honesty over inflated credentials.

## [1.0.0] — 2026-05-26

### Added
- Initial release with 20 Solana security rules (SOL-001 through SOL-020)
- 15 deterministic patterns in `security-patterns.yaml` (regex/substring matchers for the per-edit check)
- 8KB threat model + review checklist + detailed rules in `claude-security-guidance.md`
- 5 paired vulnerable/fixed example snippets under `examples/`
- CI workflow validating YAML parse, MD ≤8KB, regex compilation, and reminder ≤1KB
- MIT license
- **Note:** the v1.0.0 release's specific bounty attributions for SOL-002/SOL-003/SOL-004/SOL-005 were superseded by the v1.0.1 honest-provenance correction after the maintainer's triage of `percolator-cli#78` clarified disposition. See v1.0.1 entry above.

[1.0.1]: https://github.com/Copenhagen0x/solana-security-guidance/releases/tag/v1.0.1
[1.0.0]: https://github.com/Copenhagen0x/solana-security-guidance/releases/tag/v1.0.0
