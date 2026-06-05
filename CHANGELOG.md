# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] — 2026-06-05

### Added — integrator / client-side rules (SOL-029–031)

- **The standard's first client-side layer: three rules for the TypeScript/web3.js that builds and sends transactions** (bots, keepers, integrators), complementing the 28 on-chain (Rust) rules.
  - **SOL-029 — preflight simulation disabled.** Flags `skipPreflight: true` on a mainnet send — a blind send eats reverts/fees and can desync a live bot. Fix: keep preflight on, or `simulateTransaction()` + assert `err === null` first.
  - **SOL-030 — static priority fee.** Flags a hardcoded `microLamports` compute-unit price — underpays in congestion (tx never lands) or overpays when idle. Fix: derive from `getRecentPrioritizationFees()` and clamp.
  - **SOL-031 — stale Jupiter quote.** Flags a Jupiter quote consumed without a `contextSlot` freshness check → worse fill + MEV/sandwich exposure. Fix: refetch/reject when `contextSlot` lags the current slot.
- **Engine: the Semgrep generator is now per-rule language-aware.** A new optional `languages` field in [`security-patterns.yaml`](security-patterns.yaml) (absent ⇒ `rust`, the on-chain default) sets `languages` in the generated Semgrep ruleset; the zero-dependency scanner already keys off per-rule `paths`. Integrator rules scan `**/*.{ts,tsx,js,mjs,cjs}`; on-chain rules still `**/*.rs`. The 28 existing rules regenerate byte-identical.
- **The VS Code extension now activates on TypeScript/JavaScript too** (was Rust-only), so the integrator rules surface inline; per-file rule selection still comes from each rule's `paths`. Extension `1.0.0 → 1.1.0`.
- **20 of 31 rules now carry a deterministic pattern** (was 17 of 28). All surfaces — CLI, GitHub Action, Semgrep, VS Code, MCP, the AI-agent rules files, and the content explainer pages — regenerate from the two sources of truth. Provenance: a live integrator (Solana buyback worker) who ran the ruleset and surfaced the three client-side bugs.
- Reviewed to 0 Critical/High/Medium by code-reviewer + paranoid-goober + threat-modeler (all three, to convergence — they caught the `__tests__`/`.jsx` coverage gaps, the `microLamports: 0` false positive, and three stale-count CI tests, all fixed and re-verified). Version 1.9.0.

## [1.8.1] — 2026-06-03

### Fixed — security hardening (adversarial review of the overnight work)

- **Case-insensitive path matching ([`cli/src/glob.js`](cli/src/glob.js)).** The off-chain/test exclude globs (`**/tests/**`, `**/client/**`, …) and the `**/*.rs` include matched case-sensitively, so a `Tests/` directory was scanned as on-chain (false positives) and a `Lib.RS` file was silently never scanned. Matching is now case-insensitive across all three engine copies (CLI, MCP, VS Code extension), each with a lock-in test.
- **MCP server ([`mcp/`](mcp)).** JSON-RPC batches are bounded at 100 items (a huge batch can no longer block the event loop); an all-notification over-cap batch correctly gets no reply (JSON-RPC 2.0 §6); `isTestPath` is case-insensitive so the test-path advisory note fires for mixed-case paths too.
- **Hacks-Database validator ([`hacks/scripts/sync-hacks.js`](hacks/scripts/sync-hacks.js)).** Free-text fields that render verbatim into the public README now reject `<`, `>`, `|`, `](`, newlines, and bare URLs, so a bad entry can't inject HTML, a spoof link, a broken table, or an autolink (documented in [`hacks/SCHEMA.md`](hacks/SCHEMA.md)).
- Reviewed to 0 Critical/High/Medium by code-reviewer + paranoid-goober + threat-modeler (3 rounds to convergence — the threat-modeler found 2 Mediums the other two missed, plus a third glob copy in the extension). Version 1.8.1.

## [1.8.0] — 2026-06-03

### Added — disclosure feed ([`disclosures/`](disclosures))

- **A pipeline that helps grow the standard from new disclosures.** [`disclosures/`](disclosures) normalizes a GitHub Security Advisory, an Immunefi report, or a security-fix PR ([`adapters.js`](disclosures/scripts/adapters.js)) into one shape, scores it against per-rule keyword signatures derived from the 28 rules ([`classify.js`](disclosures/scripts/classify.js)), and emits a **candidate** Hacks-Database entry with suggested `SOL-0XX` mappings ([`ingest.js`](disclosures/scripts/ingest.js)).
- **Human-in-the-loop by design:** it never writes to `hacks/hacks.json` — a cited database only takes verified, reviewed entries. Candidates carry a `_review` block and emit in the exact `hacks.json` shape; a test asserts a fixture-derived candidate passes the real Hacks-DB validator, so a *reviewed* candidate drops straight in.
- **Self-consistency check (not a blind-accuracy claim):** a test confirms a labeled rule appears among the classifier's ranked suggestions for every catalogued exploit (bar ≥70%; top-1 is 7/8) — an internal check, since the root-cause text and the signatures are both authored here — and that every off-chain / key-compromise incident is guessed not-code-preventable. New `disclosures` CI job (13 tests, no network). Version 1.8.0.

## [1.7.0] — 2026-06-03

### Added — content engine ([`content/`](content))

- **A standalone explainer page for all 28 SOL-0XX rules** ([`content/rules/`](content/rules)) plus an index ([`content/README.md`](content/README.md)), each stitching four already-reviewed sources: the rule's definition/fix (`claude-security-guidance.md`), whether it is machine-checkable (`cli/rules.json` → 17 of 28 have a deterministic pattern), the real exploits in that class (cross-linked to the [Hacks Database](hacks/README.md)), and a paired code example where one exists ([`examples/`](examples)).
- Generated by [`content/scripts/sync-content.js`](content/scripts/sync-content.js) (zero-dependency, with `--check` + orphan detection). The rule-anchor slugs are generated GitHub-faithfully and a test asserts they don't diverge from the Hacks Database generator.
- New `content` CI job; a `node --test` suite (9 tests) checks the 28-rule parse, the 17-pattern count, that every page references only real hacks/examples, and that the pages stay in sync. Version 1.7.0.

## [1.6.0] — 2026-06-03

### Added — Solana Hacks Database ([`hacks/`](hacks))

- **A cited database of real Solana exploits mapped to SOL-0XX.** [`hacks/hacks.json`](hacks/hacks.json) records disclosed incidents (Wormhole, Mango Markets, Cashio, Crema, Nirvana, Cypher, Loopscale, and the early Solend authority bug) with date, loss, root cause, sources, and the rule class each falls under — compiled into [`hacks/README.md`](hacks/README.md) by `hacks/scripts/sync-hacks.js` (zero-dependency, with a `--check` CI gate).
- **Honest by construction:** every `sol_rules` id is cross-checked against `claude-security-guidance.md` (a typo or non-existent rule fails CI), the rule-anchor slugs are generated to match GitHub exactly, and incidents no code rule can prevent (Slope's seed-phrase leak, Raydium's key compromise, the Pump.fun insider) carry `code_preventable: false` with an empty mapping — we never claim a rule catches what it cannot.
- New `hacks` CI job (in `cli.yml`) validates the dataset and that the generated README is in sync; a `node --test` suite covers schema, rule cross-references, and the honesty invariant.

## [1.5.0] — 2026-06-03

### Added — MCP server ([`mcp/`](mcp))

- **`@jelleo/solana-security-mcp`** — a zero-dependency [Model Context Protocol](https://modelcontextprotocol.io) server (stdio JSON-RPC) that brings SOL-0XX to any MCP client (Cline, Copilot, Cursor, Claude, Windsurf) with one config entry. Exposes `scan_solana_code` (run the fast patterns over a Rust snippet, advisory findings) and `list_solana_security_rules` (the full 28-rule guidance). Vendors the reviewed scanner core + guidance, so nothing is fetched at runtime; 100% local.
- Tested with protocol-level unit tests **and** a real stdio subprocess end-to-end test; a CI job runs them on Linux + Windows. Added to the install matrix.

## [1.4.0] — 2026-06-03

### Added — AI coding-agent installers ([`integrations/`](integrations))

- The SOL-0XX standard now drops into **Codex, GitHub Copilot, Cursor, Windsurf, Cline, and Aider** as each tool's native rules/instructions file, so the assistant writes **and reviews** Solana/Anchor code against the rules. All generated from the one source (`claude-security-guidance.md`) by `cli/scripts/sync-integrations.js` — no guidance is hand-duplicated. Install matrix in [`integrations/README.md`](integrations/README.md).
- Per-tool wrappers handle each tool's quirks: Cursor `.mdc` frontmatter (`alwaysApply`), **Windsurf split into two files** under its ~6 KB per-file cap (so SOL-024–028 aren't silently dropped), and an Aider `CONVENTIONS.md` plus an **opt-in** scanner `lint-cmd` (off by default since the scanner is an advisory heuristic; when enabled it pins the version and passes `-r .` so off-chain path excludes work).
- **Honest coverage:** the AI-instruction files carry all **28 documented** rules; the machine-checkable surfaces (CLI, Action, Semgrep, extension) enforce the **17** with deterministic patterns. CI gains a `sync-integrations --check` gate (with orphan detection); the generator anchors its source slice to a unique line so a stray mention can't corrupt output.

## [1.3.1] — 2026-06-02

Marketplace-debut polish — no rule or scanner-logic changes.

- **Branded the VS Code extension** with the Jelleo mark (cream "J" + amber corner-bracket reticle on the dark grid), so the Marketplace listing is on-brand.
- **GitHub Action badge** recoloured from `purple` to the brand `yellow`/gold (`action.yml` `branding.color`) ahead of listing the Action on the GitHub Marketplace.

## [1.3.0] — 2026-06-02

Makes the standard **installable everywhere**: the SOL-0XX rules now run in your editor and in any Semgrep pipeline, and the CLI is publish-ready on npm. All three reuse the same source of truth (`security-patterns.yaml`) — no rule logic is duplicated.

### Added — VS Code extension ([`extensions/vscode/`](extensions/vscode))

- **Inline SOL-0XX squiggles as you type**, in any `.rs` file — works in **VS Code, Cursor, and Windsurf**. A finding is a `WARNING` with the rule id and a link to the rule.
- Runs the **same scanner core** as the CLI, vendored into the extension at build time (`scripts/sync-engine.js`) so the `.vsix` is self-contained. Finding→diagnostic mapping is a pure, unit-tested module (`src/diagnostics.js`) with no `vscode` import; the editor wiring (`src/extension.js`) is fail-closed — a scan error can never break the editor.
- 100% local — no network calls, no telemetry. Off-chain dirs are excluded exactly as the scanner does.

### Added — Semgrep ruleset ([`semgrep/`](semgrep))

- **`solana-security-standard.yaml`** — all 17 deterministic SOL-0XX patterns as Semgrep `pattern-regex` rules (`languages: [rust]`), usable via `semgrep --config` from a checkout or straight from a GitHub raw URL.
- Generated from `security-patterns.yaml` by `cli/scripts/sync-semgrep.js`; CI fails if the committed file drifts and runs `semgrep --validate` so a rule Semgrep's RE2 engine can't compile is caught on every change.
- **One documented divergence (SOL-011):** the scanner's depth-2 paren-balanced regex is rejected by RE2 as *"too large,"* so the Semgrep rule uses an RE2-safe delimiter-bounded window (recorded in that rule's `metadata.note`). It flags the same real `#[account(close = …)]` attributes, including long multi-line ones — verified against live Semgrep.

### Added — npm publish-readiness

- `@jelleo/solana-security-standard` is publish-ready (`publishConfig.access: public`, `prepublishOnly` gate that re-checks both generated artifacts and runs the test suite). `npx @jelleo/solana-security-standard` works once published.

## [1.2.0] — 2026-06-02

### Added — installable surface (CLI + GitHub Action)

- **Zero-dependency scanner CLI** (`npx @jelleo/solana-security-standard scan`) — matches the SOL-0XX fast patterns against full file content (so multi-line constructs are caught), with human / JSON / SARIF output and a non-zero exit on findings so it gates any CI. `rules.json` is pre-compiled from `security-patterns.yaml` so the runtime needs no YAML parser.
- **GitHub Action** (`Copenhagen0x/solana-security-guidance@v1`) — runs the same patterns as a PR check, uploads SARIF for inline code-scanning annotations, and ships the adoption badge.
- **Hardening** (adversarial review before shipping): ReDoS-prone `[^)]*` quantifiers were bounded (whole-file scans went from ~70–86 s to single-digit ms on 1 MB inputs), and Action inputs are passed via `env:` with a `--` sentinel so an untrusted `paths` value can't inject scanner flags.

## [1.1.0] — 2026-06-02

Rebranded as the **Solana Security Standard** — `SOL-0XX` is now positioned as a stable, citable bug-class taxonomy (cite it the way you'd cite a CWE). Adds 8 rules (SOL-021 through SOL-028) and corrects several rule definitions that an adversarial review found technically wrong before they shipped.

### Added — 8 new rules (SOL-021 → SOL-028)

- **SOL-021 — Terminal op gated on a live-only condition.** A close/resolve/wind-down path reuses a guard (`status == Fresh`, `expiry > now`) that can never hold once the program's status is terminal → the call reverts forever and funds lock. From our percolator v16 engine audit (F1); the maintainer fixed it as "Finding C".
- **SOL-022 — Write-only "impaired" counter.** A counter incremented when state migrates into a degraded bucket but never decremented → funds encumbered forever, slot never reusable. From our v16 audit (F2); disclosed at [percolator#74](https://github.com/aeyakovenko/percolator/issues/74), code-confirmed, not reproduced on-chain.
- **SOL-023 — Fee/penalty rounds toward the user.** Integer `/` rounds down so the user underpays and small amounts round to 0. Fix: `u64::div_ceil` the amount owed — round each amount against the less-trusted party (fee/penalty up, the user's payout down). From our v16 audit (F3, Low).
- **SOL-024 — Stale / unchecked oracle price.** A Pyth/Switchboard price used with no staleness or confidence-interval check. Documented Solana DeFi pattern.
- **SOL-025 — Sysvar read by raw deserialize.** A sysvar read by raw-deserializing account data (`bincode::deserialize::<Clock>`) instead of `Clock::get()` / `Sysvar::from_account_info` (both of which key-check internally). Documented Solana pattern.
- **SOL-026 — Duplicate mutable account.** Two accounts that must differ aren't checked → attacker passes the same one. Anchor's error 2040 (`ConstraintDuplicateMutableAccount`) auto-rejects this for `Account<>` fields — but NOT for `AccountLoader`, `UncheckedAccount`, or duplicates passed via `remaining_accounts` (confirmed by Anchor's own test suite), which still need an explicit `require_keys_neq!`. `AccountLoader` is especially deceptive: Anchor skips the check because zero-copy accounts don't serialize on exit, but the two borrows still alias the same memory, so a write through one corrupts the other.
- **SOL-027 — Unvalidated `remaining_accounts`.** `ctx.remaining_accounts` read/written/invoked without validating each one's owner/key/signer.
- **SOL-028 — Missing slippage / min-out bound.** A swap/withdraw/settle with no caller-supplied min-out / max-in.
- **2 new `security-patterns.yaml` patterns** (`sol_024` oracle staleness, `sol_025` raw-sysvar-deserialize), bringing the fast-pattern count from 15 to 17.

### Changed — corrections from adversarial review (before shipping)

These rule definitions were wrong in draft and were fixed against the actual Solana/Anchor semantics:

- **SOL-021** is gated on the program's **terminal status field**, not a "frozen clock" — Solana's clock never freezes. Wording corrected.
- **SOL-025** now targets the **raw deserialize** anti-pattern. `Clock::from_account_info` / `Sysvar::from_account_info` are SAFE (the SDK calls `check_id` internally); the project's own LiteSVM test confirms this. The exploitable variant is hand-deserializing the account buffer. The `security-patterns.yaml` matcher was re-pointed from `*::from_account_info` (false-positive) to `bincode::deserialize::<Clock|Rent>`.
- **SOL-026** now states the **exact scope of Anchor's protection**: error 2040 covers duplicate mutable `Account<>` fields only. `AccountLoader` (zero-copy), `UncheckedAccount`, and duplicates routed through `remaining_accounts` are NOT covered — so the rule no longer gives Anchor devs false comfort on those types.
- **SOL-023** fix now specifies `u64::div_ceil` on the amount the user owes, with the round-up-fee / round-down-payout rule made explicit.
- **`security-patterns.yaml` SOL-024** gained `exclude_paths` for `**/client/**`, `**/cli/**`, `**/offchain/**`, `**/sdk/**` so the `get_price_unchecked` matcher doesn't fire on off-chain client code where it's harmless.
- **`claude-security-guidance.md`** rewritten to a compact per-rule format (`### SOL-0XX · Title` + one tight bug→fix line) so all 28 rules + threat model + checklist + provenance fit the hard 8192-byte plugin-file cap. Full catalog detail lives in the README.

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

[1.3.1]: https://github.com/Copenhagen0x/solana-security-guidance/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Copenhagen0x/solana-security-guidance/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Copenhagen0x/solana-security-guidance/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Copenhagen0x/solana-security-guidance/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/Copenhagen0x/solana-security-guidance/releases/tag/v1.0.1
[1.0.0]: https://github.com/Copenhagen0x/solana-security-guidance/releases/tag/v1.0.0
