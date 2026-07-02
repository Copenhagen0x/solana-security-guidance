# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.12.1] — 2026-07-02

### Changed
- **SOL-010 (Reinit attack)** now matches the reinit *property*, not the `init_if_needed` idiom alone. Added the hand-rolled forms — a raw account-header write via `.data.borrow_mut()` / `try_borrow_mut_data()` with no zero/discriminator/`is_initialized` guard — so a native/manual reinitialization is flagged, not just Anchor's `init_if_needed`. Closes a gap from an external field test (Metaplex Candy Machine v1 config-drain slipped past the idiom-only match). Guidance + rules-meta exclusions rephrased property-first; canonical safe form is Orca's `initialize_dynamic_tick_array` discriminator check. No rule-count change (edit to SOL-010).

## [1.12.0] — 2026-06-29

### Added — 15 new Solana rules: SOL-038…SOL-052 (37 → 52)

- **15 Solana-native rules** drawn from the public Solana/DeFi bug-class taxonomy (Zellic blog case-studies), filtered to pure-Solana, genuinely-new classes: SOL-038 PDA seed collision (machine) · SOL-039 Asymmetric partial-CPI state (machine) · SOL-040 Credit from requested not measured / Token-2022 · SOL-041 Forced-balance / supply desync · SOL-042 Unbounded account-iteration compute DoS (machine) · SOL-043 Unbounded storage / slot-exhaustion griefing · SOL-044 Hardcoded slot-time rate (machine) · SOL-045 Incremental Merkle insertion error · SOL-046 Hand-rolled dispatch bypasses framework guards (machine) · SOL-047 Forged receipt token / mint · SOL-048 Default/zero value accepted as valid · SOL-049 Struct-padding / non-canonical flag read (machine) · SOL-050 Serialization symmetry mismatch · SOL-051 Predictable on-chain entropy (machine) · SOL-052 Token-2022 semantics assumed.
- **7 machine-checkable patterns** (SOL-038/039/042/044/046/049/051), each with a vulnerable/fixed example pair that fires/clears the scanner; 8 review-only. Counts 37→52 rules, 23→30 machine / 14→22 review, with every hardcoded count, tripwire, content/integrations/semgrep/benchmark/plugin-guidance digest + MCP & VS Code engine re-vendor updated.
- **SOL-010 extended** to cover the nullifier/spent-marker double-spend class (`init_if_needed` nullifier PDA without a prior-absence check, or a spent-marker checked after the transfer).

### Changed — AI-context surfaces are now scale-invariant (SSS can grow to thousands of rules)

- `sync-plugin-guidance.js` and `sync-integrations.js` now byte-budget the inline rule cues (highest-tier first) with a single "+N more — full catalog via MCP" overflow pointer, so the consumer-capped files (Claude plugin 8 KB, Windsurf 12 KB) **never overflow regardless of rule count**. The CLI / Semgrep / GitHub Action / MCP / master always carry 100% of the rules — only the inline cheat-sheets are bounded. At 52 rules everything still fits inline (plugin 8002/8192, Windsurf 8286/12000); beyond the cap it auto-overflows.

## [1.11.0] — 2026-06-10

### Added — three new rules: SOL-035, SOL-036, SOL-037 (34 → 37)

- **SOL-035 · Instructions sysvar substitution** (machine): instruction introspection (`load_instruction_at_checked` / `load_current_index_checked`) on an instructions sysvar passed as a raw `AccountInfo` whose key is never pinned — an attacker substitutes a forged instructions account to spoof an Ed25519/Secp256k1 precompile signature check or a CPI-origin check. Fix: Anchor `Sysvar<Instructions>` (pins the key) or assert `key == sysvar::instructions::ID`. Distinct from SOL-025 (raw Clock/Rent bincode deserialize) — this is the introspection-API class.
- **SOL-036 · ATA derivation unpinned** (review-only): a token account trusted as "the user's ATA" without verifying it's the canonical ATA for (owner, mint) → funds redirected to an attacker-controlled account. Review-only — absence of a derivation check has no syntactic marker; the fix is `associated_token::mint`/`::authority` constraints or a `get_associated_token_address` compare.
- **SOL-037 · Arbitrary CPI target** (review-only): a CPI whose callee program id is caller-supplied and never pinned → the call is redirected to an attacker program. The callee-identity gap that SOL-009 (which checks the *caller's* authority) doesn't cover. Fix: a typed `Program<'info, T>` or assert the program id equals the expected constant.
- First rule addition since the 8 KB ceiling was lifted — fit with room to spare (plugin digest now ~4.5 KB / 8192). Ships with meta (tier/severity/reachability/numbered exclusions), example pairs (SOL-035 machine-gated, fix exclusion-cleared; 036/037 illustrative), generated content/integrations/semgrep/MCP+VS Code engine re-vendor/benchmark/**plugin-guidance digest**, the rule-count tripwire 34→37, and every hardcoded count (README ×3 + table rows, mcp, hacks, integrations narrative 37/23/14, test assertions). Reviewed to 0 Critical/High/Medium by code-reviewer + paranoid-goober + threat-modeler.

### Changed — plugin guidance is now a generated digest (breaks the 8 KB rule ceiling)

- **`claude-security-guidance.md` stays the full hand-authored master but is no longer the file the plugin installs** — and the 8 KB Anthropic cap moves OFF it. The plugin now installs a new **generated `plugin-guidance.md`** digest: the threat model + review checklist verbatim, then one terse cue per rule (`**SOL-NNN** · Title — fix`), then a pointer to full detail (the `list_solana_security_rules` MCP tool, or the master on GitHub). A cue is ~80 B vs ~180 B of full prose, so the digest holds far more rules under the cap — the standard can keep growing without the master's size breaking the plugin file.
- New `cli/scripts/sync-plugin-guidance.js` (reuses the canonical rule parser; extracts the `Fix:` cue; **hard-fails if the digest would exceed 8192 bytes**, so a future rule that overflows fails CI rather than shipping a broken plugin file; normalizes to LF). Wired into `prepublishOnly` + a `validate.yml` `--check`; the 8 KB cap check now targets the digest. The full master is uncapped and every generator, the MCP server, and all anchor links keep reading it unchanged.
- **Install change:** the curl-install (all three README blocks) now fetches `plugin-guidance.md` and saves it as `.claude/claude-security-guidance.md` (the plugin's expected filename); `CHECKSUMS.txt` covers the digest (= exactly the verified-install fetch set). The MCP still serves the full master, so "pull full rule detail from the MCP" holds.
- **Known next ceiling (documented, not hidden):** the Windsurf integration embeds the full master and has its own 12,000-char cap (~52 rules). Routing Windsurf's body through the digest too is a separate follow-up; until then ~52 rules is the binding ceiling (up from ~40). The digest itself scales to ~82.

### Added — Claude Code plugin packaging + MCP registry manifest

- **The repo is now installable as a Claude Code plugin from its own marketplace**: `/plugin marketplace add Copenhagen0x/solana-security-standard` → `/plugin install solana-security-standard@solana-security-standard`. Ships `.claude-plugin/plugin.json` + `marketplace.json` (self-hosted, `source: "./"`), a root `.mcp.json` that auto-registers the `@jelleo/solana-security-mcp` server for installers, and a `/scan` command that runs the scanner and reports findings with exclusions-aware guidance.
- **MCP registry manifest** (`mcp/server.json`, schema 2025-12-11): `io.github.Copenhagen0x/solana-security-mcp` (GitHub-auth namespace — the registry requires the repo owner's namespace, independent of the `@jelleo` npm scope), npm/stdio package entry. The npm package gains the required `mcpName` ownership-proof field — it ships with the next npm publish, after which `mcp-publisher login github && mcp-publisher publish` (run from `mcp/`) lists the server in the official registry. Registry publish is an operator release step; if the release bumps the mcp package version past 1.2.1, bump `mcp/server.json` (both `version` fields) to match the published version first — the registry expects them equal. **Same rule for the plugin manifests:** on any release that changes plugin-shipped content (the `/scan` command, `.mcp.json`, the guidance the MCP serves), bump `version` in `.claude-plugin/plugin.json` AND the marketplace entry together — the pinned version is the plugin-update cache key; a stale pin strands installed plugin users on the cached copy. Separate hardening follow-up (operator): npm 2FA auth-and-writes + `npm publish --provenance`, and decide the npx pin policy (`@1` major-pin vs float) consistently across `.mcp.json` + `mcp/README.md` + the root README — all-or-nothing, never half-pinned.

### Added — three new rules: SOL-032, SOL-033, SOL-034 (31 → 34)

- **SOL-032 · Decimals assumed, not read** (review-only): amount math that hardcodes a token scale (`1_000_000`, `10u64.pow(9)`) instead of reading `mint.decimals` — a 6-vs-9 mint misprices by 1000×. Review-only on purpose: a scale literal is not machine-distinguishable from any other constant; shipping a guessy pattern would damage the published FP discipline.
- **SOL-033 · Stale account read after CPI** (machine, fail-open tripwire): an account field read after a CPI that can mutate it — Anchor serves the deserialized copy from *before* the call. Bounded cross-line regex (RE2-validated in the real engine, no lookarounds); `reload()` between CPI and read clears exclusion #1.
- **SOL-034 · Manual lamport mutation** (machine): direct lamport writes (`try_borrow_mut_lamports`/`lamports.borrow_mut()`) whose internal-ledger counterpart is missing — the runtime conserves the lamport sum, but the program's recorded balances don't move with it; also checks rent-exemption survival and destination validation via exclusions.
- Each ships with meta (tier/severity/reachability/numbered exclusions), a vulnerable/fixed example pair (machine pairs gated in CI; 033/034 fixes are documented exclusion-cleared), generated content pages, Semgrep + integrations + MCP/VS Code engine re-vendor, and benchmark rows (now 22/22 detection). Guidance master stays under Anthropic's 8 KB cap (8,119 bytes) via meaning-preserving trims; the rule-count tripwire moves 31 → 34.

### Added — generated benchmark scoreboard (`BENCHMARK.md`)

- **New repo-root [`BENCHMARK.md`](BENCHMARK.md)**: the real shipped engine scored against every machine rule's canonical vulnerable/fixed example pair — detection (anti-rot) and false-positive discipline per rule, with the exclusion-cleared cases documented. Generated by `cli/scripts/sync-benchmark.js`; CI fails if it goes stale, and the underlying properties were already hard-gated by `cli/test/examples.test.js` (a rule that stops detecting its bug, or starts flagging its fix, cannot merge). Scope is stated honestly in the file: a self-benchmark on curated canonical pairs, not a third-party recall claim. The exclusion-cleared allowlist moved to `examples/fixed-still-fires.json` (one source of truth shared by the test and the generator).

### Added — Action `baseline` input + composite-action self-test

- **GitHub Action: new `baseline` input** wires the CLI's baseline/diff into CI — point it at a committed baseline file and the check gates only on NEW findings. Same injection-safe plumbing as every other input (env-passed, one quoted argv entry); a malformed or missing baseline fails the run loudly (exit 2). Review baseline diffs in PRs like code — entries must carry their rule/file snapshot (enforced at load).
- **New `action-selftest` CI job** (ubuntu + windows): the composite action now exercises itself on every PR via `uses: ./` against the vulnerable examples — report-only scan, `min-tier` passthrough, a full baseline write→apply cycle that must gate green, and a fail-closed negative (an invalid `min-tier` must fail the run). Closes the standing gap where `action.yml`'s bash plumbing had zero CI coverage.

### Notes for the next release tag

- The pinned `upload-sarif` is now v4 (Dependabot, API-verified): it requires a node24-capable runner (GitHub-hosted: fine; self-hosted: runner ≥ 2.327). On older runners the annotations step is skipped (`continue-on-error`) — the gate is unaffected. Include this note in the adopter-facing release notes when `@v1` next moves.

### Added — baseline / diff scanning (`--baseline`, `--write-baseline`)

- **Adopt the standard on an existing codebase without a red gate on day one.** `--write-baseline <file>` records the scan's findings as a reviewable baseline (one entry per stable 128-bit fingerprint, each with a human-readable rule/file/line/match snapshot — review baseline diffs in PRs like code); `--baseline <file>` then reports and gates **only on findings not in the baseline**. Because matching is by fingerprint, moving or reformatting code never re-alerts an acknowledged finding — only genuinely new ones fail CI. Honesty invariants: suppression is never silent (text shows "N suppressed by baseline", JSON gains a `baseline: {suppressed, stale}` block, SARIF gains `baselineSuppressed`/`baselineStale` run properties); a malformed or missing baseline exits 2 — it never degrades to a baseline-less scan; **the snapshot is enforced at load** (a hand-minimized entry like `{"<fp>": {}}` that hides what it suppresses is rejected — the reviewability defense is checked, not just promised); stale entries (matching nothing — fixed code) are counted and warned so baselines don't rot; an INCOMPLETE (capped) scan still exits 2 regardless of the baseline, and **`--write-baseline` refuses an INCOMPLETE scan** rather than recording an authoritative-looking partial picture. Refresh with `--baseline old --write-baseline new` (keeps prior acknowledgments); use the same scan path/`-r` root when writing and applying (paths are part of the fingerprint — a different root reads as all-stale: a loud false red, never a silent miss). New module `cli/src/baseline.js`; 30 new tests. Reviewed to 0 open Critical/High/Medium by code-reviewer + paranoid-goober + threat-modeler, to convergence.

### Added — Action `min-tier` input + supply-chain pinning

- **GitHub Action: new `min-tier` input** passes the CLI's `--min-tier` noise floor through to CI (`high` drops LOW-tier hygiene findings; `low`/empty reports everything — the default). Same injection-safe plumbing as the other inputs (env-passed, quoted single argument, never interpolated into the script); an invalid value fails the run loudly (scanner exit 2), never silently scans without the floor. Documented in the README workflow example.
- **Every `uses:` in `action.yml` and the CI workflows is now SHA-pinned** (`github/codeql-action/upload-sarif`, `actions/checkout`, `actions/setup-node`, `actions/setup-python`) with the version in a comment — a hijacked floating tag can no longer swap the code that handles our SARIF and repo token. New **`.github/dependabot.yml`** keeps the pins fresh (weekly, grouped) and watches the CLI's single devDependency.

### Added — stable per-finding fingerprint

- **Every finding now carries a stable, position-independent `fingerprint`** — `sha256(JSON.stringify([rule, file, whitespace-normalized match, ordinal]))` truncated to 128 bits (32 hex chars). Identity deliberately excludes line/column, so an unchanged finding keeps its id when code drifts up or down a file, and whitespace normalization means reformatting/reindentation (or a CRLF vs LF checkout) doesn't change it either; identical repeated constructs in one file are disambiguated by occurrence ordinal. Surfaced as `fingerprint` in JSON output and as SARIF `partialFingerprints` (`sssFindingId/v1`) — the field GitHub code scanning uses to track an alert across commits, replacing its line-hash default that line drift perturbs. Sized at 128 bits because the hash inputs (file path, matched source) are attacker-controlled and a future baseline/suppression layer will trust this id as a security control: targeted second-preimage 2^128, birthday collision 2^64 — both infeasible. This is the keystone for upcoming baseline/diff scanning and fingerprint-keyed suppression. Purely additive — text output, exit codes, and every existing JSON/SARIF field are unchanged. Reviewed to 0 Critical/High/Medium by code-reviewer + paranoid-goober + threat-modeler, to convergence (incl. a re-verify pass on the 64→128-bit hardening).

## [1.10.1] — 2026-06-07

### Fixed — SOL-016 canonical-bump triage precision (no coverage change)

- **SOL-016 (canonical bump) guidance sharpened to cut false-positive noise without losing coverage.** The detector fires on the idiomatic-safe Anchor reuse `bump = <account>.bump`, which surfaced as `[high]` noise (reported in issue #3; an earlier user hit 24). Rather than down-tier the rule — which would have *hidden a real fund-loss bug*, since that same match is the only tripwire for a non-canonical bump stored at init and reused via the constraint (PDA substitution) — the rule keeps its `high` tier/severity and ships **precise triage guidance**: the reuse is safe only when the *same* account's bump was set at init via Anchor's bare `bump` / `ctx.bumps` (canonical), **not** a caller-supplied `#[instruction(bump)]` value or a `create_program_address` result. The reminder, reachability anchor, and exclusions now state this exactly, and a latent error in the prior exclusion ("an Anchor `bump` constraint enforces it" — which `bump = <stored>` does not, since it re-derives with the given bump) is corrected. The detector regex is unchanged. Reviewed to 0 Critical/High/Medium by code-reviewer + paranoid-goober + threat-modeler.

## [1.10.0] — 2026-06-06

### Added — per-rule metadata, hardened exclusions, self-testing examples

- **Per-rule metadata layer ([`rules-meta.json`](rules-meta.json)).** Every SOL-0XX rule now carries a value **tier** (high | low), a baseline **severity** (high | medium | low), a **reachability anchor** (the first call-site a reporter cites to confirm exploitability), and numbered **"do NOT flag when…" exclusions**. Surfaced in `cli/rules.json`, the Semgrep `metadata`, and the per-rule content pages. New `--min-tier <high|low>` opt-in noise floor + a [`SEVERITY.md`](SEVERITY.md) calibration rubric. **Advisory only** — the scanner still fires (fail-open); Semgrep `severity` stays `WARNING` and SARIF `level` stays `warning`, so existing gating is unchanged.
- **Hardened exclusions.** Each exclusion is a specific, verifiable condition that vulnerable code cannot satisfy — audited (3-reviewer, to convergence) so a reviewer can't cite one to wave through a real bug. Covers `has_one`-vs-signature, canonical PDA bumps, source-vs-shipped-binary divergence (`#[cfg]` / `cfg!`), oracle vendor-awareness, fail-closed gates, and off-chain-consumer trust boundaries.
- **Self-testing examples.** Every machine-checkable rule (20) ships a paired `vulnerable` / `fixed` example under [`examples/`](examples/) (Rust on-chain; TypeScript for SOL-029/030/031), wired to a real-scanner self-test (`cli/test/examples.test.js`): each `vulnerable` must fire its rule (anti-rot guard), each `fixed` is scanner-clean or a documented exclusion-cleared example.

### Changed — detection + robustness (deep-audit hardening)

- **Detection.** SOL-007 now catches the dominant Anchor idiom `&*ctx.accounts.x.data.borrow()` (was matching only bare single-identifier receivers); SOL-017 now catches qualified `mem::transmute` calls.
- **Scanner robustness.** Dense files no longer crash the scanner; an over-large scan is **fail-safe** — an incomplete scan exits non-zero and is flagged in every output (`scanComplete: false` in JSON, `scannerTruncated` in SARIF, a text banner), so a finding-flood can never silently pass a gate (`SSS_MAX_FINDINGS` tunes the cap). Overlapping/nested scan paths are de-duplicated.
- **Accuracy + hygiene.** Corrected the Wormhole and Loopscale figures/classifications in the hacks database; the VSCode extension declares an `untrustedWorkspaces` capability and cleans up its debounce timers.

### Notes

Fully backward-compatible: default scan output, exit semantics for normal scans, Semgrep `severity`, and SARIF `level` are unchanged. All new fields are additive.

## [1.9.1] — 2026-06-06

### Changed — repo renamed + supply-chain hardening

- **Repo renamed `solana-security-guidance` → `solana-security-standard`** for brand consistency (the npm packages, CLI, Action, and docs already said "standard"). The old URL 301-redirects and the old raw URLs still resolve, so existing installs, `semgrep --config` pins, the GitHub Action, and every shared link keep working unchanged. All in-repo references swept to the new name.
- **Verified install + checksums.** Each release now publishes [`CHECKSUMS.txt`](CHECKSUMS.txt) (SHA-256 of the files served over raw URLs); the README gains a "Verified install" path that pins to a tag and runs `sha256sum -c`. A new `validate` CI gate keeps the checksums in sync ([`scripts/checksums.js`](scripts/checksums.js)).
- **Signed release tags.** Tags are SSH-signed; verify with `git verify-tag` against [`.github/allowed_signers`](.github/allowed_signers) (see [`SECURITY.md`](SECURITY.md) → "Verifying a release").
- **Floating `v1` tag moved to current HEAD** — `uses: …@v1` Action adopters now get the current ruleset (incl. the integrator rules SOL-029/030/031) instead of the stale v1.3.0 it was pinned to.

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
- **GitHub Action** (`Copenhagen0x/solana-security-standard@v1`) — runs the same patterns as a PR check, uploads SARIF for inline code-scanning annotations, and ships the adoption badge.
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

[1.9.1]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.8.1...v1.9.0
[1.8.1]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Copenhagen0x/solana-security-standard/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/Copenhagen0x/solana-security-standard/releases/tag/v1.0.1
[1.0.0]: https://github.com/Copenhagen0x/solana-security-standard/releases/tag/v1.0.0
