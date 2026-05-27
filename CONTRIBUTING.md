# Contributing

PRs welcome — especially new rules drawn from your own Solana audits.

This ruleset compounds with every cycle. Each new bounty finding becomes a new rule. Community PRs are how it grows beyond what one team can audit.

## What we accept

- **New rules** drawn from disclosed Solana audits — include a reference to the published finding (GitHub issue, bug bounty disclosure, or audit report URL)
- **Tightened regexes** that reduce false positives on real Solana codebases
- **New paired vulnerable/fixed examples** under `examples/`
- **Documentation improvements** — README, CHANGELOG, threat-model corrections
- **CI improvements** — additional validation checks, false-positive integration tests

## What we don't accept

- Rules drawn purely from theory with no real-world finding behind them — bug-class taxonomies should trace to disclosed bugs, not hypotheticals
- Rules for non-Solana platforms — open a separate repo for those
- Rules that duplicate Anthropic's built-in checks (we extend the plugin, not compete with it)
- Cosmetic changes that bloat the 8 KB markdown cap without adding catch coverage

## Before opening a PR

1. **Open an issue first** if you're proposing a new rule category. Use the [new-rule-proposal](https://github.com/Copenhagen0x/solana-security-guidance/issues/new/choose) template.
2. **Test against a real codebase** — at minimum the percolator wrapper or an Anchor example. Aim for false positive rate <5% (see "QA expectations" below).
3. **Check CI will pass** — run the validation locally:
   ```bash
   python -c "import yaml; data = yaml.safe_load(open('security-patterns.yaml')); print(len(data['patterns']))"
   wc -c claude-security-guidance.md   # must be ≤8192
   ```

## Rule format

Each rule lives in **two places** that must stay in sync:

### 1. `claude-security-guidance.md` (semantic, model-backed)

A section per rule, format:

```markdown
### SOL-NNN · <one-line bug class name>
<1-2 sentence description of what goes wrong and the consequence>
**Fix:** `<one-line code fix or pattern>`
**Reference:** <Bounty / disclosure URL>
```

### 2. `security-patterns.yaml` (deterministic, per-edit)

A pattern per rule (only for rules with clean textual signatures):

```yaml
- rule_name: sol_nnn_<short_description>
  regex: "<Python regex>"          # OR substrings: ["..."]
  paths: ["**/*.rs"]
  exclude_paths: ["**/tests/**"]
  reminder: "Jelleo SOL-NNN: <≤1000 chars message ending with backlink to repo>"
```

Not every rule needs a YAML entry — semantic rules that regex can't cleanly catch (cross-file reasoning, spec-vs-impl drift) stay markdown-only.

## Rule naming convention

- IDs are sequential: `SOL-001`, `SOL-002`, ..., `SOL-NNN`. Never reuse an ID, even for deprecated rules.
- Snake-case the YAML `rule_name`: `sol_001_unauth_now_slot`
- Anchor-case the MD section: `### SOL-001 · Unauthenticated now_slot`
- The reminder field MUST start with `Jelleo SOL-NNN:` so flag provenance is visible in the dev's IDE

## QA expectations

Every new rule must show:

- **Real-codebase test** — grep your regex against at least one of: the `percolator-prog` source (~10 KLOC of real Solana wrapper code) or an Anchor example project. Report match count + false-positive count in your PR description.
- **False positive rate <5%** target. If higher, tighten the regex or move the rule to markdown-only.
- **No catastrophic backtracking** — regexes must avoid the `(a+)+` shape. CI catches the obvious cases; PR authors are responsible for the rest.

## Maintainer review process

PRs are reviewed by Jelleo maintainers. Expect:

1. CI must pass (validate.yml — YAML parse, regex compile, MD ≤8 KB)
2. At least one maintainer reviews the rule's correctness + false-positive rate
3. For rules backed by disclosed findings, we verify the finding exists at the cited URL
4. We may request example pairs under `examples/<sol_nnn>/` for headline rules

## Updating CHANGELOG.md

If your PR adds, removes, or materially changes a rule, add an entry under `[Unreleased]` in `CHANGELOG.md`. Maintainers consolidate into the next release tag.

## Code of conduct

Be respectful. Disagreements about a rule's correctness or scope should be resolved with evidence (real codebases, false positive measurements, cited findings), not opinion. Personal attacks against contributors get the comment hidden and the offender warned. Repeat offenders are blocked.

## License

By contributing, you agree your contribution is licensed under the [MIT License](LICENSE) (same as the rest of the repo).
