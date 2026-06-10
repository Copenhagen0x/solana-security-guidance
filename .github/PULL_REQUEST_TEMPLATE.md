<!--
Thanks for opening a PR. Please fill in the sections below — the more concrete,
the faster we can review.

For new rules: please open a "New rule proposal" issue FIRST so we can scope
together before you build the PR. Reduces wasted work.
-->

## Summary

<!-- 1-2 sentences. What does this PR change? -->

## Rule(s) affected

<!-- List each SOL-NNN ID this PR touches. New rules are also OK — write the proposed ID. -->

- SOL-XXX

## Source / motivation

<!-- For new rules: link to the disclosed finding (GitHub issue, bounty page, audit report).
     For regex tightening: link to the false-positive issue this fixes.
     For docs: describe what was wrong / missing. -->

## Type of change

- [ ] New rule (also opened a "New rule proposal" issue: #_____)
- [ ] Tightened regex / reduced false positives
- [ ] New example pair under `examples/`
- [ ] Documentation (README / CHANGELOG / SECURITY / CONTRIBUTING / claude-security-guidance.md)
- [ ] CI / tooling
- [ ] Other

## QA evidence

<!-- For any rule change, test against a real codebase and report numbers. -->

- **Tested against:** <!-- e.g. percolator-prog @ 6512fa1, ~10k LOC -->
- **Matches:** <!-- e.g. 3 -->
- **False positives:** <!-- e.g. 0 -->
- **Notes:** <!-- e.g. tightened from substring to regex with word boundary -->

## Checklist

- [ ] CI (`.github/workflows/validate.yml`) is green
- [ ] Regenerated the plugin digest (`cd cli && npm run sync:plugin-guidance`) — it stays under 8 KB (the master `claude-security-guidance.md` is uncapped)
- [ ] All reminder fields in `security-patterns.yaml` are under 1 KB
- [ ] All YAML rule IDs have a matching MD section (`### SOL-NNN`)
- [ ] Updated `CHANGELOG.md` under `[Unreleased]` (for rule changes)
- [ ] No secrets, credentials, customer code, or private audit material in the diff

## Additional context

<!-- Anything else reviewers should know? Open questions? Things you're unsure about? -->
