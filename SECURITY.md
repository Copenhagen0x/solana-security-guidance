# Security Policy

This repository is a security-tooling project. Issues in the ruleset itself — false positives, missed cases that should fire, regex denial-of-service, or guidance that misleads developers — are themselves a security concern.

## Reporting a vulnerability

Email **security@jelleo.com** with:

- The rule ID affected (e.g. `SOL-001`) or "ALL" if it's a cross-cutting issue
- A minimal code sample that triggers the issue
- What you expected to happen vs. what actually happened
- Your suggested fix, if any

We respond within **72 hours** for confirmed issues. Public disclosure happens within **30 days** of a fix landing, with credit to the reporter (unless you prefer anonymity).

For non-security bugs (typos, broken links, formatting, etc.), open a public GitHub issue instead — those don't need private reporting.

## In scope

- **False positives** that mislead a developer into believing safe code is unsafe (high friction → uninstalls)
- **False negatives** — bug classes one of our rules should catch but doesn't, especially when published bounty findings exist for the pattern
- **Regex denial of service** (catastrophic backtracking) in any pattern that the plugin would run on real code
- **Guidance that misleads** — an `claude-security-guidance.md` checklist item that, if followed, weakens security
- **Build / CI integrity** — anything that lets a malicious PR sneak past validation

## Out of scope

- Bugs in Anthropic's [`security-guidance` plugin](https://code.claude.com/docs/en/security-guidance) itself — report those at [`anthropics/claude-plugins-official`](https://github.com/anthropics/claude-plugins-official)
- Bugs in specific Solana programs that our rules merely flag — report those to the program's authors via their own disclosure process
- Generic security advice that isn't tied to a specific rule

## Disclosure policy

We follow coordinated disclosure. If you find an issue that affects production codebases relying on this ruleset:

1. Email us first — no public issue, no PR with a CVE in the description
2. We acknowledge within 72 hours and aim for a fix within 14 days
3. After the fix is tagged in a release, we publish a security advisory at `github.com/Copenhagen0x/solana-security-guidance/security/advisories` with credit
4. If we can't reach a fix in 30 days, we surface the issue publicly with a workaround so users aren't blind

## Hall of fame

Contributors who responsibly reported issues will be listed here once we have any. (None yet — this is a fresh project.)
