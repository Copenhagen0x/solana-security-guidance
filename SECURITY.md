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
3. After the fix is tagged in a release, we publish a security advisory at `github.com/Copenhagen0x/solana-security-standard/security/advisories` with credit
4. If we can't reach a fix in 30 days, we surface the issue publicly with a workaround so users aren't blind

## Verifying a release

Install files are fetched over plain HTTPS. For supply-chain-sensitive use, verify what you download:

- **Checksums** — each release publishes [`CHECKSUMS.txt`](CHECKSUMS.txt) (SHA-256 of the files served over raw URLs). After downloading, run `sha256sum -c CHECKSUMS.txt` (see the README's "Verified install").
- **Signed tags** — release tags are SSH-signed:

  ```bash
  git config gpg.ssh.allowedSignersFile .github/allowed_signers
  git verify-tag v1.9.1     # expect: Good "git" signature for btr.corpus@gmail.com
  ```

  Signing key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPH7L8nFtHegnLCrghC2R09Si9kIIFp59PRdPbjE7xIq`

**Honest scope:** checksums and the in-repo allowed-signers are convenience checks against a tampered `main`, a CDN swap, or transit corruption — they do **not** on their own defend against a full compromise of the maintainer's GitHub account (which could rewrite both the files and the checksums). The signed tag, verified against the key received out of band (or shown **Verified** on GitHub), is the origin check for that.

## Hall of fame

Contributors who responsibly reported issues will be listed here once we have any. (None yet — this is a fresh project.)
