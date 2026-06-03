# Solana Security Standard — VS Code extension

Flags **Solana / Anchor security bugs (SOL-0XX) inline as you code** — caller-controlled `now_slot`, missing signer/owner checks, unchecked arithmetic, `init_if_needed` reinit, raw sysvar deserialize, and more. By [Jelleo](https://jelleo.com), the team that finds the bugs.

Works in **VS Code, Cursor, and Windsurf**. Same engine as the [CLI and GitHub Action](https://github.com/Copenhagen0x/solana-security-guidance).

## What it does

Open any `.rs` file and the extension shows a warning squiggle wherever a SOL-0XX pattern fires, with the rule ID and a link to the full rule. It's a **fast, advisory tripwire** — a finding means "look here," not "definitely a bug." Off-chain code (`client/`, `cli/`, `offchain/`, `sdk/`, `tests/`) is excluded where the patterns are harmless there.

No configuration needed. Toggle with the `solanaSecurityStandard.enable` setting.

## How it fits

This is the per-edit layer of the **[Solana Security Standard](https://github.com/Copenhagen0x/solana-security-guidance)**:

- **In your editor** — this extension (live squiggles).
- **In Claude Code** — the security-guidance plugin (semantic review).
- **In CI** — the [GitHub Action](https://github.com/Copenhagen0x/solana-security-guidance) (gates PRs + badge) and the `npx @jelleo/solana-security-standard` CLI.
- **A full audit** — [jelleo.com](https://jelleo.com).

## Privacy

100% local. Your code is scanned on your machine and never leaves it — no network calls, no telemetry.

MIT · [Jelleo](https://jelleo.com)
