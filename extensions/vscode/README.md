# Solana Security Standard

Inline SOL-0XX security checks for Solana and Anchor Rust, right as you type. Works in VS Code, Cursor, and Windsurf.

## What it does

Open any `.rs` file and the extension shows a warning wherever a SOL-0XX pattern matches, with the rule ID and a link to the rule. It is a fast, advisory check: a match means "look here", not a confirmed issue. Off-chain folders (client, cli, offchain, sdk, tests) are skipped.

No setup needed. Toggle it with the `solanaSecurityStandard.enable` setting.

## How it fits

This is the editor layer of the Solana Security Standard. The same rule set also runs as a CLI (`npx @jelleo/solana-security-standard`), a GitHub Action, a Semgrep ruleset, and a Claude Code plugin.

Source code and the full rule list: https://github.com/Copenhagen0x/solana-security-standard

## Privacy

100% local. Your code is scanned on your machine and never leaves it. No network calls, no telemetry.

MIT licensed. By Jelleo.
