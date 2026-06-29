# Install the Solana Security Standard in your AI coding tool

Every file here is generated from the one source of truth (`claude-security-guidance.md`) by `cli/scripts/sync-integrations.js` - do not edit by hand. Pick your tool, copy the listed file(s) into your project, and the assistant will write and review Solana/Anchor code against the SOL-0XX rules.

| Tool | What it reads | Install |
| --- | --- | --- |
| Codex / any AGENTS.md agent | `AGENTS.md` | `codex/AGENTS.md` -> repo root (or append the section to your existing `AGENTS.md`) |
| GitHub Copilot | `.github/copilot-instructions.md` | `copilot/.github/` -> repo root |
| Cursor | `.cursor/rules/solana-security.mdc` | `cursor/.cursor/` -> repo root (applies to every request via `alwaysApply`) |
| Windsurf | `.windsurf/rules/solana-security.md` | `windsurf/.windsurf/` -> repo root (~8 KB; Windsurf allots 12 KB total across all rules) |
| Cline | `.clinerules` | `cline/.clinerules` -> repo root |
| Aider | `CONVENTIONS.md` (+ optional `.aider.conf.yml`) | `aider/*` -> repo root (the config also has an opt-in scanner lint-cmd) |
| Claude Code | `claude-security-guidance.md` + `security-patterns.yaml` | the plugin at the repo root (see top-level README) |
| VS Code / Cursor / Windsurf (inline squiggles) | the extension | install "Solana Security Standard" from the Marketplace |
| CLI / CI | `npx @jelleo/solana-security-standard` | run it anywhere; the GitHub Action gates PRs |
| Semgrep | `semgrep --config` | point at `semgrep/solana-security-standard.yaml` |
| MCP server (any MCP client) | `@jelleo/solana-security-mcp` | add to your MCP config; serves a scan tool + the rules (see `mcp/`) |

**Coverage.** The AI-instruction files (Codex, Copilot, Cursor, Windsurf, Cline, Aider) carry all **52 documented SOL-0XX rules** as guidance for the assistant. The machine-checkable surfaces (CLI, GitHub Action, Semgrep, editor extension) enforce the **30 rules that have deterministic patterns**; the other 22 are semantic rules an AI or human reviewer applies. All are generated from the same source - no rule text is duplicated by hand. Full catalog and per-rule detail: https://github.com/Copenhagen0x/solana-security-standard .
