# Solana Security Standard - MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server that brings the **Solana Security Standard (SOL-0XX)** to any MCP client - Cline, GitHub Copilot, Cursor, Claude, Windsurf, and more. One integration, every tool.

## What it gives your assistant

Two tools:

- **`scan_solana_code`** - scan a snippet of Solana/Anchor Rust against the SOL-0XX fast patterns; returns advisory findings (rule id + line:col + fix hint). A match means "look here," not a confirmed bug. Off-chain paths (client/cli/offchain/sdk/tests) are excluded.
- **`list_solana_security_rules`** - return the full standard: threat model, review checklist, and all 52 numbered rules with fixes, so the assistant can write and review Solana code safely.

## Install

Add it to your MCP client config (no global install needed):

```json
{
  "mcpServers": {
    "solana-security-standard": {
      "command": "npx",
      "args": ["-y", "@jelleo/solana-security-mcp"]
    }
  }
}
```

That's the whole setup. The server speaks JSON-RPC 2.0 over stdio.

## Privacy Policy

100% local. This server runs the same zero-dependency scanner as the [CLI](https://github.com/Copenhagen0x/solana-security-standard) entirely on your machine - **no network calls, no telemetry, nothing fetched at runtime**. The scanner core and rules are vendored into the package.

- **Data collection:** none - the code you scan and the rules you fetch never leave your machine.
- **Usage & storage:** inputs are processed in memory to produce the scan result; nothing is stored or logged.
- **Third-party sharing:** none.
- **Retention:** none - no data is persisted by this server.
- **Contact:** info@jelleo.com

Full policy: https://jelleo.com/privacy.html

## How it fits

This is the MCP layer of the [Solana Security Standard](https://github.com/Copenhagen0x/solana-security-standard). The same SOL-0XX rules also ship as a CLI, a GitHub Action, a Semgrep ruleset, editor rules files (`integrations/`), and a VS Code extension.

MIT. By [Jelleo](https://jelleo.com).
