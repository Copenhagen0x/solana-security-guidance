#!/usr/bin/env node
'use strict';
// Solana Security Standard - MCP server (zero dependencies).
//
// Speaks the Model Context Protocol over stdio: newline-delimited JSON-RPC 2.0
// messages. Exposes two tools to any MCP client (Cline, Copilot, Cursor, Claude,
// Windsurf): scan a Rust snippet for SOL-0XX patterns, and fetch the full rule set.
//
// Add to your MCP client config:
//   { "command": "npx", "args": ["-y", "@jelleo/solana-security-mcp"] }

const readline = require('readline');
const tools = require('./src/tools');

const SERVER_INFO = { name: 'solana-security-standard', version: '1.0.0' };
const PROTOCOL_VERSION = '2024-11-05';

const TOOL_DEFS = [
  {
    name: 'scan_solana_code',
    description:
      'Scan a snippet of Solana/Anchor Rust against the Solana Security Standard (SOL-0XX) fast ' +
      'patterns. Returns advisory findings (rule id + line:col + fix hint). A match means "look ' +
      'here", not a confirmed bug.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'The Rust source to scan.' },
        filename: { type: 'string', description: 'Optional path/name; used for off-chain exclude matching (e.g. tests/foo.rs).' },
      },
      required: ['code'],
    },
  },
  {
    name: 'list_solana_security_rules',
    description:
      'Return the full Solana Security Standard (SOL-0XX) guidance: threat model, review checklist, ' +
      'and all 52 numbered rules with fixes. Use it to write or review Solana/Anchor code safely.',
    inputSchema: { type: 'object', properties: {} },
  },
];

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}
function ok(id, result) {
  send({ jsonrpc: '2.0', id, result });
}
function fail(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

function callTool(name, args) {
  if (name === 'scan_solana_code') return tools.scanCode(args || {});
  if (name === 'list_solana_security_rules') return tools.listRules(args || {});
  throw new Error('Unknown tool: ' + name);
}

// Returns the response object to send (or undefined for a notification / ignored input).
// Returns the response object for a single message, or undefined for a notification /
// ignored input. A message with no id is a notification and gets NO reply, for ANY
// method (a request always carries an id), so we never emit a malformed id-less response.
function respond(msg) {
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return undefined;
  const { id, method, params } = msg;
  // No id (or null, which is not a valid JSON-RPC request id) => a notification:
  // fire-and-forget, never reply (so we never emit a malformed id-less response).
  if (id === undefined || id === null) return undefined;
  switch (method) {
    case 'initialize':
      return { jsonrpc: '2.0', id, result: { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO } };
    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };
    case 'tools/list':
      return { jsonrpc: '2.0', id, result: { tools: TOOL_DEFS } };
    case 'tools/call': {
      const name = params && params.name;
      try {
        const text = callTool(name, params && params.arguments);
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }] } };
      } catch (e) {
        // Tool errors are returned as a tool result with isError, per MCP (not a JSON-RPC error).
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true } };
      }
    }
    default:
      return { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + method } };
  }
}

// Process a JSON-RPC batch array, CAPPED so one line can't block the synchronous event loop or
// balloon the response (consistent with the 200-finding cap in tools.js). Per-line work is bounded;
// the *rate* of lines is not (a client could send many max-size batch lines) - acceptable here
// because the transport is a LOCAL stdio pipe the client owns, not a network service. Excess items
// are dropped, acknowledged with one batch-too-large error ONLY IF some item expected a reply - an
// all-notification batch gets no response at all, per JSON-RPC 2.0 section 6.
const MAX_BATCH = 100;
function respondBatch(arr) {
  const replies = arr.slice(0, MAX_BATCH).map(respond).filter((r) => r !== undefined);
  if (arr.length > MAX_BATCH && replies.length) {
    replies.push({ jsonrpc: '2.0', id: null, error: { code: -32600, message: `batch too large: ${arr.length} items (max ${MAX_BATCH})` } });
  }
  return replies;
}

function handleLine(line) {
  const t = line.trim();
  if (!t) return;
  let msg;
  try { msg = JSON.parse(t); } catch { return; } // ignore non-JSON noise
  if (Array.isArray(msg)) {
    // JSON-RPC batch (allowed by the 2024-11-05 revision): reply with an array of the
    // non-notification responses (bounded), or stay silent if it was all notifications.
    const replies = respondBatch(msg);
    if (replies.length) send(replies);
    return;
  }
  const reply = respond(msg);
  if (reply) send(reply);
}

if (require.main === module) {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  rl.on('line', handleLine);
}

module.exports = { respond, respondBatch, MAX_BATCH, callTool, TOOL_DEFS, SERVER_INFO, PROTOCOL_VERSION };
