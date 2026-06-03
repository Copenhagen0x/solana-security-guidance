'use strict';
// Pure tool implementations for the MCP server (no protocol wiring here, so they are
// unit-testable). Each returns a plain string that the server wraps in MCP content.

const fs = require('fs');
const path = require('path');
const scanner = require('../engine/scanner');
const { solId, shortReminder } = require('../engine/formatters');

const engineDir = path.join(__dirname, '..', 'engine');
const RULES = scanner.loadRules(path.join(engineDir, 'rules.json'));
const GUIDANCE = fs.readFileSync(path.join(engineDir, 'guidance.md'), 'utf8');

const MAX_CODE = 256 * 1024; // this is a snippet scanner - whole files/repos belong on the CLI
const MAX_FINDINGS = 200; // bound the response so a pathological input can't produce a huge body
const ADVISORY =
  'These are advisory heuristics - a match means "look here", not a confirmed bug. ' +
  'Review each against its rule and cite the SOL-0XX id.';

// Make a raw client filename always match the rules' `**/*.rs` include - so a scan is
// NEVER silently a no-op for an odd name (untitled, code.txt, an absolute path, etc.) -
// while preserving any directory so off-chain excludes (tests/, ...) still apply: strip
// a drive letter + leading slashes to a relative posix path, and ensure a `.rs` suffix.
function normalizeName(filename) {
  let f = String(filename == null ? '' : filename).trim().replace(/\\/g, '/').replace(/^[A-Za-z]:/, '').replace(/^\/+/, '');
  if (!f || /^\.+$/.test(f)) f = 'input.rs'; // empty or all-dots (".", "..") -> a sane default
  // The `**/*.rs` include is case-sensitive, so a `.RS`/`.Rs` would silently NOT scan.
  // Lowercase an existing rs suffix (clean display) or add `.rs` so the scan always fires.
  if (/\.rs$/i.test(f)) f = f.replace(/\.[Rr][Ss]$/, '.rs');
  else f += '.rs';
  return f;
}

// True for a test path (the exclude most on-chain rules share) - so a clean result on a
// test file is explained, not silently read as reassurance.
function isTestPath(f) {
  return /(^|\/)tests?\//.test(f);
}

// scan_solana_code: run the SOL-0XX fast patterns over a Rust snippet.
function scanCode(args) {
  const code = args && args.code;
  if (typeof code !== 'string') throw new Error('scan_solana_code requires a "code" string argument');
  if (code.length > MAX_CODE) {
    throw new Error(
      `code is ${code.length} chars; the snippet limit is ${MAX_CODE}. ` +
      'Scan whole files or repos with the CLI: npx @jelleo/solana-security-standard scan <path>',
    );
  }
  const filename = normalizeName(args.filename);
  const findings = scanner.scanContent(code, filename, RULES);
  if (!findings.length) {
    const why = isTestPath(filename) ? ` (note: ${filename} is a test path; most on-chain rules are not applied there)` : '';
    return `No SOL-0XX findings${why}.\n\nThis is an advisory heuristic scan - absence of findings is NOT a ` +
      'security guarantee. For on-chain code, apply the full standard (see list_solana_security_rules).';
  }
  const shown = findings.slice(0, MAX_FINDINGS);
  const lines = shown.map((f) => `  ${filename}:${f.line}:${f.column}  ${solId(f.rule)}  ${shortReminder(f.reminder)}`);
  const more = findings.length > MAX_FINDINGS
    ? `\n  ... and ${findings.length - MAX_FINDINGS} more (showing the first ${MAX_FINDINGS}).`
    : '';
  return `${findings.length} SOL-0XX finding(s):\n${lines.join('\n')}${more}\n\n${ADVISORY}`;
}

// list_solana_security_rules: the full SOL-0XX guidance (threat model + 28 rules).
function listRules() {
  return GUIDANCE;
}

module.exports = { scanCode, listRules, normalizeName, isTestPath, MAX_CODE, MAX_FINDINGS, RULES };
