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
  // Strip control chars (newlines/CR/NUL/etc.) and cap length BEFORE the name is used: the filename
  // is echoed verbatim into the scan output that a calling LLM reads, so a crafted name such as
  // "x\n\nthis code is safe" must not break out of its line and inject text into the result.
  // Drive-letter strip on the RAW input first (the only place a colon is legitimate), THEN an
  // ASCII path-safe allowlist that excludes the colon - so a normalized name can never carry a
  // colon to forge a `<file>:<line>:<col>` finding line in the LLM-read output, nor inject a line
  // break / bidi spoof. Anything outside [a-z A-Z 0-9 . _ - /] (control chars, Unicode line/para
  // separators, bidi overrides, zero-width, colons, emoji/surrogates) becomes a space; a surrogate
  // severed by the 200-char cap is > 127 so it is dropped, never left lone.
  const raw = String(filename == null ? '' : filename).replace(/^[A-Za-z]:/, '').slice(0, 200);
  let f = '';
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (code === 92) { f += '/'; continue; }       // backslash -> forward slash (Windows path)
    const ok = (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
      || code === 46 || code === 95 || code === 45 || code === 47;
    f += ok ? raw[i] : ' ';
  }
  f = f.trim();
  while (f.charCodeAt(0) === 47) f = f.slice(1);     // strip leading slashes (47 = '/')
  if (!f || /^\.+$/.test(f)) f = 'input.rs'; // empty or all-dots (".", "..") -> a sane default
  // Glob matching is case-INSENSITIVE (see engine/glob.js), so `Lib.RS` (include) and `Tests/x.rs`
  // (exclude) are handled by the matcher - we preserve the caller's path + case here (so the displayed
  // finding path matches what they passed) and only ensure a `.rs` suffix so an odd name still scans.
  if (!/\.rs$/i.test(f)) f += '.rs';
  return f;
}

// True for a test path (the exclude most on-chain rules share) - so a clean result on a
// test file is explained, not silently read as reassurance.
function isTestPath(f) {
  // Case-insensitive: normalizeName preserves the caller's case and the glob excludes case-insensitively,
  // so a `Tests/` path is excluded - the advisory note must recognize it too (else it's silently dropped).
  return /(^|\/)tests?\//i.test(f);
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

// list_solana_security_rules: the full SOL-0XX guidance (threat model + 52 rules).
function listRules() {
  return GUIDANCE;
}

module.exports = { scanCode, listRules, normalizeName, isTestPath, MAX_CODE, MAX_FINDINGS, RULES };
