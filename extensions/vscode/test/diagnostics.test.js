'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { computeDiagnostics, relPosix } = require('../src/diagnostics');

// Build platform-correct absolute paths for the relPosix/workspace logic.
const root = path.resolve(path.sep === '\\' ? 'C:\\repo' : '/repo');
const inWs = (p) => path.join(root, ...p.split('/'));

test('flags SOL-001 with a 0-based line and a help link', () => {
  const text = 'use anchor_lang::prelude::*;\npub fn activate(ctx: Context<A>, now_slot: u64) {}\n';
  const d = computeDiagnostics(text, inWs('src/lib.rs'), root);
  const sol1 = d.find((x) => x.ruleId === 'SOL-001');
  assert.ok(sol1, 'SOL-001 present');
  assert.equal(sol1.startLine, 1, '0-based: the fn is on the 2nd line');
  assert.ok(sol1.message.startsWith('SOL-001:'));
  assert.match(sol1.helpUri, /#sol-001$/);
  assert.ok(sol1.endCol > sol1.startCol);
});

test('a multi-line match underlines only its first line', () => {
  const text = 'pub fn a(\n  now_slot: u64,\n) {}\n';
  const d = computeDiagnostics(text, inWs('lib.rs'), root).find((x) => x.ruleId === 'SOL-001');
  assert.ok(d);
  assert.equal(d.startLine, d.endLine, 'single-line range');
});

test('a long (>100-char) single-line match never overruns the source line', () => {
  // The scanner truncates a match >100 chars to slice(0,100)+'…'; the squiggle must
  // still stay within the actual line (regression guard for the endCol cap).
  const pad = 'p'.repeat(60);
  const text = `pub fn activate(${pad}: u64, ${pad}: u64, now_slot: u64) {}\n`;
  const d = computeDiagnostics(text, inWs('src/lib.rs'), root).find((x) => x.ruleId === 'SOL-001');
  assert.ok(d, 'SOL-001 present on the long signature');
  const lineLen = text.split('\n')[d.startLine].length;
  assert.ok(d.endCol > d.startCol, 'non-empty underline');
  assert.ok(d.endCol <= lineLen, `endCol ${d.endCol} must not exceed line length ${lineLen}`);
});

test('an exact short match underlines exactly the match length', () => {
  const text = 'x.realloc(8);\n'; // sol_005 substring ".realloc(" -> 9 chars, not truncated
  const d = computeDiagnostics(text, inWs('src/lib.rs'), root).find((x) => x.ruleId === 'SOL-005');
  assert.ok(d, 'SOL-005 present');
  assert.equal(d.endCol - d.startCol, '.realloc('.length, 'underlines exactly the literal');
});

test('exclude_paths: a file under tests/ yields nothing; under src/ it fires', () => {
  const text = 'pub fn a(now_slot: u64){}';
  assert.equal(computeDiagnostics(text, inWs('src/tests/x.rs'), root).length, 0);
  assert.ok(computeDiagnostics(text, inWs('src/x.rs'), root).length >= 1);
});

test('exclude + include match case-insensitively (mixed-case dirs/extensions)', () => {
  const text = 'pub fn a(now_slot: u64){}';
  // a mixed-case Tests/ dir is still excluded (before the glob fix it was scanned as on-chain):
  assert.equal(computeDiagnostics(text, inWs('src/Tests/x.rs'), root).length, 0);
  assert.equal(computeDiagnostics(text, inWs('TESTS/x.rs'), root).length, 0);
  // a mixed-case `.RS` extension still scans (before the fix it was silently skipped):
  assert.ok(computeDiagnostics(text, inWs('Programs/Foo/Lib.RS'), root).length >= 1);
});

test('relPosix: workspace-relative, posix slashes, basename fallback outside ws', () => {
  assert.equal(relPosix(inWs('src/lib.rs'), root), 'src/lib.rs');
  const elsewhere = path.resolve(path.sep === '\\' ? 'C:\\other\\lib.rs' : '/other/lib.rs');
  assert.equal(relPosix(elsewhere, root), 'lib.rs'); // outside workspace -> basename
  assert.equal(relPosix(inWs('a/b.rs'), undefined), 'b.rs'); // no workspace -> basename
});

test('clean Rust produces no diagnostics', () => {
  assert.equal(computeDiagnostics('pub fn ok() -> u64 { 7 }\n', inWs('src/lib.rs'), root).length, 0);
});

test('degraded (no rules) is safe: empty rule set yields no diagnostics, never throws', () => {
  // This is the state diagnostics.js falls back to if the engine was never vendored
  // (loadRules throws -> RULES = []). The extension must still activate cleanly.
  const vulnerable = 'pub fn a(ctx: Context<A>, now_slot: u64) { x.realloc(8); }\n';
  assert.deepEqual(computeDiagnostics(vulnerable, inWs('src/lib.rs'), root, []), []);
});
