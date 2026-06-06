'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const scanner = require('../src/scanner');

const RULES = scanner.compileRules({
  patterns: [
    {
      rule_name: 'sol_001_now_slot',
      regex: 'fn\\s+\\w+\\([^)]*now_slot\\s*:\\s*u64',
      paths: ['**/*.rs'],
      exclude_paths: ['**/tests/**'],
      reminder: 'Jelleo SOL-001: caller now_slot.',
    },
    {
      rule_name: 'sol_005_realloc',
      substrings: ['.realloc('],
      paths: ['**/*.rs'],
      reminder: 'Jelleo SOL-005: realloc.',
    },
    {
      rule_name: 'sol_014_arith',
      regex: '(?:u64|i64)\\s*=\\s*\\w+\\s*[-+*]\\s*\\w+\\s*[;,)]',
      paths: ['**/*.rs'],
      reminder: 'Jelleo SOL-014: unchecked arithmetic.',
    },
  ],
});

test('finds now_slot across a multi-line signature', () => {
  const src = 'pub fn activate(\n    ctx: Context<A>,\n    now_slot: u64,\n) {}\n';
  const f = scanner.scanContent(src, 'src/lib.rs', RULES);
  const sol1 = f.filter((x) => x.rule === 'sol_001_now_slot');
  assert.equal(sol1.length, 1);
  assert.equal(sol1[0].line, 1, 'reports the fn line');
});

test('substring rule reports correct line/column', () => {
  const src = 'line one\nlet x = acc.realloc(10, false);\n';
  const f = scanner.scanContent(src, 'p/lib.rs', RULES);
  const sol5 = f.find((x) => x.rule === 'sol_005_realloc');
  assert.ok(sol5);
  assert.equal(sol5.line, 2);
  assert.equal(sol5.column, 12); // 1-based column of ".realloc("
});

test('sol_014 catches subtraction underflow, ignores checked_*', () => {
  const bad = scanner.scanContent('let x: u64 = a - b;\n', 'p.rs', RULES);
  assert.ok(bad.some((x) => x.rule === 'sol_014_arith'), 'a - b should fire');
  const ok = scanner.scanContent('let x = a.checked_sub(b).unwrap();\n', 'p.rs', RULES);
  assert.ok(!ok.some((x) => x.rule === 'sol_014_arith'), 'checked_sub must not fire');
});

test('exclude_paths suppresses findings under tests/', () => {
  const src = 'fn t(now_slot: u64) {}\n';
  assert.equal(scanner.scanContent(src, 'src/lib.rs', RULES).length, 1);
  assert.equal(scanner.scanContent(src, 'src/tests/mod.rs', RULES).length, 0);
});

test('paths filter: only .rs files are matched', () => {
  const src = 'fn t(now_slot: u64) {}\n';
  assert.equal(scanner.scanContent(src, 'notes.md', RULES).length, 0);
});

test('locator handles \\n correctly at end and start', () => {
  const locate = scanner.makeLocator('a\nbb\nccc');
  assert.deepEqual(locate(0), { line: 1, column: 1 }); // 'a'
  assert.deepEqual(locate(2), { line: 2, column: 1 }); // first 'b'
  assert.deepEqual(locate(5), { line: 3, column: 1 }); // first 'c'
});

test('invalid regex rule is skipped, not thrown', () => {
  const r = scanner.compileRules({ patterns: [{ rule_name: 'bad', regex: '([', paths: ['**/*.rs'] }] });
  assert.ok(r[0].invalid);
  assert.doesNotThrow(() => scanner.scanContent('whatever', 'a.rs', r));
});

test('exclude_paths is case-insensitive end-to-end (mixed-case Tests/ does not bypass)', () => {
  // Regression for the threat-modeler finding: a `Tests/` dir bypassed the test
  // exclude and was scanned as on-chain code (false positive); a `Lib.RS` file
  // silently never scanned. The exclude must hold regardless of case.
  const src = 'fn t(now_slot: u64) {}\n';
  assert.equal(scanner.scanContent(src, 'src/Tests/mod.rs', RULES).length, 0, 'Tests/ suppressed');
  assert.equal(scanner.scanContent(src, 'src/TESTS/mod.rs', RULES).length, 0, 'TESTS/ suppressed');
  assert.equal(scanner.scanContent(src, 'src/Lib.RS', RULES).length, 1, 'Lib.RS is still scanned');
});

test('findings carry tier + severity from the rule (advisory metadata)', () => {
  const r = scanner.compileRules({
    patterns: [{ rule_name: 'sol_099_x', substrings: ['BOOM'], paths: ['**/*.rs'], tier: 'high', severity: 'medium' }],
  });
  const f = scanner.scanContent('let x = BOOM;\n', 'a.rs', r);
  assert.equal(f.length, 1);
  assert.equal(f[0].tier, 'high');
  assert.equal(f[0].severity, 'medium');
});

test('a rule without metadata still scans (tier/severity undefined, not a crash)', () => {
  const r = scanner.compileRules({ patterns: [{ rule_name: 'sol_098_y', substrings: ['ZAP'], paths: ['**/*.rs'] }] });
  const f = scanner.scanContent('ZAP\n', 'a.rs', r);
  assert.equal(f.length, 1);
  assert.equal(f[0].tier, null);
  assert.equal(f[0].severity, null);
});
