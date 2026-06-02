'use strict';
// Regression tests for the round-2 review fixes (DoS, injection, path safety).
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const scanner = require('../src/scanner');
const cli = require('../src/cli');

const BUNDLED = scanner.loadRules(path.join(__dirname, '..', 'rules.json'));

function cap() {
  const c = [];
  return { isTTY: false, write(s) { c.push(s); return true; }, str() { return c.join(''); } };
}
function tmpRepo(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'sssh-'));
  for (const [n, b] of Object.entries(files)) {
    const f = path.join(d, n);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, b);
  }
  return d;
}

test('bundled regexes are linear on adversarial input (<1s on ~1MB)', () => {
  const inputs = [
    'fn foo(\n' + 'a\n'.repeat(130000), // sol_001 O(n^2) trigger (pre-fix: 86s)
    '#[account(\n' + 'x\n'.repeat(65000), // sol_011 O(n^2) trigger (pre-fix: 71s)
  ];
  for (const input of inputs) {
    const t = Date.now();
    scanner.scanContent(input, 'a.rs', BUNDLED);
    assert.ok(Date.now() - t < 1000, `scan took ${Date.now() - t}ms — possible ReDoS regression`);
  }
});

test("sol_006 catches AccountInfo<'_> but not a longer identifier", () => {
  assert.ok(scanner.scanContent("pub x: AccountInfo<'_>,", 'a.rs', BUNDLED).some((x) => x.rule.startsWith('sol_006')));
  assert.ok(scanner.scanContent("pub x: AccountInfo<'a>,", 'a.rs', BUNDLED).some((x) => x.rule.startsWith('sol_006')));
  assert.ok(!scanner.scanContent('struct MyAccountInfoWrap;', 'a.rs', BUNDLED).some((x) => x.rule.startsWith('sol_006')));
});

test('sol_011 catches close= after one- and two-level nested calls', () => {
  const hit = (c) => scanner.scanContent(c, 'a.rs', BUNDLED).some((x) => x.rule.startsWith('sol_011'));
  assert.ok(hit('#[account(mut, constraint = f(), close = dest)]'), 'depth 1');
  assert.ok(hit('#[account(constraint = outer(inner()), close = dest)]'), 'depth 2');
  assert.ok(hit('#[account(mut, close = dest)]'), 'plain');
  assert.ok(!hit('let close = dest;'), 'plain `close =` outside #[account] must not fire');
  // depth-3+ (a(b(c()))) is intentionally out of scope — bounded to keep the regex linear.
});

test('--root that is not an ancestor of the scan path warns', () => {
  const a = tmpRepo({ 'src/lib.rs': 'pub fn x(now_slot: u64){}' });
  const b = fs.mkdtempSync(path.join(os.tmpdir(), 'sssh-root-')); // sibling, not ancestor
  const err = cap();
  const code = cli.main(['scan', a, '-r', b, '--no-fail'], { stdout: cap(), stderr: err });
  assert.match(err.str(), /not an ancestor/);
  assert.notEqual(code, 2, 'a warning must not abort the scan');
});

test('onWarn fires when the file-count limit is hit', () => {
  const dir = tmpRepo({ 'a.rs': 'x', 'b.rs': 'x', 'c.rs': 'x' });
  const warnings = [];
  scanner.scan(dir, BUNDLED, { maxFiles: 2, onWarn: (m) => warnings.push(m) });
  assert.ok(warnings.some((w) => /file scan limit/.test(w)), `got ${JSON.stringify(warnings)}`);
});

test('--root makes reported paths repo-root-relative (SARIF annotations)', () => {
  const dir = tmpRepo({ 'programs/p/src/lib.rs': 'pub fn a(now_slot: u64){}' });
  const out = cap();
  cli.main(['scan', path.join(dir, 'programs'), '-f', 'json', '-r', dir, '--no-fail'], { stdout: out, stderr: cap() });
  const files = JSON.parse(out.str()).findings.map((f) => f.file);
  assert.ok(files.includes('programs/p/src/lib.rs'), `got ${JSON.stringify(files)}`);
});

test('`--` sentinel: an injected flag becomes a path, never a bypass', () => {
  const dir = tmpRepo({ 'src/lib.rs': 'pub fn a(now_slot: u64){}' });
  // The Action puts user paths after `--`. An attacker who injects "--no-fail"
  // must NOT be able to disable the failing gate — it becomes a bogus path.
  const code = cli.main(['scan', '--', dir, '--no-fail'], { stdout: cap(), stderr: cap() });
  assert.equal(code, 2, 'bogus path --no-fail -> exit 2, not a false-green 0');
});

test('ignore-dirs: findings in node_modules / target are excluded', () => {
  const dir = tmpRepo({
    'src/lib.rs': 'pub fn a(now_slot: u64){}',
    'node_modules/dep/x.rs': 'pub fn b(now_slot: u64){}',
    'target/debug/y.rs': 'pub fn c(now_slot: u64){}',
  });
  const out = cap();
  cli.main(['scan', dir, '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  const files = JSON.parse(out.str()).findings.map((f) => f.file);
  assert.ok(files.some((f) => f.endsWith('src/lib.rs')));
  assert.ok(!files.some((f) => f.includes('node_modules') || f.includes('target/')), `leaked: ${files}`);
});

test('oversized (>4MB) files are skipped', () => {
  const dir = tmpRepo({ 'big.rs': 'pub fn a(now_slot: u64){}\n' + 'x'.repeat(5 * 1024 * 1024) });
  const out = cap();
  cli.main(['scan', dir, '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  assert.equal(JSON.parse(out.str()).findingCount, 0);
});

test('SARIF caps at 5000 results and records the total', () => {
  const formatters = require('../src/formatters');
  const many = Array.from({ length: 6000 }, (_, i) => ({
    file: 'a.rs', line: i + 1, column: 1, rule: 'sol_005_realloc_no_guard', reminder: 'x', match: '.realloc(',
  }));
  const sarif = JSON.parse(formatters.sarif(many, BUNDLED));
  assert.equal(sarif.runs[0].results.length, 5000);
  assert.equal(sarif.runs[0].properties.truncated, true);
  assert.equal(sarif.runs[0].properties.totalFindings, 6000);
});
