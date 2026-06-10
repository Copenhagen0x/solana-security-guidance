'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cli = require('../src/cli');

function cap() {
  const chunks = [];
  return { isTTY: false, write(s) { chunks.push(s); return true; }, str() { return chunks.join(''); } };
}

function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sss-'));
  for (const [name, body] of Object.entries(files)) {
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, body);
  }
  return dir;
}

const VULN = 'use anchor_lang::prelude::*;\npub fn activate(ctx: Context<A>, now_slot: u64) -> Result<()> { Ok(()) }\n';
const CLEAN = '// nothing risky here\npub fn add_two() -> u64 { 2 }\n';

test('--version prints version and exits 0', () => {
  const out = cap();
  const code = cli.main(['--version'], { stdout: out, stderr: cap() });
  assert.equal(code, 0);
  assert.match(out.str(), /^\d+\.\d+\.\d+/);
});

test('--help exits 0 with usage', () => {
  const out = cap();
  const code = cli.main(['--help'], { stdout: out, stderr: cap() });
  assert.equal(code, 0);
  assert.match(out.str(), /USAGE/);
});

test('scan with findings exits 1 and reports SOL-001', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap(), err = cap();
  const code = cli.main(['scan', dir, '--no-color'], { stdout: out, stderr: err });
  assert.equal(code, 1);
  assert.match(out.str(), /SOL-001/);
});

test('--no-fail reports findings but exits 0', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap();
  const code = cli.main(['scan', dir, '--no-fail', '--no-color'], { stdout: out, stderr: cap() });
  assert.equal(code, 0);
  assert.match(out.str(), /SOL-001/);
});

test('clean code exits 0 with no findings', () => {
  const dir = tmpRepo({ 'src/lib.rs': CLEAN });
  const out = cap();
  const code = cli.main(['scan', dir], { stdout: out, stderr: cap() });
  assert.equal(code, 0);
  assert.match(out.str(), /no findings/);
});

test('--format json emits valid JSON with findings', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap();
  cli.main(['scan', dir, '--format', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  const parsed = JSON.parse(out.str());
  assert.ok(parsed.findingCount >= 1);
  assert.ok(parsed.findings.some((f) => f.ruleId === 'SOL-001'));
});

test('--format sarif emits valid SARIF 2.1.0', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap();
  cli.main(['scan', dir, '--format', 'sarif', '--no-fail'], { stdout: out, stderr: cap() });
  const sarif = JSON.parse(out.str());
  assert.equal(sarif.version, '2.1.0');
  assert.ok(Array.isArray(sarif.runs[0].results));
  assert.ok(sarif.runs[0].results.length >= 1);
  assert.ok(sarif.runs[0].tool.driver.rules.length >= 1);
  // every result references a rule that exists in the driver
  const ids = new Set(sarif.runs[0].tool.driver.rules.map((r) => r.id));
  assert.ok(sarif.runs[0].results.every((r) => ids.has(r.ruleId)));
  // `reported` is present in the non-truncated branch too; both truncation flags false
  const props = sarif.runs[0].properties;
  assert.equal(props.reported, sarif.runs[0].results.length);
  assert.equal(props.truncated, false);
  assert.equal(props.scannerTruncated, false);
});

test('an incomplete scan (finding cap hit) fails exit 2 — never a silent pass, even with --min-tier high', () => {
  // Two SOL-001 (high-tier) findings; force the cap to 1 so the scan is incomplete.
  const dir = tmpRepo({ 'src/lib.rs': VULN + 'pub fn g(ctx: C, now_slot: u64) -> Result<()> { Ok(()) }\n' });
  process.env.SSS_MAX_FINDINGS = '1';
  try {
    const out = cap();
    const code = cli.main(['scan', dir, '-f', 'json', '--min-tier', 'high'], { stdout: out, stderr: cap() });
    assert.equal(code, 2, 'a capped/incomplete scan must exit 2, never silently pass a gate');
    assert.equal(JSON.parse(out.str()).scanComplete, false, 'json marks the scan incomplete');
  } finally {
    delete process.env.SSS_MAX_FINDINGS;
  }
});

test('SARIF marks an incomplete scan with properties.scannerTruncated', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN + 'pub fn g(ctx: C, now_slot: u64) -> Result<()> { Ok(()) }\n' });
  process.env.SSS_MAX_FINDINGS = '1';
  try {
    const out = cap();
    cli.main(['scan', dir, '-f', 'sarif', '--no-fail'], { stdout: out, stderr: cap() });
    assert.equal(JSON.parse(out.str()).runs[0].properties.scannerTruncated, true);
  } finally {
    delete process.env.SSS_MAX_FINDINGS;
  }
});

test('--no-fail suppresses the incomplete-scan exit 2 (report-only opt-out)', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN + 'pub fn g(ctx: C, now_slot: u64) -> Result<()> { Ok(()) }\n' });
  process.env.SSS_MAX_FINDINGS = '1';
  try {
    const out = cap();
    const code = cli.main(['scan', dir, '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
    assert.equal(code, 0, '--no-fail opts out of gating');
    assert.equal(JSON.parse(out.str()).scanComplete, false, 'but incompleteness is still surfaced');
  } finally {
    delete process.env.SSS_MAX_FINDINGS;
  }
});

test('unknown format exits 2', () => {
  const code = cli.main(['scan', '.', '--format', 'xml'], { stdout: cap(), stderr: cap() });
  assert.equal(code, 2);
});

test('missing path exits 2', () => {
  const code = cli.main(['scan', '/no/such/path/xyz'], { stdout: cap(), stderr: cap() });
  assert.equal(code, 2);
});

test('-o writes output to a file', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const outFile = path.join(dir, 'out.json');
  const code = cli.main(['scan', dir, '-f', 'json', '-o', outFile, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  assert.equal(code, 0);
  assert.ok(fs.existsSync(outFile));
  assert.ok(JSON.parse(fs.readFileSync(outFile, 'utf8')).findingCount >= 1);
});

test('json findings carry severity + tier from rules-meta', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap();
  cli.main(['scan', dir, '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  const f = JSON.parse(out.str()).findings.find((x) => x.ruleId === 'SOL-001');
  assert.ok(f, 'SOL-001 present');
  assert.equal(f.severity, 'high');
  assert.equal(f.tier, 'high');
});

test('--min-tier high drops LOW-tier findings but keeps HIGH', () => {
  // now_slot -> SOL-001 (tier high); the 32-ones System Program literal -> SOL-018 (tier low)
  const dir = tmpRepo({ 'src/lib.rs': VULN + 'pub fn s() { let _x = "11111111111111111111111111111111"; }\n' });
  const all = cap();
  cli.main(['scan', dir, '-f', 'json', '--no-fail'], { stdout: all, stderr: cap() });
  const allIds = new Set(JSON.parse(all.str()).findings.map((x) => x.ruleId));
  assert.ok(allIds.has('SOL-001') && allIds.has('SOL-018'), 'both fire with no floor');
  const hi = cap();
  cli.main(['scan', dir, '-f', 'json', '--no-fail', '--min-tier', 'high'], { stdout: hi, stderr: cap() });
  const hiIds = new Set(JSON.parse(hi.str()).findings.map((x) => x.ruleId));
  assert.ok(hiIds.has('SOL-001'), 'high-tier SOL-001 kept');
  assert.ok(!hiIds.has('SOL-018'), 'low-tier SOL-018 dropped');
});

test('--min-tier low reports everything (the default floor, well-defined)', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN + 'pub fn s() { let _x = "11111111111111111111111111111111"; }\n' });
  const lo = cap();
  cli.main(['scan', dir, '-f', 'json', '--no-fail', '--min-tier', 'low'], { stdout: lo, stderr: cap() });
  const loIds = new Set(JSON.parse(lo.str()).findings.map((x) => x.ruleId));
  assert.ok(loIds.has('SOL-001') && loIds.has('SOL-018'), 'low floor keeps both high- and low-tier');
});

test('unknown --min-tier exits 2', () => {
  const code = cli.main(['scan', '.', '--min-tier', 'bogus'], { stdout: cap(), stderr: cap() });
  assert.equal(code, 2);
});

test('overlapping scan paths report each finding once (nested path deduped)', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap();
  // `scan <dir> <dir>/src` — src is nested in dir; the file must not double-count.
  cli.main(['scan', dir, path.join(dir, 'src'), '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  const hits = JSON.parse(out.str()).findings.filter((f) => f.ruleId === 'SOL-001');
  assert.equal(hits.length, 1, 'a file under two overlapping scan roots must be reported once');
});

test('sibling (non-overlapping) scan paths are both scanned', () => {
  const dir = tmpRepo({ 'a/lib.rs': VULN, 'b/lib.rs': VULN });
  const out = cap();
  cli.main(['scan', path.join(dir, 'a'), path.join(dir, 'b'), '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  const hits = JSON.parse(out.str()).findings.filter((f) => f.ruleId === 'SOL-001');
  assert.equal(hits.length, 2, 'distinct sibling roots must each be scanned');
});

test('json findings carry a stable 32-hex (128-bit) fingerprint', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap();
  cli.main(['scan', dir, '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  const f = JSON.parse(out.str()).findings.find((x) => x.ruleId === 'SOL-001');
  assert.ok(f, 'SOL-001 present');
  assert.match(f.fingerprint, /^[0-9a-f]{32}$/);
});

test('sarif results carry partialFingerprints (GitHub alert tracking across commits)', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap();
  cli.main(['scan', dir, '-f', 'sarif', '--no-fail'], { stdout: out, stderr: cap() });
  const r = JSON.parse(out.str()).runs[0].results[0];
  assert.ok(r.partialFingerprints, 'partialFingerprints present on the result');
  assert.match(r.partialFingerprints['sssFindingId/v1'], /^[0-9a-f]{32}$/);
});

test('json fingerprint is stable when the finding drifts to a different line', () => {
  const a = tmpRepo({ 'src/lib.rs': VULN });
  const b = tmpRepo({ 'src/lib.rs': '\n\n\n\n' + VULN }); // same relative path, finding pushed down
  const outA = cap(), outB = cap();
  cli.main(['scan', a, '-f', 'json', '--no-fail', '-r', a], { stdout: outA, stderr: cap() });
  cli.main(['scan', b, '-f', 'json', '--no-fail', '-r', b], { stdout: outB, stderr: cap() });
  const fa = JSON.parse(outA.str()).findings.find((x) => x.ruleId === 'SOL-001');
  const fb = JSON.parse(outB.str()).findings.find((x) => x.ruleId === 'SOL-001');
  assert.notEqual(fa.line, fb.line, 'the finding is on a different line');
  assert.equal(fa.fingerprint, fb.fingerprint, 'but the fingerprint is unchanged');
});
