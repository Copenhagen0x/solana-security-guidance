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

// --- baseline / diff (--baseline, --write-baseline) ---

const VULN2 = VULN + 'pub fn redeem(ctx: Context<B>, now_slot: u64) -> Result<()> { Ok(()) }\n';

test('adoption cycle: write baseline -> rescan exits 0 -> new finding gates, drifted old one stays suppressed', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const base = path.join(dir, 'sss-baseline.json');
  // Day one: record what exists.
  let code = cli.main(['scan', dir, '-r', dir, '--write-baseline', base, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  assert.equal(code, 0);
  assert.ok(fs.existsSync(base), 'baseline written');
  // Rescan unchanged: nothing new -> green.
  const out1 = cap();
  code = cli.main(['scan', dir, '-r', dir, '--baseline', base, '--no-color'], { stdout: out1, stderr: cap() });
  assert.equal(code, 0, 'no new findings -> exit 0');
  assert.match(out1.str(), /no NEW findings/);
  assert.match(out1.str(), /1 finding\(s\) suppressed by baseline/);
  // Drift the old finding down the file AND add a genuinely new one.
  fs.writeFileSync(path.join(dir, 'src', 'lib.rs'), '\n\n// drift\n' + VULN2);
  const out2 = cap();
  code = cli.main(['scan', dir, '-r', dir, '--baseline', base, '--no-color'], { stdout: out2, stderr: cap() });
  assert.equal(code, 1, 'the new finding gates');
  assert.match(out2.str(), /1 NEW finding\(s\)/);
  assert.match(out2.str(), /1 finding\(s\) suppressed by baseline/, 'drifted old finding still suppressed');
});

test('json surfaces baseline suppressed + stale counts', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const base = path.join(dir, 'b.json');
  cli.main(['scan', dir, '-r', dir, '--write-baseline', base, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  // Fix the finding entirely: its baseline entry goes stale.
  fs.writeFileSync(path.join(dir, 'src', 'lib.rs'), CLEAN);
  const out = cap();
  const code = cli.main(['scan', dir, '-r', dir, '--baseline', base, '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  assert.equal(code, 0);
  const parsed = JSON.parse(out.str());
  assert.deepEqual(parsed.baseline, { suppressed: 0, stale: 1 });
  assert.equal(parsed.findingCount, 0);
});

test('json omits the baseline block when --baseline is not used (additive field)', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const out = cap();
  cli.main(['scan', dir, '-f', 'json', '--no-fail'], { stdout: out, stderr: cap() });
  assert.ok(!('baseline' in JSON.parse(out.str())));
});

test('sarif surfaces baselineSuppressed/baselineStale in run properties', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const base = path.join(dir, 'b.json');
  cli.main(['scan', dir, '-r', dir, '--write-baseline', base, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  const out = cap();
  cli.main(['scan', dir, '-r', dir, '--baseline', base, '-f', 'sarif', '--no-fail'], { stdout: out, stderr: cap() });
  const props = JSON.parse(out.str()).runs[0].properties;
  assert.equal(props.baselineSuppressed, 1);
  assert.equal(props.baselineStale, 0);
});

test('a malformed baseline exits 2 — never degrades to a baseline-less scan', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN, 'bad.json': '{"not":"a baseline"}' });
  const err = cap();
  const code = cli.main(['scan', dir, '--baseline', path.join(dir, 'bad.json')], { stdout: cap(), stderr: err });
  assert.equal(code, 2);
  assert.match(err.str(), /unrecognized format/);
});

test('a missing baseline file exits 2', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const code = cli.main(['scan', dir, '--baseline', path.join(dir, 'nope.json')], { stdout: cap(), stderr: cap() });
  assert.equal(code, 2);
});

test('--baseline / --write-baseline without a file path exit 2', () => {
  assert.equal(cli.main(['scan', '.', '--baseline'], { stdout: cap(), stderr: cap() }), 2);
  assert.equal(cli.main(['scan', '.', '--write-baseline'], { stdout: cap(), stderr: cap() }), 2);
});

test('an INCOMPLETE scan still exits 2 even when a baseline suppresses everything', () => {
  // The cap signal must be un-maskable: a finding-flood can't be "fixed" by a baseline.
  const dir = tmpRepo({ 'src/lib.rs': VULN2 });
  const base = path.join(dir, 'b.json');
  cli.main(['scan', dir, '-r', dir, '--write-baseline', base, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  process.env.SSS_MAX_FINDINGS = '1';
  try {
    const code = cli.main(['scan', dir, '-r', dir, '--baseline', base, '-f', 'json'], { stdout: cap(), stderr: cap() });
    assert.equal(code, 2, 'capped scan exits 2 regardless of baseline');
  } finally {
    delete process.env.SSS_MAX_FINDINGS;
  }
});

test('refresh flow: --baseline old --write-baseline new keeps prior acknowledgments', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const oldB = path.join(dir, 'old.json');
  cli.main(['scan', dir, '-r', dir, '--write-baseline', oldB, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  // Add a second finding, then refresh: the new baseline must contain BOTH.
  fs.writeFileSync(path.join(dir, 'src', 'lib.rs'), VULN2);
  const newB = path.join(dir, 'new.json');
  cli.main(['scan', dir, '-r', dir, '--baseline', oldB, '--write-baseline', newB, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  const doc = JSON.parse(fs.readFileSync(newB, 'utf8'));
  assert.equal(doc.findingCount, 2, 'refreshed baseline holds the old AND the new finding');
});

test('--write-baseline records the post-min-tier set (what the scan reports is what it acknowledges)', () => {
  // VULN fires SOL-001 (high tier); the 32-ones literal fires SOL-018 (low tier).
  const dir = tmpRepo({ 'src/lib.rs': VULN + 'pub fn s() { let _x = "11111111111111111111111111111111"; }\n' });
  const base = path.join(dir, 'b.json');
  cli.main(['scan', dir, '-r', dir, '--min-tier', 'high', '--write-baseline', base, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  const doc = JSON.parse(fs.readFileSync(base, 'utf8'));
  assert.equal(doc.findingCount, 1, 'only the high-tier finding is recorded under --min-tier high');
  assert.match(Object.values(doc.fingerprints)[0].rule, /sol_001/);
});

test('--write-baseline REFUSES an INCOMPLETE scan (a partial baseline must never look authoritative)', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN2 }); // two findings; cap to 1 => truncated
  const base = path.join(dir, 'b.json');
  process.env.SSS_MAX_FINDINGS = '1';
  try {
    const err = cap();
    const code = cli.main(['scan', dir, '-r', dir, '--write-baseline', base, '--no-fail'], { stdout: cap(), stderr: err });
    assert.equal(code, 2, 'refused with exit 2 even under --no-fail');
    assert.match(err.str(), /refusing to write a baseline from an INCOMPLETE scan/);
    assert.ok(!fs.existsSync(base), 'no partial baseline file is left behind');
  } finally {
    delete process.env.SSS_MAX_FINDINGS;
  }
});

test('--write-baseline to an unwritable path exits 2', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const err = cap();
  const code = cli.main(['scan', dir, '-r', dir, '--write-baseline', path.join(dir, 'no', 'such', 'dir', 'b.json'), '--no-fail'], { stdout: cap(), stderr: err });
  assert.equal(code, 2);
  assert.match(err.str(), /cannot write baseline/);
});

test('a poisoned baseline entry without its snapshot is rejected end-to-end (exit 2)', () => {
  // The anti-poisoning gate: a hand-minimized {"<fp>": {}} entry must fail the run.
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const poisoned = JSON.stringify({
    format: 'solana-security-standard-baseline', version: 1,
    fingerprints: { ['a'.repeat(32)]: {} },
  });
  fs.writeFileSync(path.join(dir, 'poison.json'), poisoned);
  const err = cap();
  const code = cli.main(['scan', dir, '--baseline', path.join(dir, 'poison.json')], { stdout: cap(), stderr: err });
  assert.equal(code, 2);
  assert.match(err.str(), /missing its rule\/file snapshot/);
});

test('stale baseline entries warn on stderr (the baseline is rotting, refresh it)', () => {
  const dir = tmpRepo({ 'src/lib.rs': VULN });
  const base = path.join(dir, 'b.json');
  cli.main(['scan', dir, '-r', dir, '--write-baseline', base, '--no-fail', '-q'], { stdout: cap(), stderr: cap() });
  fs.writeFileSync(path.join(dir, 'src', 'lib.rs'), CLEAN);
  const err = cap();
  cli.main(['scan', dir, '-r', dir, '--baseline', base, '--no-fail'], { stdout: cap(), stderr: err });
  assert.match(err.str(), /1 baseline entry matched nothing/);
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
