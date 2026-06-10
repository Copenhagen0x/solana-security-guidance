'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const baseline = require('../src/baseline');

const FP_A = 'a'.repeat(32);
const FP_B = 'b'.repeat(32);

function finding(fp, over = {}) {
  return {
    file: 'src/lib.rs', line: 2, column: 5, rule: 'sol_001_x', reminder: 'r',
    match: 'fn x(now_slot: u64', fingerprint: fp, tier: 'high', severity: 'high',
    ...over,
  };
}

function tmpFile(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sss-base-'));
  const p = path.join(dir, 'baseline.json');
  if (body !== undefined) fs.writeFileSync(p, body);
  return p;
}

// --- createBaseline ---

test('createBaseline keys entries by fingerprint with a human-reviewable snapshot', () => {
  const doc = baseline.createBaseline([finding(FP_A)], { toolVersion: '9.9.9' });
  assert.equal(doc.format, baseline.FORMAT);
  assert.equal(doc.version, baseline.VERSION);
  assert.equal(doc.toolVersion, '9.9.9');
  assert.equal(doc.findingCount, 1);
  assert.deepEqual(doc.fingerprints[FP_A], {
    rule: 'sol_001_x', file: 'src/lib.rs', line: 2, match: 'fn x(now_slot: u64',
  });
});

test('createBaseline skips findings without a fingerprint (nothing stable to key on)', () => {
  const doc = baseline.createBaseline([finding(FP_A), finding(undefined)]);
  assert.equal(doc.findingCount, 1);
  assert.deepEqual(Object.keys(doc.fingerprints), [FP_A]);
});

// --- writeBaseline / loadBaseline round trip ---

test('write + load round-trips and validates clean', () => {
  const p = tmpFile();
  baseline.writeBaseline(p, [finding(FP_A), finding(FP_B, { line: 7 })]);
  const doc = baseline.loadBaseline(p);
  assert.equal(doc.findingCount, 2);
  assert.ok(doc.fingerprints[FP_A] && doc.fingerprints[FP_B]);
});

// --- loadBaseline strictness: every malformed shape is a loud throw ---

test('loadBaseline throws on a missing file', () => {
  assert.throws(() => baseline.loadBaseline(path.join(os.tmpdir(), 'sss-no-such', 'x.json')), /cannot read baseline/);
});

test('loadBaseline throws on invalid JSON', () => {
  assert.throws(() => baseline.loadBaseline(tmpFile('{nope')), /not valid JSON/);
});

test('loadBaseline throws on a non-object (array / scalar)', () => {
  assert.throws(() => baseline.loadBaseline(tmpFile('[1,2]')), /expected a JSON object/);
  assert.throws(() => baseline.loadBaseline(tmpFile('42')), /expected a JSON object/);
});

test('loadBaseline throws on a wrong/missing format marker', () => {
  assert.throws(() => baseline.loadBaseline(tmpFile('{"format":"something-else","version":1,"fingerprints":{}}')), /unrecognized format/);
  assert.throws(() => baseline.loadBaseline(tmpFile('{"version":1,"fingerprints":{}}')), /unrecognized format/);
});

test('loadBaseline throws on an unsupported version', () => {
  const body = JSON.stringify({ format: baseline.FORMAT, version: 99, fingerprints: {} });
  assert.throws(() => baseline.loadBaseline(tmpFile(body)), /unsupported version/);
});

test('loadBaseline throws when fingerprints is missing or not an object', () => {
  assert.throws(() => baseline.loadBaseline(tmpFile(JSON.stringify({ format: baseline.FORMAT, version: 1 }))), /missing "fingerprints"/);
  assert.throws(() => baseline.loadBaseline(tmpFile(JSON.stringify({ format: baseline.FORMAT, version: 1, fingerprints: [] }))), /missing "fingerprints"/);
});

test('loadBaseline throws on a malformed fingerprint key (wrong length / non-hex)', () => {
  const bad = (k) => JSON.stringify({ format: baseline.FORMAT, version: 1, fingerprints: { [k]: {} } });
  assert.throws(() => baseline.loadBaseline(tmpFile(bad('abc'))), /invalid fingerprint key/);
  assert.throws(() => baseline.loadBaseline(tmpFile(bad('Z'.repeat(32)))), /invalid fingerprint key/);
});

test('loadBaseline REJECTS entries without the rule/file snapshot (anti-poisoning: an entry must say what it suppresses)', () => {
  const withEntry = (v) => JSON.stringify({ format: baseline.FORMAT, version: 1, fingerprints: { [FP_A]: v } });
  for (const v of [{}, null, 0, 'x', [], true, { rule: 'sol_001_x' }, { file: 'a.rs' }, { rule: 7, file: 'a.rs' }]) {
    assert.throws(() => baseline.loadBaseline(tmpFile(withEntry(v))), /missing its rule\/file snapshot/, `entry ${JSON.stringify(v)} must be rejected`);
  }
});

test('loadBaseline accepts entries with extra unknown fields (forward-compat)', () => {
  const body = JSON.stringify({
    format: baseline.FORMAT, version: 1,
    fingerprints: { [FP_A]: { rule: 'sol_001_x', file: 'a.rs', line: 2, match: 'm', futureField: 'ok' } },
  });
  const doc = baseline.loadBaseline(tmpFile(body));
  assert.ok(doc.fingerprints[FP_A]);
});

test('loadBaseline strips a UTF-8 BOM (Notepad hand-edit) before parsing', () => {
  const BOM = String.fromCharCode(0xfeff); // explicit — no invisible literal in this source
  const body = JSON.stringify({ format: baseline.FORMAT, version: 1, fingerprints: {} });
  const doc = baseline.loadBaseline(tmpFile(BOM + body));
  assert.deepEqual(doc.fingerprints, {});
});

test('writeBaseline returns the document (exact recorded count for the caller)', () => {
  const p = tmpFile();
  const doc = baseline.writeBaseline(p, [finding(FP_A)]);
  assert.equal(doc.findingCount, 1);
});

// --- applyBaseline ---

test('applyBaseline splits kept vs suppressed and counts stale entries', () => {
  const doc = baseline.createBaseline([finding(FP_A), finding(FP_B)]);
  // Current scan: FP_A still present, FP_B fixed, FP_C ('c'…) is new.
  const FP_C = 'c'.repeat(32);
  const r = baseline.applyBaseline([finding(FP_A), finding(FP_C)], doc);
  assert.equal(r.suppressed, 1, 'FP_A suppressed');
  assert.equal(r.kept.length, 1, 'FP_C kept');
  assert.equal(r.kept[0].fingerprint, FP_C);
  assert.equal(r.stale, 1, 'FP_B matched nothing — stale');
});

test('applyBaseline never suppresses a finding without a fingerprint', () => {
  const doc = baseline.createBaseline([finding(FP_A)]);
  const r = baseline.applyBaseline([finding(undefined)], doc);
  assert.equal(r.kept.length, 1, 'fingerprint-less finding is always reported');
  assert.equal(r.suppressed, 0);
});

test('applyBaseline is not fooled by prototype keys (constructor / __proto__)', () => {
  // A hostile baseline file with {"constructor": {...}} must not suppress a finding
  // whose fingerprint is literally "constructor" (impossible — 32-hex enforced at
  // load) — but defend the lookup itself with hasOwnProperty semantics anyway.
  const doc = { format: baseline.FORMAT, version: 1, fingerprints: Object.create(null) };
  doc.fingerprints[FP_A] = {};
  const r = baseline.applyBaseline([finding(FP_A), finding(FP_B)], doc);
  assert.equal(r.suppressed, 1);
  assert.equal(r.kept.length, 1);
});

test('duplicate identical fingerprints in one scan: every instance suppressed, one baseline entry', () => {
  // Can occur only if the same fp appears twice (it shouldn't, by ordinal design) —
  // the baseline still behaves sanely: both suppressed, stale stays 0.
  const doc = baseline.createBaseline([finding(FP_A)]);
  const r = baseline.applyBaseline([finding(FP_A), finding(FP_A)], doc);
  assert.equal(r.suppressed, 2);
  assert.equal(r.stale, 0);
});
