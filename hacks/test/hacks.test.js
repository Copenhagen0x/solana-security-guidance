'use strict';
// Tests for the Solana Hacks Database. Run: node --test  (from hacks/)
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const HACKS_DIR = path.join(__dirname, '..');
const REPO_ROOT = path.join(__dirname, '..', '..');
const sync = require('../scripts/sync-hacks');

const data = JSON.parse(fs.readFileSync(path.join(HACKS_DIR, 'hacks.json'), 'utf8'));
const mdText = fs.readFileSync(path.join(REPO_ROOT, 'claude-security-guidance.md'), 'utf8');
const ruleTitles = sync.loadRuleTitles(mdText);
const validRuleIds = Object.keys(ruleTitles);

test('guidance.md parses to the full 52-rule set', () => {
  assert.strictEqual(validRuleIds.length, 52, `expected 52 rules, parsed ${validRuleIds.length}`);
  assert.ok(ruleTitles['SOL-001'] && ruleTitles['SOL-024'] && ruleTitles['SOL-028']);
});

test('hacks.json validates clean against the real rule ids', () => {
  const errors = sync.validate(data, validRuleIds);
  assert.deepStrictEqual(errors, [], 'validation errors:\n' + errors.join('\n'));
});

test('every referenced SOL rule exists in claude-security-guidance.md', () => {
  const ids = new Set(validRuleIds);
  for (const h of data.hacks) for (const r of h.sol_rules) {
    assert.ok(ids.has(r), `${h.id} references ${r} which is not a real rule`);
  }
});

test('ids are unique slugs', () => {
  const seen = new Set();
  for (const h of data.hacks) {
    assert.match(h.id, /^[a-z0-9-]+$/, `${h.id} is not a slug`);
    assert.ok(!seen.has(h.id), `duplicate id ${h.id}`);
    seen.add(h.id);
  }
});

test('dates are valid and not in the future', () => {
  const now = new Date();
  for (const h of data.hacks) {
    assert.match(h.date, /^\d{4}-\d{2}-\d{2}$/, `${h.id} bad date`);
    const d = new Date(h.date + 'T00:00:00Z');
    assert.ok(!isNaN(d.getTime()), `${h.id} unparseable date`);
    assert.ok(d <= now, `${h.id} date is in the future`);
  }
});

test('every source is an https URL', () => {
  for (const h of data.hacks) {
    assert.ok(h.sources.length >= 1, `${h.id} has no sources`);
    for (const u of h.sources) assert.match(u, /^https:\/\/\S+$/, `${h.id} bad source ${u}`);
  }
});

test('honesty invariant: code_preventable iff mapped to >=1 rule', () => {
  for (const h of data.hacks) {
    if (h.code_preventable) assert.ok(h.sol_rules.length >= 1, `${h.id} preventable but unmapped`);
    else assert.strictEqual(h.sol_rules.length, 0, `${h.id} not preventable but claims a rule`);
  }
});

test('categories are from the allowed set', () => {
  for (const h of data.hacks) {
    assert.ok(sync.VALID_CATEGORIES.includes(h.category), `${h.id} bad category ${h.category}`);
  }
});

test('dataset has a meaningful number of code-level exploits', () => {
  const mapped = data.hacks.filter((h) => h.code_preventable);
  assert.ok(mapped.length >= 6, `expected >=6 code-level exploits, got ${mapped.length}`);
});

test('README.md is in sync with hacks.json (run sync-hacks.js)', () => {
  const expected = sync.renderReadme(data, ruleTitles).replace(/\r\n/g, '\n');
  const onDisk = fs.readFileSync(path.join(HACKS_DIR, 'README.md'), 'utf8').replace(/\r\n/g, '\n');
  assert.strictEqual(onDisk, expected, 'README.md is stale — run `node scripts/sync-hacks.js`');
});

test('formatMoney renders human figures', () => {
  assert.strictEqual(sync.formatMoney(326000000), '$326M');
  assert.strictEqual(sync.formatMoney(52800000), '$52.8M');
  assert.strictEqual(sync.formatMoney(16000), '$16K');
  assert.strictEqual(sync.formatMoney(1035203), '$1M');
});

test('validator rejects a tampered entry (negative test)', () => {
  const bad = JSON.parse(JSON.stringify(data));
  bad.hacks[0].sol_rules = ['SOL-999'];
  bad.hacks[0].code_preventable = true;
  const errors = sync.validate(bad, validRuleIds);
  assert.ok(errors.some((e) => e.includes('SOL-999')), 'should reject a non-existent rule id');
});

test('validator rejects a code_preventable=false entry that claims a rule', () => {
  const bad = JSON.parse(JSON.stringify(data));
  const oos = bad.hacks.find((h) => !h.code_preventable);
  oos.sol_rules = ['SOL-006'];
  const errors = sync.validate(bad, validRuleIds);
  assert.ok(errors.some((e) => /code_preventable=false but sol_rules is non-empty/.test(e)), 'honesty invariant must reject a mapped out-of-scope entry');
});

test('validator rejects a non-object array entry without crashing', () => {
  const bad = JSON.parse(JSON.stringify(data));
  bad.hacks.push(null);
  const errors = sync.validate(bad, validRuleIds); // must not throw
  assert.ok(errors.some((e) => /not an object/.test(e)), 'should flag a non-object entry');
});

test('validator rejects an impossible day-of-month date', () => {
  const bad = JSON.parse(JSON.stringify(data));
  bad.hacks[0].date = '2022-02-30';
  const errors = sync.validate(bad, validRuleIds);
  assert.ok(errors.some((e) => /not a real date/.test(e)), 'Feb 30 must be rejected');
});
