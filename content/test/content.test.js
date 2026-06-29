'use strict';
// Tests for the content engine. Run: node --test  (from content/)
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const CONTENT_DIR = path.join(__dirname, '..');
const REPO = path.join(__dirname, '..', '..');
const c = require('../scripts/sync-content');

const md = fs.readFileSync(path.join(REPO, 'claude-security-guidance.md'), 'utf8');
const rules = c.parseRules(md);
const patternIds = c.loadPatternIds(JSON.parse(fs.readFileSync(path.join(REPO, 'cli', 'rules.json'), 'utf8')));
const hacks = JSON.parse(fs.readFileSync(path.join(REPO, 'hacks', 'hacks.json'), 'utf8'));
const hackIds = new Set(hacks.hacks.map((h) => h.id));

test('parses exactly 52 rules with ids/titles/bodies', () => {
  assert.strictEqual(rules.length, 52);
  for (const r of rules) {
    assert.match(r.id, /^SOL-\d{3}$/);
    assert.ok(r.title && r.title.length > 0, `${r.id} has no title`);
    assert.ok(r.body && r.body.length > 0, `${r.id} has no body`);
  }
  const ids = rules.map((r) => r.id);
  assert.ok(ids.includes('SOL-001') && ids.includes('SOL-028') && ids.includes('SOL-031'));
});

test('exactly 30 rules are machine-checkable (have a pattern)', () => {
  assert.strictEqual(patternIds.size, 30, `expected 30 patterns, got ${patternIds.size}`);
  // every pattern id is a real rule
  const ruleIds = new Set(rules.map((r) => r.id));
  for (const p of patternIds) assert.ok(ruleIds.has(p), `pattern ${p} has no rule`);
});

test('ruleAnchor matches GitHub slug for the tricky cases', () => {
  assert.strictEqual(c.ruleAnchor('SOL-024', 'Stale / unchecked oracle price'), 'sol-024--stale--unchecked-oracle-price');
  assert.strictEqual(c.ruleAnchor('SOL-007', 'Missing owner verification'), 'sol-007--missing-owner-verification');
  assert.strictEqual(c.ruleAnchor('SOL-028', 'Missing slippage / min-out bound'), 'sol-028--missing-slippage--min-out-bound');
});

test('content reuses the hacks generator anchor (single source of truth)', () => {
  // Structural guard: content must import the SAME ruleAnchor function, not a copy that can drift.
  const hacksSync = require('../../hacks/scripts/sync-hacks');
  assert.strictEqual(c.ruleAnchor, hacksSync.ruleAnchor, 'content must reuse hacks ruleAnchor, not a copy');
  // …and that shared function produces the right slug for every rule heading.
  const titles = hacksSync.loadRuleTitles(md);
  for (const r of rules) {
    assert.strictEqual(c.ruleAnchor(r.id, r.title), hacksSync.ruleAnchor(r.id, titles[r.id]), `${r.id} anchor mismatch`);
  }
});

test('every generated page references only real hacks and real examples', () => {
  const { files } = c.build();
  for (const [rel, content] of Object.entries(files)) {
    if (!rel.startsWith('rules/')) continue;
    // hack links: ../../hacks/README.md#<id>
    for (const m of content.matchAll(/hacks\/README\.md#([a-z0-9-]+)/g)) {
      assert.ok(hackIds.has(m[1]), `${rel} links unknown hack id ${m[1]}`);
    }
    // example links: ../../examples/<dir>/
    for (const m of content.matchAll(/examples\/([a-z0-9_]+)\//g)) {
      assert.ok(fs.existsSync(path.join(REPO, 'examples', m[1])), `${rel} links missing example ${m[1]}`);
    }
  }
});

test('each rule page declares an enforcement line', () => {
  const { files } = c.build();
  for (const r of rules) {
    const page = files[`rules/${r.id}.md`];
    assert.ok(page, `${r.id} page missing`);
    assert.match(page, /\*\*Enforcement — (machine-checkable|review-only)\.\*\*/, `${r.id} has no enforcement line`);
    const expectMachine = patternIds.has(r.id);
    assert.strictEqual(/machine-checkable/.test(page), expectMachine, `${r.id} enforcement label wrong`);
  }
});

test('index lists all 52 rules and links each page', () => {
  const { files } = c.build();
  const idx = files['README.md'];
  for (const r of rules) {
    assert.ok(idx.includes(`./rules/${r.id}.md`), `index missing link for ${r.id}`);
  }
});

test('generated content is in sync with disk (run sync-content.js)', () => {
  const { files } = c.build();
  for (const [rel, expected] of Object.entries(files)) {
    const abs = path.join(CONTENT_DIR, rel);
    const onDisk = fs.existsSync(abs) ? fs.readFileSync(abs, 'utf8').replace(/\r\n/g, '\n') : '<missing>';
    assert.strictEqual(onDisk, expected, `${rel} is stale — run \`node scripts/sync-content.js\``);
  }
});

test('no orphaned rule pages on disk', () => {
  const { files } = c.build();
  const expected = new Set(Object.keys(files).filter((f) => f.startsWith('rules/')).map((f) => path.basename(f)));
  const dir = path.join(CONTENT_DIR, 'rules');
  const onDisk = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.md')) : [];
  for (const f of onDisk) assert.ok(expected.has(f), `orphaned page rules/${f}`);
});
