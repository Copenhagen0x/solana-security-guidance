'use strict';
// Validates rules-meta.json — the per-rule metadata source (tier / severity /
// reachability / exclusions) merged into rules.json + semgrep metadata + content pages.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..', '..');
const meta = JSON.parse(fs.readFileSync(path.join(repoRoot, 'rules-meta.json'), 'utf8')).rules;
const patterns = yaml.load(
  fs.readFileSync(path.join(repoRoot, 'security-patterns.yaml'), 'utf8'),
  { schema: yaml.CORE_SCHEMA },
).patterns;
const guidance = fs.readFileSync(path.join(repoRoot, 'claude-security-guidance.md'), 'utf8');

const TIERS = new Set(['high', 'low']);
const SEVS = new Set(['high', 'medium', 'low']);

test('rules-meta covers exactly the documented SOL ids (1:1 with the guidance)', () => {
  const metaIds = Object.keys(meta).sort();
  const mdIds = [...new Set([...guidance.matchAll(/### (SOL-\d{3})/g)].map((m) => m[1]))].sort();
  assert.deepEqual(metaIds, mdIds, 'rules-meta.json ids must equal the guidance rule ids (no missing/extra)');
});

test('every entry has a valid tier, severity, and a reachability anchor', () => {
  for (const [id, m] of Object.entries(meta)) {
    assert.ok(TIERS.has(m.tier), `${id}: tier ${JSON.stringify(m.tier)} not in {high,low}`);
    assert.ok(SEVS.has(m.severity), `${id}: severity ${JSON.stringify(m.severity)} not in {high,medium,low}`);
    assert.ok(typeof m.reachability === 'string' && m.reachability.length > 10, `${id}: missing reachability anchor`);
    if ('exclusions' in m) {
      assert.ok(Array.isArray(m.exclusions) && m.exclusions.every((e) => typeof e === 'string' && e.length), `${id}: exclusions must be non-empty strings`);
    }
  }
});

test('every machine-checkable rule (security-patterns.yaml) has a rules-meta entry', () => {
  for (const p of patterns) {
    const mm = /^sol_(\d{3})_/.exec(p.rule_name);
    assert.ok(mm, `unexpected rule_name shape: ${p.rule_name}`);
    const id = 'SOL-' + mm[1];
    assert.ok(meta[id], `${p.rule_name} -> ${id} has no rules-meta.json entry (sync-rules would throw)`);
  }
});
