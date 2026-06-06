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
    // Every rule carries ≥1 numbered "do NOT flag when…" exclusion, each a
    // SPECIFIC condition (length-gated to discourage vague "looks fine" clauses).
    assert.ok(Array.isArray(m.exclusions) && m.exclusions.length >= 1, `${id}: must have ≥1 exclusion`);
    for (const e of m.exclusions) {
      assert.ok(typeof e === 'string' && e.length >= 20, `${id}: exclusion too short/vague: ${JSON.stringify(e)}`);
    }
  }
});

// Vagueness guard. The length gate alone passes a long-but-empty clause; this
// rejects pure hand-waves ("looks fine", "obviously safe") that would let a
// reviewer dismiss a finding without a verifiable condition. (Semantic quality
// of an exclusion is enforced by the 3-reviewer content audit — this is just a
// mechanical tripwire against the laziest fluff.)
const VAGUE = /\b(looks?\s+fine|obviously\s+safe|trust\s+me|seems?\s+(fine|ok|okay|correct|safe)|no\s+real\s+issue|should\s+be\s+fine|probably\s+(fine|ok|safe))\b/i;
test('no exclusion is a vague hand-wave (must be a verifiable condition)', () => {
  for (const [id, m] of Object.entries(meta)) {
    for (const e of m.exclusions) {
      assert.ok(!VAGUE.test(e), `${id}: exclusion reads as a vague hand-wave, not a verifiable condition: ${JSON.stringify(e)}`);
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
