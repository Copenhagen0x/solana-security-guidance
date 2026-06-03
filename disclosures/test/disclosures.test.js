'use strict';
// Tests for the disclosure-feed pipeline. Run: node --test  (from disclosures/)
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('node:child_process');

const DIR = path.join(__dirname, '..');
const REPO = path.join(__dirname, '..', '..');
const { classify, codePreventableGuess } = require('../scripts/classify');
const adapters = require('../scripts/adapters');
const { buildCandidate } = require('../scripts/ingest');
const hacksSync = require('../../hacks/scripts/sync-hacks');

const fixture = (n) => JSON.parse(fs.readFileSync(path.join(DIR, 'fixtures', n), 'utf8'));
const hacks = JSON.parse(fs.readFileSync(path.join(REPO, 'hacks', 'hacks.json'), 'utf8'));
const ruleTitles = hacksSync.loadRuleTitles(fs.readFileSync(path.join(REPO, 'claude-security-guidance.md'), 'utf8'));
const validRuleIds = Object.keys(ruleTitles);

test('adapters normalize each feed into the common Disclosure shape', () => {
  const g = adapters.normalize(fixture('ghsa-oracle.json'));
  assert.strictEqual(g.source_type, 'ghsa');
  assert.strictEqual(g.date, '2025-03-14');
  assert.ok(g.url.startsWith('https://') && g.title && g.body && g.protocol === 'ExampleLend');

  const i = adapters.normalize(fixture('immunefi-account.json'));
  assert.strictEqual(i.source_type, 'immunefi');
  assert.strictEqual(i.loss_usd, 250000);
  assert.strictEqual(i.protocol, 'SampleVault');

  const p = adapters.normalize(fixture('pr-arithmetic.json'));
  assert.strictEqual(p.source_type, 'pr');
  assert.strictEqual(p.date, '2025-01-20');
  assert.strictEqual(p.protocol, 'demoswap');
});

test('unknown disclosure type is rejected', () => {
  assert.throws(() => adapters.normalize({ type: 'twitter', data: {} }), /unknown disclosure type/);
});

test('classifier picks the right top rule for each fixture', () => {
  const top = (n) => {
    const d = adapters.normalize(fixture(n));
    return classify(`${d.title} ${d.body}`)[0].rule;
  };
  assert.strictEqual(top('ghsa-oracle.json'), 'SOL-024');
  assert.strictEqual(top('immunefi-account.json'), 'SOL-007');
  assert.strictEqual(top('pr-arithmetic.json'), 'SOL-014');
});

test('classifier only ever suggests real SOL-0XX rules', () => {
  const ids = new Set(validRuleIds);
  for (const n of ['ghsa-oracle.json', 'immunefi-account.json', 'pr-arithmetic.json']) {
    const d = adapters.normalize(fixture(n));
    for (const s of classify(`${d.title} ${d.body}`)) assert.ok(ids.has(s.rule), `bogus rule ${s.rule}`);
  }
});

test('self-consistency: a labeled rule appears among suggestions for >=70% of catalogued exploits', () => {
  // Internal consistency guard (the root_causes AND the signatures are authored here) — NOT a blind-
  // accuracy claim. Bar is "a labeled rule is somewhere in the ranked list", not top-1. If a future
  // hack is added whose phrasing trips no signature, recall can drop — add a signature term then.
  const mapped = hacks.hacks.filter((h) => h.code_preventable);
  let recovered = 0;
  for (const h of mapped) {
    const suggestions = classify(h.root_cause).map((s) => s.rule);
    if (h.sol_rules.some((r) => suggestions.includes(r))) recovered++;
  }
  const ratio = recovered / mapped.length;
  assert.ok(ratio >= 0.7, `recall ${recovered}/${mapped.length} (${ratio.toFixed(2)}) below 0.70 — signatures degraded`);
});

test('a key/opsec term hard-vetoes code-preventability even with code keywords present', () => {
  // An insider key abuse that also name-drops a flash loan / bonding curve must stay not-code-preventable.
  const g = codePreventableGuess('A former employee with insider access used a flash loan against the bonding curve.');
  assert.strictEqual(g.guess, false);
  assert.ok(g.offChainTerms.length >= 1);
});

test('a no-signal disclosure is not asserted code-preventable (unknown != true)', () => {
  const g = codePreventableGuess('The quick brown fox jumped over the lazy dog.');
  assert.strictEqual(g.guess, false);
  assert.deepStrictEqual(g.offChainTerms, []);
});

test('a no-signal candidate is not mislabeled key-compromise', () => {
  const d = adapters.normalize({
    type: 'pr',
    data: { number: 1, title: 'chore: bump deps', body: 'Routine dependency bump, no security impact described.', html_url: 'https://github.com/example/x/pull/1', merged_at: '2025-02-02T00:00:00Z', base: { repo: { full_name: 'example/x' } } },
  });
  const c = buildCandidate(d);
  assert.strictEqual(c.code_preventable, false);
  assert.deepStrictEqual(c.sol_rules, []);
  assert.notStrictEqual(c.category, 'key-compromise');
});

test('off-chain incidents are guessed not-code-preventable', () => {
  for (const h of hacks.hacks.filter((h) => !h.code_preventable)) {
    assert.strictEqual(codePreventableGuess(h.root_cause).guess, false, `${h.id} should guess not-code-preventable`);
  }
});

test('buildCandidate produces a review-flagged entry with suggested rules', () => {
  const d = adapters.normalize(fixture('ghsa-oracle.json'));
  const c = buildCandidate(d);
  assert.strictEqual(c.code_preventable, true);
  assert.ok(c.sol_rules.includes('SOL-024'), 'should suggest SOL-024');
  assert.deepStrictEqual(c.sources, [d.url]);
  assert.strictEqual(c._review.needs_human_review, true);
  assert.ok(c._review.classifier_suggestions.length >= 1);
  assert.match(c.id, /^[a-z0-9-]+$/);
});

test('buildCandidate flags an off-chain disclosure as not-code-preventable', () => {
  const d = adapters.normalize({
    type: 'immunefi',
    data: { project: 'WalletX', title: 'WalletX leaked seed phrases', description: 'The mobile client sent the user seed phrase / mnemonic to a logging server.', url: 'https://example.com/x', date: '2024-01-01' },
  });
  const c = buildCandidate(d);
  assert.strictEqual(c.code_preventable, false);
  assert.deepStrictEqual(c.sol_rules, []);
  assert.strictEqual(c.category, 'off-chain-wallet');
});

test('a fixture-derived candidate passes the real Hacks Database validator (structural readiness)', () => {
  for (const n of ['ghsa-oracle.json', 'immunefi-account.json', 'pr-arithmetic.json']) {
    const c = buildCandidate(adapters.normalize(fixture(n)));
    const errors = hacksSync.validate({ version: '1.0.0', description: 'x', hacks: [c] }, validRuleIds);
    assert.deepStrictEqual(errors, [], `${n} candidate fails hacks validation:\n` + errors.join('\n'));
  }
});

test('ingest CLI emits a JSON candidate on stdout', () => {
  const out = execFileSync('node', ['scripts/ingest.js', 'fixtures/ghsa-oracle.json'], { cwd: DIR, encoding: 'utf8' });
  const c = JSON.parse(out);
  assert.strictEqual(c.protocol, 'ExampleLend');
  assert.ok(c.sol_rules.includes('SOL-024'));
  assert.strictEqual(c._review.needs_human_review, true);
});
