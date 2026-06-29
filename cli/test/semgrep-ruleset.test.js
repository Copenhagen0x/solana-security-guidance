'use strict';
// Port-fidelity tests for the generated Semgrep ruleset. These do NOT need the
// `semgrep` binary — they prove the YAML is (a) in sync with the source of truth,
// (b) a schema-valid Semgrep ruleset, and (c) a faithful regex port (every literal
// substring still matches its escaped pattern-regex; every pattern compiles). A
// separate CI job runs real `semgrep` against the example fixtures end-to-end.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const gen = require('../scripts/sync-semgrep');

const repoRoot = path.join(__dirname, '..', '..');
const yamlPath = path.join(repoRoot, 'semgrep', 'solana-security-standard.yaml');
const rules = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'rules.json'), 'utf8')).patterns;

const doc = yaml.load(fs.readFileSync(yamlPath, 'utf8'), { schema: yaml.CORE_SCHEMA });
const byId = new Map(doc.rules.map((r) => [r.metadata['sol-id'], r]));

// Source-of-truth languages per rule (absent => rust, the on-chain default). The
// generated Semgrep `languages` must equal this — proving the mapping, not just
// "always rust" (integrator rules SOL-029+ are typescript/javascript).
const srcPatterns = yaml.load(
  fs.readFileSync(path.join(repoRoot, 'security-patterns.yaml'), 'utf8'),
  { schema: yaml.CORE_SCHEMA },
).patterns;
const srcLangById = new Map(
  srcPatterns.map((p) => [
    gen.solId(p.rule_name),
    Array.isArray(p.languages) && p.languages.length ? p.languages : ['rust'],
  ]),
);
const VALID_LANGS = new Set(['rust', 'typescript', 'javascript']);

test('committed ruleset is in sync with security-patterns.yaml (else run npm run sync:semgrep)', () => {
  const norm = (s) => s.replace(/\r\n/g, '\n');
  const expected = gen.serialize(gen.build());
  assert.equal(norm(fs.readFileSync(yamlPath, 'utf8')), norm(expected));
});

// Mirrors the "Validate guidance files" CI gate (which the local suite otherwise can't
// see), so an over-long reminder fails locally instead of only on a pushed branch.
// Reminders are the IDE-displayed text; deep detail belongs in the uncapped rules-meta.
test('every reminder is within the 1024-byte cap', () => {
  for (const p of srcPatterns) {
    const bytes = Buffer.byteLength(p.reminder || '', 'utf8');
    assert.ok(bytes <= 1024, `${p.rule_name}: reminder is ${bytes} bytes (>1024) — trim it; move detail to the rules-meta exclusions`);
  }
});

test('one Semgrep rule per deterministic (regex|substrings) source rule', () => {
  const matchers = rules.filter((r) => r.regex || (r.substrings && r.substrings.length));
  assert.equal(doc.rules.length, matchers.length);
  for (const r of matchers) {
    const id = gen.solId(r.rule_name);
    assert.ok(byId.has(id), `missing Semgrep rule for ${id}`);
  }
});

test('every rule is schema-valid for Semgrep', () => {
  const SEV = new Set(['ERROR', 'WARNING', 'INFO']);
  const seen = new Set();
  for (const r of doc.rules) {
    assert.ok(typeof r.id === 'string' && r.id.startsWith('solana-security-standard.'), `bad id ${r.id}`);
    assert.ok(!seen.has(r.id), `duplicate id ${r.id}`);
    seen.add(r.id);
    assert.ok(Array.isArray(r.languages) && r.languages.length >= 1, `${r.id} languages must be non-empty`);
    assert.ok(r.languages.every((l) => VALID_LANGS.has(l)), `${r.id} languages ${JSON.stringify(r.languages)} not all valid`);
    assert.deepEqual(r.languages, srcLangById.get(r.metadata['sol-id']), `${r.id} languages must match source (default rust)`);
    assert.ok(SEV.has(r.severity), `${r.id} severity ${r.severity}`);
    assert.ok(typeof r.message === 'string' && r.message.length > 0, `${r.id} message`);
    assert.ok(Array.isArray(r.patterns) && r.patterns.length === 1, `${r.id} patterns`);
    assert.ok(typeof r.patterns[0]['pattern-regex'] === 'string', `${r.id} pattern-regex`);
    // metadata + a self-referential help link
    assert.equal(r.metadata.category, 'security');
    assert.match(r.metadata.references[0], /#sol-\d{3}$/);
  }
});

test('every pattern-regex is a compilable regex', () => {
  for (const r of doc.rules) {
    const rx = r.patterns[0]['pattern-regex'];
    assert.doesNotThrow(() => new RegExp(rx), `${r.id}: ${rx} does not compile`);
  }
});

test('regex rules port verbatim (except documented RE2 overrides)', () => {
  for (const r of rules.filter((x) => x.regex && !gen.SEMGREP_OVERRIDES[x.rule_name])) {
    const sg = byId.get(gen.solId(r.rule_name));
    assert.equal(sg.patterns[0]['pattern-regex'], r.regex, `${r.rule_name} regex mismatch`);
  }
});

test('every RE2 override is applied, documented, and free of nested counted repetition', () => {
  for (const [name, ov] of Object.entries(gen.SEMGREP_OVERRIDES)) {
    const sg = byId.get(gen.solId(name));
    assert.ok(sg, `override ${name} has no generated rule`);
    assert.equal(sg.patterns[0]['pattern-regex'], ov.regex, `${name} override not applied`);
    assert.ok(sg.metadata.note && sg.metadata.note.length > 20, `${name} divergence not documented in metadata`);
    // The point of an override is RE2 compile-size safety. A single counted repetition
    // can't nest, and nesting is exactly what blew up the scanner's regex in RE2.
    const counted = (ov.regex.match(/\{\d/g) || []).length; // {0,400} counts; literal {} in [^;{}] does not
    assert.ok(counted <= 1, `${name} override has ${counted} counted repetitions — nesting risks RE2 size blowup`);
  }
});

test('sol_011 override matches every case the scanner test pins, plus long multi-line, not the negative', () => {
  const re = () => new RegExp(gen.SEMGREP_OVERRIDES.sol_011_close_attr.regex);
  assert.ok(re().test('#[account(mut, constraint = f(), close = dest)]'), 'depth 1');
  assert.ok(re().test('#[account(constraint = outer(inner()), close = dest)]'), 'depth 2');
  assert.ok(re().test('#[account(mut, close = dest)]'), 'plain');
  assert.ok(re().test('#[account(\n  seeds = [b"v", x.key().as_ref()],\n  bump,\n  close = authority,\n)]'), 'long multi-line');
  assert.ok(!re().test('let close = dest;'), 'isolated close= outside #[account] must not fire');
});

test('sol_011 override attributes to the NEAREST #[account( — no cross-attribute drift', () => {
  // Two adjacent attributes; only the second has close=. The window excludes `#`, so the
  // match must START at the second attribute, not the innocent first one (else Semgrep
  // would report the finding on the wrong line). Regression guard for the [^;{}#] fix.
  const src = '#[account(mut)]\npub user: Account<X>,\n#[account(mut, close = receiver)]\npub vault: Account<Y>,\n';
  const m = new RegExp(gen.SEMGREP_OVERRIDES.sol_011_close_attr.regex).exec(src);
  assert.ok(m, 'matches the close= attribute');
  assert.equal(m.index, src.indexOf('#[account(mut, close'), 'match starts at the close= attribute, not the first');
});

test('substring rules: every literal still matches its escaped pattern-regex (no escaping drift)', () => {
  for (const r of rules.filter((x) => x.substrings && x.substrings.length)) {
    const sg = byId.get(gen.solId(r.rule_name));
    const re = new RegExp(sg.patterns[0]['pattern-regex']);
    for (const lit of r.substrings) {
      assert.ok(re.test(lit), `${r.rule_name}: escaped pattern fails to match its own literal "${lit}"`);
    }
    // and a regex-metachar-bearing near-miss must NOT spuriously match (escaping is literal,
    // not interpreted): e.g. ".realloc(" must not also match "Xrealloc(" via the dot.
    if (r.substrings.some((s) => s.startsWith('.'))) {
      assert.ok(!re.test('Xrealloc('), `${r.rule_name}: leading-dot literal matched as wildcard`);
    }
  }
});

test('no RE2-incompatible constructs (lookaround / backref / atomic / possessive)', () => {
  for (const r of doc.rules) {
    const rx = r.patterns[0]['pattern-regex'];
    assert.ok(!/\(\?[=!<]/.test(rx), `${r.id}: lookaround not supported by Semgrep RE2`);
    assert.ok(!/\\[1-9]/.test(rx), `${r.id}: backreference not supported by Semgrep RE2`);
    assert.ok(!/\(\?>/.test(rx), `${r.id}: atomic group not supported by Semgrep RE2`);
    assert.ok(!/[*+?}]\+/.test(rx), `${r.id}: possessive quantifier not supported by Semgrep RE2`);
  }
});

test('exclude paths mirror the scanner exactly', () => {
  for (const r of rules) {
    if (!(r.regex || (r.substrings && r.substrings.length))) continue;
    const sg = byId.get(gen.solId(r.rule_name));
    const got = (sg.paths && sg.paths.exclude) || [];
    assert.deepEqual(got, r.exclude_paths || [], `${r.rule_name} exclude_paths`);
  }
});
