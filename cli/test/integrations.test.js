'use strict';
// Port-fidelity tests for the generated AI-tool integration files. They prove the
// integrations/ tree is (a) in sync with the guidance source and orphan-free, (b)
// carries all 28 SOL-0XX rules + the behavioral intro in every tool's file, and
// (c) uses each tool's expected wrapper (Cursor frontmatter, Windsurf under its
// per-file cap, the opt-in pinned Aider lint).

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const gen = require('../scripts/sync-integrations');

const repoRoot = path.join(__dirname, '..', '..');
const intDir = path.join(repoRoot, 'integrations');
const norm = (s) => s.replace(/\r\n/g, '\n');
const EXPECTED_IDS = Array.from({ length: 52 }, (_, i) => 'SOL-0' + String(i + 1).padStart(2, '0'));
const read = (rel) => fs.readFileSync(path.join(intDir, rel), 'utf8');

function walk(dir, base, acc = []) {
  for (const n of fs.readdirSync(dir)) {
    const p = path.join(dir, n);
    if (fs.lstatSync(p).isDirectory()) walk(p, base, acc); // lstat: don't follow symlinks
    else acc.push(path.relative(base, p).split(path.sep).join('/'));
  }
  return acc;
}

test('committed integrations are in sync with the guidance (else run npm run sync:integrations)', () => {
  for (const [rel, content] of Object.entries(gen.build())) {
    const dst = path.join(intDir, rel);
    assert.ok(fs.existsSync(dst), `missing ${rel}`);
    assert.equal(norm(fs.readFileSync(dst, 'utf8')), norm(content), `${rel} out of sync`);
  }
});

test('no orphan files under integrations/ (every on-disk file is generated)', () => {
  const generated = new Set(Object.keys(gen.build()));
  for (const f of walk(intDir, intDir)) assert.ok(generated.has(f), `orphan file not produced by the generator: ${f}`);
});

test('every AI-tool rules file carries all 52 SOL-0XX rules + the behavioral intro', () => {
  const ruleFiles = Object.keys(gen.TOOLS); // codex, copilot, cursor, windsurf, cline, aider
  assert.equal(ruleFiles.length, 6, 'six AI-tool rules files');
  for (const rel of ruleFiles) {
    const t = read(rel);
    for (const id of EXPECTED_IDS) assert.ok(t.includes(id), `${rel} missing ${id}`);
    assert.ok(t.includes('SOL-0XX'), `${rel} names the standard`);
    assert.match(t, /When you write, edit, or review/, `${rel} carries the behavioral instruction`);
  }
});

test('Windsurf is a single file under the 12,000-char per-file workspace cap', () => {
  const t = read(gen.WINDSURF_FILE);
  assert.ok(t.length < gen.WINDSURF_MAX, `${t.length} chars, over the ${gen.WINDSURF_MAX} cap`);
  for (const id of EXPECTED_IDS) assert.ok(t.includes(id), `windsurf missing ${id}`);
});

test('Cursor .mdc has valid frontmatter and no risky unquoted *-glob (YAML alias)', () => {
  const t = read('cursor/.cursor/rules/solana-security.mdc');
  assert.ok(t.startsWith('---\n'), 'frontmatter block present');
  assert.match(t, /^alwaysApply: true$/m);
  assert.ok(!/globs:\s*\*/.test(t), 'no unquoted *-glob (would parse as a YAML alias)');
});

test('Aider: conventions loaded by default; scanner lint-cmd is opt-in, pinned, and roots the scan', () => {
  const cfg = read('aider/.aider.conf.yml');
  assert.match(cfg, /^read: CONVENTIONS\.md$/m, 'conventions loaded by default');
  assert.match(cfg, /#\s*lint-cmd:/, 'lint-cmd is commented (opt-in, not a default hard gate)');
  assert.match(cfg, /solana-security-standard@1 scan -r \./, 'opt-in lint-cmd is pinned + rooted');
});

test('install matrix lists every tool', () => {
  const r = read('README.md');
  for (const tool of ['Codex', 'Copilot', 'Cursor', 'Windsurf', 'Cline', 'Aider', 'Semgrep', 'CLI', 'Claude Code']) {
    assert.ok(r.includes(tool), `README matrix missing ${tool}`);
  }
});

test('README is honest about coverage: 52 documented vs 30 machine-checkable', () => {
  const r = read('README.md');
  assert.match(r, /52 documented SOL-0XX rules/);
  assert.match(r, /30 rules that have/);
  assert.match(r, /generated from the one source of truth/i);
});
