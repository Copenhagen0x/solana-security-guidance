'use strict';
// Self-testing examples — runs the REAL scanner over examples/.
//
// For every machine-checkable rule (the ones in rules.json) that ships a
// vulnerable/fixed example pair, this asserts:
//   1. vulnerable.{rs,ts} FIRES its own rule — an anti-rot guard: if a regex is
//      broken or narrowed so it stops detecting the canonical bug, this fails.
//   2. fixed.{rs,ts} is either scanner-CLEAN of that rule, OR is listed in
//      FIXED_STILL_FIRES with a reason. Some fixes are runtime/structural (the
//      syntactic pattern is retained on purpose — e.g. `.realloc()` stays,
//      `invoke_signed` stays); for those the scanner (a fail-open tripwire)
//      still fires and the fix satisfies the rule's EXCLUSION, not silence.
// Plus coverage (every machine rule has an example) and allowlist-rot guards.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { loadRules, scanContent } = require('../src/scanner');

const repoRoot = path.join(__dirname, '..', '..');
const examplesDir = path.join(repoRoot, 'examples');
const rules = loadRules(path.join(__dirname, '..', 'rules.json'));

/** rule_name (sol_001_foo) -> SOL-id (SOL-001). */
function ruleNameToId(name) {
  const m = /^sol_(\d{3})/.exec(name || '');
  return m ? 'SOL-' + m[1] : null;
}

const machineRuleIds = new Set(rules.map((r) => ruleNameToId(r.name)).filter(Boolean));

// Fixed examples whose fix is runtime/structural: the syntactic pattern is kept
// on purpose, so the fail-open scanner still fires; the fix clears the rule's
// EXCLUSION, not the regex. The allowlist lives in examples/fixed-still-fires.json
// (one source of truth, shared with scripts/sync-benchmark.js); each entry
// documents which exclusion does the work.
const FIXED_STILL_FIRES = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'examples', 'fixed-still-fires.json'), 'utf8'),
);
delete FIXED_STILL_FIRES._comment;

function exampleExt(dir) {
  return fs.existsSync(path.join(examplesDir, dir, 'vulnerable.ts')) ? 'ts' : 'rs';
}
function scanExample(dir, which, ext) {
  const rel = `${dir}/${which}.${ext}`;
  const content = fs.readFileSync(path.join(examplesDir, dir, `${which}.${ext}`), 'utf8');
  return scanContent(content, rel, rules);
}
function firesRule(findings, solId) {
  return findings.some((f) => ruleNameToId(f.rule) === solId);
}

const exampleDirs = fs
  .readdirSync(examplesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory() && /^sol_\d{3}_/.test(d.name))
  .map((d) => d.name)
  .sort();

for (const dir of exampleDirs) {
  const solId = 'SOL-' + dir.slice(4, 7);
  // Review-only rules (no machine matcher, e.g. SOL-003/004) ship illustrative
  // examples but cannot be scanner-asserted — skip them here.
  if (!machineRuleIds.has(solId)) continue;
  const ext = exampleExt(dir);

  test(`${solId}: vulnerable.${ext} fires the scanner (anti-rot)`, () => {
    assert.ok(fs.existsSync(path.join(examplesDir, dir, `vulnerable.${ext}`)), `${dir}/vulnerable.${ext} missing`);
    const f = scanExample(dir, 'vulnerable', ext);
    assert.ok(firesRule(f, solId), `${solId} must fire on its own vulnerable example (matcher rot?)`);
  });

  test(`${solId}: fixed.${ext} is scanner-clean OR a documented exclusion-cleared example`, () => {
    assert.ok(fs.existsSync(path.join(examplesDir, dir, `fixed.${ext}`)), `${dir}/fixed.${ext} missing`);
    const f = scanExample(dir, 'fixed', ext);
    if (firesRule(f, solId)) {
      assert.ok(
        FIXED_STILL_FIRES[solId],
        `${solId} fixed example still fires but is not in FIXED_STILL_FIRES — either the bug was not actually fixed, or document why the syntactic pattern is retained (exclusion-cleared).`,
      );
    }
  });
}

test('every machine-checkable rule ships a vulnerable/fixed example pair', () => {
  const have = new Set(exampleDirs.map((d) => 'SOL-' + d.slice(4, 7)));
  const missing = [...machineRuleIds].filter((id) => !have.has(id)).sort();
  assert.deepEqual(missing, [], `machine rules missing an example dir: ${missing.join(', ')}`);
});

test('FIXED_STILL_FIRES allowlist has no stale entries', () => {
  for (const id of Object.keys(FIXED_STILL_FIRES)) {
    assert.ok(machineRuleIds.has(id), `${id} in FIXED_STILL_FIRES is not a machine-checkable rule`);
    const dir = exampleDirs.find((d) => 'SOL-' + d.slice(4, 7) === id);
    assert.ok(dir, `${id} in FIXED_STILL_FIRES has no example dir`);
    const ext = exampleExt(dir);
    const f = scanExample(dir, 'fixed', ext);
    assert.ok(
      firesRule(f, id),
      `${id} is in FIXED_STILL_FIRES but its fixed example no longer fires — remove it from the allowlist (the fix is now scanner-clean).`,
    );
  }
});
