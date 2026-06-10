'use strict';
// Baseline support: record the current findings' fingerprints, then report only
// findings that are NEW relative to that baseline. This is how a repo adopts the
// standard without a red gate on day one — existing findings are acknowledged in
// a reviewable file, and CI alerts only on what a change introduces.
//
// Honesty invariants (load-bearing — reviewers cite these):
//   - Suppression is NEVER silent: the caller surfaces how many findings the
//     baseline removed (and how many baseline entries are stale) in EVERY format.
//   - A baseline that can't be read/parsed/validated is a HARD error (the CLI
//     exits 2) — it must never degrade to "scan without baseline".
//   - Entries are keyed by fingerprint but carry a human-readable snapshot
//     (rule, file, line, match at capture time), so a baseline diff in a PR is
//     reviewable line-by-line — an entry smuggled in to hide a new bug is visible
//     to the reviewer as exactly what it suppresses. (A repo-resident baseline is
//     still repo-resident: review baseline changes like code. See README.)
//   - An INCOMPLETE scan (finding cap) stays INCOMPLETE — baseline filtering
//     never touches that signal; the CLI's exit-2 gate fires regardless.

const fs = require('fs');

const FORMAT = 'solana-security-standard-baseline';
const VERSION = 1;

/** Serialize findings into a baseline document (stable key order for clean diffs). */
function createBaseline(findings, { tool = 'solana-security-standard', toolVersion = '0.0.0' } = {}) {
  const fingerprints = {};
  for (const f of findings) {
    if (!f.fingerprint) continue; // custom -p rules predating fingerprints: nothing stable to key on
    if (fingerprints[f.fingerprint]) continue; // defensive: fp is unique per finding by construction
    fingerprints[f.fingerprint] = {
      rule: f.rule,
      file: f.file,
      // Informational snapshot only — line drifts with edits; the fingerprint is
      // the identity. Kept so a human can review what each entry acknowledges.
      line: f.line,
      match: f.match,
    };
  }
  return {
    format: FORMAT,
    version: VERSION,
    tool,
    toolVersion,
    findingCount: Object.keys(fingerprints).length,
    fingerprints,
  };
}

function writeBaseline(path, findings, opts) {
  const doc = createBaseline(findings, opts);
  fs.writeFileSync(path, JSON.stringify(doc, null, 2) + '\n');
  return doc; // so the caller can report the EXACT recorded count (post-dedup)
}

/**
 * Load + strictly validate a baseline file. Throws (with a precise message) on
 * anything malformed — the caller turns that into a loud exit 2, never a
 * baseline-less scan.
 */
function loadBaseline(path) {
  let raw;
  try {
    raw = fs.readFileSync(path, 'utf8');
  } catch (e) {
    throw new Error(`cannot read baseline ${path}: ${e.message}`);
  }
  let doc;
  try {
    // charCodeAt avoids an invisible BOM literal in this source: readFileSync('utf8')
    // decodes a UTF-8 BOM (a Notepad hand-edit adds one) to one U+FEFF char; strip it.
    // Content is still strictly validated below — this only avoids a cryptic parse error.
    doc = JSON.parse(raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw);
  } catch (e) {
    throw new Error(`baseline ${path} is not valid JSON: ${e.message}`);
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error(`baseline ${path}: expected a JSON object`);
  }
  if (doc.format !== FORMAT) {
    throw new Error(`baseline ${path}: unrecognized format ${JSON.stringify(doc.format)} (expected "${FORMAT}")`);
  }
  if (doc.version !== VERSION) {
    throw new Error(`baseline ${path}: unsupported version ${JSON.stringify(doc.version)} (this tool reads version ${VERSION})`);
  }
  if (!doc.fingerprints || typeof doc.fingerprints !== 'object' || Array.isArray(doc.fingerprints)) {
    throw new Error(`baseline ${path}: missing "fingerprints" object`);
  }
  for (const fp of Object.keys(doc.fingerprints)) {
    if (!/^[0-9a-f]{32}$/.test(fp)) {
      throw new Error(`baseline ${path}: invalid fingerprint key ${JSON.stringify(fp)} (expected 32 hex chars)`);
    }
    // The human-readable snapshot is the anti-poisoning defense: a reviewer of a
    // baseline diff must SEE what each entry suppresses. A hand-minimized entry
    // (e.g. {"<fp>": {}}) that hides that is rejected loud — every entry
    // createBaseline writes passes. Unknown extra fields stay accepted
    // (forward-compat); only the identifying snapshot is required.
    const e = doc.fingerprints[fp];
    if (!e || typeof e !== 'object' || Array.isArray(e) || typeof e.rule !== 'string' || typeof e.file !== 'string') {
      throw new Error(`baseline ${path}: entry ${JSON.stringify(fp)} is missing its rule/file snapshot — every entry must say what it suppresses (regenerate with --write-baseline)`);
    }
  }
  return doc;
}

/**
 * Split findings against a baseline.
 * @returns {{kept: object[], suppressed: number, stale: number}}
 *   kept       — findings NOT in the baseline (these gate the build)
 *   suppressed — findings removed because their fingerprint is baselined
 *   stale      — baseline entries that matched nothing this scan (the finding was
 *                fixed or its code changed); surfaced so baselines don't rot silently
 */
function applyBaseline(findings, baseline) {
  const fps = baseline.fingerprints;
  const seen = new Set();
  const kept = [];
  let suppressed = 0;
  for (const f of findings) {
    if (f.fingerprint && Object.prototype.hasOwnProperty.call(fps, f.fingerprint)) {
      suppressed++;
      seen.add(f.fingerprint);
    } else {
      kept.push(f);
    }
  }
  const stale = Object.keys(fps).length - seen.size;
  return { kept, suppressed, stale };
}

module.exports = { FORMAT, VERSION, createBaseline, writeBaseline, loadBaseline, applyBaseline };
