#!/usr/bin/env node
'use strict';
// Turn a raw disclosure (GHSA / Immunefi / security-PR) into a CANDIDATE Hacks-Database entry with
// suggested SOL-0XX rule mappings, for a human to verify and triage. It NEVER writes to hacks.json —
// a cited database only takes verified, human-reviewed entries. Zero dependencies.
//
//   node scripts/ingest.js <disclosure.json>     print a candidate entry (envelope: { type, data })
//   cat disclosure.json | node scripts/ingest.js   (also reads stdin)

const fs = require('fs');
const { normalize } = require('./adapters');
const { classify, codePreventableGuess } = require('./classify');

// Suggested hacks-DB category for a rule (a default for the human to confirm).
const RULE_CATEGORY = {
  'SOL-024': 'oracle-manipulation', 'SOL-028': 'oracle-manipulation', 'SOL-002': 'oracle-manipulation',
  'SOL-006': 'missing-authority', 'SOL-009': 'missing-authority', 'SOL-020': 'missing-authority', 'SOL-001': 'missing-authority',
  'SOL-004': 'accounting', 'SOL-014': 'accounting', 'SOL-022': 'accounting', 'SOL-023': 'accounting', 'SOL-011': 'accounting',
  'SOL-007': 'account-validation', 'SOL-008': 'account-validation', 'SOL-010': 'account-validation', 'SOL-013': 'account-validation',
  'SOL-015': 'account-validation', 'SOL-016': 'account-validation', 'SOL-017': 'account-validation', 'SOL-018': 'account-validation',
  'SOL-019': 'account-validation', 'SOL-025': 'account-validation', 'SOL-026': 'account-validation', 'SOL-027': 'account-validation',
  'SOL-003': 'accounting', 'SOL-005': 'account-validation', 'SOL-012': 'account-validation', 'SOL-021': 'accounting',
};

function slugify(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function offChainCategory(offChainTerms) {
  const t = offChainTerms.join(' ');
  if (/seed phrase|mnemonic|wallet/.test(t)) return 'off-chain-wallet';
  return 'key-compromise';
}

// Build a candidate Hacks-Database entry (same shape as hacks.json, plus a _review block).
function buildCandidate(d) {
  const text = `${d.title} ${d.body}`;
  const suggestions = classify(text);
  const cp = codePreventableGuess(text);
  const topRules = cp.guess ? suggestions.slice(0, 3).map((s) => s.rule) : [];
  const category = cp.guess
    ? RULE_CATEGORY[topRules[0]] || 'account-validation'
    : cp.offChainTerms.length
      ? offChainCategory(cp.offChainTerms)
      // No signal at all (classifier matched nothing): neutral default for the human to reclassify —
      // do NOT assert 'key-compromise' for a disclosure we simply failed to recognize.
      : 'account-validation';
  const idDate = d.date ? d.date.slice(0, 7) : 'unknown';
  return {
    id: `${slugify(d.protocol) || 'unknown'}-${idDate}`,
    name: d.title || 'TODO: short bug title',
    protocol: d.protocol || 'TODO',
    date: d.date || 'TODO: YYYY-MM-DD',
    loss_usd: Number.isInteger(d.loss_usd) ? d.loss_usd : 0,
    category,
    code_preventable: cp.guess,
    sol_rules: topRules,
    root_cause: d.body || 'TODO: 2-3 sentence technical root cause',
    rule_link: cp.guess
      ? `TODO: one sentence on why ${topRules.join(' / ') || 'the suggested rule(s)'} map to this bug.`
      : 'TODO: explain why no on-chain code rule prevents this (key/opsec/off-chain).',
    sources: d.url ? [d.url] : [],
    _review: {
      needs_human_review: true,
      from: { source_type: d.source_type, source: d.source },
      classifier_suggestions: suggestions.map((s) => ({ rule: s.rule, score: s.score, hits: s.hits })),
      code_preventable_guess: cp,
      notes:
        'Candidate only — verify the facts, confirm/curate the sol_rules, fill the TODOs, and check ' +
        'every source resolves before adding to hacks/hacks.json. The classifier is a heuristic.',
    },
  };
}

function readInput() {
  const file = process.argv[2];
  if (file) return fs.readFileSync(file, 'utf8');
  return fs.readFileSync(0, 'utf8'); // stdin
}

function main() {
  let envelope;
  try {
    envelope = JSON.parse(readInput());
  } catch (e) {
    console.error('ingest: could not parse input JSON (expected { "type": "ghsa|immunefi|pr", "data": {…} }).');
    process.exit(1);
  }
  let candidate;
  try {
    candidate = buildCandidate(normalize(envelope));
  } catch (e) {
    console.error('ingest: ' + e.message);
    process.exit(1);
  }
  // Human-readable rationale to stderr; machine-readable candidate to stdout (so it can be piped).
  const sug = candidate._review.classifier_suggestions;
  console.error(`\nCandidate for ${candidate.protocol} (${candidate.date}) — REVIEW BEFORE USE`);
  console.error(`  code_preventable (guess): ${candidate.code_preventable}`);
  console.error(`  suggested rules: ${candidate.sol_rules.join(', ') || '(none — looks not-code-preventable)'}`);
  console.error('  classifier ranking: ' + (sug.length ? sug.map((s) => `${s.rule}(${s.score})`).join(' ') : '(no signal)'));
  console.error('');
  process.stdout.write(JSON.stringify(candidate, null, 2) + '\n');
}

if (require.main === module) main();

module.exports = { buildCandidate, RULE_CATEGORY, slugify };
