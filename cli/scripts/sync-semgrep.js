'use strict';
// Regenerate ../../semgrep/solana-security-standard.yaml from the source-of-truth
// ../../security-patterns.yaml.
//
// The YAML is the single source the Claude Code plugin consumes. It is compiled
// into two distributable artifacts that stay in lockstep with it (CI enforces):
//
//   security-patterns.yaml  (SOURCE OF TRUTH)
//      |--> cli/rules.json                     (sync-rules.js)    -> the scanner
//      `--> semgrep/solana-security-standard.yaml (this script)   -> Semgrep
//
// Every SOL-0XX rule with a `regex` or `substrings` matcher becomes one Semgrep
// rule using `pattern-regex` (a raw regex over the file, no AST parse needed).
// All current matchers are RE2-compatible (no lookaround/backreferences), which
// is what Semgrep's regex engine requires. Substring matchers are literal, so
// they are regex-escaped before being OR-joined into one pattern. Run:
//   `npm run sync:semgrep`  (needs the js-yaml devDependency).
// CI verifies the generated file is in sync via `--check`.

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..', '..');
const srcYaml = path.join(repoRoot, 'security-patterns.yaml');
const metaSrc = path.join(repoRoot, 'rules-meta.json');
const dstYaml = path.join(repoRoot, 'semgrep', 'solana-security-standard.yaml');
const REPO = 'https://github.com/Copenhagen0x/solana-security-standard';

/** Derive a display id like "SOL-001" from a rule_name like "sol_001_foo". */
function solId(ruleName) {
  const m = /^sol[_-]?(\d{3})/i.exec(ruleName || '');
  return m ? `SOL-${m[1]}` : (ruleName || 'SOL-?');
}

/** Escape regex metacharacters so a literal substring matches itself in RE2. */
function reEscape(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// RE2 overrides. Semgrep's engine (Rust `regex`/RE2) is linear-time and EXPANDS
// bounded repetitions, so a pattern the JS scanner accepts can exceed RE2's
// compile-size limit ("regular expression is too large"). For such a rule we ship
// an RE2-safe equivalent here; the scanner keeps its own (more precise) regex.
// Each override is keyed by rule_name and carries the reason it diverges.
const SEMGREP_OVERRIDES = {
  sol_011_close_attr: {
    regex: '#\\[account\\([^;{}#]{0,400}?close\\s*=',
    note:
      "RE2-safe port: the scanner's depth-2 paren-balanced regex is rejected by " +
      'Semgrep as "too large" (RE2 expands the nested {0,N} repetitions). This ' +
      'delimiter-bounded window flags `close =` within a 400-char #[account( ... ) ' +
      'region. It stops the window at ; { } and # — none appear inside an attribute, ' +
      'and stopping at # means the NEAREST #[account( wins so the finding lands on ' +
      'the right attribute even when two are adjacent. It favors recall over the ' +
      "scanner's exact paren-balancing; both flag the same real " +
      '#[account(close = ...)] attributes incl. long multi-line ones. Known limit: a ' +
      'raw-string literal (r#"..."#) inside a constraint before close= would stop the ' +
      'window early — a theoretical Semgrep-only miss; the scanner still catches it.',
  },
};

/** Build the single RE2 pattern for a rule: its override, its regex, or its escaped substrings OR-joined. */
function toRegex(p) {
  const ov = SEMGREP_OVERRIDES[p.rule_name];
  if (ov) return ov.regex;
  if (p.regex) return p.regex;
  if (Array.isArray(p.substrings) && p.substrings.length) {
    const alts = p.substrings.map(reEscape);
    return alts.length === 1 ? alts[0] : `(?:${alts.join('|')})`;
  }
  return null; // semantic-only rule (no deterministic matcher) — not portable to Semgrep
}

function build() {
  // CORE_SCHEMA: no code-executing tags, only plain maps/lists/scalars (same as sync-rules.js).
  const doc = yaml.load(fs.readFileSync(srcYaml, 'utf8'), { schema: yaml.CORE_SCHEMA });
  const patterns = (doc && doc.patterns) || [];
  // Per-rule metadata (tier/severity) from rules-meta.json. Surfaced ONLY in
  // Semgrep `metadata` (advisory) — the rule `severity` stays WARNING so existing
  // consumer gating on Semgrep severity is unchanged.
  const meta = (JSON.parse(fs.readFileSync(metaSrc, 'utf8')) || {}).rules || {};
  const rules = [];
  for (const p of patterns) {
    const rx = toRegex(p);
    if (!rx) continue; // skip rules with neither regex nor substrings
    const id = solId(p.rule_name);
    const m = meta[id] || {};
    const slug = p.rule_name.replace(/_/g, '-'); // sol_001_unauth_now_slot -> sol-001-unauth-now-slot
    // Per-rule languages: absent => rust (the on-chain default). Integrator rules
    // (SOL-029+) set [typescript, javascript] so Semgrep scans the right files —
    // `pattern-regex` still does the matching, but `languages` is what restricts
    // the file set, so a rust-only default would silently never run on TS.
    const langs = Array.isArray(p.languages) && p.languages.length ? p.languages.slice() : ['rust'];
    // Reject unsupported languages at GENERATION time (not just in CI tests): a stray
    // `generic` would make Semgrep scan every file type, turning a scoped advisory rule
    // into a universal one. Keep in lockstep with VALID_LANGS in the ruleset test.
    for (const l of langs) {
      if (!['rust', 'typescript', 'javascript'].includes(l)) {
        throw new Error(`sync-semgrep: rule ${p.rule_name} has unsupported language "${l}" (allowed: rust, typescript, javascript)`);
      }
    }
    const rule = {
      id: `solana-security-standard.${slug}`,
      languages: langs,
      severity: 'WARNING',
      message: p.reminder || `${id} — Solana Security Standard`,
      patterns: [{ 'pattern-regex': rx }],
    };
    // Mirror the scanner's exclude_paths so Semgrep skips off-chain dirs (client/cli/
    // tests/...) where these on-chain patterns are harmless. languages:[rust] already
    // restricts to .rs, so no `include` is needed.
    if (Array.isArray(p.exclude_paths) && p.exclude_paths.length) {
      rule.paths = { exclude: p.exclude_paths.slice() };
    }
    rule.metadata = {
      'sol-id': id,
      category: 'security',
      confidence: 'LOW', // advisory tripwire: a hit means "look here", not "definitely a bug"
      technology: langs.includes('rust') ? ['solana', 'anchor'] : ['solana'].concat(langs),
      references: [`${REPO}#${id.toLowerCase()}`],
      license: 'MIT',
    };
    // SSS baseline severity + submission-floor tier (advisory metadata; does NOT
    // change the rule's WARNING severity that consumers gate on).
    if (m.tier) rule.metadata['sss-tier'] = m.tier;
    if (m.severity) rule.metadata['sss-severity'] = m.severity;
    // Numbered "do NOT flag when…" exclusions (advisory guidance a reviewer cites
    // when dismissing a finding; Semgrep still fires — fail-open, no auto-suppression).
    if (Array.isArray(m.exclusions) && m.exclusions.length) rule.metadata['sss-exclusions'] = m.exclusions.slice();
    const ov = SEMGREP_OVERRIDES[p.rule_name];
    if (ov) rule.metadata.note = ov.note; // record why this rule's regex diverges from the scanner
    rules.push(rule);
  }
  return { rules };
}

function serialize(obj) {
  const header =
    '# Solana Security Standard — Semgrep ruleset (SOL-0XX).\n' +
    '# GENERATED from ../security-patterns.yaml by cli/scripts/sync-semgrep.js — do not edit by hand.\n' +
    '# Regenerate: `npm --prefix cli run sync:semgrep`.\n' +
    '# Run:        `semgrep --config semgrep/solana-security-standard.yaml <path>`.\n';
  // lineWidth:-1 keeps long regexes/messages on one line (no folding that could alter a
  // pattern); noRefs:true expands repeated arrays instead of emitting YAML anchors/aliases.
  return header + yaml.dump(obj, { lineWidth: -1, noRefs: true });
}

if (require.main === module) {
  const data = build();
  const out = serialize(data);
  if (process.argv.includes('--check')) {
    // Line-ending-agnostic compare: a Windows checkout may store CRLF while `out` is LF.
    const norm = (s) => s.replace(/\r\n/g, '\n');
    const current = fs.existsSync(dstYaml) ? norm(fs.readFileSync(dstYaml, 'utf8')) : '';
    if (current !== norm(out)) {
      console.error('semgrep/solana-security-standard.yaml is out of sync — run `npm run sync:semgrep`.');
      process.exit(1);
    }
    console.log('semgrep ruleset is in sync.');
  } else {
    fs.mkdirSync(path.dirname(dstYaml), { recursive: true });
    fs.writeFileSync(dstYaml, out);
    console.log(`synced ${data.rules.length} rules -> ${path.relative(repoRoot, dstYaml)}`);
  }
}

module.exports = { build, serialize, toRegex, reEscape, solId, SEMGREP_OVERRIDES };
