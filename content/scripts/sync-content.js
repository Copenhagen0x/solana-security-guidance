'use strict';
// Content engine. Generates one explainer page per SOL-0XX rule (content/rules/SOL-0XX.md)
// plus an index (content/README.md), stitching four already-reviewed sources:
//   - claude-security-guidance.md  -> the rule's title, description, and fix
//   - cli/rules.json               -> whether the rule is machine-checkable (has a pattern)
//   - hacks/hacks.json             -> the real exploits in that rule's class
//   - examples/                    -> a paired vulnerable/fixed code example, where one exists
// Zero dependencies. Pages are DERIVED — never hand-edit; run the generator.
//
//   node scripts/sync-content.js          regenerate content/rules/*.md + README.md
//   node scripts/sync-content.js --check   fail (exit 1) if any page is stale or orphaned (CI)

const fs = require('fs');
const path = require('path');

const CONTENT_DIR = path.join(__dirname, '..');
const RULES_OUT = path.join(CONTENT_DIR, 'rules');
const README_OUT = path.join(CONTENT_DIR, 'README.md');
const REPO = path.join(__dirname, '..', '..');
const GUIDANCE_MD = path.join(REPO, 'claude-security-guidance.md');
const RULES_JSON = path.join(REPO, 'cli', 'rules.json');
const HACKS_JSON = path.join(REPO, 'hacks', 'hacks.json');
const EXAMPLES_DIR = path.join(REPO, 'examples');
const RULES_META = path.join(REPO, 'rules-meta.json');

const norm = (s) => s.replace(/\r\n/g, '\n');

function formatMoney(n) {
  if (n >= 1e9) return '$' + (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1e6) return '$' + (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1e3) return '$' + Math.round(n / 1e3) + 'K';
  return '$' + n;
}

// The GitHub rule-anchor slug — imported from the hacks generator so the two cannot diverge (both
// link to the same claude-security-guidance.md headings). Single source of truth.
const { ruleAnchor } = require('../../hacks/scripts/sync-hacks');

// Parse the rules out of the "## Rules" section: each is "### SOL-0XX · Title\n<body>".
function parseRules(md) {
  const afterRules = md.split(/^## Rules\s*$/m)[1];
  if (!afterRules) throw new Error('could not find "## Rules" section');
  const block = afterRules.split(/^## /m)[0]; // stop before the next ## (Provenance)
  return block
    .split(/^### /m)
    .slice(1)
    .map((b) => {
      const nl = b.indexOf('\n');
      const heading = b.slice(0, nl).trim();
      const body = b.slice(nl + 1).trim();
      const m = heading.match(/^(SOL-(\d{3}))\s+·\s+(.+)$/);
      if (!m) throw new Error('unparseable rule heading: ' + heading);
      return { id: m[1], num: m[2], title: m[3].trim(), body };
    });
}

// SOL ids that have a deterministic pattern (rule_name "sol_017_..." -> "SOL-017").
function loadPatternIds(rulesJson) {
  const ids = new Set();
  for (const p of rulesJson.patterns || []) {
    const m = String(p.rule_name || '').match(/^sol_(\d{3})_/);
    if (m) ids.add('SOL-' + m[1]);
  }
  return ids;
}

// SOL-0XX -> [{protocol, date, loss_usd, id}], code-preventable hacks only, newest first.
function loadHacksByRule(hacksJson) {
  const byRule = {};
  for (const h of hacksJson.hacks || []) {
    if (!h.code_preventable) continue;
    for (const r of h.sol_rules) (byRule[r] = byRule[r] || []).push(h);
  }
  for (const r of Object.keys(byRule)) byRule[r].sort((a, b) => (a.date > b.date ? -1 : 1));
  return byRule;
}

// rule num "001" -> example dir "sol_001_unauth_now_slot", if present.
function loadExamples() {
  const out = {};
  if (!fs.existsSync(EXAMPLES_DIR)) return out;
  for (const name of fs.readdirSync(EXAMPLES_DIR)) {
    const m = name.match(/^sol_(\d{3})_/);
    if (m && fs.statSync(path.join(EXAMPLES_DIR, name)).isDirectory()) out[m[1]] = name;
  }
  return out;
}

function renderRulePage(rule, ctx) {
  const hasPattern = ctx.patternIds.has(rule.id);
  const hacks = ctx.hacksByRule[rule.id] || [];
  const example = ctx.examples[rule.num];
  const L = [];
  L.push(`# ${rule.id} · ${rule.title}`);
  L.push('');
  L.push(rule.body);
  L.push('');
  L.push(
    hasPattern
      ? '**Enforcement — machine-checkable.** A deterministic pattern flags this automatically in the [CLI](../../cli), the [GitHub Action](../../action.yml), the [Semgrep ruleset](../../semgrep), the [VS Code extension](../../extensions/vscode), and the [MCP server](../../mcp).'
      : '**Enforcement — review-only.** A judgment-call class with no deterministic pattern: it lives in the standard\'s review checklist and in your AI agent\'s [rules file](../../integrations), so the model reviews for it.',
  );
  L.push('');
  const m = ctx.meta[rule.id];
  if (m) {
    const tierTxt =
      m.tier === 'low'
        ? 'LOW — hygiene / defense-in-depth / operational (filtered out by `--min-tier high`)'
        : 'HIGH — high-value; surfaced even at a strict submission floor';
    L.push(`**Value tier — ${String(m.tier || '').toUpperCase()}.** ${tierTxt}`);
    L.push('');
    L.push(
      `**Baseline severity — ${m.severity}.** A starting point, not a verdict: calibrate by preconditions × access level (take the lower) per [SEVERITY.md](../../SEVERITY.md).`,
    );
    L.push('');
    if (m.reachability) {
      L.push(
        `**Reachability anchor.** To confirm this is exploitable (not merely present), cite ${m.reachability}.`,
      );
      L.push('');
    }
    if (Array.isArray(m.exclusions) && m.exclusions.length) {
      L.push('**Do NOT flag when** — cite the number when suppressing a finding:');
      L.push('');
      m.exclusions.forEach((e, i) => L.push(`${i + 1}. ${e}`));
      L.push('');
    }
  }
  L.push('## Real exploits in this class');
  L.push('');
  if (hacks.length) {
    for (const h of hacks) {
      L.push(`- **${h.protocol}** — ${formatMoney(h.loss_usd)} (${h.date}) — [how it happened](../../hacks/README.md#${h.id})`);
    }
  } else {
    L.push('No publicly catalogued exploit in the [Hacks Database](../../hacks/README.md) maps to this class yet. The rule is drawn from documented Solana audit patterns, not a specific in-the-wild loss.');
  }
  L.push('');
  if (example) {
    L.push('## See it in code');
    L.push('');
    L.push(`Paired vulnerable / fixed snippet: [\`examples/${example}/\`](../../examples/${example}/).`);
    L.push('');
  }
  L.push('---');
  L.push(
    `*Part of the [Solana Security Standard](../../README.md). Full rule text: [${rule.id}](../../claude-security-guidance.md#${ruleAnchor(rule.id, rule.title)}).*`,
  );
  L.push('');
  return L.join('\n');
}

function renderIndex(rules, ctx) {
  const withPattern = rules.filter((r) => ctx.patternIds.has(r.id)).length;
  const withHack = rules.filter((r) => (ctx.hacksByRule[r.id] || []).length).length;
  const L = [];
  L.push(`# Rule content — all ${rules.length} SOL-0XX explainers`);
  L.push('');
  L.push('> One page per rule: what it catches, the fix, whether it is machine-checkable, the real exploits in that class, and a code example where one exists. Generated from the standard + patterns + the [Hacks Database](../hacks/) + examples by [`scripts/sync-content.js`](./scripts/sync-content.js) — do not hand-edit.');
  L.push('');
  L.push(`**${withPattern} of ${rules.length}** rules are machine-checkable (deterministic pattern); the rest are review-only. **${withHack}** map to a catalogued real-world exploit.`);
  L.push('');
  L.push('| Rule | Title | Tier | Severity | Enforcement | Real exploits | Example |');
  L.push('| --- | --- | --- | --- | --- | --- | --- |');
  for (const r of rules) {
    const m = ctx.meta[r.id] || {};
    const enforcement = ctx.patternIds.has(r.id) ? 'pattern' : 'review';
    const hacks = ctx.hacksByRule[r.id] || [];
    const exploits = hacks.length ? hacks.map((h) => h.protocol).join(', ') : '—';
    const example = ctx.examples[r.num] ? '✓' : '—';
    L.push(`| [${r.id}](./rules/${r.id}.md) | ${r.title} | ${m.tier || '—'} | ${m.severity || '—'} | ${enforcement} | ${exploits} | ${example} |`);
  }
  L.push('');
  L.push('Maintained by [Jelleo](https://jelleo.com). MIT.');
  L.push('');
  return L.join('\n');
}

function build() {
  const md = fs.readFileSync(GUIDANCE_MD, 'utf8');
  const rules = parseRules(md);
  const ctx = {
    patternIds: loadPatternIds(JSON.parse(fs.readFileSync(RULES_JSON, 'utf8'))),
    hacksByRule: loadHacksByRule(JSON.parse(fs.readFileSync(HACKS_JSON, 'utf8'))),
    examples: loadExamples(),
    meta: (JSON.parse(fs.readFileSync(RULES_META, 'utf8')) || {}).rules || {},
  };
  const files = {}; // relpath -> content
  for (const r of rules) files[`rules/${r.id}.md`] = norm(renderRulePage(r, ctx));
  files['README.md'] = norm(renderIndex(rules, ctx));
  return { rules, ctx, files };
}

function main() {
  const check = process.argv.includes('--check');
  const { rules, files } = build();
  // Tripwire — BUMP this number when you add/remove a rule. The --check diff catches
  // stale pages; this catches a guidance parse that silently lost or gained a rule.
  if (rules.length !== 52) {
    console.error(`content: expected 52 rules, parsed ${rules.length}`);
    process.exit(1);
  }
  if (check) {
    let stale = [];
    for (const [rel, content] of Object.entries(files)) {
      const abs = path.join(CONTENT_DIR, rel);
      const cur = fs.existsSync(abs) ? norm(fs.readFileSync(abs, 'utf8')) : '';
      if (cur !== content) stale.push(rel);
    }
    // orphan detection: a rules/*.md on disk that the generator no longer produces
    const expected = new Set(Object.keys(files).filter((f) => f.startsWith('rules/')).map((f) => path.basename(f)));
    const onDisk = fs.existsSync(RULES_OUT) ? fs.readdirSync(RULES_OUT).filter((f) => f.endsWith('.md')) : [];
    const orphans = onDisk.filter((f) => !expected.has(f));
    if (stale.length || orphans.length) {
      if (stale.length) console.error('content out of sync — run `node scripts/sync-content.js`:\n  ' + stale.join('\n  '));
      if (orphans.length) console.error('orphaned content pages (no matching rule):\n  ' + orphans.map((o) => 'rules/' + o).join('\n  '));
      process.exit(1);
    }
    console.log(`content: ${rules.length} rule pages + index in sync.`);
  } else {
    fs.mkdirSync(RULES_OUT, { recursive: true });
    for (const [rel, content] of Object.entries(files)) {
      const abs = path.join(CONTENT_DIR, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, content);
    }
    console.log(`content: wrote ${rules.length} rule pages + README.md.`);
  }
}

if (require.main === module) main();

module.exports = { parseRules, loadPatternIds, loadHacksByRule, ruleAnchor, formatMoney, renderRulePage, renderIndex, build };
