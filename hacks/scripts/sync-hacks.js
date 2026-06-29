'use strict';
// Validate hacks/hacks.json and regenerate hacks/README.md from it. Zero dependencies.
// hacks.json is the source of truth; README.md is a derived index (like security-patterns.yaml
// -> the artifacts). Rule IDs are cross-checked against claude-security-guidance.md so a hack can
// never reference a SOL-0XX rule that does not exist.
//
//   node scripts/sync-hacks.js          regenerate hacks/README.md (and validate)
//   node scripts/sync-hacks.js --check   validate + fail (exit 1) if README.md is stale (CI)

const fs = require('fs');
const path = require('path');

const HACKS_DIR = path.join(__dirname, '..');
const REPO_ROOT = path.join(__dirname, '..', '..');
const HACKS_JSON = path.join(HACKS_DIR, 'hacks.json');
const README = path.join(HACKS_DIR, 'README.md');
const GUIDANCE_MD = path.join(REPO_ROOT, 'claude-security-guidance.md');

const VALID_CATEGORIES = [
  'oracle-manipulation',
  'account-validation',
  'missing-authority',
  'accounting',
  'key-compromise',
  'off-chain-wallet',
];

const norm = (s) => s.replace(/\r\n/g, '\n');

// Parse the canonical rule id -> title map from the guidance markdown (single source of truth).
function loadRuleTitles(mdText) {
  const titles = {};
  const re = /^###\s+(SOL-\d{3})\s+·\s+(.+?)\s*$/gm;
  let m;
  while ((m = re.exec(mdText)) !== null) titles[m[1]] = m[2];
  return titles;
}

function formatMoney(n) {
  if (n >= 1e9) return '$' + (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1e6) return '$' + (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1e3) return '$' + Math.round(n / 1e3) + 'K';
  return '$' + n;
}

// GitHub heading slug for "SOL-0XX · Title": lowercase, drop punctuation in place (keep _ and -),
// then map EACH whitespace char to one hyphen (no collapsing) so "a / b" -> "a--b" — matches the
// live md anchors. The single source of truth for rule anchors; content/ imports this.
function ruleAnchor(rule, title) {
  return `${rule.toLowerCase()}--${title.toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s/g, '-')}`;
}

// Validate the dataset against valid rule ids. Returns an array of error strings (empty = clean).
function validate(data, validRuleIds) {
  const errors = [];
  const ruleSet = new Set(validRuleIds);
  if (!data || typeof data !== 'object') return ['hacks.json: not an object'];
  if (typeof data.version !== 'string' || !data.version) errors.push('top-level: missing "version" string');
  if (typeof data.description !== 'string' || !data.description) errors.push('top-level: missing "description" string');
  if (!Array.isArray(data.hacks) || data.hacks.length === 0) {
    errors.push('top-level: "hacks" must be a non-empty array');
    return errors;
  }
  const seenIds = new Set();
  const today = new Date();
  today.setHours(23, 59, 59, 999);
  for (const h of data.hacks) {
    if (!h || typeof h !== 'object' || Array.isArray(h)) {
      errors.push(`entry is not an object: ${JSON.stringify(h)}`);
      continue;
    }
    const id = (h && h.id) || '<no-id>';
    const req = ['id', 'name', 'protocol', 'date', 'loss_usd', 'category', 'code_preventable', 'sol_rules', 'root_cause', 'rule_link', 'sources'];
    for (const k of req) {
      if (!(k in h)) errors.push(`${id}: missing field "${k}"`);
    }
    if (typeof h.id !== 'string' || !/^[a-z0-9-]+$/.test(h.id || '')) errors.push(`${id}: id must be a lowercase slug [a-z0-9-]`);
    if (seenIds.has(h.id)) errors.push(`${id}: duplicate id`);
    seenIds.add(h.id);
    for (const k of ['name', 'protocol', 'root_cause', 'rule_link']) {
      if (typeof h[k] !== 'string' || !h[k].trim()) errors.push(`${id}: "${k}" must be a non-empty string`);
      // These render verbatim into the public README markdown — reject raw HTML / link / table
      // injection chars so a bad entry can't smuggle a <script>, a ](evil) link, or a broken | cell.
      else if (/[<>|\r\n]|\]\(|https?:\/\//.test(h[k])) errors.push(`${id}: "${k}" must not contain < > | newlines, "](", or a bare URL — it renders verbatim into the README`);
    }
    if (typeof h.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(h.date || '')) {
      errors.push(`${id}: date must be YYYY-MM-DD`);
    } else {
      const d = new Date(h.date + 'T00:00:00Z');
      // Round-trip so an impossible day (e.g. 2022-02-30, which Date silently rolls to Mar 2) is rejected.
      if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== h.date) errors.push(`${id}: date is not a real date (${h.date})`);
      else if (d > today) errors.push(`${id}: date is in the future (${h.date})`);
    }
    if (!Number.isInteger(h.loss_usd) || h.loss_usd < 0) errors.push(`${id}: loss_usd must be a non-negative integer`);
    if (!VALID_CATEGORIES.includes(h.category)) errors.push(`${id}: category "${h.category}" not in {${VALID_CATEGORIES.join(', ')}}`);
    if (typeof h.code_preventable !== 'boolean') errors.push(`${id}: code_preventable must be a boolean`);
    if (!Array.isArray(h.sol_rules)) {
      errors.push(`${id}: sol_rules must be an array`);
    } else {
      for (const r of h.sol_rules) {
        if (typeof r !== 'string' || !/^SOL-\d{3}$/.test(r)) errors.push(`${id}: sol_rules entry "${r}" must look like SOL-001`);
        else if (!ruleSet.has(r)) errors.push(`${id}: sol_rules references ${r}, which is not a rule in claude-security-guidance.md`);
      }
      // honesty invariant: a code-preventable hack maps to >=1 rule; an out-of-scope one maps to none.
      if (h.code_preventable === true && h.sol_rules.length === 0) errors.push(`${id}: code_preventable=true but sol_rules is empty`);
      if (h.code_preventable === false && h.sol_rules.length > 0) errors.push(`${id}: code_preventable=false but sol_rules is non-empty (don't claim a rule catches it)`);
    }
    if (!Array.isArray(h.sources) || h.sources.length === 0) {
      errors.push(`${id}: sources must be a non-empty array`);
    } else {
      for (const u of h.sources) {
        if (typeof u !== 'string' || !/^https:\/\/\S+$/.test(u)) errors.push(`${id}: source "${u}" must be an https URL`);
      }
    }
  }
  return errors;
}

function renderReadme(data, ruleTitles) {
  const hacks = data.hacks.slice();
  const byDate = (a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : a.id < b.id ? -1 : 1);
  const mapped = hacks.filter((h) => h.code_preventable).sort(byDate);
  const outOfScope = hacks.filter((h) => !h.code_preventable).sort(byDate);
  const totalMapped = mapped.reduce((s, h) => s + h.loss_usd, 0);

  // rule -> hacks that reference it (only mapped hacks have rules)
  const ruleToHacks = {};
  for (const h of mapped) for (const r of h.sol_rules) (ruleToHacks[r] = ruleToHacks[r] || []).push(h);
  const coveredRules = Object.keys(ruleToHacks).sort();

  const GH = 'https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md';
  const slug = (rule, title) => `${GH}#${ruleAnchor(rule, title)}`;

  const L = [];
  L.push('# The Solana Hacks Database');
  L.push('');
  L.push('> Real, disclosed Solana exploits mapped to the [Solana Security Standard](../claude-security-guidance.md) (`SOL-0XX`) rule class each one falls under. Generated from [`hacks.json`](./hacks.json) — do not edit by hand (run `node scripts/sync-hacks.js`).');
  L.push('');
  L.push(`**${mapped.length} code-level exploits** — ${formatMoney(totalMapped)} lost — mapped to **${coveredRules.length} of the 52 rules**. Plus **${outOfScope.length} notable incidents no code rule prevents** (stolen keys, off-chain wallets), listed for honesty about scope.`);
  L.push('');
  L.push('Every entry is cited. A mapping says "this rule class is the one that flags this bug" — not that any tool would have auto-fixed it. We never claim a rule catches an incident it cannot (see [`SCHEMA.md`](./SCHEMA.md)).');
  L.push('');

  L.push('## Coverage by rule');
  L.push('');
  L.push('Which SOL-0XX rule class each exploit falls under.');
  L.push('');
  L.push('| Rule | Class | Exploits |');
  L.push('| --- | --- | --- |');
  for (const r of coveredRules) {
    const title = ruleTitles[r] || '';
    const names = ruleToHacks[r].map((h) => h.protocol).join(', ');
    L.push(`| [${r}](${slug(r, title)}) | ${title} | ${names} |`);
  }
  L.push('');

  L.push('## Code-level exploits');
  L.push('');
  L.push('| Date | Protocol | Loss | Class | Rules |');
  L.push('| --- | --- | --- | --- | --- |');
  for (const h of mapped) {
    L.push(`| ${h.date} | [${h.protocol}](#${h.id}) | ${formatMoney(h.loss_usd)} | ${h.category} | ${h.sol_rules.join(', ')} |`);
  }
  L.push('');

  L.push('## Details');
  L.push('');
  for (const h of mapped) {
    L.push(`### ${h.protocol} — ${formatMoney(h.loss_usd)} <a id="${h.id}"></a>`);
    L.push('');
    L.push(`**${h.name}** · ${h.date} · \`${h.sol_rules.join('` `')}\``);
    L.push('');
    L.push(`**What happened.** ${h.root_cause}`);
    L.push('');
    L.push(`**Why it maps here.** ${h.rule_link}`);
    L.push('');
    L.push('**Sources:** ' + h.sources.map((u, i) => `[${i + 1}](${u})`).join(' · '));
    L.push('');
  }

  L.push('## Not preventable by a code rule');
  L.push('');
  L.push('These are real Solana losses, but no on-chain code rule prevents them — they are key compromises or off-chain/client failures. Listed so the database is honest about what code review covers and what it does not.');
  L.push('');
  L.push('| Date | Protocol | Loss | Why no code rule applies |');
  L.push('| --- | --- | --- | --- |');
  for (const h of outOfScope) {
    L.push(`| ${h.date} | ${h.protocol} | ${formatMoney(h.loss_usd)} | ${h.root_cause} |`);
  }
  L.push('');

  L.push('## Contributing');
  L.push('');
  L.push('Add an exploit by appending to [`hacks.json`](./hacks.json) (schema: [`SCHEMA.md`](./SCHEMA.md)) and running `node scripts/sync-hacks.js`. Every entry needs a cited source and an honest mapping. CI re-runs the generator and fails if `README.md` is out of sync.');
  L.push('');
  L.push('Maintained by [Jelleo](https://jelleo.com). MIT. Part of the [Solana Security Standard](../README.md).');
  L.push('');
  return L.join('\n');
}

function main() {
  const check = process.argv.includes('--check');
  const data = JSON.parse(fs.readFileSync(HACKS_JSON, 'utf8'));
  const mdText = fs.readFileSync(GUIDANCE_MD, 'utf8');
  const ruleTitles = loadRuleTitles(mdText);
  const validRuleIds = Object.keys(ruleTitles);
  if (validRuleIds.length === 0) {
    console.error('sync-hacks: could not parse any SOL-0XX rules from claude-security-guidance.md');
    process.exit(1);
  }

  const errors = validate(data, validRuleIds);
  if (errors.length) {
    console.error('hacks.json validation failed:');
    for (const e of errors) console.error('  - ' + e);
    process.exit(1);
  }

  const readme = renderReadme(data, ruleTitles);
  if (check) {
    const cur = fs.existsSync(README) ? norm(fs.readFileSync(README, 'utf8')) : '';
    if (cur !== norm(readme)) {
      console.error('hacks/README.md is out of sync with hacks.json — run `node scripts/sync-hacks.js`');
      process.exit(1);
    }
    console.log(`hacks: ${data.hacks.length} entries valid; README.md in sync.`);
  } else {
    fs.writeFileSync(README, norm(readme));
    console.log(`hacks: ${data.hacks.length} entries valid; wrote README.md.`);
  }
}

if (require.main === module) main();

module.exports = { validate, renderReadme, loadRuleTitles, formatMoney, ruleAnchor, VALID_CATEGORIES };
