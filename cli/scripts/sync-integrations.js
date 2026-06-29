'use strict';
// Regenerate ../../integrations/** from claude-security-guidance.md.
//
// Every AI coding tool reads a "rules / instructions" file; this emits the
// Solana Security Standard (SOL-0XX) into each tool's native format from the ONE
// source of truth (the guidance markdown). The SOL-0XX body is shared; only the
// per-tool header / frontmatter / path differs - no guidance is duplicated by hand.
//
//   claude-security-guidance.md  (SOURCE)
//      -> integrations/codex/AGENTS.md
//      -> integrations/copilot/.github/copilot-instructions.md
//      -> integrations/cursor/.cursor/rules/solana-security.mdc
//      -> integrations/windsurf/.windsurf/rules/solana-security.md
//      -> integrations/cline/.clinerules
//      -> integrations/aider/CONVENTIONS.md (+ .aider.conf.yml)
//      -> integrations/README.md  (install matrix)
//
// Run: `npm run sync:integrations`.  CI verifies with `--check` (which also flags orphans).

const fs = require('fs');
const path = require('path');

const repoRoot = path.join(__dirname, '..', '..');
const srcGuidance = path.join(repoRoot, 'claude-security-guidance.md');
const outDir = path.join(repoRoot, 'integrations');
const REPO = 'https://github.com/Copenhagen0x/solana-security-standard';
// Windsurf WORKSPACE rule files are capped at 12,000 chars each (the 6,000 cap is
// for the GLOBAL rules file); the total across all rules is also 12,000. Our single
// ~8 KB file is under the per-file cap - build() asserts it. Source: Windsurf docs,
// "Creating & Modifying Rules" (windsurf.com/university).
const WINDSURF_MAX = 12000;
const WINDSURF_FILE = 'windsurf/.windsurf/rules/solana-security.md';

// The substantive guidance: everything from the "## Threat model" heading onward
// (threat model + review checklist + the 28 SOL-0XX rules + provenance). The H1
// title/blurb is dropped and replaced per tool. The anchor is matched at a LINE
// START and must be unique, so a stray inline mention can't shift/corrupt the slice.
function coreBody() {
  const md = fs.readFileSync(srcGuidance, 'utf8').replace(/\r\n/g, '\n'); // a Windows checkout may store CRLF
  const anchor = '\n## Threat model\n';
  const i = md.indexOf(anchor);
  if (i === -1) throw new Error('sync-integrations: line-anchored "## Threat model" heading not found in guidance');
  if (md.indexOf(anchor) !== md.lastIndexOf(anchor)) {
    throw new Error('sync-integrations: "## Threat model" heading appears more than once - ambiguous slice');
  }
  return md.slice(i + 1).trimEnd() + '\n'; // +1 skips the anchor's leading newline
}

const pg = require('./sync-plugin-guidance');

// Rule tier (high|low) from the advisory meta — prioritizes which cues stay inline
// when the full set would overflow a tool's cap.
function loadTiers() {
  const rules = (JSON.parse(fs.readFileSync(path.join(repoRoot, 'rules-meta.json'), 'utf8')) || {}).rules || {};
  const t = {};
  for (const id of Object.keys(rules)) t[id] = rules[id].tier === 'high' ? 'high' : 'low';
  return t;
}

// SCALE-INVARIANT AI-context body. SSS may grow to thousands of rules, but every AI
// tool file is consumer-capped (Windsurf hard-caps at 12,000 chars). So the tool
// files carry the threat model + review checklist + terse SOL-0XX cues (id · title ·
// fix), byte-budgeted (highest-tier first) with ONE overflow pointer. The CLI /
// Semgrep / Action / MCP / master still carry 100% of the rules; only this inline
// cheat-sheet is bounded — so it never overflows for any N.
function aiBody() {
  const md = fs.readFileSync(srcGuidance, 'utf8').replace(/\r\n/g, '\n');
  const rules = pg.parseRules(md);
  const tiers = loadTiers();
  const headBlock = pg.preamble(md) + '\n\n## Rules — flag the pattern, apply the fix, cite the SOL-0XX id\n\n';
  const cues = rules.map((r) => ({
    id: r.id,
    tier: tiers[r.id] || 'low',
    line: `- **${r.id}** · ${r.title} — ${pg.extractFix(r.body)}`,
  }));
  // Budget the BODY so even the largest per-tool header + INTRO stays under the cap.
  const CAP = WINDSURF_MAX - 1100;
  const fullBody = headBlock + cues.map((c) => c.line).join('\n') + '\n';
  if (Buffer.byteLength(fullBody, 'utf8') <= CAP) return fullBody;
  const RESERVE = 380; // headroom for the single overflow line
  let used = Buffer.byteLength(headBlock, 'utf8');
  const keep = new Set();
  const byPriority = [...cues].sort(
    (a, b) => (a.tier === 'high' ? 0 : 1) - (b.tier === 'high' ? 0 : 1) || a.id.localeCompare(b.id)
  );
  for (const c of byPriority) {
    const add = Buffer.byteLength(c.line + '\n', 'utf8');
    if (used + add <= CAP - RESERVE) {
      keep.add(c.id);
      used += add;
    }
  }
  const kept = cues.filter((c) => keep.has(c.id));
  const omitted = cues.length - kept.length;
  return (
    headBlock +
    kept.map((c) => c.line).join('\n') +
    '\n' +
    `- *+ ${omitted} more rules — the CLI scanner, Semgrep, GitHub Action, and the \`list_solana_security_rules\` MCP tool enforce/serve the complete catalog; full per-rule detail in \`claude-security-guidance.md\` at ${REPO}.*\n`
  );
}

const INTRO =
  'When you write, edit, or review Solana code in this project — on-chain Anchor/Rust programs AND ' +
  'the TypeScript/JavaScript that builds and sends transactions (bots, keepers, integrators) — apply ' +
  'the Solana Security Standard (SOL-0XX) below. Solana programs are stateless: treat every caller ' +
  'as hostile until cryptographically proven otherwise. For each rule, flag the pattern, fix it ' +
  'as described, and cite the SOL-0XX id in your explanation. Off-chain code (client / cli / offchain ' +
  '/ sdk / tests) is generally exempt from the on-chain (Rust) rules, EXCEPT the integrator rules ' +
  'SOL-029..031, which apply specifically to that transaction-sending TypeScript/JavaScript. Full ' +
  'catalog: ' + REPO + ' . Audits: jelleo.com .\n';

// id -> full file content. Each wraps the shared body with the tool's convention.
const TOOLS = {
  'codex/AGENTS.md': (body) =>
    '# AGENTS.md\n\n' +
    '## Solana Security Standard (SOL-0XX)\n\n' +
    INTRO + '\n' + body,

  'copilot/.github/copilot-instructions.md': (body) =>
    '# Copilot instructions: Solana Security Standard (SOL-0XX)\n\n' +
    INTRO + '\n' + body,

  'cursor/.cursor/rules/solana-security.mdc': (body) =>
    '---\n' +
    'description: Solana Security Standard (SOL-0XX) - flag and fix Solana/Anchor security bugs\n' +
    'alwaysApply: true\n' +
    '---\n\n' +
    INTRO + '\n' + body,

  [WINDSURF_FILE]: (body) =>
    '# Solana Security Standard (SOL-0XX)\n\n' +
    INTRO + '\n' + body,

  'cline/.clinerules': (body) =>
    '# Solana Security Standard (SOL-0XX)\n\n' +
    INTRO + '\n' + body,

  'aider/CONVENTIONS.md': (body) =>
    '# Solana Security Standard (SOL-0XX) - coding conventions\n\n' +
    INTRO + '\n' + body,
};

// Static companion files (not derived from the guidance body).
const STATIC = {
  // The conventions file is the solid default. The scanner lint-cmd is OPT-IN
  // (commented): the scanner is an advisory heuristic - a hit means "look here",
  // not a confirmed bug - so as a hard lint gate it would prompt fixes on correct
  // code. When enabled, `-r .` makes the off-chain path excludes resolve against
  // the repo root (Aider appends the edited file), and the version is range-pinned.
  'aider/.aider.conf.yml':
    '# Solana Security Standard for Aider.\n' +
    '# Loads the SOL-0XX conventions into every session so Aider writes and reviews\n' +
    '# Solana/Anchor code against the rules.\n' +
    'read: CONVENTIONS.md\n' +
    '\n' +
    '# Optional: also run the real scanner as a Rust lint gate after edits. OFF by\n' +
    '# default - the scanner is an advisory heuristic (a match means "look here", not\n' +
    '# a confirmed bug), so as a hard gate it can prompt fixes on correct code.\n' +
    '# Uncomment to enable. `-r .` makes the off-chain excludes work on the appended\n' +
    '# file path; `@1` pins to major 1 (gets 1.x updates, not a 2.0 jump).\n' +
    '# lint-cmd:\n' +
    '#   - "rust: npx --yes @jelleo/solana-security-standard@1 scan -r ."\n',
};

function readme() {
  const rows = [
    ['Codex / any AGENTS.md agent', '`AGENTS.md`', '`codex/AGENTS.md` -> repo root (or append the section to your existing `AGENTS.md`)'],
    ['GitHub Copilot', '`.github/copilot-instructions.md`', '`copilot/.github/` -> repo root'],
    ['Cursor', '`.cursor/rules/solana-security.mdc`', '`cursor/.cursor/` -> repo root (applies to every request via `alwaysApply`)'],
    ['Windsurf', '`.windsurf/rules/solana-security.md`', '`windsurf/.windsurf/` -> repo root (~8 KB; Windsurf allots 12 KB total across all rules)'],
    ['Cline', '`.clinerules`', '`cline/.clinerules` -> repo root'],
    ['Aider', '`CONVENTIONS.md` (+ optional `.aider.conf.yml`)', '`aider/*` -> repo root (the config also has an opt-in scanner lint-cmd)'],
    ['Claude Code', '`claude-security-guidance.md` + `security-patterns.yaml`', 'the plugin at the repo root (see top-level README)'],
    ['VS Code / Cursor / Windsurf (inline squiggles)', 'the extension', 'install "Solana Security Standard" from the Marketplace'],
    ['CLI / CI', '`npx @jelleo/solana-security-standard`', 'run it anywhere; the GitHub Action gates PRs'],
    ['Semgrep', '`semgrep --config`', 'point at `semgrep/solana-security-standard.yaml`'],
    ['MCP server (any MCP client)', '`@jelleo/solana-security-mcp`', 'add to your MCP config; serves a scan tool + the rules (see `mcp/`)'],
  ];
  const table = ['| Tool | What it reads | Install |', '| --- | --- | --- |']
    .concat(rows.map((r) => `| ${r[0]} | ${r[1]} | ${r[2]} |`))
    .join('\n');
  return (
    '# Install the Solana Security Standard in your AI coding tool\n\n' +
    'Every file here is generated from the one source of truth ' +
    '(`claude-security-guidance.md`) by `cli/scripts/sync-integrations.js` - do not edit by hand. ' +
    'Pick your tool, copy the listed file(s) into your project, and the assistant will write and ' +
    'review Solana/Anchor code against the SOL-0XX rules.\n\n' +
    table + '\n\n' +
    '**Coverage.** The AI-instruction files (Codex, Copilot, Cursor, Windsurf, Cline, Aider) carry ' +
    'all **52 documented SOL-0XX rules** as guidance for the assistant. The machine-checkable ' +
    'surfaces (CLI, GitHub Action, Semgrep, editor extension) enforce the **30 rules that have ' +
    'deterministic patterns**; the other 22 are semantic rules an AI or human reviewer applies. ' +
    'All are generated from the same source - no rule text is duplicated by hand. ' +
    'Full catalog and per-rule detail: ' + REPO + ' .\n'
  );
}

function build() {
  const body = aiBody();
  const files = {};
  for (const [rel, render] of Object.entries(TOOLS)) files[rel] = render(body);
  for (const [rel, content] of Object.entries(STATIC)) files[rel] = content;
  files['README.md'] = readme();
  if (Buffer.byteLength(files[WINDSURF_FILE], 'utf8') >= WINDSURF_MAX) {
    throw new Error(`sync-integrations: Windsurf file is ${Buffer.byteLength(files[WINDSURF_FILE], 'utf8')} bytes, over the ${WINDSURF_MAX} cap`);
  }
  return files;
}

function writeAll(files) {
  for (const [rel, content] of Object.entries(files)) {
    const dst = path.join(outDir, rel);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.writeFileSync(dst, content);
  }
}

// All files currently on disk under integrations/, as posix-relative paths.
// lstat (not stat): don't follow symlinks, so a stray symlink can't loop the walk.
function onDiskTree(dir = outDir, base = outDir, acc = []) {
  if (!fs.existsSync(dir)) return acc;
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    if (fs.lstatSync(p).isDirectory()) onDiskTree(p, base, acc);
    else acc.push(path.relative(base, p).split(path.sep).join('/'));
  }
  return acc;
}

if (require.main === module) {
  const files = build();
  const norm = (s) => s.replace(/\r\n/g, '\n');
  if (process.argv.includes('--check')) {
    const stale = [];
    for (const [rel, content] of Object.entries(files)) {
      const dst = path.join(outDir, rel);
      const cur = fs.existsSync(dst) ? norm(fs.readFileSync(dst, 'utf8')) : '(missing)';
      if (cur !== norm(content)) stale.push(rel + (cur === '(missing)' ? ' (missing)' : ' (changed)'));
    }
    // Orphans: files on disk the generator no longer emits (a renamed/removed tool).
    for (const rel of onDiskTree()) if (!(rel in files)) stale.push(rel + ' (orphan - delete it)');
    if (stale.length) {
      console.error('integrations/ out of sync - run `npm run sync:integrations`:\n  ' + stale.join('\n  '));
      process.exit(1);
    }
    console.log('integrations are in sync.');
  } else {
    writeAll(files);
    console.log(`synced ${Object.keys(files).length} integration files -> integrations/`);
  }
}

module.exports = { build, coreBody, TOOLS, STATIC, WINDSURF_MAX, WINDSURF_FILE };
