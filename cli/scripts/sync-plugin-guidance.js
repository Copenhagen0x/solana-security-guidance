'use strict';
// Generate plugin-guidance.md (repo root) from claude-security-guidance.md.
//   node cli/scripts/sync-plugin-guidance.js           regenerate plugin-guidance.md
//   node cli/scripts/sync-plugin-guidance.js --check    fail (exit 1) if stale / over cap
//
// WHY THIS EXISTS — the 8KB ceiling, solved.
// The Claude Code plugin reads a single guidance file that Anthropic caps at 8192
// bytes. Full per-rule prose is ~180 B/rule, so that file maxes out around ~40
// rules. To let the standard grow past that, `claude-security-guidance.md` stays
// the full hand-authored MASTER (now uncapped — every generator/MCP/link keeps
// reading it), and the plugin instead installs THIS generated DIGEST: the threat
// model + review checklist verbatim, then one terse cue per rule (id · title ·
// fix), then a pointer to the full detail (the MCP tool or the master on GitHub).
// A terse line is ~80 B, so the digest holds ~80+ rules under the cap.
//
// Invariants (reviewers cite these):
//   - GENERATED — never hand-edit; CI `--check` fails if stale.
//   - HARD-FAILS if the output exceeds 8192 bytes — a future rule that would
//     overflow the digest fails CI here, it never ships a broken plugin file.
//   - Reuses the master's canonical `### SOL-NNN · Title` structure (the same slice
//     sync-content.js uses); a master reshuffle that breaks parsing fails loud.
//   - Normalizes to LF on write so the Windows `--check` + byte cap never
//     false-fail on a CRLF checkout.

const fs = require('fs');
const path = require('path');

const repoRoot = path.join(__dirname, '..', '..');
const srcPath = path.join(repoRoot, 'claude-security-guidance.md');
const outPath = path.join(repoRoot, 'plugin-guidance.md');
const MAX_BYTES = 8192; // Anthropic plugin-guidance-file cap

// Canonical rule slice — mirrors content/scripts/sync-content.js parseRules so the
// digest and the content pages always agree on what a "rule" is.
function parseRules(md) {
  const afterRules = md.split(/^## Rules\s*$/m)[1];
  if (!afterRules) throw new Error('sync-plugin-guidance: could not find "## Rules" section');
  const block = afterRules.split(/^## /m)[0]; // stop before the next ## (Provenance)
  return block
    .split(/^### /m)
    .slice(1)
    .map((b) => {
      const nl = b.indexOf('\n');
      const heading = b.slice(0, nl).trim();
      const body = b.slice(nl + 1).trim();
      const m = heading.match(/^(SOL-(\d{3}))\s+·\s+(.+)$/);
      if (!m) throw new Error('sync-plugin-guidance: unparseable rule heading: ' + heading);
      return { id: m[1], title: m[3].trim(), body };
    });
}

// Everything from "## Threat model" up to (but not including) "## Rules" — the
// threat model + review checklist, copied verbatim into the digest. Line-anchored
// + uniqueness-checked so a stray inline mention can't shift the slice.
function preamble(md) {
  const anchor = '\n## Threat model\n';
  if (md.indexOf(anchor) !== md.lastIndexOf(anchor)) {
    throw new Error('sync-plugin-guidance: "## Threat model" appears more than once — ambiguous slice');
  }
  const start = md.indexOf(anchor);
  if (start === -1) throw new Error('sync-plugin-guidance: "## Threat model" heading not found');
  const rulesAnchor = md.indexOf('\n## Rules');
  if (rulesAnchor === -1 || rulesAnchor < start) throw new Error('sync-plugin-guidance: "## Rules" heading not found after threat model');
  return md.slice(start + 1, rulesAnchor).trimEnd();
}

// The fix cue for one rule: the body's "Fix:" clause to end-of-body, minus the
// "Fix:" prefix and any trailing *(provenance)* italics. NOT split-on-period —
// some fixes (SOL-023) carry a mid-clause period/parenthetical.
function extractFix(body) {
  // Strip a trailing *(provenance)* note FIRST, then find "Fix:". Order matters:
  // if a future rule's note itself contained "Fix:", a lastIndexOf-before-strip
  // would grab into the note and silently emit a corrupted cue.
  const cleaned = body.replace(/\s*\*\([^)]*\)\*\s*$/, '').trim();
  const i = cleaned.lastIndexOf('Fix:');
  if (i === -1) throw new Error('sync-plugin-guidance: rule body has no "Fix:" clause: ' + body.slice(0, 60));
  let fix = cleaned.slice(i + 'Fix:'.length).trim();
  fix = fix.replace(/\.$/, '').trim(); // drop a single trailing period (terse cue)
  if (fix.includes('\n') || fix.includes('|')) {
    // bodies are single-line and pipe-free today; guard so a future edit can't
    // silently break the markdown digest line.
    throw new Error('sync-plugin-guidance: fix cue contains a newline or pipe: ' + fix);
  }
  return fix;
}

// Rule tier (high|low) from the advisory meta — used to prioritize which cues stay
// inline when the full set would overflow the cap. Missing/unknown => low.
function loadTiers() {
  const metaPath = path.join(repoRoot, 'rules-meta.json');
  const rules = (JSON.parse(fs.readFileSync(metaPath, 'utf8')) || {}).rules || {};
  const t = {};
  for (const id of Object.keys(rules)) t[id] = rules[id].tier === 'high' ? 'high' : 'low';
  return t;
}

function render() {
  const md = fs.readFileSync(srcPath, 'utf8').replace(/\r\n/g, '\n');
  const rules = parseRules(md);
  const tiers = loadTiers();
  const head = [
    '<!-- GENERATED by cli/scripts/sync-plugin-guidance.js from claude-security-guidance.md — do not edit by hand. Regenerate: cd cli && npm run sync:plugin-guidance -->',
    '# Solana Security Standard — by Jelleo',
    '',
    '> Compact `SOL-0XX` rule cues for inline AI guidance. **Full per-rule detail** (impact, numbered exclusions, examples): the `list_solana_security_rules` MCP tool, or the complete `claude-security-guidance.md` at github.com/Copenhagen0x/solana-security-standard . Each rule has a stable ID — cite like a CWE.',
    '',
    preamble(md),
    '',
    '## Rules — flag the pattern, apply the fix, cite the SOL-0XX id',
    '',
  ];
  const cues = rules.map((r) => ({
    id: r.id,
    tier: tiers[r.id] || 'low',
    line: `- **${r.id}** · ${r.title} — ${extractFix(r.body)}`,
  }));

  // Fast path: if the entire set fits under the cap, emit every rule (no overflow).
  const full = head.concat(cues.map((c) => c.line), ['']).join('\n');
  if (Buffer.byteLength(full, 'utf8') <= MAX_BYTES) return full;

  // Scale path: SSS may grow to thousands of rules; the plugin file is hard-capped
  // by the consumer (Anthropic, 8192 B). So this digest is SCALE-INVARIANT — it
  // byte-budgets the cues (highest-tier first, then ascending id) and funnels the
  // remainder to ONE overflow pointer. The CLI scanner / Semgrep / Action / MCP /
  // master still carry 100% of the rules; only this inline cheat-sheet is bounded.
  const RESERVE = 330; // headroom reserved for the single overflow line
  let used = Buffer.byteLength(head.join('\n') + '\n', 'utf8');
  const keep = new Set();
  const fits = (c) => used + Buffer.byteLength(c.line + '\n', 'utf8') <= MAX_BYTES - RESERVE;
  const take = (c) => { keep.add(c.id); used += Buffer.byteLength(c.line + '\n', 'utf8'); };
  const byId = (a, b) => a.id.localeCompare(b.id);
  // High-tier cues get FIRST claim on the whole budget (ascending id within the tier);
  // low-tier cues are added ONLY if EVERY high-tier cue was kept. So a high-tier rule is
  // never dropped while a low-tier cue stays inline — the scale-invariant test. Two
  // passes (not one sorted prefix) so a single long high-tier cue can't strand shorter
  // high-tier cues behind it.
  const highCues = cues.filter((c) => c.tier === 'high').sort(byId);
  const lowCues = cues.filter((c) => c.tier !== 'high').sort(byId);
  let anyHighDropped = false;
  for (const c of highCues) { if (fits(c)) take(c); else anyHighDropped = true; }
  if (!anyHighDropped) for (const c of lowCues) { if (fits(c)) take(c); }
  const lines = [...head];
  let omitted = 0;
  for (const c of cues) {
    // cues is in master/id order — emit kept rules in that order for readability
    if (keep.has(c.id)) lines.push(c.line);
    else omitted += 1;
  }
  lines.push(
    `- *+ ${omitted} more rules — the CLI scanner, Semgrep, GitHub Action, and the \`list_solana_security_rules\` MCP tool enforce/serve the complete catalog; full per-rule detail in \`claude-security-guidance.md\` at github.com/Copenhagen0x/solana-security-standard.*`
  );
  lines.push('');
  return lines.join('\n');
}

if (require.main === module) {
  const content = render();
  const bytes = Buffer.byteLength(content, 'utf8');
  if (bytes > MAX_BYTES) {
    console.error(
      `plugin-guidance.md would be ${bytes} bytes, over the ${MAX_BYTES} cap. ` +
      'Tighten the digest line format (or the preamble) before adding more rules — ' +
      'see cli/scripts/sync-plugin-guidance.js.'
    );
    process.exit(1);
  }
  if (process.argv.includes('--check')) {
    const cur = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8').replace(/\r\n/g, '\n') : '';
    if (cur !== content) {
      console.error('plugin-guidance.md is out of sync with claude-security-guidance.md — run `npm run sync:plugin-guidance` (in cli/)');
      process.exit(1);
    }
    console.log(`plugin-guidance.md is in sync (${bytes}/${MAX_BYTES} bytes).`);
  } else {
    fs.writeFileSync(outPath, content); // content is LF-joined above
    console.log(`wrote plugin-guidance.md (${bytes}/${MAX_BYTES} bytes, ${render().split('\n').length} lines)`);
  }
}

module.exports = { render, parseRules, preamble, extractFix, MAX_BYTES };
