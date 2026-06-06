'use strict';
// Pure finding -> diagnostic mapping. Intentionally does NOT import `vscode`, so
// it is unit-testable with node:test. extension.js turns these plain descriptors
// into vscode.Diagnostic objects.

const path = require('path');

// Fail-soft engine load. The scanner core is vendored into ../engine at build time
// (engine/ is gitignored). If it is absent — a fresh source checkout before
// `npm run sync` — the `require`s below AND loadRules throw; we swallow all of it so
// the extension activates as a clean no-op instead of throwing at module load, which
// would take down the whole extension host. Packaged .vsix / CI always have engine/.
let scanner = null;
let solId = (s) => s;
let shortReminder = (s) => s;
let RULES = [];
try {
  scanner = require('../engine/scanner');
  ({ solId, shortReminder } = require('../engine/formatters'));
  RULES = scanner.loadRules(path.join(__dirname, '..', 'engine', 'rules.json'));
} catch {
  scanner = null;
  RULES = [];
}
const REPO = 'https://github.com/Copenhagen0x/solana-security-standard';

// A workspace-relative POSIX path so the rules' paths/exclude_paths globs
// (**/tests/**, **/client/**, ...) apply. Falls back to the basename when the
// file is outside the workspace (so an off-tree file still scans, just unscoped).
function relPosix(fileName, workspaceRoot) {
  let rel = workspaceRoot ? path.relative(workspaceRoot, fileName) : path.basename(fileName);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) rel = path.basename(fileName);
  return rel.split(path.sep).join('/');
}

// Returns plain 0-based diagnostic descriptors for a Rust document's text.
function computeDiagnostics(text, fileName, workspaceRoot, rules = RULES) {
  if (!scanner) return []; // engine not vendored -> no-op (see fail-soft load above)
  const rel = relPosix(fileName, workspaceRoot);
  const lines = text.split('\n');
  return scanner.scanContent(text, rel, rules).map((f) => {
    const line = Math.max(0, f.line - 1);
    const col = Math.max(0, f.column - 1);
    // Underline span. The scanner truncates a match >100 chars to `slice(0,100)+'…'`,
    // so f.match length is NOT a reliable end for long matches (and a multi-line match
    // should only underline its first line). Cap the end at the source line's length so
    // the squiggle is exact for short matches and never overruns the line otherwise.
    const lineLen = (lines[line] || '').replace(/\r$/, '').length;
    const m = f.match || '';
    // The scanner only ever yields a >100-char match field by truncating (to exactly
    // 101 chars), so length is a char-independent truncation test (a genuine match that
    // merely ends in '…' is kept whole at <=100 and stays exact).
    const truncated = m.length > 100;
    const nl = m.indexOf('\n'); // a newline inside the (kept) match -> match spans lines
    const rawEnd = nl !== -1 || truncated ? lineLen : col + m.length;
    const endCol = Math.min(Math.max(rawEnd, col + 1), Math.max(col + 1, lineLen));
    return {
      startLine: line,
      startCol: col,
      endLine: line,
      endCol,
      ruleId: solId(f.rule),
      message: `${solId(f.rule)}: ${shortReminder(f.reminder)}`,
      helpUri: `${REPO}#${solId(f.rule).toLowerCase()}`,
    };
  });
}

module.exports = { computeDiagnostics, relPosix, RULES, REPO };
