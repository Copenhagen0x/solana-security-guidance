'use strict';
// CLI for the Solana Security Standard scanner.
//   solana-security-standard scan [paths...] [options]
//
// Zero runtime dependencies. Powers both terminal use and the GitHub Action.

const fs = require('fs');
const path = require('path');
const scanner = require('./scanner');
const formatters = require('./formatters');
const baseline = require('./baseline');

const PKG = require('../package.json');
const DEFAULT_RULES = path.join(__dirname, '..', 'rules.json');

const HELP = `solana-security-standard ${PKG.version}
Scan Solana/Rust code against the Solana Security Standard (SOL-0XX).

USAGE
  solana-security-standard scan [options] [--] [paths...]

OPTIONS
  -f, --format <text|json|sarif>  output format (default: text)
  -o, --output <file>             write to a file instead of stdout
  -p, --patterns <rules.json>     custom rules — TRUSTED files only (runs their regexes)
  -r, --root <dir>                base for reported paths — must be an ancestor of the paths
      --no-fail                   always exit 0 (report only; don't fail CI)
      --min-tier <high|low>       report only findings at/above this value tier.
                                  high = high-value only (drops LOW-tier hygiene/
                                  operational noise); low = everything (the default).
                                  A noise floor, NOT a verdict — not for audit-grade scans.
      --baseline <file>           report only findings NOT in this baseline (their
                                  count is always surfaced — suppression is never
                                  silent). An unreadable/invalid baseline exits 2;
                                  it never degrades to a baseline-less scan.
      --write-baseline <file>     record the scan's findings (after --min-tier,
                                  BEFORE --baseline filtering, so refreshing a
                                  baseline keeps prior acknowledgments) as a
                                  reviewable baseline file. Exit codes unchanged —
                                  pair with --no-fail for day-one adoption.
  -q, --quiet                     text mode: print only the findings, no banner
      --no-color                  disable ANSI color
      --                          end of options; everything after is a path
  -v, --version                   print version
  -h, --help                      show this help

EXIT CODES
  0  no findings (or --no-fail)
  1  findings present
  2  usage / runtime error, OR an INCOMPLETE scan (finding cap hit; results partial)

ENVIRONMENT
  SSS_MAX_FINDINGS  findings cap before a scan is flagged INCOMPLETE (default 100000)

Full rule catalog: https://github.com/Copenhagen0x/solana-security-standard`;

function parseArgs(argv) {
  const o = {
    paths: [],
    format: 'text',
    output: null,
    patterns: DEFAULT_RULES,
    root: null,
    fail: true,
    minTier: null,
    baseline: null,
    writeBaseline: null,
    quiet: false,
    color: undefined,
    help: false,
    version: false,
    command: null,
  };
  let positionalOnly = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (positionalOnly) { o.paths.push(a); continue; }
    switch (a) {
      case '--': positionalOnly = true; break; // end of options: rest are paths, never flags
      case '-h': case '--help': o.help = true; break;
      case '-v': case '--version': o.version = true; break;
      case '-q': case '--quiet': o.quiet = true; break;
      case '--no-fail': o.fail = false; break;
      case '--min-tier': o.minTier = argv[++i]; break;
      case '--baseline': o.baseline = argv[++i]; break;
      case '--write-baseline': o.writeBaseline = argv[++i]; break;
      case '--no-color': o.color = false; break;
      case '-f': case '--format': o.format = argv[++i]; break;
      case '-o': case '--output': o.output = argv[++i]; break;
      case '-p': case '--patterns': o.patterns = argv[++i]; break;
      case '-r': case '--root': o.root = argv[++i]; break;
      default:
        if (a === 'scan' && o.command === null) o.command = 'scan';
        else if (a.startsWith('-')) { if (!o.unknown) o.unknown = a; } // keep the FIRST unknown flag (don't let a later one mask it)
        else o.paths.push(a);
    }
  }
  if (!o.paths.length) o.paths = ['.'];
  return o;
}

function main(argv, io = {}) {
  const out = io.stdout || process.stdout;
  const err = io.stderr || process.stderr;
  const o = parseArgs(argv);

  if (o.version) { out.write(PKG.version + '\n'); return 0; }
  if (o.help || (!o.command && argv.length === 0)) { out.write(HELP + '\n'); return o.help ? 0 : 2; }
  if (o.unknown) { err.write(`error: unknown option ${o.unknown}\n`); return 2; }
  if (!['text', 'json', 'sarif'].includes(o.format)) {
    err.write(`error: unknown format '${o.format}' (text|json|sarif)\n`);
    return 2;
  }
  if (o.minTier && !['high', 'low'].includes(o.minTier)) {
    err.write(`error: unknown --min-tier '${o.minTier}' (high|low)\n`);
    return 2;
  }
  // A flag given without its file value (e.g. `--baseline` at end of argv) must be
  // a loud usage error, not a confusing downstream read/write failure.
  if (o.baseline !== null && !o.baseline) { err.write('error: --baseline requires a file path\n'); return 2; }
  if (o.writeBaseline !== null && !o.writeBaseline) { err.write('error: --write-baseline requires a file path\n'); return 2; }
  if (o.command && o.command !== 'scan') { err.write(`error: unknown command '${o.command}'\n`); return 2; }

  let rules;
  try {
    rules = scanner.loadRules(o.patterns);
  } catch (e) {
    err.write(`error: cannot load rules from ${o.patterns}: ${e.message}\n`);
    return 2;
  }
  const invalid = rules.filter((r) => r.invalid);
  if (invalid.length) {
    for (const r of invalid) err.write(`warning: skipping rule ${r.name}: ${r.invalid}\n`);
  }

  // Load the baseline BEFORE scanning: a malformed baseline is a hard usage error
  // (exit 2, fail-fast) — it must never degrade to a baseline-less scan that
  // suddenly reports (or gates on) everything the baseline was acknowledging.
  let base = null;
  if (o.baseline) {
    try {
      base = baseline.loadBaseline(o.baseline);
    } catch (e) {
      err.write(`error: ${e.message}\n`);
      return 2;
    }
  }

  if (o.root) {
    const absRoot = path.resolve(o.root);
    for (const p of o.paths) {
      const r = path.relative(absRoot, path.resolve(p));
      if (r === '..' || r.startsWith('..' + path.sep) || r.startsWith('../') || path.isAbsolute(r)) {
        err.write(`warning: --root ${o.root} is not an ancestor of ${p}; reported paths will contain '..'\n`);
      }
    }
  }
  // Validate every requested path exists before scanning anything.
  for (const p of o.paths) {
    if (!fs.existsSync(p)) { err.write(`error: path not found: ${p}\n`); return 2; }
  }
  // Drop a scan path nested inside another requested path (e.g. `scan . ./src`)
  // so a file in the overlap isn't scanned — and reported — twice. Deduping by
  // reported path doesn't work (the same file has a different rel path under each
  // scan root), so redundant roots are eliminated up front. Single-path scans
  // (the common case) are untouched.
  let scanPaths = o.paths;
  if (o.paths.length > 1) {
    const fold = (s) => (process.platform === 'win32' ? s.toLowerCase() : s); // win32 FS is case-insensitive
    const abs = o.paths.map((p) => ({ p, a: fold(path.resolve(p)) })).sort((x, y) => x.a.length - y.a.length);
    const kept = [];
    for (const cur of abs) {
      if (!kept.some((k) => cur.a === k.a || cur.a.startsWith(k.a + path.sep))) kept.push(cur);
    }
    scanPaths = kept.map((k) => k.p);
  }
  let findings = [];
  let truncated = false; // a finding-cap hit => the scan is INCOMPLETE
  for (const p of scanPaths) {
    try {
      // SSS_MAX_FINDINGS lets a power user raise/lower the incompleteness cap (a
      // non-finite/zero value falls back to the scanner's default inside scan()).
      const res = scanner.scan(p, rules, { root: o.root, maxFindings: Number(process.env.SSS_MAX_FINDINGS), onWarn: (m) => err.write(`warning: ${m}\n`) });
      if (res.truncated) truncated = true;
      for (const f of res) findings.push(f);
    } catch (e) {
      err.write(`error: scanning ${p}: ${e.message}\n`);
      return 2;
    }
  }

  // Value-tier floor (opt-in). Ranks: low < high. `--min-tier high` keeps only
  // HIGH-tier findings (drops LOW-tier hygiene/defense-in-depth/operational noise).
  // `--min-tier low` is the default floor — reports everything (so the flag has a
  // well-defined, non-surprising meaning for BOTH values). A finding with no tier
  // (e.g. a custom -p rules file) is ALWAYS kept — never silently hidden.
  if (o.minTier) {
    const RANK = { low: 0, high: 1 };
    const floor = RANK[o.minTier];
    findings = findings.filter((f) => (f.tier in RANK ? RANK[f.tier] : Infinity) >= floor);
  }

  // Record the baseline from the post-min-tier, PRE-suppression set: refreshing a
  // baseline (--baseline old --write-baseline new) must keep prior acknowledgments,
  // not just the still-new findings. Written before filtering for the same reason.
  if (o.writeBaseline) {
    // An INCOMPLETE scan must never become an authoritative-looking baseline: the
    // file would silently encode a partial picture every future scan gates against.
    if (truncated) {
      err.write('error: refusing to write a baseline from an INCOMPLETE scan (finding cap hit) — narrow the scan scope or raise SSS_MAX_FINDINGS\n');
      return 2;
    }
    let doc;
    try {
      doc = baseline.writeBaseline(o.writeBaseline, findings, { toolVersion: PKG.version });
    } catch (e) {
      err.write(`error: cannot write baseline ${o.writeBaseline}: ${e.message}\n`);
      return 2;
    }
    if (!o.quiet) err.write(`Wrote baseline with ${doc.findingCount} finding(s) to ${o.writeBaseline}\n`);
  }

  // Apply the baseline LAST, and keep the counts — every output format surfaces
  // how many findings the baseline removed (suppression is never silent) and how
  // many baseline entries matched nothing (stale — the baseline is rotting).
  let baseInfo = null;
  if (base) {
    const r = baseline.applyBaseline(findings, base);
    findings = r.kept;
    baseInfo = { suppressed: r.suppressed, stale: r.stale };
    if (r.stale > 0 && !o.quiet) {
      err.write(`warning: ${r.stale} baseline entr${r.stale === 1 ? 'y' : 'ies'} matched nothing (fixed or changed code) — consider refreshing with --write-baseline\n`);
    }
  }

  let rendered;
  const color = o.color === undefined ? Boolean(out.isTTY) : o.color;
  if (o.format === 'json') rendered = formatters.json(findings, { truncated, baseline: baseInfo }) + '\n';
  else if (o.format === 'sarif') rendered = formatters.sarif(findings, rules, { version: PKG.version, truncated, baseline: baseInfo }) + '\n';
  else rendered = formatters.text(findings, { color: o.quiet ? false : color, truncated, baseline: baseInfo });

  if (o.output) {
    try { fs.writeFileSync(o.output, rendered); }
    catch (e) { err.write(`error: cannot write ${o.output}: ${e.message}\n`); return 2; }
    if (!o.quiet) err.write(`Wrote ${findings.length} finding(s) to ${o.output}\n`);
  } else {
    out.write(rendered);
  }

  // An INCOMPLETE scan (finding cap hit) must never silently pass a gate — fail
  // it distinctly (exit 2) unless the user opted out of gating with --no-fail.
  if (truncated && o.fail) return 2;
  if (findings.length && o.fail) return 1;
  return 0;
}

module.exports = { main, parseArgs };
