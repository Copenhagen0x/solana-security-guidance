'use strict';
// CLI for the Solana Security Standard scanner.
//   solana-security-standard scan [paths...] [options]
//
// Zero runtime dependencies. Powers both terminal use and the GitHub Action.

const fs = require('fs');
const path = require('path');
const scanner = require('./scanner');
const formatters = require('./formatters');

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
  -q, --quiet                     text mode: print only the findings, no banner
      --no-color                  disable ANSI color
      --                          end of options; everything after is a path
  -v, --version                   print version
  -h, --help                      show this help

EXIT CODES
  0  no findings (or --no-fail)
  1  findings present
  2  usage / runtime error

Full rule catalog: https://github.com/Copenhagen0x/solana-security-guidance`;

function parseArgs(argv) {
  const o = {
    paths: [],
    format: 'text',
    output: null,
    patterns: DEFAULT_RULES,
    root: null,
    fail: true,
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
      case '--no-color': o.color = false; break;
      case '-f': case '--format': o.format = argv[++i]; break;
      case '-o': case '--output': o.output = argv[++i]; break;
      case '-p': case '--patterns': o.patterns = argv[++i]; break;
      case '-r': case '--root': o.root = argv[++i]; break;
      default:
        if (a === 'scan' && o.command === null) o.command = 'scan';
        else if (a.startsWith('-')) { o.unknown = a; }
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

  if (o.root) {
    const absRoot = path.resolve(o.root);
    for (const p of o.paths) {
      const r = path.relative(absRoot, path.resolve(p));
      if (r === '..' || r.startsWith('..' + path.sep) || r.startsWith('../') || path.isAbsolute(r)) {
        err.write(`warning: --root ${o.root} is not an ancestor of ${p}; reported paths will contain '..'\n`);
      }
    }
  }
  let findings = [];
  for (const p of o.paths) {
    if (!fs.existsSync(p)) { err.write(`error: path not found: ${p}\n`); return 2; }
    try {
      findings.push(...scanner.scan(p, rules, { root: o.root, onWarn: (m) => err.write(`warning: ${m}\n`) }));
    } catch (e) {
      err.write(`error: scanning ${p}: ${e.message}\n`);
      return 2;
    }
  }

  let rendered;
  const color = o.color === undefined ? Boolean(out.isTTY) : o.color;
  if (o.format === 'json') rendered = formatters.json(findings) + '\n';
  else if (o.format === 'sarif') rendered = formatters.sarif(findings, rules, { version: PKG.version }) + '\n';
  else rendered = formatters.text(findings, { color: o.quiet ? false : color });

  if (o.output) {
    try { fs.writeFileSync(o.output, rendered); }
    catch (e) { err.write(`error: cannot write ${o.output}: ${e.message}\n`); return 2; }
    if (!o.quiet) err.write(`Wrote ${findings.length} finding(s) to ${o.output}\n`);
  } else {
    out.write(rendered);
  }

  if (findings.length && o.fail) return 1;
  return 0;
}

module.exports = { main, parseArgs };
