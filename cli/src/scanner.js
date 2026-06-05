'use strict';
// Core scanner for the Solana Security Standard (SOL-0XX).
//
// Reads the deterministic per-edit rules (the same security-patterns.yaml the
// Claude Code plugin uses, pre-compiled to rules.json) and flags matches in
// Rust (on-chain) and TypeScript/JavaScript (integrator) source. Zero runtime
// dependencies — it powers the CLI, the GitHub
// Action, and (via the same module) the editor extensions.
//
// Matching is done against the FULL FILE CONTENT, not line-by-line, so a
// multi-line construct (e.g. a function signature split across lines) is still
// caught; the line/column is derived from the match offset.

const fs = require('fs');
const path = require('path');
const { matchesAny } = require('./glob');

// Hand-written Rust is tiny; anything larger is generated/vendored. Skip it so a
// huge file can't blow memory or run the regexes over megabytes.
const MAX_FILE_BYTES = 4 * 1024 * 1024;
// Backstop against a runaway / maliciously huge tree.
const MAX_FILES = 200_000;

const IGNORE_DIRS = new Set([
  '.git', 'node_modules', 'target', 'dist', 'build', '.next', '.svelte-kit',
  'out', 'coverage', '.cargo', '.venv', 'venv', '__pycache__',
]);

/** Compile a raw rule (from rules.json) into a fast-to-apply form. */
function compileRule(rule) {
  const c = {
    name: rule.rule_name || '?',
    reminder: rule.reminder || '',
    paths: rule.paths && rule.paths.length ? rule.paths : ['**/*'],
    exclude: rule.exclude_paths || [],
    regex: null,
    substrings: null,
    invalid: null,
  };
  if (rule.regex) {
    try {
      c.regex = new RegExp(rule.regex, 'g');
    } catch (e) {
      c.invalid = `invalid regex: ${e.message}`;
    }
  } else if (rule.substrings && rule.substrings.length) {
    c.substrings = rule.substrings.slice();
  } else {
    c.invalid = 'rule has neither regex nor substrings';
  }
  return c;
}

function compileRules(raw) {
  const patterns = (raw && raw.patterns) || [];
  return patterns.map(compileRule);
}

function loadRules(rulesPath) {
  return compileRules(JSON.parse(fs.readFileSync(rulesPath, 'utf8')));
}

/** Build an offset -> {line, column} locator for one file (1-based). */
function makeLocator(content) {
  const nl = [];
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) nl.push(i);
  return (offset) => {
    let lo = 0, hi = nl.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (nl[mid] < offset) lo = mid + 1; else hi = mid;
    }
    const lineStart = lo === 0 ? 0 : nl[lo - 1] + 1;
    return { line: lo + 1, column: offset - lineStart + 1 };
  };
}

/** Return every match offset for a compiled rule against `content`. */
function matchOffsets(content, rule) {
  const out = [];
  if (rule.regex) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(content)) !== null) {
      out.push({ index: m.index, text: m[0] });
      if (m.index === rule.regex.lastIndex) rule.regex.lastIndex++; // never loop on zero-width
    }
  } else if (rule.substrings) {
    for (const sub of rule.substrings) {
      if (!sub) continue;
      let idx = content.indexOf(sub);
      while (idx !== -1) {
        out.push({ index: idx, text: sub });
        idx = content.indexOf(sub, idx + sub.length);
      }
    }
  }
  return out;
}

/** Scan a single file's content. `relPath` is POSIX-relative to the scan root. */
function scanContent(content, relPath, rules) {
  let locate = null;
  const findings = [];
  for (const rule of rules) {
    if (rule.invalid) continue;
    if (!matchesAny(relPath, rule.paths)) continue;
    if (rule.exclude.length && matchesAny(relPath, rule.exclude)) continue;
    const hits = matchOffsets(content, rule);
    if (hits.length && !locate) locate = makeLocator(content);
    for (const h of hits) {
      const { line, column } = locate(h.index);
      findings.push({
        file: relPath,
        line,
        column,
        rule: rule.name,
        reminder: rule.reminder,
        match: h.text.length > 100 ? h.text.slice(0, 100) + '…' : h.text,
      });
    }
  }
  return findings;
}

// Iterative (explicit stack) so a pathologically deep tree can't blow the call
// stack; MAX_FILES backstops a runaway tree.
function walk(root, maxFiles) {
  const acc = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue; // don't follow symlinks (loop/escape safety)
      if (e.isDirectory()) {
        if (IGNORE_DIRS.has(e.name)) continue;
        stack.push(path.join(dir, e.name));
      } else if (e.isFile()) {
        acc.push(path.join(dir, e.name));
        if (acc.length >= maxFiles) return acc;
      }
    }
  }
  return acc;
}

function toPosixRel(baseDir, file) {
  return path.relative(baseDir, file).split(path.sep).join('/');
}

/**
 * Scan a file or directory.
 * @returns {file,line,column,rule,reminder,match}[]
 */
function scan(target, rules, opts = {}) {
  const st = fs.statSync(target);
  const baseDir = opts.root || (st.isDirectory() ? target : path.dirname(target));
  const maxFiles = opts.maxFiles || MAX_FILES;
  const files = st.isDirectory() ? walk(target, maxFiles) : [target];
  if (files.length >= maxFiles && typeof opts.onWarn === 'function') {
    try {
      opts.onWarn(`reached the ${maxFiles}-file scan limit under ${target}; some files were not scanned`);
    } catch { /* a broken stderr pipe must not abort the scan */ }
  }
  const findings = [];
  for (const file of files) {
    const rel = toPosixRel(baseDir, file);
    // Skip vendored/generated trees even if they appear in the relative path.
    if (rel.split('/').some((seg) => IGNORE_DIRS.has(seg))) continue;
    // Only read files some rule could match (avoids reading every binary).
    if (!rules.some((r) => !r.invalid && matchesAny(rel, r.paths))) continue;
    let content;
    try {
      if (fs.statSync(file).size > MAX_FILE_BYTES) continue; // skip oversized/generated files
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    findings.push(...scanContent(content, rel, rules));
  }
  findings.sort((a, b) =>
    a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || a.column - b.column,
  );
  return findings;
}

module.exports = {
  compileRule,
  compileRules,
  loadRules,
  makeLocator,
  matchOffsets,
  scanContent,
  scan,
  toPosixRel,
};
