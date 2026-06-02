'use strict';
// Regenerate cli/rules.json from the source-of-truth ../../security-patterns.yaml.
//
// The YAML stays the single source the Claude Code plugin consumes; rules.json
// is the pre-parsed form the zero-dependency scanner reads at runtime (so the
// CLI / Action never need a YAML parser). Run: `npm run sync` (needs the
// js-yaml devDependency). CI verifies rules.json is in sync with the YAML.

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const repoRoot = path.join(__dirname, '..', '..');
const srcYaml = path.join(repoRoot, 'security-patterns.yaml');
const dstJson = path.join(__dirname, '..', 'rules.json');

function build() {
  // js-yaml's load() is safe by default — it has no code-executing tags like
  // PyYAML's !!python/object. CORE_SCHEMA makes that explicit and rejects any
  // custom/typed tags, so only plain maps/lists/scalars are accepted.
  const doc = yaml.load(fs.readFileSync(srcYaml, 'utf8'), { schema: yaml.CORE_SCHEMA });
  const patterns = (doc && doc.patterns) || [];
  return {
    patterns: patterns.map((p) => {
      const r = { rule_name: p.rule_name };
      if (p.regex) r.regex = p.regex;
      if (p.substrings) r.substrings = p.substrings;
      if (p.paths) r.paths = p.paths;
      if (p.exclude_paths) r.exclude_paths = p.exclude_paths;
      if (p.reminder) r.reminder = p.reminder;
      return r;
    }),
  };
}

function serialize(obj) {
  return JSON.stringify(obj, null, 2) + '\n';
}

if (require.main === module) {
  const data = build();
  const out = serialize(data);
  // --check: fail (exit 1) if rules.json is stale, without writing (for CI).
  if (process.argv.includes('--check')) {
    // Compare line-ending-agnostically: a Windows checkout may have CRLF on disk
    // while `out` is generated with LF — identical content, different bytes.
    const norm = (s) => s.replace(/\r\n/g, '\n');
    const current = fs.existsSync(dstJson) ? norm(fs.readFileSync(dstJson, 'utf8')) : '';
    if (current !== norm(out)) {
      console.error('rules.json is out of sync with security-patterns.yaml — run `npm run sync`.');
      process.exit(1);
    }
    console.log('rules.json is in sync.');
  } else {
    fs.writeFileSync(dstJson, out);
    console.log(`synced ${data.patterns.length} rules -> ${path.relative(repoRoot, dstJson)}`);
  }
}

module.exports = { build, serialize };
