'use strict';
// Vendor the (already-reviewed) scanner core + rules + guidance into ./engine so the
// published MCP package is self-contained. engine/ is gitignored and regenerated on
// `pretest` / `prepublishOnly`; CI verifies it is in sync with cli/ + the guidance.
//   node scripts/sync-engine.js           regenerate engine/
//   node scripts/sync-engine.js --check    fail (exit 1) if engine/ is stale (CI)

const fs = require('fs');
const path = require('path');

const cliDir = path.join(__dirname, '..', '..', 'cli'); // repo/mcp/scripts -> repo/cli
const repoRoot = path.join(__dirname, '..', '..'); // repo/
const engineDir = path.join(__dirname, '..', 'engine');

// [absolute source, engine-relative dest]
const FILES = [
  [path.join(cliDir, 'src', 'scanner.js'), 'scanner.js'],
  [path.join(cliDir, 'src', 'glob.js'), 'glob.js'],
  [path.join(cliDir, 'src', 'formatters.js'), 'formatters.js'],
  [path.join(cliDir, 'rules.json'), 'rules.json'],
  [path.join(repoRoot, 'claude-security-guidance.md'), 'guidance.md'],
];

const norm = (s) => s.replace(/\r\n/g, '\n'); // compare line-ending-agnostically

if (require.main === module) {
  const check = process.argv.includes('--check');
  let stale = [];
  if (!check) fs.mkdirSync(engineDir, { recursive: true });
  for (const [src, dst] of FILES) {
    const content = fs.readFileSync(src, 'utf8');
    const target = path.join(engineDir, dst);
    if (check) {
      const cur = fs.existsSync(target) ? norm(fs.readFileSync(target, 'utf8')) : '';
      if (cur !== norm(content)) stale.push(dst);
    } else {
      fs.writeFileSync(target, norm(content)); // normalize to LF so the vendored copy is stable across OSes
    }
  }
  if (check) {
    if (stale.length) {
      console.error('mcp/engine is out of sync with cli/ + guidance - run `npm run sync`:\n  ' + stale.join('\n  '));
      process.exit(1);
    }
    console.log('mcp engine is in sync.');
  } else {
    console.log(`vendored ${FILES.length} files -> engine/`);
  }
}

module.exports = { FILES };
