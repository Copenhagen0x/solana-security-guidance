'use strict';
// Vendor the (already-reviewed) scanner core + rules from ../../cli into ./engine
// so the packaged .vsix is self-contained. engine/ is gitignored and regenerated
// on `pretest` and `vscode:prepublish`. CI verifies it's in sync with cli/.
//   node scripts/sync-engine.js          regenerate engine/
//   node scripts/sync-engine.js --check   fail if engine/ is stale (CI)

const fs = require('fs');
const path = require('path');

const cliDir = path.join(__dirname, '..', '..', '..', 'cli'); // repo/extensions/vscode/scripts -> repo/cli
const engineDir = path.join(__dirname, '..', 'engine');

const FILES = [
  ['src/scanner.js', 'scanner.js'],
  ['src/glob.js', 'glob.js'],
  ['src/formatters.js', 'formatters.js'],
  ['rules.json', 'rules.json'],
];

const norm = (s) => s.replace(/\r\n/g, '\n');

function run() {
  const check = process.argv.includes('--check');
  if (!check) fs.mkdirSync(engineDir, { recursive: true });
  let stale = false;
  for (const [from, to] of FILES) {
    const src = norm(fs.readFileSync(path.join(cliDir, from), 'utf8'));
    const dst = path.join(engineDir, to);
    if (check) {
      const cur = fs.existsSync(dst) ? norm(fs.readFileSync(dst, 'utf8')) : '';
      if (cur !== src) { console.error(`engine/${to} is out of sync with cli/${from}`); stale = true; }
    } else {
      fs.writeFileSync(dst, src);
    }
  }
  if (check) {
    if (stale) { console.error('run `npm run sync` in extensions/vscode'); process.exit(1); }
    console.log('engine is in sync.');
  } else {
    console.log(`vendored ${FILES.length} files -> engine/`);
  }
}

run();
