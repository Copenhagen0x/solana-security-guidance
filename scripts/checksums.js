'use strict';
// Generate / verify CHECKSUMS.txt — SHA-256 of the files users fetch directly over
// raw.githubusercontent (curl install + `semgrep --config`). Lets a consumer confirm
// the bytes they downloaded match what we published, instead of blindly trusting the
// fetch. Zero dependencies.
//
//   node scripts/checksums.js           regenerate CHECKSUMS.txt
//   node scripts/checksums.js --check    fail (exit 1) if CHECKSUMS.txt is stale (CI)
//
// After downloading the files + CHECKSUMS.txt, a consumer verifies with:
//   sha256sum -c CHECKSUMS.txt
//
// Hashes are taken over the LF-normalized bytes (the repo is `* text=auto eol=lf`, so
// raw.githubusercontent serves LF) — so a `curl`'d file on any OS matches.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const repoRoot = path.join(__dirname, '..');
const OUT = path.join(repoRoot, 'CHECKSUMS.txt');

// The files distributed over raw URLs (the install/config surface).
const FILES = [
  'claude-security-guidance.md',
  'security-patterns.yaml',
  'semgrep/solana-security-standard.yaml',
];

function sha256LF(rel) {
  const text = fs.readFileSync(path.join(repoRoot, rel), 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

function build() {
  const header =
    '# SHA-256 of the files served over raw.githubusercontent (curl install + `semgrep --config`).\n' +
    '# Verify a download:  sha256sum -c CHECKSUMS.txt   (run from the dir holding the files)\n' +
    '# Regenerate:         node scripts/checksums.js\n' +
    '# Hashes are over LF-normalized bytes (what GitHub serves).\n';
  const lines = FILES.map((f) => `${sha256LF(f)}  ${f}`);
  return header + lines.join('\n') + '\n';
}

if (require.main === module) {
  const out = build();
  if (process.argv.includes('--check')) {
    const norm = (s) => s.replace(/\r\n/g, '\n');
    const cur = fs.existsSync(OUT) ? norm(fs.readFileSync(OUT, 'utf8')) : '';
    if (cur !== norm(out)) {
      console.error('CHECKSUMS.txt is out of sync with the distributed files — run `node scripts/checksums.js`.');
      process.exit(1);
    }
    console.log('CHECKSUMS.txt is in sync.');
  } else {
    fs.writeFileSync(OUT, out);
    console.log(`wrote CHECKSUMS.txt (${FILES.length} files).`);
  }
}

module.exports = { build, sha256LF, FILES };
