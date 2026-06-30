'use strict';
// Publish guard: the MCP-registry manifest (server.json) must point at the version being
// published. If it lags package.json, `npm publish` ships the new code but every registry/npx
// install stays pinned to the OLD version until someone remembers to bump server.json. This runs
// in prepublishOnly so a mismatched publish fails loudly instead of drifting silently.
//
// Release order: bump package.json + server.json to the new version -> `npm publish` (this gate
// passes) -> `mcp-publisher publish` (registry now points at the just-published npm version).
const pkg = require('../package.json');
const srv = require('../server.json');

const want = pkg.version;
const seen = [srv.version, srv.packages && srv.packages[0] && srv.packages[0].version];

if (seen.some((v) => v !== want)) {
  console.error(
    `version-sync: server.json (${JSON.stringify(seen)}) != package.json (${want}). ` +
    'Bump server.json to match before publishing, then re-run `mcp-publisher publish` to update the registry.',
  );
  process.exit(1);
}
console.log(`version-sync OK: ${want}`);
