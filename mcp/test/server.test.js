'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { spawn } = require('node:child_process');
const srv = require('../server');
const tools = require('../src/tools');

// --- tool unit tests ---

test('scan_solana_code flags SOL-001 on caller-controlled now_slot', () => {
  const out = tools.scanCode({ code: 'pub fn a(now_slot: u64){}', filename: 'src/lib.rs' });
  assert.match(out, /SOL-001/);
  assert.match(out, /src\/lib\.rs:1:/);
});

test('scan_solana_code on clean code reports no findings + an advisory note', () => {
  const out = tools.scanCode({ code: 'pub fn ok() -> u64 { 7 }\n', filename: 'src/lib.rs' });
  assert.match(out, /No SOL-0XX findings/);
  assert.match(out, /NOT a/);
});

test('scan_solana_code honors off-chain excludes via filename', () => {
  const code = 'pub fn a(now_slot: u64){}';
  assert.match(tools.scanCode({ code, filename: 'src/x.rs' }), /SOL-001/);
  assert.match(tools.scanCode({ code, filename: 'tests/x.rs' }), /No SOL-0XX findings/);
});

test('scan_solana_code rejects a missing/invalid code arg', () => {
  assert.throws(() => tools.scanCode({}), /requires a "code" string/);
  assert.throws(() => tools.scanCode({ code: 42 }), /requires a "code" string/);
});

test('list_solana_security_rules returns the full guidance (all 28 rules + threat model)', () => {
  const g = tools.listRules();
  for (let i = 1; i <= 28; i++) assert.ok(g.includes('SOL-0' + String(i).padStart(2, '0')), 'missing SOL-0' + i);
  assert.match(g, /Threat model/);
});

// --- protocol (respond) tests ---

test('initialize returns protocolVersion + serverInfo + tools capability', () => {
  const r = srv.respond({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(r.result.protocolVersion, srv.PROTOCOL_VERSION);
  assert.deepEqual(r.result.serverInfo, srv.SERVER_INFO);
  assert.ok(r.result.capabilities.tools);
});

test('tools/list returns both tools with object input schemas', () => {
  const r = srv.respond({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const names = r.result.tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['list_solana_security_rules', 'scan_solana_code']);
  for (const t of r.result.tools) assert.equal(t.inputSchema.type, 'object');
});

test('tools/call wraps a tool result in MCP text content', () => {
  const r = srv.respond({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'scan_solana_code', arguments: { code: 'pub fn a(now_slot: u64){}' } } });
  assert.equal(r.result.content[0].type, 'text');
  assert.match(r.result.content[0].text, /SOL-001/);
  assert.ok(!r.result.isError);
});

test('tools/call on a bad arg returns isError content (not a JSON-RPC error)', () => {
  const r = srv.respond({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'scan_solana_code', arguments: {} } });
  assert.ok(r.result.isError);
  assert.match(r.result.content[0].text, /Error:/);
  assert.ok(!r.error, 'tool failures are results, not protocol errors');
});

test('tools/call on an unknown tool returns isError', () => {
  const r = srv.respond({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'nope' } });
  assert.ok(r.result.isError);
  assert.match(r.result.content[0].text, /Unknown tool/);
});

test('a notification (no id) gets no response', () => {
  assert.equal(srv.respond({ jsonrpc: '2.0', method: 'notifications/initialized' }), undefined);
});

test('an unknown request method returns method-not-found (-32601)', () => {
  const r = srv.respond({ jsonrpc: '2.0', id: 6, method: 'frobnicate' });
  assert.equal(r.error.code, -32601);
});

test('non-JSON-RPC / malformed input is ignored, not crashed on', () => {
  assert.equal(srv.respond({ foo: 'bar' }), undefined);
  assert.equal(srv.respond(null), undefined);
  assert.equal(srv.respond({ jsonrpc: '2.0' }), undefined);
});

// --- guards added after adversarial review ---

test('scan_solana_code rejects oversized input (snippet cap, not the 4MB file cap)', () => {
  assert.throws(() => tools.scanCode({ code: 'x'.repeat(tools.MAX_CODE + 1) }), /snippet limit/);
  assert.doesNotThrow(() => tools.scanCode({ code: 'x'.repeat(1024) }));
});

test('scan_solana_code normalizes odd filenames so a scan is never silently a no-op', () => {
  const code = 'pub fn a(now_slot: u64){}'; // SOL-001
  for (const filename of ['untitled', 'code.txt', '/Users/x/p/src/lib.rs', 'C:/x/lib.rs', 'Lib.RS', '..', '']) {
    assert.match(tools.scanCode({ code, filename }), /SOL-001/, `still flags with filename "${filename}"`);
  }
  // a genuine test path stays excluded (intentional), and the clean result explains why
  const t = tools.scanCode({ code, filename: 'crate/tests/x.rs' });
  assert.match(t, /No SOL-0XX findings/);
  assert.match(t, /test path/);
});

test('normalizeName yields a glob-matchable lowercase-.rs relative path', () => {
  assert.equal(tools.normalizeName('lib.rs'), 'lib.rs');
  assert.equal(tools.normalizeName('Lib.RS'), 'Lib.rs'); // lowercase the ext (the **/*.rs glob is case-sensitive), NOT Lib.RS.rs
  assert.equal(tools.normalizeName('code.txt'), 'code.txt.rs'); // append so the scan fires
  assert.equal(tools.normalizeName('untitled'), 'untitled.rs');
  assert.equal(tools.normalizeName('/Users/x/src/lib.rs'), 'Users/x/src/lib.rs'); // leading slash stripped
  assert.equal(tools.normalizeName('C:/x/lib.rs'), 'x/lib.rs'); // drive + slash stripped
  assert.equal(tools.normalizeName('..'), 'input.rs'); // all-dots -> sane default
  assert.equal(tools.normalizeName(''), 'input.rs');
});

test('a notification-shaped message (no id) never gets a reply, for any method', () => {
  for (const method of ['initialize', 'ping', 'tools/list', 'tools/call', 'notifications/initialized']) {
    const r = srv.respond({ jsonrpc: '2.0', method, params: { name: 'scan_solana_code', arguments: { code: '' } } });
    assert.equal(r, undefined, `no reply for notification ${method}`);
  }
});

// --- end-to-end stdio integration (real subprocess) ---

function spawnServer() {
  const proc = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], { stdio: ['pipe', 'pipe', 'inherit'] });
  proc.stdin.on('error', () => {}); // swallow EPIPE if the child exits early
  return proc;
}

test('end-to-end: a real stdio process answers initialize + tools/call', async () => {
  const proc = spawnServer();
  let timer;
  const got = new Promise((resolve, reject) => {
    let buf = '';
    proc.stdout.on('data', (d) => {
      buf += d;
      const parts = buf.split('\n');
      const complete = (buf.endsWith('\n') ? parts : parts.slice(0, -1)).filter(Boolean); // only fully-received lines
      if (complete.length >= 2) {
        try { resolve(complete.slice(0, 2).map((l) => JSON.parse(l))); } catch (e) { reject(e); }
      }
    });
    proc.on('error', reject);
    timer = setTimeout(() => reject(new Error('e2e timeout')), 5000);
    timer.unref(); // don't hold the event loop open for 5s after the test resolves
  });
  proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');
  proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'scan_solana_code', arguments: { code: 'pub fn a(now_slot: u64){}' } } }) + '\n');
  try {
    const [init, call] = await got;
    assert.equal(init.result.serverInfo.name, 'solana-security-standard');
    assert.match(call.result.content[0].text, /SOL-001/);
  } finally {
    clearTimeout(timer);
    proc.kill();
  }
});

test('end-to-end: a JSON-RPC batch yields an array of responses (notifications dropped)', async () => {
  const proc = spawnServer();
  let timer;
  const got = new Promise((resolve, reject) => {
    let buf = '';
    proc.stdout.on('data', (d) => {
      buf += d;
      if (buf.includes('\n')) {
        try { resolve(JSON.parse(buf.slice(0, buf.indexOf('\n')))); } catch (e) { reject(e); }
      }
    });
    proc.on('error', reject);
    timer = setTimeout(() => reject(new Error('batch timeout')), 5000);
    timer.unref();
  });
  proc.stdin.write(JSON.stringify([
    { jsonrpc: '2.0', id: 1, method: 'ping' },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  ]) + '\n');
  try {
    const batch = await got;
    assert.ok(Array.isArray(batch), 'batch response is an array');
    assert.equal(batch.length, 2, 'two replies; the notification is dropped');
    assert.deepEqual(batch.map((r) => r.id).sort(), [1, 2]);
  } finally {
    clearTimeout(timer);
    proc.kill();
  }
});
