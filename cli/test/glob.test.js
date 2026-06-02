'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { matchesGlob, matchesAny } = require('../src/glob');

test('**/*.rs matches .rs at any depth, not other extensions', () => {
  assert.ok(matchesGlob('a/b/c.rs', '**/*.rs'));
  assert.ok(matchesGlob('c.rs', '**/*.rs'));
  assert.ok(!matchesGlob('a/b.txt', '**/*.rs'));
  assert.ok(!matchesGlob('a/b.rs.bak', '**/*.rs'));
});

test('**/tests/** requires tests as a full path segment', () => {
  assert.ok(matchesGlob('a/tests/b.rs', '**/tests/**'));
  assert.ok(matchesGlob('tests/b.rs', '**/tests/**'));
  assert.ok(matchesGlob('a/b/tests/deep/c.rs', '**/tests/**'));
  assert.ok(!matchesGlob('a/b.rs', '**/tests/**'));
  assert.ok(!matchesGlob('a/testsx/b.rs', '**/tests/**'), 'must not match testsx/');
  assert.ok(!matchesGlob('a/mytests/b.rs', '**/tests/**'), 'must not match mytests/');
});

test('off-chain exclude globs', () => {
  for (const g of ['**/client/**', '**/cli/**', '**/offchain/**', '**/sdk/**']) {
    const seg = g.split('/')[1];
    assert.ok(matchesGlob(`app/${seg}/x.rs`, g), `${g} should match app/${seg}/x.rs`);
    assert.ok(matchesGlob(`${seg}/x.rs`, g), `${g} should match ${seg}/x.rs`);
    assert.ok(!matchesGlob('app/program/x.rs', g), `${g} should not match program code`);
  }
});

test('**/state*.rs and literal dots', () => {
  assert.ok(matchesGlob('src/state.rs', '**/state*.rs'));
  assert.ok(matchesGlob('src/v16/state_machine.rs', '**/state*.rs'));
  assert.ok(matchesGlob('state.rs', '**/state*.rs'));
  assert.ok(!matchesGlob('src/market.rs', '**/state*.rs'));
});

test('matchesAny', () => {
  assert.ok(matchesAny('a/tests/x.rs', ['**/foo/**', '**/tests/**']));
  assert.ok(!matchesAny('a/src/x.rs', ['**/foo/**', '**/tests/**']));
});
