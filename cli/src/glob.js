'use strict';
// Minimal glob matcher for the path filters in security-patterns.yaml.
// Supports exactly the subset those filters use:
//   **  -> any run of path segments (including across `/`, or none)
//   *   -> any run of chars except `/`
//   literals (incl. `.`) are matched exactly.
// It is intentionally NOT a full glob (no {a,b}, no [a-z], no ?). Paths are
// matched as POSIX-style (forward-slash) strings relative to the scan root.

const _cache = new Map();

function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        // `**` — consume it; if followed by `/`, the whole `**/` is an
        // OPTIONAL prefix of any depth (so `**/x` also matches bare `x`).
        i++;
        if (glob[i + 1] === '/') {
          i++;
          re += '(?:[^/]+/)*';
        } else {
          re += '.*';
        }
      } else {
        re += '[^/]*';
      }
    } else if ('\\^$.|?+()[]{}'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  // Case-INSENSITIVE: a `Tests/` dir must still match `**/tests/**` and a `Lib.RS` file must still
  // match `**/*.rs`. Path globs describe dir/file *names*, which users case differently; matching
  // case-sensitively let `Tests/` bypass the test exclude (scanned as on-chain) and `Lib.RS` bypass
  // the include (silently unscanned). The patterns here are ASCII, so the `i` flag is sufficient.
  return new RegExp('^' + re + '$', 'i');
}

function compiled(glob) {
  let r = _cache.get(glob);
  if (!r) {
    r = globToRegExp(glob);
    _cache.set(glob, r);
  }
  return r;
}

function matchesGlob(path, glob) {
  return compiled(glob).test(path);
}

function matchesAny(path, globs) {
  for (const g of globs) if (compiled(g).test(path)) return true;
  return false;
}

module.exports = { globToRegExp, matchesGlob, matchesAny };
