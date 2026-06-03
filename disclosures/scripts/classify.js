'use strict';
// Classify a Solana security disclosure against the Solana Security Standard (SOL-0XX).
// Heuristic, keyword-signature based: it SUGGESTS the rule class(es) a disclosure falls under so a
// human can triage it into the Hacks Database — it does NOT auto-label. Zero dependencies.
//
// Signatures are lowercase substrings indicative of each rule's bug class, derived from the rule
// definitions in claude-security-guidance.md. A rule's score = how many DISTINCT signatures it hits.

// SOL-0XX -> indicative lowercase terms (substring match on the lowercased disclosure text).
const SIGNATURES = {
  'SOL-001': ['now_slot', 'caller-controlled clock', 'caller-supplied slot', 'clock::get', 'unauthenticated slot', 'slot from instruction'],
  'SOL-002': ['cross-market', 'cross market', 'shared pool', 'insurance fund', 'aggregate counter', 'per-market'],
  'SOL-003': ['wrapper re-implement', 'wrapper reimplement', 'reimplements the engine', 'duplicated engine logic', 'wrapper handler'],
  'SOL-004': ['margin', 'health factor', 'collateral factor', 'liquidation threshold', 'under-collateralized', 'undercollateralized', 'risk math', 'missing term'],
  'SOL-005': ['realloc', 'reallocate account', 'resize account', 'account resize'],
  'SOL-006': ['missing signer', 'is_signer', 'no signer check', 'unauthenticated caller', 'privileged handler', 'without authorization', 'signer<'],
  'SOL-007': ['owner check', 'owner ==', 'owner verification', 'owner not verified', 'not verified', 'account owner', 'fake', 'fabricated', 'forged', 'spoofed account', 'attacker-supplied account', 'attacker-controlled account', 'type cosplay', 'account confusion', 'same-layout account', 'arbitrary account', 'unvalidated account', 'never validated', 'without verifying'],
  'SOL-008': ['find_program_address', 'unverified pda', 'pda validation', 'derive the pda', 'wrong pda', 'arbitrary pda'],
  'SOL-009': ['invoke_signed', 'cpi without', 'cross-program invocation', 'cpi authority', 'unauthorized cpi'],
  'SOL-010': ['init_if_needed', 'reinit', 're-initialize', 'reinitialization', 'reinitialize'],
  'SOL-011': ['account close', 'close =', 'close attribute', 'lamport drain via close', 'residual data', 'not fully drained'],
  'SOL-012': ['rent exemption', 'rent-exempt', 'not rent exempt', 'account purge', 'garbage collected'],
  'SOL-013': ['token-2022', 'token 2022', 'token program id', 'spl token program', 'wrong token program'],
  'SOL-014': ['overflow', 'underflow', 'checked_add', 'checked_sub', 'checked arithmetic', 'integer overflow', 'arithmetic overflow', 'wrapping'],
  'SOL-015': ['has_one', 'anchor constraint', 'missing constraint', 'constraint =', 'unconstrained account', 'no constraint linking'],
  'SOL-016': ['bump seed', 'canonical bump', 'non-canonical bump', 'stored bump', 'unvalidated bump'],
  'SOL-017': ['transmute', 'raw deserialize', 'unsafe cast', 'bytemuck', 'reinterpret cast', 'data.borrow'],
  'SOL-018': ['system program id', 'hardcoded system program', '11111111111111111111111111111111'],
  'SOL-019': ['discriminator', 'try_deserialize_unchecked', 'account discriminator', 'missing discriminator', '8-byte discriminator'],
  'SOL-020': ['setauthority', 'set_authority', 'ownership hijack', 'authority transfer', 'change authority'],
  'SOL-021': ['terminal state', 'close path', 'resolve path', 'funds locked', 'permanently locked', 'cannot be closed', 'stuck forever', 'live-only condition'],
  'SOL-022': ['impaired counter', 'write-only counter', 'encumbered forever', 'never decremented', 'never released', 'degraded bucket'],
  'SOL-023': ['rounds toward the user', 'fee rounding', 'rounds down', 'integer division', 'div_ceil', 'dust rounding', 'rounding error'],
  'SOL-024': ['oracle', 'pyth', 'switchboard', 'price feed', 'stale price', 'confidence interval', 'price manipulation', 'manipulated price', 'manipulate the price', 'price oracle', 'spot price', 'mispriced', 'flash loan', 'flash-loan', 'bonding curve', 'bonding-curve', 'manipulation-resistance', 'manipulation resistance', 'time-weighted', 'twap'],
  'SOL-025': ['sysvar', 'clock sysvar', 'rent sysvar', 'instructions sysvar', 'look-alike account', 'bincode::deserialize', 'sysvar account'],
  'SOL-026': ['duplicate mutable', 'duplicate account', 'same account twice', 'account aliasing', 'require_keys_neq', 'passed the same account'],
  'SOL-027': ['remaining_accounts', 'remaining accounts', 'unvalidated accounts', 'attacker-controlled account list'],
  'SOL-028': ['slippage', 'min-out', 'min_out', 'minimum output', 'sandwich', 'max-in', 'no output bound', 'adverse price'],
};

// Terms that indicate a loss that NO on-chain code rule prevents (key/opsec/off-chain).
const NOT_CODE_TERMS = [
  'private key', 'seed phrase', 'mnemonic', 'compromised key', 'stolen key', 'key compromise',
  'leaked key', 'insider', 'former employee', 'rogue employee', 'social engineering', 'phishing',
  'rug pull', 'exit scam', 'dns hijack', 'frontend compromise', 'front-end compromise',
  'session token', 'api key leak', 'multisig compromise', 'wallet drainer',
];

function matchedTerms(text, terms) {
  const t = String(text || '').toLowerCase();
  return terms.filter((term) => t.includes(term));
}

// Returns ranked suggestions: [{ rule, score, hits: [terms] }], score>0, best first.
function classify(text) {
  const out = [];
  for (const rule of Object.keys(SIGNATURES)) {
    const hits = matchedTerms(text, SIGNATURES[rule]);
    if (hits.length) out.push({ rule, score: hits.length, hits });
  }
  out.sort((a, b) => b.score - a.score || (a.rule < b.rule ? -1 : 1));
  return out;
}

// Heuristic guess: is the root cause something an on-chain code rule can prevent? (A human confirms;
// this is only a conservative default.) Rules, in order:
//   1. ANY key/opsec/off-chain term present -> false. These are definitionally not code-preventable;
//      a key compromise that also used a flash loan is still a key compromise (hard veto — so a
//      strong code keyword can never flip a stolen-key incident to "code-preventable").
//   2. else, true only if there is an actual code signal. No signal at all -> false (unknown is not
//      a claim of code-preventability), which also keeps the candidate self-consistent
//      (code_preventable=false <-> empty sol_rules, the Hacks-DB honesty invariant).
function codePreventableGuess(text) {
  const offChainTerms = matchedTerms(text, NOT_CODE_TERMS);
  if (offChainTerms.length) return { guess: false, offChainTerms };
  return { guess: classify(text).length > 0, offChainTerms };
}

module.exports = { SIGNATURES, NOT_CODE_TERMS, classify, codePreventableGuess, matchedTerms };
