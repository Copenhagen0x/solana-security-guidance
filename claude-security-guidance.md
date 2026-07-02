# Solana Security Standard — by Jelleo

> `SOL-0XX` rules from real audits + 2 bounty wins. Catalog → github.com/Copenhagen0x/solana-security-standard · jelleo.com

Each rule has a stable ID (`SOL-0XX`) — cite like a CWE.

## Threat model

Assume every caller is hostile until cryptographically proven otherwise. Dominant classes: trust-boundary breaks (instruction data → trusted state), authority confusion (signer/PDA/owner), state integrity (cross-market leaks), time & lifecycle (caller clocks, terminal guards), value accounting (decimals, lamports, post-CPI staleness), oracle trust (stale prices), Anchor gaps (constraints, `init_if_needed`, bump). Integrator layer (SOL-029-031): off-chain TS/JS tx code (preflight, fees, stale routes), flagged on `.ts`/`.js`.

## Review checklist

Critical first: SOL-001, 003, 004, 021, 023, 024, 015, 006/007, 014, 019, 032, 033, 034 (titles below).

## Rules

### SOL-001 · Unauthenticated now_slot
Caller-controlled clock into state (pass `u64::MAX`, real cranks then reject as stale → permanent DoS). Fix: authenticate against `Clock::get()?.slot`. *(2 confirmed wins: prog#107, cli#78 F33)*

### SOL-002 · Cross-market state asymmetry
Counter written by one market and read by another with no per-market scoping → permissionless cross-market inflation drains a shared pool. Fix: gate every write by per-market authorization.

### SOL-003 · Wrapper re-implements engine
Wrapper redoes engine logic (close/settle/accrue), drifts, skips side-effects. Fix: delegate to the engine; the wrapper only marshals accounts.

### SOL-004 · Penalty/health terms omitted
Risk/margin math drops a spec-mandated term → under-collateralized positions allowed. Fix: include every term the spec lists.

### SOL-005 · Anchor resize without checks
`realloc()` with no owner / size-bound / rent-exemption guard. Fix: verify all three before resizing.

### SOL-006 · Missing signer check
Privileged handler mutates state without verifying the signer. Fix: `Signer<>`, or check `is_signer`.

### SOL-007 · Missing owner verification
`AccountInfo` deserialized without `owner == program_id` → attacker passes a same-layout account from another program. Fix: check owner first.

### SOL-008 · Unverified PDA
PDA used without `find_program_address` validation → attacker passes any account as the PDA. Fix: derive and compare.

### SOL-009 · CPI without authority check
`invoke_signed` without verifying the caller's authority (signing with a PDA ≠ authorization). Fix: check authority before the CPI.

### SOL-010 · Reinit attack
A reinitialization that overwrites a live account — matched on the PROPERTY, not one idiom. Two forms: (1) Anchor `init_if_needed` on an account holding value/authority → a 2nd call reinits, dropping balances (and the same footgun enables nullifier/spent-marker double-spend: an `init_if_needed` nullifier PDA that doesn't abort on a pre-existing entry, or a spent-marker checked AFTER the transfer, lets one note redeem twice); (2) a hand-rolled reinit — a raw `.data.borrow_mut()` / `try_borrow_mut_data()` write of the account header with no `#[account(zero)]` / discriminator / `is_initialized` guard, so a caller re-inits a live account and overwrites its stored authority (the Metaplex Candy Machine v1 config-drain). `owner == program_id` proves ownership, NOT freshness. Fix: reject a re-init before the write (check discriminator).

### SOL-011 · Lamport drain via close
`close =` on an account not fully drained, or a close that doesn't zero data (residual reads). Fix: drain + zero + controlled destination.

### SOL-012 · Rent exemption check missing
Funded account not verified rent-exempt → runtime purges it, state lost. Fix: assert rent-exempt.

### SOL-013 · Token Program ID confusion
Hardcoded SPL Token ID but the account is Token-2022 (or vice versa). Fix: `anchor_spl::token::ID` via typed accounts.

### SOL-014 · Unchecked integer arithmetic
`+ - *` on ints without `checked_*` → release builds wrap silently, and the wrap IS the bug. Fix: `a.checked_add(b).ok_or(Overflow)?`.

### SOL-015 · Anchor constraints missing
`Account<'info, T>` cross-references another account with no `has_one =` / `constraint =`. Fix: tie related accounts together with constraints.

### SOL-016 · Bump seed unvalidated
A stored `.bump` used without a canonical check → PDA substitution. `bump = x.bump` reuse is safe ONLY IF that account's bump was set at init by bare `bump`/`ctx.bumps`, never caller-supplied `#[instruction(bump)]` or a `create_program_address` bump. Fix: bare `bump` / `find_program_address`.

### SOL-017 · Raw AccountInfo without typed deserialize
Data buffer cast to a struct with no deserialize-then-validate (`&*account.data.borrow()`, `transmute`). Fix: typed deserialize + length/field checks.

### SOL-018 · Hardcoded System Program ID
`"111…"` literal instead of the imported constant. Fix: `solana_program::system_program::ID`.

### SOL-019 · Missing discriminator check
Deserialize without the 8-byte Anchor discriminator (`try_deserialize_unchecked`) → wrong-type account (same length) accepted. Fix: `try_deserialize`.

### SOL-020 · SetAuthority without verification
`SetAuthority` without checking the current authority matches the expected key → ownership hijack. Fix: verify current authority first.

### SOL-021 · Terminal op gated on a live-only condition
A close/resolve reuses a guard (`status==Fresh`, `expiry>now`) that can't hold once status is **terminal** → reverts forever, funds lock. Fix: a terminal release that ignores freshness/expiry.

### SOL-022 · Write-only "impaired" counter
A counter bumped when state degrades (valid→impaired), never decremented → funds encumbered forever, slot never reusable. Fix: add the inverse settlement.

### SOL-023 · Fee/penalty rounds toward the user
Fee/penalty uses integer `/` (rounds down) → user underpays, dust → 0 (evasion + leakage). Fix: `div_ceil` what the user **owes** — round against the less-trusted party (fee UP, payout DOWN).

### SOL-024 · Stale / unchecked oracle price
A Pyth/Switchboard price with no staleness or confidence check → attacker trades/liquidates at a mispriced value. Fix: `get_price_no_older_than(...)`; reject wide-confidence.

### SOL-025 · Sysvar read by raw deserialize
A sysvar (Clock/Rent) read by **raw-deserializing** account data (`bincode::deserialize::<Clock>`) instead of `Clock::get()` / `Sysvar::from_account_info` (which key-check) → attacker passes a look-alike. Fix: `Clock::get()` / Anchor `Sysvar<>`.

### SOL-026 · Duplicate mutable account (native programs)
Two accounts that must differ aren't checked → attacker passes one twice, collapsing a delta check. Fix: `require_keys_neq!`. *(Anchor catches dupe `Account<>` only; NOT `AccountLoader`/`UncheckedAccount`/remaining_accounts.)*

### SOL-027 · Unvalidated remaining_accounts
`ctx.remaining_accounts` read/written/invoked without checking each one's owner/key/signer — attacker-controlled. Fix: validate every account like a declared one.

### SOL-028 · Missing slippage / min-out bound
A swap/withdraw/settle derives an output with no caller min-out/max-in → adverse-move/sandwich exposure. Fix: take + enforce a caller bound.

### SOL-029 · Preflight simulation disabled
`skipPreflight: true` (or no `simulateTransaction`) before a mainnet send → reverts are paid, not caught; a live bot desyncs. Fix: keep preflight on, or simulate + assert `err === null`.

### SOL-030 · Static priority fee
Hardcoded `microLamports` priority fee → underpays in congestion or overpays when idle. Fix: derive from `getRecentPrioritizationFees()` and clamp.

### SOL-031 · Stale Jupiter quote
Jupiter quote swapped without a `contextSlot` freshness check → stale route = worse fill + sandwich/MEV. Fix: refetch/reject when `contextSlot` lags the current slot.

### SOL-032 · Decimals assumed, not read
Amount math hardcodes a scale (`1_000_000`, `10u64.pow(9)`) instead of reading `mint.decimals` → a 6-vs-9 mint misprices 1000×. Fix: read `mint.decimals`; normalize first.

### SOL-033 · Stale account read after CPI
An account field read after a CPI that can mutate it (or cached from before) → decisions on stale balance/authority. Fix: `reload()` / re-read after the CPI.

### SOL-034 · Manual lamport mutation
Direct lamport writes (`try_borrow_mut_lamports`) without the matching debit/credit → funds conjured/burned vs program accounting. Fix: mutate both sides; assert conservation.

### SOL-035 · Instructions sysvar substitution
Instruction introspection (`load_instruction_at_checked`, `load_current_index_checked`) to confirm a precompile (Ed25519/Secp256k1) signature — on an instructions sysvar passed as a raw `AccountInfo` whose key is never pinned, OR trusting that a precompile ran without checking WHAT it verified → attacker forges the sysvar, or includes a real precompile ix over their own pubkey/message, and spoofs the check. Fix: pin the sysvar (Anchor `Sysvar<Instructions>`, or assert `key == sysvar::instructions::ID`) AND validate the introspected instruction's program id plus its parsed signer pubkey and message against the expected values — confirming only that "a precompile ran" is bypassable with any real signature.

### SOL-036 · ATA derivation unpinned
A token account is trusted as "the user's ATA" without verifying it's the canonical ATA for (owner, mint) → attacker passes a different token account they control, redirecting deposits/payouts. Fix: Anchor `associated_token::mint` + `associated_token::authority` constraints, or compare against `get_associated_token_address(owner, mint)` (owner+mint from validated on-chain state, not caller data) before use.

### SOL-037 · Arbitrary CPI target
A CPI whose callee program id comes from an account or instruction data that's never checked against the expected program → attacker redirects the call to a malicious program. (SOL-009 checks the CALLER's authority; this checks the CALLEE's identity.) Fix: pin the callee — a typed `Program<'info, T>`, or assert the program id equals the expected constant — AND validate the accounts (and any PDA-signer seeds/amounts) passed into the CPI; pinning the program alone leaves account substitution / confused-deputy open (see SOL-027).

### SOL-038 · PDA seed collision
A PDA seed scheme with unpinned element boundaries - a caller-controlled variable-length seed (`String`/`Vec<u8>`/slice) adjacent to another variable element, or two schemes whose fixed prefixes differ in length - lets two DISTINCT logical accounts derive the SAME address (Solana hashes `seeds=[...]` as one flat buffer), so an attacker shifts bytes across a boundary to alias a victim's PDA -> overwrite/spoof/type-confusion. Distinct from SOL-008/016 (which verify a PDA, not the scheme's ambiguity). Fix: fixed-width per-type seed tag of a consistent width across the registry (e.g. all u32) from one program-wide enum registry (never per-file constants, never mixed tag widths); hash/length-prefix every variable element or separate two variables with a fixed-width element, never adjoin two unbounded ones

### SOL-039 · Asymmetric partial-CPI state
A handler mutates its OWN accounts (records a withdrawal, clears a debt, burns shares) then fires a fund-moving CPI whose `Result` is SWALLOWED (`let _ =`, `.ok()`, `.unwrap_or*`, a logged `.is_err()`, or a `match`/`if let Err` arm that does not re-`?`). On Solana only an `Err` returned from the top-level instruction reverts account writes, so a caught inner-CPI failure leaves the outer mutation committed while no tokens moved -> the attacker farms one-sided state by forcing the CPI to fail. Distinct from SOL-033 (stale read after a successful CPI). Fix: propagate the CPI with `?` so the whole instruction reverts; if you must catch the error, roll back every prior self-mutation

### SOL-040 · Credit from requested, not measured (Token-2022)
A deposit/vault handler credits shares from the REQUESTED `amount` instead of the MEASURED pre/post delta of the destination token account. Under a Token-2022 mint with a transfer-fee or transfer-hook the vault receives strictly less than `amount`, so the depositor is over-credited and the vault under-collateralized; the surplus drains to the next withdrawer. Distinct from SOL-032 (decimals) and SOL-013 (wrong token program). Fix: credit the measured pre/post balance delta (`reload()` before/after), not the requested amount; pin BOTH the destination ATA mint AND authority (a measured delta alone is not enough)

### SOL-041 · Forced-balance / supply desync
A raw on-chain balance - an account's `lamports()` or a token account's `amount` - is read as the AUTHORITATIVE internal supply/reserve driving a price/share/payout. Anyone can force-add balance the program never accounted for (a direct transfer, rent top-up, or pre-funded init before the program runs), inflating that total with no matching ledger entry -> desynced invariants, excess shares minted, pool drained (the SafeMoon reflection class). Distinct from SOL-011/034 (which write lamports out of sync). Fix: drive math from a program-owned recorded ledger updated by measured deltas; read the raw balance only to assert `live >= recorded`

### SOL-042 · Unbounded account-iteration compute DoS
An instruction loops over a caller-controlled collection (`remaining_accounts`, a user-grown `Vec`/list) with no per-call length cap, so work scales until the tx exceeds the ~1.4M compute-unit ceiling and EVERY call reverts - permanently bricking the instruction (and any crank/settlement behind it). Cheap-to-grow, expensive-to-process is the lever. Distinct from SOL-027 (validates each account's identity, not the count). Fix: `require!(list.len() <= MAX)` with MAX proven to fit the CU budget, or paginate across txns with a stored cursor

### SOL-043 · Unbounded storage / slot-exhaustion griefing
A permissionless instruction lets an attacker consume an unbounded share of a persistent SHARED resource - a monotonic global registry/list, program-subsidized account growth, or front-running the init of a depended-on singleton - denying state every other user relies on. Distinct from SOL-012 (rent funding): here growth is attacker-driven and one-way. Fix: per-caller fixed-size caller-paid PDAs, or a self-limiting shared cap (decrement-on-close + a refundable stake); admin-gate close

### SOL-044 · Hardcoded slot-time rate
Interest/emissions/vesting/funding accrual computed from a hardcoded slot->time conversion (a `SLOTS_PER_YEAR` constant, or a slot delta scaled by an assumed ~400ms/slot) instead of `Clock::get()?.unix_timestamp`. Solana slot time is not constant (it drifts, historically slower), so accrual silently diverges from wall-clock -> compounding over/under-payment an attacker farms around known slow/fast periods. Distinct from SOL-001 (trusting a caller-supplied slot). Fix: accrue on `Clock::get()?.unix_timestamp` deltas (store `last_update_ts`), never a hardcoded slots-per-period constant

### SOL-045 · Incremental Merkle insertion error
An incrementally-maintained Merkle tree (SPL account-compression `ConcurrentMerkleTree`, Bubblegum cNFTs, or a hand-rolled filled-subtrees/changelog) updates its root from cached state instead of a full recompute. A wrong incremental update for some insert/replace sequence (off-by-one height, stale reused sibling, mismatched empty-node hash, wrong path direction, out-of-order changelog) diverges from the canonical root -> a forged-leaf proof validates or a real leaf is silently dropped. Distinct from SOL-008 (the account is the right tree; its root is wrong). Fix: delegate root maintenance AND proof verification to spl-account-compression via CPI (pin `merkle_tree.owner`); else differential-test the tree

### SOL-046 · Hand-rolled dispatch bypasses framework guards
A program routes instructions by hand (`match instruction_data[0]` / a native `entrypoint!` that splits the tag byte) instead of Anchor's `#[program]` macro, so NONE of Anchor's auto-generated guards run - no 8-byte discriminator, none of the `#[account(...)]` constraints (`has_one`/`seeds`/`owner`/`signer`/`mut`) - because that code is only emitted for `#[derive(Accounts)]` handlers. Accounts arrive as a bare `&[AccountInfo]`; wrong-type/owner/unsigned/substituted accounts sail through at once. Distinct from SOL-019 (Anchor present, one missing discriminator). Fix: route through `#[program]` + `#[derive(Accounts)]`, or manually re-validate every account on every native arm (discriminator, owner, PDA, signer)

### SOL-047 · Forged receipt token / mint
A redeem/burn/claim path accepts a caller-supplied receipt `Mint` or share token account and burns it for the underlying asset without asserting it is the mint the deposit path produced -> the attacker passes a mint they control, mints themselves a balance, and the program treats those worthless tokens as genuine shares, draining the vault. Distinct from SOL-007 (owner) and SOL-015 (generic missing constraint). Fix: pin the receipt mint to the stored canonical mint (`address = vault.receipt_mint`) AND bind the burned account's `token::mint`

### SOL-048 · Default/zero value accepted as valid
An authorization/membership gate trusts a stored field whose pre-init default is the zero value - `Pubkey::default()`, a `[0u8;32]` merkle/whitelist root, a zero nonce, or a freshly-`init`'d (zeroed) account - so the UNINITIALIZED state passes the check and an attacker submits a proof/key matching the zero sentinel (or beats the admin to the gate). On Solana an 8-byte discriminator proves the account was created, not that THIS field was set, so an `Account<T>` check does not rescue you. Distinct from SOL-010 (re-initializing an existing value). Fix: reject the zero sentinel at the gate (`require_keys_neq!(stored, Pubkey::default())`) and assert `is_initialized` on a bound config account

### SOL-049 · Struct-padding / non-canonical flag read
A security-relevant byte (an `is_admin`/`is_initialized`/`is_frozen` flag, or alignment/padding) read through a HAND-ROLLED zero-copy reinterpretation - a manual `transmute`, a `*const T` cast over `data.borrow()`, or a hand-written `unsafe impl bytemuck::Pod` - where the byte is attacker-writable and never canonicalized: a `bool` that is any non-zero byte reads true, and padding bytes survive the typed reinterpret. Distinct from SOL-017 (use typed deserialize; this survives a typed zero-copy). Fix: use Anchor `#[account(zero_copy)]` / the real `Pod` derive (never a hand `unsafe impl`); store flags as u8 and assert canonicality on every load and write AND validate the account owner + discriminator (canonicalization alone is bypassable)

### SOL-050 · Serialization symmetry mismatch
The bytes written for an account and the bytes read back come from two DIFFERENT layouts - write `u64`/read `u32`, a reordered struct field, a second hand-written reader, a `#[repr(Rust)]` zero-copy struct the compiler may reorder, or a hand-computed offset off by N - so the loaded value is not the stored value, silently corrupting a `balance`/`authority`/`bump`; an attacker tunes the bytes at the disagreeing offset. Distinct from SOL-017/025 (an unverified raw deserialize; this survives a fully-typed, owner-checked one). Fix: pack and unpack through ONE shared (de)serializer over the same type; guard with a `size_of` tripwire + a `unpack(pack(x)) == x` test

### SOL-051 · Predictable on-chain entropy
A value-bearing draw (lottery winner, NFT trait roll, raffle, randomized ordering, airdrop pick) is seeded from on-chain-observable values - `Clock` `unix_timestamp`/`slot`, the `RecentBlockhashes`/`SlotHashes` sysvar, or any field readable before the tx lands - so it is not secret: the submitter simulates and only sends when they win (grinds it), and the slot leader can steer the slot/blockhash -> the prize is deterministically claimable. Distinct from SOL-001 (trusting a caller-supplied slot for auth; here the slot is honest but misused as randomness). Fix: use a VRF (Switchboard/ORAO) or a real commit-reveal; owner-check the oracle result account and bind it to this draw

### SOL-052 · Token-2022 semantics assumed
Code that accepts a Token-2022 mint but assumes classic SPL-Token behavior: it credits the requested (not received) amount, or never handles extensions - transfer-fee skims a cut so the vault receives less than booked, a transfer-hook runs attacker code mid-CPI, non-transferable / default-frozen silently breaks a transfer or locks a deposit -> vault under-collateralized or shares minted against tokens that never arrived. Distinct from SOL-013 (which program id) and SOL-032 (decimals). Fix: pin classic `Program<Token>` on every token CPI, or measure the received delta and reject unsupported Token-2022 extensions before value moves

## Provenance

Honest origins (full table in README): SOL-001 = 2 confirmed bounty wins; SOL-002 = public class; SOL-003/004/005 = our bounty-5 patterns; SOL-021/022/023 = our v16 audit; SOL-029-031 = a live integrator report; SOL-038-052 = public Solana/DeFi bug-class taxonomy; rest = documented Solana/DeFi hygiene.

Maintained by [Jelleo](https://jelleo.com). MIT.
