# The Solana Hacks Database

> Real, disclosed Solana exploits mapped to the [Solana Security Standard](../claude-security-guidance.md) (`SOL-0XX`) rule class each one falls under. Generated from [`hacks.json`](./hacks.json) — do not edit by hand (run `node scripts/sync-hacks.js`).

**8 code-level exploits** — $514M lost — mapped to **8 of the 52 rules**. Plus **3 notable incidents no code rule prevents** (stolen keys, off-chain wallets), listed for honesty about scope.

Every entry is cited. A mapping says "this rule class is the one that flags this bug" — not that any tool would have auto-fixed it. We never claim a rule catches an incident it cannot (see [`SCHEMA.md`](./SCHEMA.md)).

## Coverage by rule

Which SOL-0XX rule class each exploit falls under.

| Rule | Class | Exploits |
| --- | --- | --- |
| [SOL-004](https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md#sol-004--penaltyhealth-terms-omitted) | Penalty/health terms omitted | Cypher Protocol |
| [SOL-006](https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md#sol-006--missing-signer-check) | Missing signer check | Solend |
| [SOL-007](https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md#sol-007--missing-owner-verification) | Missing owner verification | Solend, Wormhole, Cashio, Crema Finance |
| [SOL-015](https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md#sol-015--anchor-constraints-missing) | Anchor constraints missing | Cashio |
| [SOL-017](https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md#sol-017--raw-accountinfo-without-typed-deserialize) | Raw AccountInfo without typed deserialize | Crema Finance |
| [SOL-024](https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md#sol-024--stale--unchecked-oracle-price) | Stale / unchecked oracle price | Nirvana Finance, Mango Markets, Loopscale |
| [SOL-025](https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md#sol-025--sysvar-read-by-raw-deserialize) | Sysvar read by raw deserialize | Wormhole |
| [SOL-028](https://github.com/Copenhagen0x/solana-security-standard/blob/main/claude-security-guidance.md#sol-028--missing-slippage--min-out-bound) | Missing slippage / min-out bound | Nirvana Finance, Loopscale |

## Code-level exploits

| Date | Protocol | Loss | Class | Rules |
| --- | --- | --- | --- | --- |
| 2021-08-19 | [Solend](#solend-updatereserveconfig-2021-08) | $16K | missing-authority | SOL-006, SOL-007 |
| 2022-02-02 | [Wormhole](#wormhole-2022-02) | $326M | account-validation | SOL-025, SOL-007 |
| 2022-03-23 | [Cashio](#cashio-2022-03) | $52.8M | account-validation | SOL-015, SOL-007 |
| 2022-07-02 | [Crema Finance](#crema-finance-2022-07) | $8.8M | account-validation | SOL-007, SOL-017 |
| 2022-07-28 | [Nirvana Finance](#nirvana-finance-2022-07) | $3.5M | oracle-manipulation | SOL-024, SOL-028 |
| 2022-10-11 | [Mango Markets](#mango-markets-2022-10) | $116M | oracle-manipulation | SOL-024 |
| 2023-08-07 | [Cypher Protocol](#cypher-protocol-2023-08) | $1M | accounting | SOL-004 |
| 2025-04-26 | [Loopscale](#loopscale-2025-04) | $5.8M | oracle-manipulation | SOL-024, SOL-028 |

## Details

### Solend — $16K <a id="solend-updatereserveconfig-2021-08"></a>

**Solend UpdateReserveConfig authority bypass** · 2021-08-19 · `SOL-006` `SOL-007`

**What happened.** The UpdateReserveConfig instruction did not verify that the caller owned the lending market it operated on — the attacker created their own lending-market account and passed it in, then lowered the liquidation threshold and inflated the liquidation bonus to make nearly all positions liquidatable (≈$2M put at risk, so liquidators — potentially the attacker — could profit). It was contained with only ≈$16K realized, but the class — a privileged handler that fails to verify the caller owns the account it mutates — is among the most common Solana bugs.

**Why it maps here.** SOL-006 (a privileged handler that does not verify the signer/authority) and SOL-007 (an account trusted without checking owner == program_id — here a lending market the attacker created and passed as their own) both flag accepting an attacker-controlled config account.

**Sources:** [1](https://www.helius.dev/blog/solana-hacks)

### Wormhole — $326M <a id="wormhole-2022-02"></a>

**Wormhole bridge guardian-signature forgery** · 2022-02-02 · `SOL-025` `SOL-007`

**What happened.** The Solana bridge's verify_signatures used the deprecated load_instruction_at instead of load_instruction_at_checked, so it never verified that the supplied instructions sysvar was the real Sysvar1nstructions account. The attacker passed a look-alike account containing a fabricated Secp256k1 verification result, forged the guardian signature set, and minted 120,000 wETH with no backing — at the time the largest-ever exploit of a Solana program (≈$326M).

**Why it maps here.** SOL-025 (sysvar read by raw/unchecked deserialize instead of a key-checking accessor) is exactly this bug; SOL-007 (owner/account not verified) is the same class of trusting an attacker-supplied account.

**Sources:** [1](https://www.halborn.com/blog/post/explained-the-wormhole-hack-february-2022) · [2](https://www.certik.com/blog/wormhole-bridge-exploit-incident-analysis)

### Cashio — $52.8M <a id="cashio-2022-03"></a>

**Cashio infinite-mint via unvalidated collateral mint** · 2022-03-23 · `SOL-015` `SOL-007`

**What happened.** Collateral validation checked that the token type matched the saber_swap.arrow account but never validated the mint field inside that arrow account. The attacker supplied a fake arrow account, deposited worthless collateral, and minted over 2 billion unbacked CASH, collapsing the stablecoin to zero.

**Why it maps here.** SOL-015 (an Account cross-reference with no has_one / constraint tying related accounts together) and SOL-007 (owner/field not verified) catch the missing link in the collateral account chain.

**Sources:** [1](https://www.halborn.com/blog/post/explained-the-cashio-hack-march-2022) · [2](https://www.coindesk.com/tech/2022/03/23/stablecoin-cashio-suffers-infinite-glitch-exploit-tvl-drops-by-28m)

### Crema Finance — $8.8M <a id="crema-finance-2022-07"></a>

**Crema Finance fake tick-account fee drain** · 2022-07-02 · `SOL-007` `SOL-017`

**What happened.** The CLMM read pool tick data from a tick account whose owner was not verified — the attacker created a fake tick account and wrote the pool's initialized tick address into it to pass a weak identity check. Fee math then trusted the fabricated tick data, and the attacker claimed inflated fees, draining the pools (≈69,423 SOL + 6.5M USDC) using Solend flash loans.

**Why it maps here.** SOL-007 (AccountInfo used without owner == program_id) and SOL-017 (raw account data trusted without typed deserialize + validation) flag trusting an attacker-controlled tick account.

**Sources:** [1](https://www.halborn.com/blog/post/explained-the-crema-finance-hack-july-2022) · [2](https://rekt.news/crema-finance-rekt)

### Nirvana Finance — $3.5M <a id="nirvana-finance-2022-07"></a>

**Nirvana Finance bonding-curve price manipulation** · 2022-07-28 · `SOL-024` `SOL-028`

**What happened.** A $10M USDC flash loan was used to mint ANA and push the protocol's bonding-curve price far above its real value within one transaction; the attacker then redeemed the inflated ANA for ≈$3.5M, with no time-weighting or manipulation-resistance on the price input.

**Why it maps here.** SOL-024 (a price used with no staleness/confidence/manipulation check) and SOL-028 (no slippage / min-out bound on a value-deriving swap) cover a single-transaction price that can be moved by the caller.

**Sources:** [1](https://www.coindesk.com/tech/2022/07/28/solana-defi-protocol-nirvana-drained-of-liquidity-after-flash-loan-exploit) · [2](https://www.theblock.co/post/159975/solana-stablecoin-nirvana-sinks-90-amid-3-5-million-flash-loan-exploit)

### Mango Markets — $116M <a id="mango-markets-2022-10"></a>

**Mango Markets oracle manipulation** · 2022-10-11 · `SOL-024`

**What happened.** The attacker opened a large MNGO perpetual position, then spent a few million dollars buying MNGO spot across thin markets to pump the oracle-reported price ~2,300% in minutes. The inflated mark let them borrow against the position and drain ≈$116M from the protocol before the price collapsed.

**Why it maps here.** SOL-024 (a Pyth/Switchboard price consumed with no manipulation-resistance — confidence interval, thin-market/deviation guard) is the exact class: a price feed trusted as if it could not be moved by the caller.

**Sources:** [1](https://blockworks.com/news/mango-markets-mangled-by-oracle-manipulation-for-112m) · [2](https://www.coindesk.com/markets/2022/10/12/how-market-manipulation-led-to-a-100m-exploit-on-solana-defi-exchange-mango)

### Cypher Protocol — $1M <a id="cypher-protocol-2023-08"></a>

**Cypher Protocol isolated-pool margin miscount** · 2023-08-07 · `SOL-004`

**What happened.** When a sub-account switched to an isolated state, the master account failed to track that change, and a margin check before borrowing did not account for it — combined with oracle feeds not yet being active, this let a user borrow far beyond their real collateral. ≈38,530 SOL + $123,184 USDC ($1.04M) were taken.

**Why it maps here.** SOL-004 (risk/margin math that drops a spec-mandated term, allowing under-collateralized positions) maps to a margin check that ignores the isolated-state accounting term.

**Sources:** [1](https://www.halborn.com/blog/post/explained-the-cypher-protocol-hack-august-2023) · [2](https://www.coindesk.com/business/2023/08/07/solana-based-cypher-protocol-experiences-exploit-freezes-smart-contract)

### Loopscale — $5.8M <a id="loopscale-2025-04"></a>

**Loopscale RateX collateral price manipulation** · 2025-04-26 · `SOL-024` `SOL-028`

**What happened.** Loopscale priced RateX PT collateral from a single time-point on-chain price feed (a liquidity pool) with no time-weighting or multi-source aggregation. A flash-loan trade depressed the reported PT price just before loan origination, so the protocol accepted manipulated values and issued under-collateralized loans, draining ≈$5.8M (5.7M USDC + 1,200 SOL at prevailing prices).

**Why it maps here.** SOL-024 (single-source price with no manipulation-resistance) and SOL-028 (no bound protecting against an adverse same-transaction price move) cover instantaneous-price collateral valuation.

**Sources:** [1](https://www.halborn.com/blog/post/explained-the-loopscale-hack-april-2025) · [2](https://www.theblock.co/post/352083/solana-defi-protocol-loopscale-hit-with-5-8-million-exploit-two-weeks-after-launch)

## Not preventable by a code rule

These are real Solana losses, but no on-chain code rule prevents them — they are key compromises or off-chain/client failures. Listed so the database is honest about what code review covers and what it does not.

| Date | Protocol | Loss | Why no code rule applies |
| --- | --- | --- | --- |
| 2022-08-03 | Slope | $8M | Slope's mobile wallet transmitted users' seed phrases in plaintext to a centralized logging server, where they were exposed. Thousands of wallets were drained. This was an off-chain client/operational failure, not a flaw in any on-chain program. |
| 2022-12-16 | Raydium | $4.4M | An attacker obtained the pool-owner authority's private key (a compromised admin key, not a contract bug) and called legitimate privileged admin functions such as withdrawPNL to extract fees and funds from liquidity pools. |
| 2024-05-16 | Pump.fun | $1.9M | A former employee retained access to a privileged withdrawal authority and combined it with flash loans to manipulate bonding-curve liquidity and extract ≈$1.9M. The root cause was insider access to a privileged key/authority, not a missing on-chain check. |

## Contributing

Add an exploit by appending to [`hacks.json`](./hacks.json) (schema: [`SCHEMA.md`](./SCHEMA.md)) and running `node scripts/sync-hacks.js`. Every entry needs a cited source and an honest mapping. CI re-runs the generator and fails if `README.md` is out of sync.

Maintained by [Jelleo](https://jelleo.com). MIT. Part of the [Solana Security Standard](../README.md).
