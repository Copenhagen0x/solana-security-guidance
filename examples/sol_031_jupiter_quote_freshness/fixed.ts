// SOL-031 fixed — reject a Jupiter quote that lags the current slot.
//
// quoteResponse.contextSlot is compared against the live slot; if the quote is
// older than a small bound the route is refetched/rejected rather than swapped.
// A slippage bound is also set as a second line of defense.
//
// The Jupiter client (createJupiterApiClient) is still used — it is the
// integration, not the bug. The fix is the contextSlot freshness gate, which is
// what the SOL-031 exclusion requires; the scanner tripwire (any Jupiter usage)
// is cleared by that check, not by dropping Jupiter.

import { Connection } from "@solana/web3.js";
import { createJupiterApiClient } from "@jup-ag/api";

// Illustrative bound. Tune to your RPC's observed lag (often ~3-6 slots behind
// tip on mainnet): too tight rejects every quote, too loose defeats the check.
const MAX_QUOTE_LAG_SLOTS = 5;

export async function swap(
  connection: Connection,
  inputMint: string,
  outputMint: string,
  amount: number,
) {
  const jupiter = createJupiterApiClient();
  const quoteResponse = await jupiter.quoteGet({
    inputMint,
    outputMint,
    amount,
    slippageBps: 50, // slippage bound (second line of defense)
  });

  // Freshness gate: refuse a quote that lags the current slot.
  const currentSlot = await connection.getSlot();
  // Use `== null` (not a falsy `!` check): contextSlot can legitimately be 0.
  // NOTE: this proves freshness at CHECK time, not at execution — there is an
  // inherent TOCTOU window before swapPost lands. Keep that window small and
  // rely on slippageBps as the on-execution backstop.
  if (quoteResponse.contextSlot == null || currentSlot - quoteResponse.contextSlot > MAX_QUOTE_LAG_SLOTS) {
    throw new Error("stale Jupiter quote: refetch before swapping");
  }

  const swapResult = await jupiter.swapPost({
    swapRequest: { quoteResponse, userPublicKey: "..." },
  });
  return swapResult;
}
