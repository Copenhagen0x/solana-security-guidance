// SOL-031 vulnerable — Jupiter quote consumed with no freshness check.
//
// The code fetches a Jupiter quote and immediately builds + sends the swap
// without checking quoteResponse.contextSlot against the current slot. If the
// quote is even a few slots old the route may have moved; the swap executes on
// a stale route and is exposed to adverse price movement / MEV.
//
// Bug class: stale Jupiter quote (no contextSlot freshness gate).

import { createJupiterApiClient } from "@jup-ag/api";

export async function swap(inputMint: string, outputMint: string, amount: number) {
  const jupiter = createJupiterApiClient();
  const quoteResponse = await jupiter.quoteGet({
    inputMint,
    outputMint,
    amount,
    slippageBps: 50,
  });

  // BUG: no quoteResponse.contextSlot freshness check before consuming it.
  const swapResult = await jupiter.swapPost({
    swapRequest: { quoteResponse, userPublicKey: "..." },
  });
  return swapResult;
}
