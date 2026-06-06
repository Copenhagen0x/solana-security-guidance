// SOL-030 vulnerable — hardcoded priority fee.
//
// A static microLamports constant ignores live network conditions: too low
// during congestion (the transaction stalls and a time-sensitive action — a
// liquidation, an oracle update — misses its window) and wastefully high when
// the network is quiet.
//
// Bug class: static priority fee instead of a dynamic, oracle-derived one.

import { ComputeBudgetProgram, TransactionInstruction } from "@solana/web3.js";

export function priorityFeeIx(): TransactionInstruction {
  // BUG: hardcoded fee, blind to getRecentPrioritizationFees().
  return ComputeBudgetProgram.setComputeUnitPrice({
    microLamports: 50000,
  });
}
