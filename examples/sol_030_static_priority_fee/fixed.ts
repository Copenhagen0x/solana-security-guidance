// SOL-030 fixed — derive the priority fee from recent network fees, clamped.
//
// The fee is taken from getRecentPrioritizationFees() (a live signal) and
// clamped to a sane ceiling so it adapts to congestion without overpaying.
// No hardcoded microLamports literal remains.

import {
  Connection,
  ComputeBudgetProgram,
  TransactionInstruction,
  PublicKey,
} from "@solana/web3.js";

const MAX_PRIORITY_FEE = 1_000_000; // ceiling guard

export async function priorityFeeIx(
  connection: Connection,
  writableAccounts: PublicKey[],
): Promise<TransactionInstruction> {
  const recent = await connection.getRecentPrioritizationFees({
    lockedWritableAccounts: writableAccounts,
  });
  // Illustrative: max of recent fees. Production may prefer a p75/p90 percentile
  // to avoid one outlier slot spiking the fee (the ceiling below still caps it).
  const observed = recent.length
    ? Math.max(...recent.map((r) => r.prioritizationFee))
    : 0;
  const priorityFee = Math.min(observed, MAX_PRIORITY_FEE);

  return ComputeBudgetProgram.setComputeUnitPrice({
    microLamports: priorityFee,
  });
}
