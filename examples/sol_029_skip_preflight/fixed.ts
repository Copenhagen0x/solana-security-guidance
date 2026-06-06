// SOL-029 fixed — preflight on, and simulate-then-assert before broadcast.
//
// Preflight stays enabled (skipPreflight: false) and the transaction is
// simulated first; if simulation reports an error the send is aborted. A
// transaction that would fail on chain never gets broadcast.

import { Connection, Transaction, Keypair } from "@solana/web3.js";

export async function send(
  connection: Connection,
  tx: Transaction,
  payer: Keypair,
): Promise<string> {
  tx.sign(payer);

  // Simulate first; refuse to broadcast a transaction that would fail.
  const sim = await connection.simulateTransaction(tx);
  if (sim.value.err !== null) {
    throw new Error(`refusing to send: simulation failed: ${JSON.stringify(sim.value.err)}`);
  }

  // Preflight stays ON for the real send.
  const sig = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
  });
  return sig;
}
