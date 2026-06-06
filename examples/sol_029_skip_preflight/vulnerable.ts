// SOL-029 vulnerable — skipPreflight: true on a value-moving mainnet send.
//
// Disabling preflight skips simulation, so a transaction that WILL fail on
// chain (bad account, insufficient funds, failing CPI) is still broadcast and
// the fee is burned — and a malformed value transfer can land in a state the
// client never validated. There is no simulateTransaction guard before send.
//
// Bug class: skipping preflight/simulation on a mainnet value transfer.

import { Connection, Transaction, Keypair } from "@solana/web3.js";

export async function send(
  connection: Connection,
  tx: Transaction,
  payer: Keypair,
): Promise<string> {
  tx.sign(payer);
  // BUG: skipPreflight disables on-chain simulation before broadcast.
  const sig = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: true,
  });
  return sig;
}
