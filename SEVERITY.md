# Severity — how to rate a Solana Security Standard finding

A SOL-0XX hit is a **tripwire**: "look here," not "confirmed bug." When you triage one into a real finding, assign severity from **what an attacker actually needs** — not from the rule's name. This keeps severities calibrated to reachability instead of inflating every match of a scary-looking pattern.

Each rule ships a **baseline severity** in [`rules-meta.json`](./rules-meta.json) (shown on every [rule page](./content/rules/)). The baseline is a *starting point*. Calibrate it with the two axes below and **take the lower** of the two.

## Axis 1 — preconditions (how much has to be true for the attack to fire)

| Preconditions | Severity |
| --- | --- |
| **0** — fires from a single permissionless instruction, no special state | High |
| **1–2** — needs a specific (but reachable) account/config/state, or one prior tx | Medium |
| **3+** — needs an improbable state, a race window, or a chain of preconditions | Low |

## Axis 2 — minimum access level (who can trigger it)

| Caller required | Severity |
| --- | --- |
| **Permissionless** — any wallet | High |
| **Authenticated** — a lower-privilege but obtainable role | Medium |
| **Admin / privileged** — only a trusted key | Low |

## The rule

1. Score each axis, then **take the LOWER** of the two (a permissionless trigger that still needs 3 improbable preconditions is Low, not High).
2. A **threat-model boost** (real funds at stake, a confirmed exploit in the class — see the [Hacks Database](./hacks/)) may raise the result by **at most one step**. It never sets severity on its own.
3. Floor for direct fund loss: if a single tx provably moves user funds to the attacker, it is at least **High** regardless of the above.

## Reachability anchor (required)

Before you assign any severity, cite the **first reachable call-site** that proves the pattern is actually exercised (each rule page names what to cite). The scanner gives you the match location; *you* confirm it's reachable. A finding with no reachability anchor is a candidate, not a finding — score it Informational until anchored.

## The honest line

This is **guidance for a human or AI reviewer** to rate a finding consistently. The Standard does not execute your code, prove exploitability, or sign off on a severity — a SOL-0XX scan tells you *where to look*. Proving a finding is genuinely exploitable, fixing it, and issuing a signed, attested audit report is what a full [Jelleo](https://jelleo.com) audit does. The free Standard is the tripwire; the audit is the verdict.

---
*Part of the [Solana Security Standard](./README.md). Maintained by [Jelleo](https://jelleo.com). MIT.*
