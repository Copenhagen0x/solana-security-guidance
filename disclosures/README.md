# Disclosure feed — grow the standard from new disclosures

A pipeline that turns a fresh Solana security disclosure — a [GitHub Security Advisory](https://github.com/advisories), an [Immunefi](https://immunefi.com) report, or a security-fix pull request — into a **candidate** [Hacks Database](../hacks/) entry with suggested `SOL-0XX` rule mappings, for a human to verify and triage. It's how the standard keeps growing as new exploits land.

It **never auto-writes** to `hacks/hacks.json`. A cited database only takes verified, human-reviewed entries — the same honesty the rest of this repo holds itself to. The classifier is a heuristic that surfaces the *likely* rule class; it does not label.

## Use it

```bash
# 1. Get the disclosure as a JSON envelope: { "type": "ghsa" | "immunefi" | "pr", "data": { … } }
#    e.g. a GitHub advisory:  gh api /advisories/GHSA-xxxx-xxxx-xxxx > adv.json
#    then wrap it as {"type":"ghsa","data": <that object>}

# 2. Get a candidate Hacks-DB entry + suggested SOL-0XX rules (rationale to stderr, JSON to stdout):
node scripts/ingest.js disclosure.json          # or:  cat disclosure.json | node scripts/ingest.js

# 3. Review the candidate's _review block, verify the facts + sources, fill the TODOs, curate the
#    sol_rules, paste it into hacks/hacks.json, then regenerate:
(cd ../hacks && node scripts/sync-hacks.js)
```

The candidate is emitted in the exact `hacks.json` shape (plus a `_review` block) — a test asserts a fixture-derived candidate passes the **real** Hacks-DB validator, so once you fill the TODOs and verify, it drops straight in.

## How it works

- [`scripts/adapters.js`](scripts/adapters.js) — normalize each feed (GHSA advisory JSON, Immunefi report, security PR) into one `Disclosure` shape.
- [`scripts/classify.js`](scripts/classify.js) — score the disclosure text against per-rule keyword signatures derived from the 28 rules; return ranked `SOL-0XX` suggestions plus a code-preventable / off-chain guess.
- [`scripts/ingest.js`](scripts/ingest.js) — adapter → classifier → a candidate entry.

A self-consistency check guards against signature rot: a test classifies every catalogued exploit's root cause and confirms a labeled rule appears **among the ranked suggestions** for **≥70%** of them (today 8/8; top-1 is only 7/8), and that every off-chain / key-compromise incident is guessed not-code-preventable. This is an internal consistency check — the root-cause text and the keyword signatures are both authored in this repo — **not** a measure of blind accuracy on unseen disclosures.

## Sourcing the feeds

The adapters take JSON you fetch — kept out of CI on purpose, so a network or API hiccup never turns into a red build:

- **GHSA** — the GitHub Advisory Database: `gh api /advisories/GHSA-…`, or query by ecosystem.
- **Immunefi** — a disclosed report's fields (`project`, `title`, `description`, `amount_usd`, `url`, `date`).
- **PR** — a security-fix PR or commit: `gh api /repos/<owner>/<repo>/pulls/<n>`.

Maintained by [Jelleo](https://jelleo.com). MIT. Part of the [Solana Security Standard](../README.md).
