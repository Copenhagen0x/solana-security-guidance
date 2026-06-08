#!/usr/bin/env bash
# adopt-badge.sh — open a ONE-TIME PR adding the Solana Security Standard badge
# to the consuming repo's README, using context from the scan that just ran.
#
# Hard rules (every reviewer should hold these):
#   * Best-effort: NEVER hard-fail. No `set -e`. Any problem logs a note/warning
#     and exits 0 — an adopter's security check must never break over a badge.
#   * Never touches the adopter's checkout: ALL git work happens in an isolated
#     `git worktree` under a temp dir. The live $GITHUB_WORKSPACE tree, its HEAD,
#     its README, and its git identity config are never modified, so later steps
#     in the same job are unaffected.
#   * Safe context only: a push to the repo's OWN default branch. Never on PR /
#     pull_request_target / fork contexts (where GITHUB_TOKEN is read-only or the
#     base token could be abused).
#   * Idempotent: skips if the badge is already in the README, if a badge PR
#     (open / closed / merged) already exists, or if the branch already exists
#     on the remote. It never nags and never force-pushes.
#   * No untrusted / unescaped interpolation: the PR body is a QUOTED heredoc
#     (no shell expansion); values are substituted via bash string replacement
#     and every one is charset-validated first (digits / a git SHA / the action's
#     own semver / a constant). Nothing caller-controlled reaches gh/git/the body.
#   * PR only: it proposes a PR; it never commits to the adopter's own branches.
set -uo pipefail

note() { printf '::notice title=Solana Security Standard::%s\n' "$1"; }
warn() { printf '::warning title=Solana Security Standard::%s\n' "$1"; }

BRANCH="sss/adopt-badge"
BADGE='[![Solana Security Standard](https://img.shields.io/badge/Solana%20Security%20Standard-SOL--0XX-a855f7?labelColor=6d28d9)](https://github.com/Copenhagen0x/solana-security-standard)'
MARK='img.shields.io/badge/Solana%20Security%20Standard-SOL--0XX'   # idempotency marker

# 1) context guards ----------------------------------------------------------
[ "${GITHUB_EVENT_NAME:-}" = "push" ] \
  || { note "skipped — only runs on a push to the default branch"; exit 0; }
[ -n "${DEFAULT_BRANCH:-}" ] && [ "${GITHUB_REF:-}" = "refs/heads/${DEFAULT_BRANCH}" ] \
  || { note "skipped — not the default branch"; exit 0; }
case "$DEFAULT_BRANCH" in (*[!A-Za-z0-9._/-]*) note "skipped — unexpected default-branch name"; exit 0 ;; esac
[ -n "${GH_TOKEN:-}" ] \
  || { note "skipped — no token (grant 'contents: write' + 'pull-requests: write' to enable)"; exit 0; }
REPO="${GITHUB_REPOSITORY:-}"
case "$REPO" in (?*/?*) : ;; (*) note "skipped — no repository context"; exit 0 ;; esac
case "$REPO" in (*[!A-Za-z0-9._/-]*|*/*/*) note "skipped — unexpected repository name"; exit 0 ;; esac

README="${GITHUB_WORKSPACE:-.}/README.md"
[ -f "$README" ] || { note "skipped — no README.md at the repo root"; exit 0; }
[ -L "$README" ] && { note "skipped — README.md is a symlink (left untouched)"; exit 0; }

# 2) idempotency -------------------------------------------------------------
if grep -qF "$MARK" "$README"; then
  note "badge already present — nothing to do"; exit 0
fi
existing=$(gh pr list --repo "$REPO" --state all --head "$BRANCH" --json number --jq 'length' 2>/dev/null || echo 0)
case "$existing" in (*[!0-9]*|'') existing=0 ;; esac
if [ "$existing" -ne 0 ]; then
  note "a badge PR was already proposed before — not reopening"; exit 0
fi
if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
  note "branch $BRANCH already exists on the remote — not overwriting"; exit 0
fi

# 3) context from the scan that already ran (validated; no network, no re-scan) --
findings=0
if [ -f "${SARIF:-}" ]; then
  findings=$(jq '[.runs[].results[]?] | length' "$SARIF" 2>/dev/null || echo 0)
fi
case "$findings" in (*[!0-9]*|'') findings=0 ;; esac
files=$(find "${GITHUB_WORKSPACE:-.}" -type f -name '*.rs' 2>/dev/null | wc -l | tr -d ' ')
case "$files" in (*[!0-9]*|'') files=0 ;; esac
version=$(jq -r '.version // "unknown"' "${SSS_DIR:-.}/cli/package.json" 2>/dev/null || echo unknown)
case "$version" in (''|*[!0-9A-Za-z._+-]*) version="unknown" ;; esac
sha="${GITHUB_SHA:-}"; sha="${sha:0:7}"
case "$sha" in (''|*[!0-9a-fA-F]*) sha="unknown" ;; esac
if [ "$findings" -eq 0 ]; then result="0 findings"; else result="${findings} finding(s)"; fi

# 4) build the change in an ISOLATED worktree (live checkout/HEAD untouched) --
wt=$(mktemp -d) || { warn "mktemp failed — skipping badge PR"; exit 0; }
cleanup() { git worktree remove --force "$wt" >/dev/null 2>&1 || rm -rf "$wt"; }
trap cleanup EXIT
if ! git worktree add -b "$BRANCH" "$wt" HEAD >/dev/null 2>&1; then
  warn "couldn't create an isolated worktree — skipping badge PR"; exit 0
fi
wt_readme="$wt/README.md"
[ -f "$wt_readme" ] || { note "no README in the worktree — skipping"; exit 0; }

# Insert the badge after the first real H1 (a column-0 `# ` line NOT inside a
# fenced code block); if there's no such H1, prepend. The marker re-check makes a
# double-insert impossible. CommonMark-correct fence tracking (delimiter char +
# length) avoids false toggles on mismatched (``` vs ~~~) or longer fences. The
# README's existing line-ending style is preserved, so the PR is a clean
# one-line diff (no CRLF→LF normalization noise on Windows-authored repos).
# Detect the README's line-ending style up front so the final file matches it.
crlf=0
if LC_ALL=C grep -q $'\r' "$wt_readme" 2>/dev/null; then crlf=1; fi
ins=$(mktemp) || { warn "mktemp failed — skipping badge PR"; exit 0; }
# Pass 1 — insert (LF output; CR is stripped for matching). The fence run length
# and char are tracked so a mismatched (``` vs ~~~) or shorter fence inside a
# longer one does NOT toggle state — the badge can't land inside a code block.
awk -v b="$BADGE" '
  BEGIN{ infence=0; fchar=""; flen=0; done=0 }
  { sub(/\r$/,"") }
  {
    probe=$0; sub(/^[ \t]+/,"",probe); run=""
    if (probe ~ /^`/ || probe ~ /^~/) {
      c=substr(probe,1,1); n=0
      while (substr(probe,n+1,1)==c) n++
      if (n>=3) run=substr(probe,1,n)
    }
    if (run!="") {                                        # a fence-delimiter line
      c=substr(run,1,1); L=length(run)
      if (!infence) { infence=1; fchar=c; flen=L; print; next }   # open
      rest=substr(probe,L+1)                              # close iff same char,
      if (c==fchar && L>=flen && rest ~ /^[ \t]*$/) {     # length>=open, only ws
        infence=0; fchar=""; flen=0; print; next
      }
      print; next                                         # else: fence content
    }
    if (!infence && !done && /^#[ \t]/) { print; print ""; print b; done=1; next }
    print
  }
' "$wt_readme" > "$ins"
if ! grep -qF "$MARK" "$ins"; then                        # no H1 → prepend
  { printf '%s\n\n' "$BADGE"; cat "$wt_readme"; } > "$ins"
fi
# Pass 2 — restore CRLF line endings if the original used them, so the PR diff is
# just the inserted line(s) and not a whole-file LF normalization.
if [ "$crlf" -eq 1 ]; then
  awk '{ sub(/\r$/,""); printf "%s\r\n", $0 }' "$ins" > "${ins}.crlf" && mv -f "${ins}.crlf" "$ins" || rm -f "${ins}.crlf"
fi
cp "$ins" "$wt_readme"; rm -f "$ins"

git -C "$wt" add -- README.md
# Per-invocation identity (-c …) so no persistent git config is written anywhere.
git -C "$wt" \
  -c user.name="solana-security-standard[bot]" \
  -c user.email="solana-security-standard[bot]@users.noreply.github.com" \
  commit -m "docs: add the Solana Security Standard badge" >/dev/null 2>&1 \
  || { note "nothing to commit — skipping"; exit 0; }

if ! git -C "$wt" push -u origin "$BRANCH" >/dev/null 2>&1; then
  warn "couldn't push the badge branch — grant 'contents: write' to enable the badge PR"
  exit 0
fi

# 5) open the PR -------------------------------------------------------------
# QUOTED heredoc = zero shell expansion; values are substituted below and each
# was charset-validated above, so no metacharacter can reach gh/markdown/shell.
body=$(cat <<'TMPL'
### 🛡️ Your CI now runs the Solana Security Standard

This one-time PR adds the **Solana Security Standard** badge to your README, because your pipeline now runs the SOL-0XX security scan.

> **This run** &nbsp; @@RESULT@@ &nbsp;·&nbsp; @@FILES@@ Rust files scanned &nbsp;·&nbsp; ruleset `v@@VERSION@@` &nbsp;·&nbsp; commit `@@SHA@@`

**What it adds — one line to `README.md`:**

@@BADGE@@

It links to the open standard — SOL-0XX rules distilled from $514M of real Solana exploits — and signals you hold your code to it.

**Don't want it?** Just close this PR — nothing else changes and your scan keeps running. To never see it again, set `add-badge: false` in your workflow.

---
Opened automatically by the [Solana Security Standard](https://github.com/Copenhagen0x/solana-security-standard) action.
TMPL
)
body=${body//@@RESULT@@/$result}
body=${body//@@FILES@@/$files}
body=${body//@@VERSION@@/$version}
body=${body//@@SHA@@/$sha}
body=${body//@@BADGE@@/$BADGE}

if gh pr create --repo "$REPO" --title "Add the Solana Security Standard badge" \
     --body "$body" --base "$DEFAULT_BRANCH" --head "$BRANCH" >/dev/null 2>&1; then
  note "opened the Solana Security Standard badge PR 🎉"
else
  warn "couldn't open the PR — grant 'pull-requests: write' to enable it (branch pushed: $BRANCH)"
fi
exit 0
