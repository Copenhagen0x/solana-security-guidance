'use strict';
// Output formatters for scan findings: text (humans), json (tooling),
// sarif (GitHub code-scanning -> inline PR annotations + Security tab).

/** Derive a display id like "SOL-001" from a rule_name like "sol_001_foo". */
function solId(ruleName) {
  const m = /^sol[_-]?(\d{3})/i.exec(ruleName || '');
  return m ? `SOL-${m[1]}` : (ruleName || 'SOL-?');
}

/** First sentence / trimmed form of a reminder, stripped of the "Jelleo SOL-NNN:" prefix. */
function shortReminder(reminder, max = 140) {
  let r = (reminder || '').replace(/^Jelleo\s+SOL-\d{3}:\s*/i, '').trim();
  r = r.replace(/\s+See:\s*\S+$/i, ''); // drop the trailing "See: <url>"
  if (r.length > max) r = r.slice(0, max - 1).trimEnd() + '…';
  return r;
}

function text(findings, { color = false } = {}) {
  if (!findings.length) return 'Solana Security Standard: no findings.\n';
  const bold = (s) => (color ? `\x1b[1m${s}\x1b[0m` : s);
  const dim = (s) => (color ? `\x1b[2m${s}\x1b[0m` : s);
  const yellow = (s) => (color ? `\x1b[33m${s}\x1b[0m` : s);
  const lines = [];
  let lastFile = null;
  for (const f of findings) {
    if (f.file !== lastFile) {
      lines.push('');
      lines.push(bold(f.file));
      lastFile = f.file;
    }
    const loc = dim(`${String(f.line).padStart(4)}:${String(f.column)}`);
    const sev = f.severity ? ` ${dim('[' + f.severity + ']')}` : '';
    lines.push(`  ${loc}  ${yellow(solId(f.rule))}${sev}  ${shortReminder(f.reminder)}`);
  }
  lines.push('');
  const files = new Set(findings.map((f) => f.file)).size;
  lines.push(`${findings.length} finding(s) across ${files} file(s).`);
  return lines.join('\n') + '\n';
}

function json(findings) {
  return JSON.stringify(
    {
      standard: 'Solana Security Standard (SOL-0XX)',
      tool: 'solana-security-standard',
      findingCount: findings.length,
      findings: findings.map((f) => ({
        ruleId: solId(f.rule),
        ruleName: f.rule,
        file: f.file,
        line: f.line,
        column: f.column,
        severity: f.severity,        // SSS baseline impact (advisory; calibrate per SEVERITY.md)
        tier: f.tier,                // submission-floor value: high | low
        message: shortReminder(f.reminder, 1000),
        match: f.match,
        exclusions: f.exclusions,    // numbered "do NOT flag when…" (cite by index+1 when suppressing)
      })),
    },
    null,
    2,
  );
}

function sarif(findings, rules = [], { version = '0.0.0' } = {}) {
  // Stable rule list for the driver (deduped by rule_name, in id order).
  const seen = new Map();
  for (const r of rules) {
    if (r && r.name && !seen.has(r.name)) {
      seen.set(r.name, {
        id: r.name,
        name: solId(r.name),
        shortDescription: { text: `${solId(r.name)} — Solana Security Standard` },
        fullDescription: { text: shortReminder(r.reminder, 1000) || solId(r.name) },
        helpUri: `https://github.com/Copenhagen0x/solana-security-standard#${solId(r.name).toLowerCase()}`,
        defaultConfiguration: { level: 'warning' },
        properties: { tags: ['security', 'solana'] },
      });
    }
  }
  const ruleArr = [...seen.values()];
  const ruleIndex = new Map(ruleArr.map((r, i) => [r.id, i]));
  // GitHub code scanning silently drops a run with > 5000 results. Cap, and
  // record the truncation in properties so it isn't a silent "all clear".
  const MAX_RESULTS = 5000;
  const truncated = findings.length > MAX_RESULTS;
  const used = truncated ? findings.slice(0, MAX_RESULTS) : findings;
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'solana-security-standard',
              informationUri: 'https://github.com/Copenhagen0x/solana-security-standard',
              version,
              rules: ruleArr,
            },
          },
          properties: truncated
            ? { truncated: true, totalFindings: findings.length, reported: MAX_RESULTS }
            : { totalFindings: findings.length },
          results: used.map((f) => ({
            ruleId: f.rule,
            ruleIndex: ruleIndex.has(f.rule) ? ruleIndex.get(f.rule) : undefined,
            // level stays 'warning' (advisory) so existing GitHub code-scanning
            // gating is unchanged; the SSS baseline severity/tier ride in properties.
            level: 'warning',
            message: { text: `${solId(f.rule)}: ${shortReminder(f.reminder, 1000)}` },
            properties: { sssSeverity: f.severity, tier: f.tier },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  region: { startLine: f.line, startColumn: f.column },
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2,
  );
}

module.exports = { solId, shortReminder, text, json, sarif };
