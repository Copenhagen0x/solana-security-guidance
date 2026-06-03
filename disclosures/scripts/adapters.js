'use strict';
// Normalize a raw disclosure from one of three feeds into a common Disclosure record, so the
// classifier and ingest step are feed-agnostic. Zero dependencies. Defensive about missing fields.
//
// Disclosure = { source_type, source, url, title, body, protocol, date, loss_usd }
//   source_type: 'ghsa' | 'immunefi' | 'pr'
//   date: 'YYYY-MM-DD' (best effort; '' if unknown)
//   loss_usd: integer | null

function isoDate(s) {
  const m = String(s || '').match(/^(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : '';
}

function clean(s) {
  return String(s == null ? '' : s).trim();
}

// GitHub Security Advisory JSON (e.g. `gh api /advisories/GHSA-xxxx-xxxx-xxxx`).
function fromGhsa(a) {
  a = a || {};
  const refs = Array.isArray(a.references) ? a.references : [];
  const r0 = refs.length ? refs[0] : null;
  const refUrl = typeof r0 === 'string' ? r0 : (r0 && typeof r0 === 'object' && r0.url) || '';
  const pkg = Array.isArray(a.vulnerabilities) && a.vulnerabilities[0] && a.vulnerabilities[0].package;
  return {
    source_type: 'ghsa',
    source: clean(a.ghsa_id) || 'GHSA',
    url: clean(a.html_url || refUrl),
    title: clean(a.summary),
    body: clean(a.description),
    protocol: clean((pkg && pkg.name) || a.protocol || ''),
    date: isoDate(a.published_at || a.published),
    loss_usd: Number.isInteger(a.loss_usd) ? a.loss_usd : null,
  };
}

// An Immunefi-style disclosed report (normalized — Immunefi has no single public JSON schema).
function fromImmunefi(r) {
  r = r || {};
  return {
    source_type: 'immunefi',
    source: 'Immunefi',
    url: clean(r.url),
    title: clean(r.title),
    body: clean(r.description || r.body),
    protocol: clean(r.project || r.protocol),
    date: isoDate(r.date || r.disclosed_at),
    loss_usd: Number.isInteger(r.amount_usd) ? r.amount_usd : Number.isInteger(r.loss_usd) ? r.loss_usd : null,
  };
}

// A GitHub pull request / commit that fixes a security issue (e.g. `gh api /repos/o/r/pulls/N`).
function fromPullRequest(p) {
  p = p || {};
  const repo = (p.base && p.base.repo && p.base.repo.full_name) || p.repo || '';
  return {
    source_type: 'pr',
    source: repo ? `PR ${repo}#${clean(p.number)}` : 'PR',
    url: clean(p.html_url),
    title: clean(p.title),
    body: clean(p.body),
    protocol: clean(repo.split('/').pop() || ''),
    date: isoDate(p.merged_at || p.created_at),
    loss_usd: null,
  };
}

const ADAPTERS = { ghsa: fromGhsa, immunefi: fromImmunefi, pr: fromPullRequest };

// Dispatch on an envelope { type, data }.
function normalize(envelope) {
  const type = envelope && envelope.type;
  const fn = ADAPTERS[type];
  if (!fn) throw new Error(`unknown disclosure type "${type}" (expected one of ${Object.keys(ADAPTERS).join(', ')})`);
  return fn(envelope.data);
}

module.exports = { fromGhsa, fromImmunefi, fromPullRequest, normalize, ADAPTERS };
