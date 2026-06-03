'use strict';
// Solana Security Standard — VS Code extension entrypoint.
// Thin wiring around the pure ./diagnostics module: scan open Rust documents and
// surface SOL-0XX findings as inline warnings. Works in VS Code, Cursor, Windsurf.

const vscode = require('vscode');
const { computeDiagnostics } = require('./diagnostics');

let collection;
const timers = new Map();

function workspaceRootFor(doc) {
  const f = vscode.workspace.getWorkspaceFolder(doc.uri);
  return f ? f.uri.fsPath : undefined;
}

function enabled() {
  return vscode.workspace.getConfiguration('solanaSecurityStandard').get('enable', true);
}

function refresh(doc) {
  if (!collection || !doc) return;
  if (doc.languageId !== 'rust' || doc.uri.scheme !== 'file' || !enabled()) {
    collection.delete(doc.uri);
    return;
  }
  try {
    const descs = computeDiagnostics(doc.getText(), doc.uri.fsPath, workspaceRootFor(doc));
    const diags = descs.map((d) => {
      const range = new vscode.Range(d.startLine, d.startCol, d.endLine, d.endCol);
      const diag = new vscode.Diagnostic(range, d.message, vscode.DiagnosticSeverity.Warning);
      diag.source = 'Solana Security Standard';
      diag.code = { value: d.ruleId, target: vscode.Uri.parse(d.helpUri) };
      return diag;
    });
    collection.set(doc.uri, diags);
  } catch {
    // A scan OR mapping error must never break the editor; leave prior diagnostics as-is.
  }
}

function refreshDebounced(doc, ms = 400) {
  const key = doc.uri.toString();
  clearTimeout(timers.get(key));
  timers.set(key, setTimeout(() => { timers.delete(key); refresh(doc); }, ms));
}

function activate(context) {
  collection = vscode.languages.createDiagnosticCollection('solana-security-standard');
  context.subscriptions.push(collection);

  vscode.workspace.textDocuments.forEach(refresh);
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(refresh),
    vscode.workspace.onDidSaveTextDocument(refresh),
    vscode.workspace.onDidChangeTextDocument((e) => refreshDebounced(e.document)),
    vscode.workspace.onDidCloseTextDocument((d) => collection && collection.delete(d.uri)),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('solanaSecurityStandard.enable')) {
        vscode.workspace.textDocuments.forEach(refresh);
      }
    }),
  );
}

function deactivate() {
  for (const t of timers.values()) clearTimeout(t);
  timers.clear();
  if (collection) collection.dispose();
}

module.exports = { activate, deactivate };
