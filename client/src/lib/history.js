/**
 * Scan history persisted in the browser via localStorage.
 * Replaces the original SQLite-backed server history so the app is fully
 * self-contained on a static host (Vercel).
 */

const KEY = 'vs-scan-history';
const MAX_ENTRIES = 50;

function readAll() {
  try {
    return JSON.parse(localStorage.getItem(KEY) || '[]');
  } catch {
    return [];
  }
}

function writeAll(entries) {
  localStorage.setItem(KEY, JSON.stringify(entries.slice(0, MAX_ENTRIES)));
}

/**
 * Save a completed scan. `results` is the full scanResults object the UI uses
 * (findings, recon, aiReport, agentLogs, scanId, ...).
 */
export function saveScan(results) {
  const entries = readAll();
  const record = {
    id: results.scanId,
    filename: results.filename || results.summary?.filename || 'pasted_code.js',
    created_at: new Date().toISOString(),
    risk_label: results.aiReport?.riskLabel || 'Secure',
    total_vulnerabilities: results.findings?.length || 0,
    language: results.recon?.language || 'unknown',
    ai_generated: !!results.aiGenerated,
    full: results
  };
  // De-dupe by id, newest first
  const next = [record, ...entries.filter(e => e.id !== record.id)];
  writeAll(next);
  return record;
}

/** List metadata for all scans (newest first). */
export function getHistory() {
  return readAll();
}

/** Get the full stored scanResults for a given id. */
export function getScan(id) {
  return readAll().find(e => e.id === id)?.full || null;
}

export function deleteScan(id) {
  writeAll(readAll().filter(e => e.id !== id));
}

export function clearHistory() {
  localStorage.removeItem(KEY);
}
