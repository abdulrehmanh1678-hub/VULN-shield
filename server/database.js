/**
 * Database Layer (Phase 7)
 * Uses better-sqlite3 for a zero-setup, file-based SQLite database to persist
 * scan history and their associated reports.
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(path.join(dataDir, 'vulnshield.db'));

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

/**
 * Initialize schema on first run
 */
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    language TEXT,
    framework TEXT,
    total_vulnerabilities INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    risk_label TEXT DEFAULT 'Unknown',
    ai_generated INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    code_snippet TEXT,
    full_report TEXT
  );
`);

const scanDb = {
  /**
   * Insert a completed scan record into the database.
   */
  save(id, filename, scanResults, aiReport) {
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO scans 
        (id, filename, language, framework, total_vulnerabilities, risk_score, risk_label, ai_generated, created_at, code_snippet, full_report)
      VALUES 
        (@id, @filename, @language, @framework, @total_vulnerabilities, @risk_score, @risk_label, @ai_generated, @created_at, @code_snippet, @full_report)
    `);
    
    stmt.run({
      id,
      filename,
      language: scanResults.summary?.language || 'Unknown',
      framework: scanResults.summary?.framework || 'Unknown',
      total_vulnerabilities: scanResults.summary?.totalVulnerabilities || 0,
      risk_score: aiReport?.report?.riskScore || 0,
      risk_label: aiReport?.report?.riskLabel || 'Unknown',
      ai_generated: aiReport?.aiGenerated ? 1 : 0,
      created_at: new Date().toISOString(),
      code_snippet: null, // Don't store full code for privacy
      full_report: JSON.stringify({ scanResults, aiReport })
    });
  },

  /**
   * Get all scans (summary list for history sidebar).
   */
  getAll() {
    return db.prepare(`
      SELECT id, filename, language, framework, total_vulnerabilities, risk_score, risk_label, ai_generated, created_at
      FROM scans
      ORDER BY created_at DESC
      LIMIT 50
    `).all();
  },

  /**
   * Get a single scan by ID (full report data).
   */
  getById(id) {
    const row = db.prepare('SELECT * FROM scans WHERE id = ?').get(id);
    if (!row) return null;
    try {
      row.full_report = JSON.parse(row.full_report);
    } catch (e) {
      row.full_report = null;
    }
    return row;
  },

  /**
   * Delete a scan record.
   */
  delete(id) {
    db.prepare('DELETE FROM scans WHERE id = ?').run(id);
  },

  /**
   * Get count of scans.
   */
  getCount() {
    return db.prepare('SELECT COUNT(*) as count FROM scans').get().count;
  }
};

module.exports = scanDb;
