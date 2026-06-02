const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const orchestrator = require('../agent/orchestrator');
const aiReporter = require('../agent/aiReporter');
const scanDb = require('../database');

// Multer: memory storage (no disk files) for uploaded code files
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB per file
  fileFilter: (req, file, cb) => {
    const allowed = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.java', '.php', '.rb', '.cs', '.cpp', '.c', '.txt', '.html'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${ext} not supported for scanning`), false);
    }
  }
});

// ─── POST /api/scan ──────────────────────────────────────────────────────────
// Scan pasted code or up to 10 uploaded files
router.post('/', upload.array('files', 10), async (req, res) => {
  try {
    const scanId = uuidv4();
    let allFindings = [];
    let lastScanResult = null;
    let filename = 'pasted_code.js';

    // === File Upload mode (Phase 6) ===
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        const code = file.buffer.toString('utf8');
        const result = await orchestrator.runScan(code, file.originalname);
        allFindings.push(...result.findings);
        lastScanResult = result;
      }
      filename = req.files.map(f => f.originalname).join(', ');

      // Build unified summary
      const unifiedResult = {
        ...lastScanResult,
        findings: allFindings,
        summary: {
          ...lastScanResult.summary,
          totalVulnerabilities: allFindings.length,
          filesScanned: req.files.length
        }
      };
      lastScanResult = unifiedResult;

    } else {
      // === Code paste mode ===
      const { code } = req.body;
      filename = req.body.filename || 'pasted_code.js';

      if (!code) {
        return res.status(400).json({ success: false, error: 'No code content provided' });
      }

      lastScanResult = await orchestrator.runScan(code, filename);
    }

    // === Phase 5: AI Report Generation ===
    const aiReport = await aiReporter.generateReport(lastScanResult);

    // === Phase 7: Save to Database ===
    scanDb.save(scanId, filename, lastScanResult, aiReport);

    return res.status(200).json({
      ...lastScanResult,
      scanId,
      aiReport: aiReport.report,
      aiGenerated: aiReport.aiGenerated
    });

  } catch (err) {
    console.error('[Scan Route Error]', err);
    return res.status(500).json({ success: false, error: err.message || 'Internal server error' });
  }
});

// ─── GET /api/scan/history ────────────────────────────────────────────────────
// Get list of past scans
router.get('/history', (req, res) => {
  try {
    const scans = scanDb.getAll();
    res.json({ success: true, scans });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── GET /api/scan/:id ────────────────────────────────────────────────────────
// Get single scan with full report
router.get('/:id', (req, res) => {
  try {
    const scan = scanDb.getById(req.params.id);
    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found' });
    res.json({ success: true, scan });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── DELETE /api/scan/:id ─────────────────────────────────────────────────────
router.delete('/:id', (req, res) => {
  try {
    scanDb.delete(req.params.id);
    res.json({ success: true, message: 'Scan deleted' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
