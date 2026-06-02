const express = require('express');
const router = express.Router();
const { generatePDF } = require('../pdfGenerator');
const scanDb = require('../database');

/**
 * GET /api/export/:id/pdf
 * Generate and download a PDF report for a given scan ID
 */
router.get('/:id/pdf', async (req, res) => {
  try {
    const scan = scanDb.getById(req.params.id);
    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found' });

    const fullReport = scan.full_report || {};
    const { scanResults, aiReport } = fullReport;

    const pdfBuffer = await generatePDF(scanResults || {}, aiReport || {});

    const filename = `vulnshield_report_${req.params.id.slice(0, 8)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.end(pdfBuffer);

  } catch (err) {
    console.error('[Export PDF Error]', err);
    res.status(500).json({ success: false, error: 'Failed to generate PDF: ' + err.message });
  }
});

/**
 * GET /api/export/:id/json
 * Download the full scan data as a JSON file
 */
router.get('/:id/json', (req, res) => {
  try {
    const scan = scanDb.getById(req.params.id);
    if (!scan) return res.status(404).json({ success: false, error: 'Scan not found' });

    const filename = `vulnshield_report_${req.params.id.slice(0, 8)}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.json({ exportedAt: new Date().toISOString(), scan });

  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
