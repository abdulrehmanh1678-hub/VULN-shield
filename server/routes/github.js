const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { scanGitHubRepo } = require('../githubScanner');
const aiReporter = require('../agent/aiReporter');
const scanDb = require('../database');

/**
 * POST /api/github
 * Clone and scan a public GitHub repository
 */
router.post('/', async (req, res) => {
  const { repoUrl } = req.body;

  if (!repoUrl || !repoUrl.startsWith('https://github.com/')) {
    return res.status(400).json({
      success: false,
      error: 'Please provide a valid public GitHub HTTPS URL (e.g., https://github.com/owner/repo)'
    });
  }

  try {
    const scanId = uuidv4();
    const progressLogs = [];

    const onProgress = (log) => {
      progressLogs.push({ timestamp: new Date().toISOString(), ...log });
      console.log(`[GitHub Scanner] [${log.step}] ${log.message}`);
    };

    const scanResult = await scanGitHubRepo(repoUrl, onProgress);

    if (!scanResult.success) {
      return res.status(422).json(scanResult);
    }

    // AI Report generation on the combined findings
    const aiReport = await aiReporter.generateReport(scanResult);

    // Save to database
    scanDb.save(scanId, repoUrl, scanResult, aiReport);

    return res.status(200).json({
      ...scanResult,
      scanId,
      progressLogs,
      aiReport: aiReport.report,
      aiGenerated: aiReport.aiGenerated
    });

  } catch (err) {
    console.error('[GitHub Route Error]', err);
    return res.status(500).json({
      success: false,
      error: err.message || 'Failed to scan GitHub repository'
    });
  }
});

module.exports = router;
