const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const scanRouter = require('./routes/scan');
const githubRouter = require('./routes/github');
const exportRouter = require('./routes/export');
const aiReporter = require('./agent/aiReporter');

const app = express();
const PORT = process.env.PORT || 5000;
const clientDist = path.join(__dirname, '..', 'client', 'dist');

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// JSON body parser (skip for multipart/form-data, multer handles that)
app.use((req, res, next) => {
  if (req.headers['content-type'] && req.headers['content-type'].includes('multipart/form-data')) {
    return next();
  }
  express.json({ limit: '10mb' })(req, res, next);
});

app.use(express.urlencoded({ extended: true }));

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/scan', scanRouter);
app.use('/api/github', githubRouter);
app.use('/api/export', exportRouter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    aiEnabled: aiReporter.isConfigured(),
    aiProvider: aiReporter.getProviderLabel()
  });
});

// Serve React frontend in production
if (fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get(/^(?!\/api).*/, (req, res) => {
    res.sendFile(path.join(clientDist, 'index.html'));
  });
}

// ─── Error Handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Server Error]', err.stack);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  const aiLabel = aiReporter.isConfigured()
    ? `✓ ${aiReporter.getProviderLabel()} Connected`
    : '✗ No API Key (Static Mode)';
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║       VulnShield Security Scanner            ║
  ║  Server running on http://localhost:${PORT}     ║
  ║  AI Report: ${aiLabel.padEnd(28)} ║
  ╚══════════════════════════════════════════════╝
  `);
});

module.exports = app;
