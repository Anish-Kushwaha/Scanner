const express = require('express');
const cors = require('cors');
const scanner = require('./api/scanner.js');
const app = express();

app.use(cors());
app.use(express.json());

// Root route - Scanner dashboard
app.get('/', (req, res) => {
  res.json({
    name: 'Vulnerability Security Scanner',
    version: '3.2',
    author: 'ANISH KUSHWAHA',
    endpoints: {
      scan: 'POST /api/scan',
      status: 'GET /api/status',
      report: 'GET /api/report/:id'
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Main scanning endpoint
app.post('/api/scan', async (req, res) => {
  try {
    const { target } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target URL is required' });
    }

    console.log(`[SCAN] Starting scan for: ${target}`);
    
    // Run vulnerability scan
    const scanResults = await scanner.scanTarget(target);
    
    res.json({
      success: true,
      target: target,
      timestamp: new Date().toISOString(),
      results: scanResults
    });
    
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Get scan status
app.get('/api/status', (req, res) => {
  res.json({
    scanner: 'active',
    last_scan: new Date().toISOString(),
    uptime: process.uptime()
  });
});

module.exports = app;
