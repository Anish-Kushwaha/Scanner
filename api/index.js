const express = require('express');
const app = express();
const qrcode = require('qrcode');
const jsQR = require('jsqr');
const { createCanvas, loadImage } = require('canvas');

// Your existing QR code generation and scanning logic
// (Copy from your index.js but adapt for serverless)

app.use(express.json());

app.get('/', (req, res) => {
  res.json({ 
    message: 'Scanner API is running!',
    endpoints: ['/api/generate', '/api/scan']
  });
});

// QR Generation endpoint
app.get('/api/generate', async (req, res) => {
  try {
    const { data = 'https://example.com' } = req.query;
    const qrDataUrl = await qrcode.toDataURL(data);
    res.json({ qrCode: qrDataUrl });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// QR Scanning endpoint
app.post('/api/scan', async (req, res) => {
  try {
    // Your scanning logic here
    res.json({ message: 'Scan endpoint - implement logic' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Export as Vercel serverless function
module.exports = app;
