const express = require('express');
const qrcode = require('qrcode');
const jsQR = require('jsqr');
const { createCanvas, loadImage } = require('canvas');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();

// Middleware - CRITICAL
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configure multer for file uploads
const upload = multer({ 
  dest: '/tmp/uploads/',  // Use Vercel's writable tmp directory
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// ========== ROOT ROUTE (ELIMINATES 404) ==========
app.get('/', (req, res) => {
  res.json({
    message: '✅ Scanner QR Code API - DEPLOYED & WORKING',
    status: 'Online',
    version: '2.0',
    deployed_on: 'Vercel',
    repo: 'https://github.com/Anish-Kushwaha/Scanner',
    endpoints: [
      'GET  /generate?data=YourText',
      'POST /scan (JSON: {imageUrl: "https://..."})',
      'POST /scan-file (multipart form with "file" field)',
      'GET  /generate-vcard?name=X&phone=Y&email=Z',
      'GET  /generate-wifi?ssid=X&password=Y&encryption=WPA2'
    ],
    example: 'https://scanner-rose-rho.vercel.app/generate?data=HelloWorld',
    note: 'Frontend can call these endpoints directly'
  });
});

// ========== 1. GENERATE QR CODE ==========
app.get('/generate', async (req, res) => {
  try {
    const { data = 'https://github.com/Anish-Kushwaha/Scanner' } = req.query;
    
    if (!data || data.trim() === '') {
      return res.status(400).json({ error: 'Missing "data" query parameter' });
    }
    
    const qrDataUrl = await qrcode.toDataURL(data);
    res.json({ 
      success: true,
      qrCode: qrDataUrl,  // Base64 image
      data: data,
      format: 'data:image/png;base64'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ========== 2. SCAN QR FROM URL ==========
app.post('/scan', async (req, res) => {
  try {
    const { imageUrl } = req.body;
    
    if (!imageUrl) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing "imageUrl" in request body' 
      });
    }
    
    // Load image from URL
    const image = await loadImage(imageUrl);
    const canvas = createCanvas(image.width, image.height);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(image, 0, 0);
    
    // Extract image data
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    
    // Decode QR
    const decoded = jsQR(imageData.data, imageData.width, imageData.height);
    
    if (decoded) {
      res.json({
        success: true,
        data: decoded.data,
        version: decoded.version,
        location: decoded.location
      });
    } else {
      res.json({
        success: false,
        error: 'No QR code found in image'
      });
    }
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ========== 3. SCAN QR FROM FILE UPLOAD ==========
app.post('/scan-file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        error: 'No file uploaded. Use field name "file"' 
      });
    }
    
    const filePath = req.file.path;
    
    // Load uploaded image
    const image = await loadImage(filePath);
    const canvas = createCanvas(image.width, image.height);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(image, 0, 0);
    
    // Extract image data
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    
    // Decode QR
    const decoded = jsQR(imageData.data, imageData.width, imageData.height);
    
    // Clean up uploaded file (important for Vercel)
    fs.unlinkSync(filePath);
    
    if (decoded) {
      res.json({
        success: true,
        data: decoded.data,
        originalname: req.file.originalname
      });
    } else {
      res.json({
        success: false,
        error: 'No QR code found in uploaded image'
      });
    }
  } catch (error) {
    // Clean up file if exists
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ========== 4. GENERATE VCARD QR ==========
app.get('/generate-vcard', async (req, res) => {
  try {
    const { 
      name = 'John Doe', 
      phone = '+1234567890', 
      email = 'john@example.com',
      organization = 'ACME Inc'
    } = req.query;
    
    const vcardData = 
`BEGIN:VCARD
VERSION:3.0
FN:${name}
TEL:${phone}
EMAIL:${email}
ORG:${organization}
END:VCARD`;
    
    const qrDataUrl = await qrcode.toDataURL(vcardData);
    
    res.json({
      success: true,
      qrCode: qrDataUrl,
      contact: { name, phone, email, organization },
      vcard: vcardData,
      note: 'Scan this QR to save contact'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ========== 5. GENERATE WIFI QR ==========
app.get('/generate-wifi', async (req, res) => {
  try {
    const { 
      ssid = 'MyWiFi',
      password = 'SecurePassword123',
      encryption = 'WPA',
      hidden = 'false'
    } = req.query;
    
    const wifiData = `WIFI:S:${ssid};T:${encryption};P:${password};H:${hidden};;`;
    
    const qrDataUrl = await qrcode.toDataURL(wifiData);
    
    res.json({
      success: true,
      qrCode: qrDataUrl,
      wifi: { ssid, password: '••••••••', encryption, hidden },
      wifiString: wifiData,
      note: 'Scan this QR to connect to WiFi'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ========== 6. HEALTH CHECK ==========
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    memory: process.memoryUsage(),
    uptime: process.uptime()
  });
});

// ========== ERROR HANDLER ==========
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: err.message
  });
});

// ========== VERCEL SERVERLESS EXPORT ==========
// REMOVE app.listen() - Vercel doesn't use it
// ADD this line instead:
module.exports = app;
