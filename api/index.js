// This file routes requests to Python scanner
const { spawn } = require('child_process');
const path = require('path');

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { target } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target URL is required' });
    }

    // Run Python scanner
    const pythonProcess = spawn('python3', [
      path.join(__dirname, 'index.py'),
      '--target', target
    ]);

    let result = '';
    let error = '';

    pythonProcess.stdout.on('data', (data) => {
      result += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      error += data.toString();
    });

    pythonProcess.on('close', (code) => {
      if (code !== 0) {
        return res.status(500).json({ 
          error: `Python scanner failed: ${error}`,
          code: code
        });
      }

      try {
        const parsedResult = JSON.parse(result);
        res.json(parsedResult);
      } catch (e) {
        res.json({ raw_result: result, error: error });
      }
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
