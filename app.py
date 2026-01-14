from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import json
import logging
from datetime import datetime
from scanner_logic import AnishSecurityScanner
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.json
        target_url = data.get('target_url', '').strip()
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Initialize scanner
        scanner = AnishSecurityScanner()
        
        # Start scanning
        results = scanner.run_complete_scan(target_url)
        
        # Generate report file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"scan_report_{timestamp}.json"
        
        with open(f"reports/{report_filename}", 'w') as f:
            json.dump(results, f, indent=4)
        
        results['report_filename'] = report_filename
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<filename>')
def get_report(filename):
    try:
        with open(f"reports/{filename}", 'r') as f:
            report_data = json.load(f)
        return jsonify(report_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

if __name__ == '__main__':
    # Create reports directory if it doesn't exist
    os.makedirs('reports', exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)
