# 🛡️ Vulnerability Scanner v3.3

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-Available-brightgreen.svg)](https://anish-kushwaha.github.io/Scanner)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-black.svg)](https://github.com/Anish-Kushwaha/Scanner)

**Advanced Web Vulnerability & Network Security Scanner with Futuristic Web Interface**  
*Created by Anish Kushwaha*

## 📋 Table of Contents
- [✨ Features](#-features)
- [🚀 Live Demo](#-live-demo)
- [🛠️ Installation](#️-installation)
- [📁 Project Structure](#-project-structure)
- [🔧 How It Works](#-how-it-works)
- [⚡ Quick Start](#-quick-start)
- [📊 Scanner Modules](#-scanner-modules)
- [🧪 Demo Mode](#-demo-mode)
- [📄 Report Generation](#-report-generation)
- [⚖️ Legal Disclaimer](#️-legal-disclaimer)
- [👨💻 About The Author](#️-about-the-author)
- [📄 License](#-license)

---

## ✨ Features

### 🔍 **Network Intelligence**
- **Port Scanning**: Comprehensive port detection with banner grabbing
- **Service Detection**: Automatic service identification on open ports
- **Vulnerability Matching**: Real-time vulnerability pattern matching
- **Rate Limiting**: Intelligent scanning to avoid detection

### 🌐 **Web Security Analysis**
- **XSS Detection**: Cross-Site Scripting vulnerability testing
- **SQL Injection**: SQLi payload testing and detection
- **Directory Traversal**: Hidden directory and file discovery
- **Server Analysis**: Header analysis and version detection

### 🚀 **Plesk Panel Scanner**
- **Admin Panel Detection**: Automatic Plesk panel identification
- **Bypass Testing**: SQL injection bypass attempt testing
- **Config Files**: Sensitive configuration file discovery
- **Known Paths**: Common Plesk vulnerability path checking

### 📊 **Reconnaissance Suite**
- **DNS Enumeration**: A, MX, TXT, CNAME record extraction
- **WHOIS Lookup**: Domain registration information gathering
- **Geolocation**: IP address geographic location mapping
- **Subdomain Discovery**: Potential subdomain identification

### 🎨 **Web Interface**
- **Futuristic UI**: Dark blue hacker-themed interface with glowing effects
- **Real-time Dashboard**: Live progress tracking and results display
- **Interactive Terminal**: Command-line style logging interface
- **Responsive Design**: Fully functional on desktop and mobile
- **JSON Export**: Complete scan report download capability

---

## 🚀 Live Demo

**🌐 Live Website:** [https://anish-kushwaha.github.io/Scanner](https://anish-kushwaha.github.io/Scanner)  
**🐙 GitHub Repository:** [https://github.com/Anish-Kushwaha/Scanner](https://github.com/Anish-Kushwaha/Scanner)

> *Note: The live demo may require local setup for full functionality. See installation section below.*

---

## 🛠️ Installation

### 📋 Prerequisites
- Python 3.8 or higher
- pip package manager
- Git (for cloning repository)
- 500MB free disk space

### 🖥️ Step-by-Step Installation

#### **Option 1: Clone from GitHub (Recommended)**
```bash
# 1. Clone the repository
git clone https://github.com/Anish-Kushwaha/Scanner.git
cd Scanner

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Create necessary directories
mkdir -p reports

# 4. Run the application
python app.py

# 5. Access in your browser
# Open: http://localhost:5000
```

#### **Option 2: Download ZIP**

1. Download the ZIP from GitHub Repository
2. Extract to your preferred location
3. Open terminal in the extracted folder
4. Follow steps 2-5 from Option 1

📦 Dependencies

The scanner automatically installs these packages:

· Flask 2.3.3 - Web framework
· requests 2.31.0 - HTTP requests
· beautifulsoup4 4.12.2 - HTML parsing
· python-whois 0.9.3 - WHOIS lookup
· dnspython 2.4.2 - DNS resolution
· Flask-CORS 4.0.0 - Cross-origin resource sharing

---

## 📁 Project Structure

```
Scanner/
├── app.py                    # Main Flask application
├── scanner_logic.py          # Core scanner logic
├── requirements.txt          # Python dependencies
├── LICENSE                   # MIT License
├── README.md                 # This documentation
├── templates/
│   └── index.html           # Main web interface
├── static/
│   ├── css/
│   │   └── style.css        # Futuristic styling
│   └── js/
│       └── script.js        # Interactive functionality
└── reports/                  # Generated scan reports
```

---

## 🔧 How It Works

### 🔄 Scanning Process Flow

1. Target Input: User enters URL (auto-fixes missing scheme)
2. Reconnaissance: DNS resolution, WHOIS lookup, geolocation
3. Network Scan: Port scanning on common ports (21-8888)
4. Web Analysis: XSS, SQLi, directory traversal testing
5. Plesk Detection: Specialized Plesk panel scanning
6. Report Generation: JSON report compilation and download

### ⚙️ Technical Architecture

· Frontend: HTML5, CSS3, JavaScript (Vanilla)
· Backend: Flask (Python) with REST API
· Database: JSON file storage (no external DB required)
· Security: Rate limiting, timeout handling, error management
· Performance: Multi-threaded scanning for speed optimization

### 🎯 Key Algorithms

1. Port Scanner: TCP SYN-based connection testing
2. Banner Grabbing: HTTP HEAD requests for service identification
3. Vulnerability Matching: Regex pattern matching for known CVEs
4. DNS Resolution: Parallel DNS record type queries
5. Geolocation: IP-based geographic data retrieval

---

## ⚡ Quick Start

### 1️⃣ Basic Usage

```python
# After installation, simply run:
python app.py
# Then open http://localhost:5000
```

### 2️⃣ Target Format Examples

```
Valid target formats:
- https://stmarysschoolbxr.org
- http://stmarysschoolbxr.org:8443
- stmarysschoolbxr.org:8443 (auto-fixes to https)
- 148.72.90.52
- 148.72.90.52:8443
```
> *Note: The above given URL, IP, PORT, and Administrative Panel, all are real. These credentials are of my school website. You can try login page of Admin Controls on .[https://148.72.90.52:8443]*

### 3️⃣ Scanning Parameters

· Timeout: 5 seconds per request
· Port Range: 21-8888 (common services)
· Threads: 10 concurrent connections
· Rate Limit: 10ms between requests

---

## **📊 Scanner Modules**

### 🔌 Network Scanner

```python
# Scans these ports by default:
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 
                443, 445, 3306, 3389, 8080, 8443, 8888]

# Banner grabbing for:
BANNER_GRAB_PORTS = [21, 22, 23, 25, 80, 110, 143, 
                     443, 3306, 3389]
```

### 🕸️ Web Vulnerability Checks
```
· XSS Payload: <script>alert('XSS')</script>
· SQLi Payload: ' OR '1'='1
· Directory List: /admin, /backup, /config, /logs
· Known Paths: /.env, /config.php, /.git/config

🚨 Vulnerability Patterns Detected

Pattern Vulnerability Severity
Apache/2.2 CVE-2017-5638 High
PHP/5.x Multiple CVEs Critical
nginx/1.x Known vulnerabilities Medium
IIS/6.x Multiple CVEs High
PleskLin CVE-2023-24044 Critical
```
---

# 🧪 Demo Mode

## The scanner includes a Demo Mode for testing without actual scanning:

### Features of Demo Mode:

· Pre-populated scan results
· All scanner modules demonstrated
· Interactive dashboard with sample data
· No network requests made
· Perfect for learning and testing

### How to Use Demo:

1. Open the scanner interface
2. Click "LOAD DEMO DATA" button
3. Explore all features with sample data
4. Understand scanner output format

### Demo Data Includes:

· Sample open ports (22, 80, 443, 3306)
· Mock vulnerabilities (XSS, SQLi)
· Example Plesk findings
· Geolocation data
· DNS records

---

### 📄 Report Generation

Report Features:

· JSON Format: Machine-readable output
· Timestamp: ISO 8601 format timing
· Comprehensive Data: All scan results included
· Downloadable: One-click export
· Structured: Organized by scan type

Report Structure:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "target_info": {
    "domain": "example.com",
    "ip": "192.168.1.1",
    "port": 8443
  },
  "geolocation": { ... },
  "whois": { ... },
  "network_scan": [ ... ],
  "web_vulnerabilities": [ ... ],
  "plesk_scan": [ ... ],
  "summary": {
    "open_ports": 4,
    "vulnerabilities_found": 3,
    "risk_level": "MEDIUM"
  }
}
```

## Using Reports:

1. Click "Download JSON Report" after scan
2. Analyze with security tools
3. Import into SIEM systems
4. Use for compliance documentation
5. Track security posture over time

---

## ⚖️ Legal Disclaimer

### ⚠️ IMPORTANT WARNING ⚠️

```
THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY.

YOU MUST:
- Have explicit written permission from system owners
- Use only on systems you own or manage
- Comply with all applicable laws and regulations
- Not use for malicious or illegal purposes

THE AUTHOR IS NOT RESPONSIBLE FOR:
- Any illegal or unauthorized use
- Damage caused by misuse
- Legal consequences of improper use
- Violation of terms of service

By using this tool, you agree to use it ethically and legally.
```

## Ethical Use Guidelines:

1. Get Permission: Always obtain written authorization
2. Define Scope: Clearly document what you're testing
3. Respect Limits: Don't overload target systems
4. Report Responsibly: Share findings with system owners
5. Follow Laws: Comply with Computer Fraud and Abuse Act

---

# 👨💻 About The Author

## 👋 Hi, I'm Anish Kushwaha

Student • Engineer • Cybersecurity Learner • Cosmology Enthusiast  

I'm passionate about understanding systems at their deepest level — from network security and penetration testing to physics and cosmology.

## 🌐 Connect With Me

[![Website](https://img.shields.io/badge/🌍%20Website-FF7139?style=for-the-badge&logo=firefox&logoColor=white)](https://Anish-kushwaha.b12sites.com)  
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Anish-Kushwaha)  
[![LeetCode](https://img.shields.io/badge/LeetCode-000000?style=for-the-badge&logo=LeetCode&logoColor=#d16c06)](https://leetcode.com/Anish-Kushwaha/)  
[![HackerRank](https://img.shields.io/badge/HackerRank-2EC866?style=for-the-badge&logo=HackerRank&logoColor=white)](https://www.hackerrank.com/Anish_Kushwaha)  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/anish-kushwaha-43a915383)  
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://x.com/Anish_Kushwaha_)  
[![Facebook](https://img.shields.io/badge/Facebook-1877F2?style=for-the-badge&logo=facebook&logoColor=white)](https://facebook.com/Anishkushwahaji)  
[![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@cosmologist_anish)  

---

> *"I don't follow the universe — I reprogram it."*  
> © 2026 Anish Kushwaha

---

## 📄 License

### This project is licensed under the MIT License - see the LICENSE file for details.

```
MIT License

Copyright (c) 2026 Anish Kushwaha

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---
```
<div align="center">

🚀 Ready to Secure Your Systems?

.[https://img.shields.io/badge/START_SCANNING-Now-blue?style=for-the-badge&logo=shield-check).

⚚Ⓐ⚚
Stay curious, stay secure.

</div>
