"""
🛡️ VULNERABILITY SECURITY SCANNER v3.2
Website: Anish-Kushwaha.github.io/Scanner
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import socket
import threading
import time
import dns.resolver
import requests
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityScanner:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                            3306, 3389, 8080, 8443, 8888]
        self.banner_ports = [21, 22, 80, 443, 3306]
        
        # Admin panels to check
        self.admin_panels = [
            "/admin", "/login", "/wp-admin", "/administrator", 
            "/dashboard", "/control", "/manage", "/cpanel", 
            "/plesk", "/webadmin", "/admin.php", "/admin.asp"
        ]
        
        # Vulnerable files to check
        self.vulnerable_files = [
            "/.env", "/config.php", "/.git/config", "/phpinfo.php",
            "/test.php", "/debug.php", "/backup.zip", "/backup.sql",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/.htaccess", "/web.config", "/README.md", "/CHANGELOG.md"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        # SQLi payloads
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1--",
            "admin'--"
        ]
    
    def parse_url(self, url):
        """Parse URL and get domain, port"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        return {
            'domain': domain,
            'port': port,
            'full_url': url,
            'scheme': parsed.scheme
        }
    
    def resolve_ip(self, domain):
        """Get IP address from domain"""
        try:
            return socket.gethostbyname(domain)
        except:
            return None
    
    def scan_port(self, ip, port):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Get banner
                banner = ""
                if port in self.banner_ports:
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    except:
                        banner = "Open"
                
                # Check vulnerabilities in banner
                vulnerabilities = []
                if "Apache/2.2" in banner:
                    vulnerabilities.append("Outdated Apache (CVE-2017-5638)")
                if "PHP/5." in banner:
                    vulnerabilities.append("Outdated PHP version")
                if "nginx/1." in banner:
                    vulnerabilities.append("Outdated nginx")
                if "IIS/6." in banner:
                    vulnerabilities.append("Outdated IIS")
                
                return {
                    'port': port,
                    'status': 'OPEN',
                    'banner': banner[:200] if banner else "",
                    'vulnerabilities': vulnerabilities,
                    'service': self.get_service_name(port)
                }
            sock.close()
        except:
            pass
        
        return None
    
    def scan_ports(self, ip):
        """Scan all common ports"""
        open_ports = []
        threads = []
        results = []
        
        def scan_and_collect(ip, port):
            result = self.scan_port(ip, port)
            if result:
                results.append(result)
        
        # Create threads for each port
        for port in self.common_ports:
            t = threading.Thread(target=scan_and_collect, args=(ip, port))
            threads.append(t)
            t.start()
            time.sleep(0.01)  # Rate limiting
        
        # Wait for threads to complete
        for t in threads:
            t.join(timeout=3)
        
        return sorted(results, key=lambda x: x['port'])
    
    def get_service_name(self, port):
        """Get service name from port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 139: 'NETBIOS',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MYSQL',
            3389: 'RDP', 8080: 'HTTP-PROXY', 8443: 'HTTPS-ALT',
            8888: 'HTTP-ALT'
        }
        return services.get(port, f'PORT-{port}')
    
    def get_dns_info(self, domain):
        """Get DNS records"""
        info = {'A': [], 'MX': [], 'TXT': [], 'CNAME': []}
        
        try:
            # A records
            answers = dns.resolver.resolve(domain, 'A')
            info['A'] = [str(r) for r in answers]
        except:
            info['A'] = []
        
        try:
            # MX records
            answers = dns.resolver.resolve(domain, 'MX')
            info['MX'] = [str(r.exchange) for r in answers]
        except:
            info['MX'] = []
        
        try:
            # TXT records
            answers = dns.resolver.resolve(domain, 'TXT')
            info['TXT'] = [str(r) for r in answers]
        except:
            info['TXT'] = []
        
        return info
    
    def get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            import whois
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
                'name_servers': w.name_servers[:3] if w.name_servers else []
            }
        except:
            return {'error': 'WHOIS lookup failed'}
    
    def get_geolocation(self, ip):
        """Get IP location"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            data = response.json()
            
            if data['status'] == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'timezone': data.get('timezone', 'Unknown')
                }
        except:
            pass
        
        return {'error': 'Geolocation failed'}
    
    def scan_admin_panels(self, url):
        """Check for admin panels"""
        found_panels = []
        
        for panel in self.admin_panels:
            try:
                panel_url = f"{url.rstrip('/')}/{panel.lstrip('/')}"
                response = requests.get(panel_url, timeout=3, verify=False)
                
                if response.status_code < 400:
                    found_panels.append({
                        'url': panel_url,
                        'status': response.status_code,
                        'panel': panel,
                        'severity': 'HIGH' if response.status_code == 200 else 'MEDIUM'
                    })
            except:
                continue
        
        return found_panels
    
    def scan_vulnerable_files(self, url):
        """Check for vulnerable/exposed files"""
        found_files = []
        
        for file_path in self.vulnerable_files:
            try:
                file_url = f"{url.rstrip('/')}/{file_path.lstrip('/')}"
                response = requests.get(file_url, timeout=3, verify=False)
                
                if response.status_code < 400:
                    found_files.append({
                        'url': file_url,
                        'status': response.status_code,
                        'file': file_path,
                        'severity': 'HIGH' if '.env' in file_path or 'config' in file_path else 'MEDIUM'
                    })
            except:
                continue
        
        return found_files
    
    def scan_xss(self, url):
        """Check for XSS vulnerabilities"""
        xss_vulns = []
        
        for payload in self.xss_payloads:
            try:
                test_url = f"{url}?test={payload}"
                response = requests.get(test_url, timeout=3, verify=False)
                
                if payload in response.text:
                    xss_vulns.append({
                        'type': 'XSS',
                        'url': test_url,
                        'payload': payload,
                        'severity': 'CRITICAL'
                    })
                    break
            except:
                continue
        
        return xss_vulns
    
    def scan_sqli(self, url):
        """Check for SQL injection"""
        sqli_vulns = []
        
        for payload in self.sqli_payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=3, verify=False)
                
                if any(word in response.text.lower() for word in ['sql', 'syntax', 'mysql', 'error', 'warning']):
                    sqli_vulns.append({
                        'type': 'SQLi',
                        'url': test_url,
                        'payload': payload,
                        'severity': 'CRITICAL'
                    })
                    break
            except:
                continue
        
        return sqli_vulns
    
    def scan_web_security(self, url):
        """Complete web security scan"""
        vulnerabilities = []
        
        # Get basic info
        try:
            headers = {'User-Agent': 'Anish-Security-Scanner/3.2'}
            response = requests.get(url, timeout=5, verify=False, headers=headers)
            
            server_info = {
                'status': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'security_headers': {
                    'x-frame-options': response.headers.get('X-Frame-Options', 'MISSING'),
                    'x-content-type-options': response.headers.get('X-Content-Type-Options', 'MISSING'),
                    'x-xss-protection': response.headers.get('X-XSS-Protection', 'MISSING'),
                    'content-security-policy': response.headers.get('Content-Security-Policy', 'MISSING'),
                    'strict-transport-security': response.headers.get('Strict-Transport-Security', 'MISSING')
                }
            }
            
            # Check for missing security headers
            for header, value in server_info['security_headers'].items():
                if value == 'MISSING':
                    vulnerabilities.append({
                        'type': 'MISSING_SECURITY_HEADER',
                        'header': header.upper(),
                        'severity': 'MEDIUM',
                        'description': f'Missing {header} security header'
                    })
            
            # Check server version vulnerabilities
            server = server_info['server'].lower()
            if 'apache/2.2' in server:
                vulnerabilities.append({
                    'type': 'OUTDATED_SERVER',
                    'severity': 'HIGH',
                    'description': 'Outdated Apache 2.2 - Vulnerable to multiple CVEs'
                })
            if 'nginx/1.' in server:
                vulnerabilities.append({
                    'type': 'OUTDATED_SERVER',
                    'severity': 'MEDIUM',
                    'description': 'Outdated nginx version'
                })
            
        except Exception as e:
            server_info = {'error': str(e)}
        
        # Run vulnerability scans
        vulnerabilities.extend(self.scan_xss(url))
        vulnerabilities.extend(self.scan_sqli(url))
        
        # Find admin panels
        admin_panels = self.scan_admin_panels(url)
        
        # Find exposed files
        exposed_files = self.scan_vulnerable_files(url)
        
        return {
            'server_info': server_info,
            'vulnerabilities': vulnerabilities,
            'admin_panels': admin_panels,
            'exposed_files': exposed_files
        }
    
    def run_full_scan(self, target_url):
        """Run complete security scan"""
        start_time = datetime.now()
        
        # Parse URL
        url_info = self.parse_url(target_url)
        domain = url_info['domain']
        
        # Resolve IP
        ip = self.resolve_ip(domain)
        
        if not ip:
            return {'error': f'Could not resolve IP for {domain}'}
        
        # Initialize results
        results = {
            'target_info': {
                'original_url': target_url,
                'domain': domain,
                'ip': ip,
                'port': url_info['port'],
                'full_url': url_info['full_url']
            },
            'timestamp': datetime.now().isoformat(),
            'scan_progress': '10% - Gathering information...'
        }
        
        # 1. Geolocation
        results['scan_progress'] = '20% - Getting location...'
        results['geolocation'] = self.get_geolocation(ip)
        
        # 2. DNS Information
        results['scan_progress'] = '30% - Checking DNS...'
        results['dns_info'] = self.get_dns_info(domain)
        
        # 3. WHOIS Information
        results['scan_progress'] = '40% - WHOIS lookup...'
        results['whois_info'] = self.get_whois_info(domain)
        
        # 4. Port Scanning
        results['scan_progress'] = '50% - Scanning ports...'
        results['port_scan'] = self.scan_ports(ip)
        
        # 5. Web Security Scan
        results['scan_progress'] = '70% - Web vulnerability scan...'
        web_results = self.scan_web_security(url_info['full_url'])
        results.update(web_results)
        
        # Calculate statistics
        open_ports = len(results.get('port_scan', []))
        vulnerabilities = len(results.get('vulnerabilities', []))
        admin_panels = len(results.get('admin_panels', []))
        exposed_files = len(results.get('exposed_files', []))
        
        # Determine risk level
        total_issues = vulnerabilities + admin_panels + exposed_files
        if total_issues > 5:
            risk_level = 'CRITICAL 🔴'
        elif total_issues > 2:
            risk_level = 'HIGH 🟠'
        elif total_issues > 0:
            risk_level = 'MEDIUM 🟡'
        else:
            risk_level = 'LOW 🟢'
        
        # Final results
        results['scan_progress'] = '100% - Scan complete!'
        results['scan_duration'] = str(datetime.now() - start_time)
        
        results['summary'] = {
            'open_ports': open_ports,
            'vulnerabilities_found': vulnerabilities,
            'admin_panels_found': admin_panels,
            'exposed_files_found': exposed_files,
            'total_issues': total_issues,
            'risk_level': risk_level,
            'scan_time': results['scan_duration']
        }
        
        return results

# ==================== HTTP SERVER FOR VERCEL ====================
class ScannerHTTPHandler(BaseHTTPRequestHandler):
    scanner = SecurityScanner()
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/':
            # Serve HTML interface
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            html = self.get_html_interface()
            self.wfile.write(html.encode())
        
        elif self.path == '/health':
            # Health check endpoint
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {
                'status': 'online',
                'service': 'Anish Security Scanner v3.2',
                'timestamp': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path.startswith('/scan?target='):
            # Handle scan via GET
            query = self.path.split('?')[1] if '?' in self.path else ''
            params = parse_qs(query)
            target = params.get('target', [''])[0]
            
            if target:
                self.handle_scan(target)
            else:
                self.send_error(400, 'Target parameter required')
        
        else:
            self.send_error(404, 'Endpoint not found')
    
    def do_POST(self):
        """Handle POST requests (scan)"""
        if self.path == '/scan':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode())
                target = data.get('target', '')
                
                if target:
                    self.handle_scan(target)
                else:
                    self.send_error(400, 'Target parameter required')
            except:
                self.send_error(400, 'Invalid JSON data')
        else:
            self.send_error(404, 'Endpoint not found')
    
    def handle_scan(self, target):
        """Process scan request"""
        try:
            # Run the scan
            results = self.scanner.run_full_scan(target)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps(results, indent=2).encode())
            
        except Exception as e:
            self.send_error(500, f'Scan failed: {str(e)}')
    
    def get_html_interface(self):
        """Generate HTML interface"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Anish Security Scanner v3.2</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            border-bottom: 2px solid #00ff00;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .glitch {
            font-size: 3em;
            text-shadow: 2px 2px 0 #ff0000;
            animation: glitch 1s infinite;
        }
        @keyframes glitch {
            0% { transform: translate(0); }
            20% { transform: translate(-2px, 2px); }
            40% { transform: translate(-2px, -2px); }
            60% { transform: translate(2px, 2px); }
            80% { transform: translate(2px, -2px); }
            100% { transform: translate(0); }
        }
        .scanner-box {
            background: #111;
            border: 1px solid #00ff00;
            padding: 20px;
            margin-bottom: 20px;
        }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            background: #000;
            border: 1px solid #00ff00;
            color: #00ff00;
            font-family: monospace;
        }
        button {
            padding: 10px 20px;
            background: #00ff00;
            color: #000;
            border: none;
            font-weight: bold;
            cursor: pointer;
        }
        .results {
            display: none;
        }
        .loading {
            color: #ffff00;
            font-style: italic;
        }
        .critical { color: #ff0000; }
        .high { color: #ff6600; }
        .medium { color: #ffff00; }
        .low { color: #00ff00; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="glitch">VULNERABILITY SECURITY SCANNER</h1>
            <h3>v3.2 - Advanced Vulnerability Scanner</h3>
            <p>Website: Anish-Kushwaha.github.io/Scanner</p>
            <p>⚠️ FOR AUTHORIZED SECURITY TESTING ONLY</p>
        </div>
        
        <div class="scanner-box">
            <h2>🔍 TARGET SCANNING</h2>
            <input type="text" id="targetUrl" placeholder="Enter target URL (example.com or https://example.com:8443)">
            <button onclick="startScan()">START SCAN</button>
            
            <div id="loading" class="loading" style="display: none;">
                Scanning in progress... Please wait.
            </div>
        </div>
        
        <div id="results" class="results">
            <!-- Results will be displayed here -->
        </div>
    </div>
    
    <script>
        async function startScan() {
            const target = document.getElementById('targetUrl').value.trim();
            if (!target) {
                alert('Please enter a target URL');
                return;
            }
            
            document.getElementById('loading').style.display = 'block';
            
            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ target: target })
                });
                
                const data = await response.json();
                displayResults(data);
                
            } catch (error) {
                alert('Scan failed: ' + error.message);
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        }
        
        function displayResults(data) {
            const resultsDiv = document.getElementById('results');
            resultsDiv.style.display = 'block';
            
            let html = `
                <div class="scanner-box">
                    <h2>🎯 TARGET INFORMATION</h2>
                    <p><strong>Domain:</strong> ${data.target_info.domain}</p>
                    <p><strong>IP Address:</strong> ${data.target_info.ip}</p>
                    <p><strong>Port:</strong> ${data.target_info.port}</p>
                </div>
                
                <div class="scanner-box">
                    <h2>📍 GEOLOCATION</h2>
                    <p><strong>Country:</strong> ${data.geolocation.country || 'Unknown'}</p>
                    <p><strong>City:</strong> ${data.geolocation.city || 'Unknown'}</p>
                    <p><strong>ISP:</strong> ${data.geolocation.isp || 'Unknown'}</p>
                </div>
                
                <div class="scanner-box">
                    <h2>📊 SCAN SUMMARY</h2>
                    <p><strong>Risk Level:</strong> <span class="${data.summary.risk_level.toLowerCase().split(' ')[0]}">${data.summary.risk_level}</span></p>
                    <p><strong>Open Ports:</strong> ${data.summary.open_ports}</p>
                    <p><strong>Vulnerabilities Found:</strong> ${data.summary.vulnerabilities_found}</p>
                    <p><strong>Admin Panels:</strong> ${data.summary.admin_panels_found}</p>
                    <p><strong>Scan Duration:</strong> ${data.summary.scan_time}</p>
                </div>
            `;
            
            // Add vulnerabilities if found
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                html += `<div class="scanner-box">
                    <h2>⚠️ VULNERABILITIES FOUND</h2>`;
                
                data.vulnerabilities.forEach(vuln => {
                    html += `<p class="${vuln.severity.toLowerCase()}">
                        <strong>${vuln.type}</strong>: ${vuln.description || vuln.payload}
                    </p>`;
                });
                
                html += `</div>`;
            }
            
            resultsDiv.innerHTML = html;
        }
    </script>
</body>
</html>
"""

# ==================== VERCEL SERVERLESS HANDLER ====================
def handler(event, context):
    """Vercel serverless function handler"""
    from io import StringIO
    import sys
    
    # Capture output
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    
    try:
        # Create handler instance
        handler = ScannerHTTPHandler()
        
        # Parse event
        method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        body = event.get('body', '')
        headers = event.get('headers', {})
        
        # Process request
        if method == 'GET' and path == '/':
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/html',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': handler.get_html_interface()
            }
        
        elif method == 'POST' and path == '/scan':
            if not body:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'No target provided'})
                }
            
            try:
                data = json.loads(body)
                target = data.get('target', '')
                
                if not target:
                    return {
                        'statusCode': 400,
                        'headers': {'Content-Type': 'application/json'},
                        'body': json.dumps({'error': 'Target parameter required'})
                    }
                
                # Run scan
                scanner = SecurityScanner()
                results = scanner.run_full_scan(target)
                
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps(results)
                }
                
            except Exception as e:
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': str(e)})
                }
        
        else:
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Endpoint not found'})
            }
    
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': str(e)})
        }
    
    finally:
        sys.stdout = old_stdout

# ==================== LOCAL DEVELOPMENT ====================
if __name__ == "__main__":
    # Run local development server
    print("🚀 Starting Vulnerabilities Security Scanner v3.2...")
    print("🌐 Open: http://localhost:8080")
    print("🔒 Scanner is ready for testing!")
    print("=" * 50)
    
    server = HTTPServer(('localhost', 8080), ScannerHTTPHandler)
    server.serve_forever()
