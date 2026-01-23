from http.server import BaseHTTPRequestHandler
import json
import requests
import socket
import re
import time
from urllib.parse import urlparse, urljoin
from datetime import datetime
import sys

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

class handler(BaseHTTPRequestHandler):
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {
                "name": "⚠️ VULNERABILITY SECURITY SCANNER",
                "version": "3.2",
                "author": "ANISH KUSHWAHA",
                "website": "Anish-kushwaha.b1zisites.com",
                "email": "Anish-Kushwaha@zohomail.in",
                "endpoints": {
                    "scan": "POST /api/scan with JSON: {\"target\": \"url\"}",
                    "health": "GET /health"
                },
                "features": [
                    "Port Scanning",
                    "Geolocation Lookup",
                    "Server Detection",
                    "SQL Injection Testing",
                    "XSS Vulnerability Testing",
                    "Directory Bruteforce",
                    "Security Headers Check"
                ],
                "warning": "Unauthorized scanning is illegal. Use only on systems you own or have permission for."
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
            
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "service": "Vulnerability Scanner API",
                "version": "3.2"
            }).encode())
            
        elif self.path == '/api/scan':
            # Demo response for GET request
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                "message": "Use POST method with JSON: {\"target\": \"url\"}",
                "example": {"target": "https://example.com"},
                "demo_data": self.get_demo_data()
            }).encode())
            
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "Endpoint not found",
                "available_endpoints": ["/", "/health", "/api/scan (POST)"]
            }).encode())
    
    def do_POST(self):
        if self.path == '/api/scan':
            try:
                # Read JSON data
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                target = data.get('target', '').strip()
                
                if not target:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "error": "Target URL is required",
                        "example": {"target": "https://example.com"}
                    }).encode())
                    return
                
                print(f"[SCAN] Starting vulnerability scan for: {target}")
                
                # Run full vulnerability scan
                scan_results = self.full_vulnerability_scan(target)
                
                # Send response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(scan_results, indent=2).encode())
                
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "Invalid JSON format",
                    "example": {"target": "https://example.com"}
                }).encode())
                
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": f"Scanner error: {str(e)}",
                    "target": target if 'target' in locals() else "unknown"
                }).encode())
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "Endpoint not found"
            }).encode())
    
    # ================= SCANNER FUNCTIONS =================
    
    def full_vulnerability_scan(self, target_url):
        """Complete vulnerability scanner with all features"""
        print(f"[SCAN] Starting comprehensive scan for: {target_url}")
        
        results = {
            "scan_id": f"scan_{int(time.time())}",
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "Full Security Audit",
            "scan_status": "completed",
            "vulnerabilities": [],
            "network_info": {},
            "web_info": {},
            "geolocation": {},
            "technologies": [],
            "summary": {}
        }
        
        try:
            # Auto-fix URL scheme if missing
            if not urlparse(target_url).scheme:
                target_url = "https://" + target_url
                results["target_fixed"] = target_url
            
            # Parse URL
            parsed = urlparse(target_url)
            domain = parsed.netloc.split(':')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            protocol = parsed.scheme
            
            print(f"[INFO] Parsed: Domain={domain}, Port={port}, Protocol={protocol}")
            
            # 1. Get IP address
            ip_address = self.resolve_dns(domain)
            results["network_info"]["domain"] = domain
            results["network_info"]["ip"] = ip_address if ip_address else "Could not resolve"
            results["network_info"]["port"] = port
            results["network_info"]["protocol"] = protocol
            
            if ip_address and ip_address != "Could not resolve":
                print(f"[INFO] Resolved IP: {ip_address}")
                
                # 2. Get geolocation
                print("[INFO] Getting geolocation...")
                results["geolocation"] = self.get_geolocation(ip_address)
                
                # 3. Port scan
                print("[INFO] Starting port scan...")
                open_ports = self.port_scan(ip_address)
                results["network_info"]["open_ports"] = open_ports
                results["network_info"]["open_ports_count"] = len(open_ports)
                
                # Check for vulnerable services
                for port_info in open_ports:
                    if port_info["service"] in ["ftp", "telnet"]:
                        results["vulnerabilities"].append({
                            "id": f"vuln_{len(results['vulnerabilities']) + 1}",
                            "type": "Insecure Service",
                            "service": port_info["service"],
                            "port": port_info["port"],
                            "risk": "MEDIUM",
                            "description": f"{port_info['service'].upper()} service exposed on default port (no encryption)",
                            "recommendation": "Use SFTP/SSH instead of FTP/Telnet"
                        })
                    
                    # Check for outdated services in banner
                    banner = port_info.get("banner", "").lower()
                    if "apache/2.2" in banner:
                        results["vulnerabilities"].append({
                            "id": f"vuln_{len(results['vulnerabilities']) + 1}",
                            "type": "Outdated Software",
                            "service": "Apache",
                            "version": "2.2",
                            "risk": "HIGH",
                            "description": "Outdated Apache version 2.2 detected",
                            "cve": "CVE-2017-5638"
                        })
            
            # 4. Web vulnerability checks
            print("[INFO] Checking web vulnerabilities...")
            web_results = self.web_vulnerability_checks(target_url)
            results["web_info"] = web_results
            
            # Add server warnings as vulnerabilities
            for warning in web_results.get("warnings", []):
                results["vulnerabilities"].append({
                    "id": f"vuln_{len(results['vulnerabilities']) + 1}",
                    "type": "Server Configuration",
                    "risk": "MEDIUM",
                    "description": warning,
                    "recommendation": "Update to latest stable version"
                })
            
            # 5. SQL Injection test
            print("[INFO] Testing for SQL Injection...")
            sqli_results = self.test_sql_injection(target_url)
            if sqli_results["vulnerable"]:
                results["vulnerabilities"].append({
                    "id": f"vuln_{len(results['vulnerabilities']) + 1}",
                    "type": "SQL Injection",
                    "risk": "CRITICAL",
                    "description": sqli_results["description"],
                    "payload": sqli_results["payload"],
                    "url": sqli_results.get("url", target_url),
                    "recommendation": "Use parameterized queries and input validation"
                })
            
            # 6. XSS test
            print("[INFO] Testing for XSS...")
            xss_results = self.test_xss(target_url)
            if xss_results["vulnerable"]:
                results["vulnerabilities"].append({
                    "id": f"vuln_{len(results['vulnerabilities']) + 1}",
                    "type": "Cross-Site Scripting (XSS)",
                    "risk": "HIGH",
                    "description": xss_results["description"],
                    "payload": xss_results["payload"],
                    "url": xss_results.get("url", target_url),
                    "recommendation": "Implement proper output encoding and Content Security Policy"
                })
            
            # 7. Directory brute force
            print("[INFO] Scanning for exposed directories...")
            exposed_dirs = self.brute_force_directories(target_url)
            if exposed_dirs:
                results["vulnerabilities"].append({
                    "id": f"vuln_{len(results['vulnerabilities']) + 1}",
                    "type": "Exposed Directories",
                    "risk": "MEDIUM",
                    "description": f"Found {len(exposed_dirs)} exposed directories",
                    "count": len(exposed_dirs),
                    "directories": exposed_dirs[:5],  # Show first 5
                    "recommendation": "Restrict access to sensitive directories"
                })
            
            # 8. Security headers check
            print("[INFO] Checking security headers...")
            headers_check = self.check_security_headers(target_url)
            results["web_info"]["security_headers"] = headers_check
            
            # Add missing headers as vulnerabilities
            missing_headers = headers_check.get("missing_headers", [])
            if missing_headers:
                results["vulnerabilities"].append({
                    "id": f"vuln_{len(results['vulnerabilities']) + 1}",
                    "type": "Missing Security Headers",
                    "risk": "MEDIUM",
                    "description": f"Missing {len(missing_headers)} security headers",
                    "missing_headers": missing_headers,
                    "recommendation": "Implement proper security headers"
                })
            
            # 9. Technology detection
            results["technologies"] = web_results.get("technologies", [])
            
            # 10. Generate summary
            vuln_count = len(results["vulnerabilities"])
            results["summary"] = {
                "total_vulnerabilities": vuln_count,
                "risk_level": self.calculate_risk_level(results["vulnerabilities"]),
                "open_ports": results["network_info"].get("open_ports_count", 0),
                "technologies_found": len(results["technologies"]),
                "scan_duration": "completed",
                "status": "success"
            }
            
            print(f"[SUCCESS] Scan completed. Found {vuln_count} vulnerabilities.")
            
        except Exception as e:
            print(f"[ERROR] Scan failed: {str(e)}")
            results["error"] = str(e)
            results["scan_status"] = "failed"
            results["summary"] = {
                "status": "error",
                "error": str(e),
                "total_vulnerabilities": 0,
                "risk_level": "UNKNOWN"
            }
        
        return results
    
    def resolve_dns(self, domain):
        """Resolve domain to IP address"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror as e:
            print(f"[DNS] Failed to resolve {domain}: {e}")
            return None
        except Exception as e:
            print(f"[DNS] Error resolving {domain}: {e}")
            return None
    
    def get_geolocation(self, ip):
        """Get geolocation information for IP address"""
        try:
            print(f"[GEOLOCATION] Looking up {ip}...")
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = response.json()
            
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "organization": data.get("org", "Unknown"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone", "Unknown"),
                    "zip": data.get("zip", "Unknown")
                }
            else:
                return {"error": "Geolocation lookup failed", "message": data.get("message", "Unknown error")}
        except requests.exceptions.Timeout:
            return {"error": "Geolocation timeout"}
        except Exception as e:
            return {"error": f"Geolocation error: {str(e)}"}
    
    def port_scan(self, ip, ports=None):
        """Scan common ports on target IP"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                     3306, 3389, 5900, 8080, 8443, 8888]
        
        open_ports = []
        
        print(f"[PORT SCAN] Scanning {len(ports)} ports on {ip}")
        
        for port in ports:
            try:
                # Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                # Try to connect
                start_time = time.time()
                result = sock.connect_ex((ip, port))
                connect_time = int((time.time() - start_time) * 1000)  # ms
                
                if result == 0:  # Port is open
                    banner = self.get_banner(ip, port)
                    service = self.get_service_name(port)
                    
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "status": "open",
                        "banner": banner[:200] if banner else "No banner",
                        "response_time_ms": connect_time,
                        "protocol": "tcp"
                    })
                    print(f"[PORT] {port}/tcp OPEN - {service}")
                
                sock.close()
                
            except socket.timeout:
                continue
            except Exception as e:
                continue
        
        return open_ports
    
    def get_banner(self, ip, port):
        """Try to get banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Send appropriate probe based on port
            if port in [80, 443, 8080, 8443, 8888]:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            elif port == 21:
                sock.send(b"\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-Client\r\n")
            elif port == 25:
                sock.send(b"EHLO example.com\r\n")
            elif port == 110:
                sock.send(b"USER test\r\n")
            elif port == 143:
                sock.send(b"a1 LOGIN\r\n")
            
            # Receive response
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner
            
        except Exception as e:
            return ""
    
    def get_service_name(self, port):
        """Get service name from port number"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5900: "VNC", 8080: "HTTP Proxy",
            8443: "HTTPS-alt", 8888: "HTTP-alt"
        }
        return services.get(port, f"Unknown ({port})")
    
    def web_vulnerability_checks(self, url):
        """Check web vulnerabilities and detect technologies"""
        results = {
            "server_info": {},
            "headers": {},
            "warnings": [],
            "technologies": [],
            "response_info": {}
        }
        
        try:
            print(f"[WEB] Testing {url}")
            response = requests.get(url, timeout=15, verify=False, allow_redirects=True)
            
            # Basic response info
            results["response_info"]["status_code"] = response.status_code
            results["response_info"]["url"] = response.url
            results["response_info"]["redirects"] = len(response.history)
            results["response_info"]["content_length"] = len(response.content)
            results["response_info"]["encoding"] = response.encoding
            
            # Headers
            results["headers"] = dict(response.headers)
            
            # Server detection
            server_header = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            results["server_info"]["server"] = server_header
            results["server_info"]["powered_by"] = powered_by
            
            # Technology detection from headers
            tech_detected = set()
            
            # Server type
            if "nginx" in server_header.lower():
                tech_detected.add("nginx")
            if "apache" in server_header.lower():
                tech_detected.add("apache")
            if "iis" in server_header.lower():
                tech_detected.add("iis")
            if "cloudflare" in server_header.lower():
                tech_detected.add("cloudflare")
            
            # Backend technologies
            if "php" in powered_by.lower():
                tech_detected.add("php")
            if "asp.net" in powered_by.lower():
                tech_detected.add("asp.net")
            if "node.js" in powered_by.lower():
                tech_detected.add("node.js")
            
            # Framework detection from HTML
            html_content = response.text.lower()
            
            # CMS detection
            if "wordpress" in html_content or "wp-content" in html_content or "wp-includes" in html_content:
                tech_detected.add("wordpress")
            if "joomla" in html_content:
                tech_detected.add("joomla")
            if "drupal" in html_content:
                tech_detected.add("drupal")
            
            # JavaScript frameworks
            if "react" in html_content:
                tech_detected.add("react")
            if "vue" in html_content:
                tech_detected.add("vue.js")
            if "angular" in html_content:
                tech_detected.add("angular")
            
            results["technologies"] = list(tech_detected)
            
            # Vulnerability warnings
            if "Apache/2.2" in server_header:
                results["warnings"].append("Outdated Apache 2.2 detected (CVE-2017-5638)")
            if "nginx/1." in server_header and "nginx/1.18" not in server_header:
                results["warnings"].append("Outdated nginx version detected")
            if "PHP/5." in powered_by:
                results["warnings"].append("Outdated PHP 5.x detected (end of life)")
            
            # Check for exposed information
            if "phpinfo" in html_content:
                results["warnings"].append("phpinfo() page may be exposed")
            if "database error" in html_content or "sql error" in html_content:
                results["warnings"].append("Database error messages exposed")
            
        except requests.exceptions.Timeout:
            results["error"] = "Connection timeout"
        except requests.exceptions.ConnectionError:
            results["error"] = "Connection failed"
        except requests.exceptions.SSLError:
            results["error"] = "SSL certificate error"
        except Exception as e:
            results["error"] = f"Web check error: {str(e)}"
        
        return results
    
    def test_sql_injection(self, url):
        """Test for SQL Injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "admin' --",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1"
        ]
        
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                content = response.text.lower()
                
                # Common SQL error patterns
                sql_errors = [
                    "sql", "syntax", "mysql", "postgresql", "oracle",
                    "database", "query", "odbc", "jdbc", "pdo"
                ]
                
                for error in sql_errors:
                    if error in content:
                        return {
                            "vulnerable": True,
                            "payload": payload,
                            "url": test_url,
                            "description": f"SQL Injection detected with payload: {payload}",
                            "error_indicator": error
                        }
            except:
                continue
        
        return {"vulnerable": False, "description": "No SQL Injection vulnerabilities detected"}
    
    def test_xss(self, url):
        """Test for Cross-Site Scripting vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        for payload in payloads:
            test_url = f"{url}?q={requests.utils.quote(payload)}"
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                
                # Check if payload appears unescaped in response
                if payload in response.text:
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "url": test_url,
                        "description": "XSS vulnerability detected",
                        "type": "Reflected XSS"
                    }
            except:
                continue
        
        return {"vulnerable": False, "description": "No XSS vulnerabilities detected"}
    
    def brute_force_directories(self, base_url):
        """Brute force common directories and files"""
        common_paths = [
            # Administration panels
            "/admin", "/administrator", "/wp-admin", "/wp-login.php",
            "/admin/login", "/admin/index.php", "/admin/admin.php",
            
            # Configuration files
            "/.env", "/config.php", "/configuration.php", "/settings.php",
            "/config.json", "/config.yaml", "/config.yml",
            
            # Backup files
            "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
            "/database.sql", "/dump.sql", "/backup/database.sql",
            
            # Development files
            "/.git", "/.git/config", "/.git/HEAD",
            "/package.json", "/composer.json", "/requirements.txt",
            
            # Information disclosure
            "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
            "/server-status", "/server-info",
            
            # API endpoints
            "/api", "/api/v1", "/graphql", "/graphql.php",
            "/swagger", "/swagger.json", "/openapi.json",
            
            # Common directories
            "/uploads", "/images", "/assets", "/css", "/js",
            "/logs", "/temp", "/tmp", "/cache"
        ]
        
        exposed = []
        
        for path in common_paths:
            try:
                full_url = urljoin(base_url, path)
                response = requests.get(full_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    exposed.append({
                        "url": full_url,
                        "status_code": response.status_code,
                        "path": path,
                        "content_length": len(response.content)
                    })
                    
            except requests.exceptions.Timeout:
                continue
            except:
                continue
        
        return exposed
    
    def check_security_headers(self, url):
        """Check for security headers"""
        try:
            response = requests.head(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                "X-Frame-Options": "Prevents clickjacking",
                "X-Content-Type-Options": "Prevents MIME type sniffing",
                "X-XSS-Protection": "Cross-site scripting protection",
                "Content-Security-Policy": "Content security policy",
                "Strict-Transport-Security": "HTTP Strict Transport Security",
                "Referrer-Policy": "Controls referrer information",
                "Permissions-Policy": "Browser feature permissions",
                "X-Permitted-Cross-Domain-Policies": "Cross-domain policy"
            }
            
            results = {}
            missing = []
            
            for header, description in security_headers.items():
                if header in headers:
                    results[header] = {
                        "value": headers[header],
                        "present": True,
                        "description": description
                    }
                else:
                    results[header] = {
                        "value": "MISSING",
                        "present": False,
                        "description": description
                    }
                    missing.append(header)
            
            results["summary"] = {
                "total_checked": len(security_headers),
                "missing_count": len(missing),
                "present_count": len(security_headers) - len(missing),
                "score": f"{(len(security_headers) - len(missing))}/{len(security_headers)}",
                "missing_headers": missing
            }
            
            return results
            
        except Exception as e:
            return {"error": f"Headers check failed: {str(e)}"}
    
    def calculate_risk_level(self, vulnerabilities):
        """Calculate overall risk level based on vulnerabilities"""
        if not vulnerabilities:
            return "LOW"
        
        critical_count = sum(1 for v in vulnerabilities if v.get("risk") == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.get("risk") == "HIGH")
        medium_count = sum(1 for v in vulnerabilities if v.get("risk") == "MEDIUM")
        low_count = sum(1 for v in vulnerabilities if v.get("risk") == "LOW")
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 0:
            return "HIGH"
        elif medium_count > 0:
            return "MEDIUM"
        elif low_count > 0:
            return "LOW"
        else:
            return "INFO"
    
    def get_demo_data(self):
        """Return demo data for testing"""
        return {
            "target": {
                "url": "https://example.com",
                "domain": "example.com",
                "ip": "93.184.216.34",
                "port": 443
            },
            "geolocation": {
                "country": "United States",
                "region": "Massachusetts",
                "city": "Cambridge",
                "isp": "Fastly",
                "latitude": 42.3626,
                "longitude": -71.0843
            },
            "network_info": {
                "open_ports": [
                    {
                        "port": 80,
                        "service": "HTTP",
                        "banner": "nginx/1.18.0",
                        "status": "open"
                    },
                    {
                        "port": 443,
                        "service": "HTTPS",
                        "banner": "nginx/1.18.0",
                        "status": "open"
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "type": "Missing Security Headers",
                    "risk": "MEDIUM",
                    "description": "Missing Content-Security-Policy header"
                }
            ]
        }

# Vercel serverless function handler
if __name__ == "__main__":
    # Test the scanner locally
    scanner = handler
    print("Vulnerability Scanner API v3.2")
    print("Deployed on Vercel as serverless function")
