from http.server import BaseHTTPRequestHandler
import json
import requests
import socket
import re
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
            self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
            self.end_headers()
            
            response = {
                "name": "⚠️ VULNERABILITY SECURITY SCANNER",
                "version": "3.2",
                "author": "ANISH KUSHWAHA",
                "website": "Anish-kushwaha.b1zisites.com",
                "email": "Anish_Kushwaha@proton.me",
                "endpoints": {
                    "scan": "POST /api/scan with JSON: {\"target\": \"url\"}",
                    "health": "GET /health"
                },
                "warning": "Unauthorized scanning is illegal. Use only on systems you own or have permission for."
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
            
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "healthy",
                "timestamp": datetime.now().isoformat()
            }).encode())
            
        elif self.path == '/api/scan':
            # Demo response for GET request to /api/scan
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
            self.end_headers()
            self.wfile.write(json.dumps({
                "message": "Use POST method with JSON: {\"target\": \"url\"}",
                "example": {"target": "https://example.com"}
            }).encode())
            
        else:
            self.send_response(404)
            self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
            self.end_headers()
    
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
                    self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
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
                self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
                self.end_headers()
                self.wfile.write(json.dumps(scan_results, indent=2).encode())
                
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "Invalid JSON format",
                    "example": {"target": "https://example.com"}
                }).encode())
                
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": f"Scanner error: {str(e)}",
                    "target": target if 'target' in locals() else "unknown"
                }).encode())
        else:
            self.send_response(404)
            self.send_header('Access-Control-Allow-Origin', '*')  # CORS header
            self.end_headers()
    
    # ================= VULNERABILITY SCANNER =================
    
    def full_vulnerability_scan(self, target_url):
        """Complete vulnerability scanner"""
        results = {
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "Full Security Audit",
            "vulnerabilities": [],
            "network_info": {},
            "web_info": {},
            "summary": {}
        }
        
        try:
            # Auto-fix URL scheme
            if not urlparse(target_url).scheme:
                target_url = "https://" + target_url
                results["target_fixed"] = target_url
            
            parsed = urlparse(target_url)
            domain = parsed.netloc.split(':')[0]
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            # 1. Get IP and network info
            ip = self.resolve_dns(domain)
            results["network_info"]["domain"] = domain
            results["network_info"]["ip"] = ip if ip else "Could not resolve"
            results["network_info"]["port"] = port
            
            if ip and ip != "Could not resolve":
                # 2. Port scan
                open_ports = self.port_scan(ip)
                results["network_info"]["open_ports"] = open_ports
                results["network_info"]["open_ports_count"] = len(open_ports)
                
                # Check for vulnerable services
                for port_info in open_ports:
                    if port_info["service"] in ["ftp", "ssh", "telnet"]:
                        results["vulnerabilities"].append({
                            "type": "Insecure Service",
                            "service": port_info["service"],
                            "port": port_info["port"],
                            "risk": "MEDIUM",
                            "description": f"{port_info['service'].upper()} service exposed on default port"
                        })
            
            # 3. Web vulnerability checks
            web_results = self.web_vulnerability_checks(target_url)
            results["web_info"] = web_results
            
            # 4. SQL Injection test
            sqli_results = self.test_sql_injection(target_url)
            if sqli_results["vulnerable"]:
                results["vulnerabilities"].append({
                    "type": "SQL Injection",
                    "risk": "CRITICAL",
                    "description": sqli_results["description"],
                    "payload": sqli_results["payload"],
                    "url": sqli_results.get("url", target_url)
                })
            
            # 5. XSS test
            xss_results = self.test_xss(target_url)
            if xss_results["vulnerable"]:
                results["vulnerabilities"].append({
                    "type": "Cross-Site Scripting (XSS)",
                    "risk": "HIGH",
                    "description": xss_results["description"],
                    "payload": xss_results["payload"],
                    "url": xss_results.get("url", target_url)
                })
            
            # 6. Directory brute force
            exposed_dirs = self.brute_force_directories(target_url)
            if exposed_dirs:
                results["vulnerabilities"].append({
                    "type": "Exposed Directories",
                    "risk": "MEDIUM",
                    "description": f"Found {len(exposed_dirs)} exposed directories",
                    "directories": exposed_dirs,
                    "count": len(exposed_dirs)
                })
            
            # 7. Security headers check
            headers_check = self.check_security_headers(target_url)
            results["web_info"]["security_headers"] = headers_check
            
            # Summary
            vuln_count = len(results["vulnerabilities"])
            results["summary"] = {
                "total_vulnerabilities": vuln_count,
                "risk_level": self.calculate_risk_level(results["vulnerabilities"]),
                "scan_duration": "completed",
                "open_ports": results["network_info"].get("open_ports_count", 0),
                "status": "success"
            }
            
        except Exception as e:
            results["error"] = str(e)
            results["scan_status"] = "partial"
            results["summary"] = {
                "status": "error",
                "error": str(e),
                "total_vulnerabilities": 0,
                "risk_level": "UNKNOWN"
            }
        
        return results
    
    def resolve_dns(self, domain):
        """Resolve domain to IP"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None
        except:
            return None
    
  # Scan common ranges
def get_scan_ports(mode="fast"):
    if mode == "fast":
        # 50 most common ports
        return [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
                1723,3306,3389,5900,8080,8443]
    elif mode == "normal":
        # 100 common ports
        return list(range(1, 1025))[:100]  # First 100 ports
    elif mode == "full":
        # All well-known ports (0-1023)
        return list(range(1, 1024))
    elif mode == "extensive":
        # All registered ports (0-49151)
        return list(range(1, 49152))
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = self.get_service_name(port)
                    # Try to get banner
                    banner = ""
                    try:
                        banner_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        banner_sock.settimeout(2)
                        banner_sock.connect((ip, port))
                        banner_sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = banner_sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                        banner_sock.close()
                    except:
                        banner = "No banner"
                    
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "status": "open",
                        "banner": banner.strip()
                    })
            except:
                pass
        
        return open_ports
    
    def get_service_name(self, port):
        """Get service name from port"""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 80: "http",
            443: "https", 3306: "mysql", 3389: "rdp",
            8080: "http-proxy", 8443: "https-alt"
        }
        return services.get(port, "unknown")
    
    def web_vulnerability_checks(self, url):
        """Check web vulnerabilities"""
        results = {}
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            results["status_code"] = response.status_code
            results["headers"] = dict(response.headers)
            
            # Check for server info in headers
            server = response.headers.get('Server', '')
            results["server"] = server
            
            # Check for outdated servers
            vuln_warnings = []
            if "Apache/2.2" in server:
                vuln_warnings.append("Outdated Apache version detected (pre-2.4)")
            if "PHP/5." in server:
                vuln_warnings.append("Outdated PHP version detected")
            if "nginx/1." in server:
                vuln_warnings.append("Outdated nginx version detected")
            
            if vuln_warnings:
                results["warnings"] = vuln_warnings
                
        except requests.exceptions.Timeout:
            results["error"] = "Connection timeout"
        except requests.exceptions.ConnectionError:
            results["error"] = "Connection failed"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def test_sql_injection(self, url):
        """Test for SQL Injection"""
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "admin' --"
        ]
        
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                content = response.text.lower()
                
                if "sql" in content or "syntax" in content or "mysql" in content:
                    return {
                        "vulnerable": True,
                        "payload": payload,
                        "url": test_url,
                        "description": f"SQL Injection possible with payload: {payload}"
                    }
            except:
                continue
        
        return {"vulnerable": False, "description": "No SQL Injection detected"}
    
    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        payload = "<script>alert('XSS_TEST')</script>"
        test_url = f"{url}?q={requests.utils.quote(payload)}"
        
        try:
            response = requests.get(test_url, timeout=5, verify=False)
            if payload in response.text:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "url": test_url,
                    "description": "XSS vulnerability detected"
                }
        except:
            pass
        
        return {"vulnerable": False, "description": "No XSS detected"}
    
    def brute_force_directories(self, base_url):
        """Brute force common directories"""
        common_dirs = [
            "/admin", "/wp-admin", "/phpmyadmin", "/administrator",
            "/backup", "/config", "/.env", "/config.php",
            "/login", "/admin/login", "/dashboard", "/phpinfo.php",
            "/test.php", "/debug", "/api", "/swagger", "/graphql"
        ]
        
        exposed = []
        
        for directory in common_dirs:
            try:
                full_url = urljoin(base_url, directory)
                response = requests.get(full_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    exposed.append({
                        "url": full_url,
                        "status": response.status_code,
                        "directory": directory
                    })
            except:
                continue
        
        return exposed
    
    def check_security_headers(self, url):
        """Check security headers"""
        try:
            response = requests.head(url, timeout=5, verify=False)
            headers = response.headers
            
            security_headers = [
                "X-Frame-Options",
                "X-Content-Type-Options", 
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security"
            ]
            
            results = {}
            missing = []
            
            for header in security_headers:
                if header in headers:
                    results[header] = headers[header]
                else:
                    results[header] = "MISSING"
                    missing.append(header)
            
            results["missing_count"] = len(missing)
            results["missing_headers"] = missing
            results["score"] = f"{(len(security_headers) - len(missing))}/{len(security_headers)}"
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def calculate_risk_level(self, vulnerabilities):
        """Calculate overall risk level"""
        if not vulnerabilities:
            return "LOW"
        
        critical_count = sum(1 for v in vulnerabilities if v.get("risk") == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.get("risk") == "HIGH")
        medium_count = sum(1 for v in vulnerabilities if v.get("risk") == "MEDIUM")
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 0:
            return "HIGH"
        elif medium_count > 0:
            return "MEDIUM"
        else:
            return "LOW"

# Vercel requires this
if __name__ == "__main__":
    pass
