import requests
import socket
import threading
import json
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
import logging
import whois
import dns.resolver

# Disable warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings()

class AnishSecurityScanner:
    def __init__(self):
        self.DEFAULT_TIMEOUT = 5
        self.COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443, 8888]
        self.BANNER_GRAB_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389]
        self.KNOWN_PATHS = [
            "/.env", "/config.php", "/.git/config", "/plesk-stat/", "/export.tar.gz",
            "/backup.zip", "/phpinfo.php", "/test.php", "/readme.html", "/admin", "/login",
            "/robots.txt", "/sitemap.xml", "/wp-admin", "/adminer.php", "/phpmyadmin"
        ]
        self.VULN_PATTERNS = {
            "Apache/2.2": "Outdated Apache version (pre-2.4), vulnerable to CVE-2017-5638",
            "PleskLin": "Potential Plesk server, check for CVE-2023-24044",
            "PHP/5.": "Outdated PHP version, may be vulnerable to multiple CVEs",
            "nginx/1.": "Outdated nginx version, check for known CVEs",
            "IIS/6.": "Outdated IIS version, vulnerable to multiple CVEs"
        }
        self.XSS_PAYLOAD = "<script>alert('XSS')</script>"
        self.SQLI_PAYLOAD = "' OR '1'='1"
        self.DIRECTORY_LIST = ["/admin", "/backup", "/config", "/db", "/logs", "/test", "/upload"]
        
        # Setup logging
        logging.basicConfig(filename="anish_scanner.log", level=logging.INFO,
                          format="%(asctime)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger(__name__)
    
    def parse_url_and_detect_port(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        port = parsed.port
        if not port:
            port = 8443
        return domain, port
    
    def resolve_ip(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except Exception as e:
            self.logger.error(f"Error resolving IP for {domain}: {e}")
            return None
    
    def get_geolocation(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=self.DEFAULT_TIMEOUT)
            data = response.json()
            if data['status'] == 'success':
                return {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0)
                }
            return {"error": "Geolocation failed"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_whois_info(self, domain):
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers
            }
        except Exception as e:
            return {"error": str(e)}
    
    def get_dns_records(self, domain):
        records = {}
        try:
            for record_type in ['A', 'MX', 'TXT', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except:
                    records[record_type] = []
        except Exception as e:
            records["error"] = str(e)
        return records
    
    def scan_port(self, ip, port, results, rate_limit=0.01):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.DEFAULT_TIMEOUT)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = ""
                    if port in self.BANNER_GRAB_PORTS:
                        try:
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(1024).decode(errors="ignore")
                        except:
                            banner = "Open, but no banner"
                    vuln_info = self.check_vuln_banner(banner)
                    results.append({
                        "port": port,
                        "banner": banner.strip(),
                        "vuln_info": vuln_info,
                        "status": "open"
                    })
        except Exception as e:
            self.logger.error(f"Error scanning port {port} on {ip}: {e}")
        finally:
            time.sleep(rate_limit)
    
    def check_vuln_banner(self, banner):
        for pattern, desc in self.VULN_PATTERNS.items():
            if pattern in banner:
                return f"⚠️ {desc}"
        return "No known vulnerabilities detected"
    
    def run_network_scan(self, ip):
        threads = []
        results = []
        for port in self.COMMON_PORTS:
            thread = threading.Thread(target=self.scan_port, args=(ip, port, results))
            thread.start()
            threads.append(thread)
        for t in threads:
            t.join()
        return sorted(results, key=lambda x: x['port'])
    
    def scan_web_vulnerabilities(self, base_url):
        results = []
        try:
            r = requests.get(base_url, verify=False, timeout=self.DEFAULT_TIMEOUT)
            soup = BeautifulSoup(r.text, "html.parser")
            
            # Extract hidden details
            meta_tags = {meta.get('name'): meta.get('content') for meta in soup.find_all('meta') if meta.get('name')}
            title = soup.title.string.strip() if soup.title else "No title"
            headers = dict(r.headers)
            
            results.append({
                "type": "Page Info",
                "title": title,
                "meta": meta_tags,
                "headers": headers,
                "status_code": r.status_code
            })
            
            # Check for XSS
            xss_url = urljoin(base_url, f"?test={self.XSS_PAYLOAD}")
            r_xss = requests.get(xss_url, verify=False, timeout=self.DEFAULT_TIMEOUT)
            if self.XSS_PAYLOAD in r_xss.text:
                results.append({
                    "type": "XSS",
                    "url": xss_url,
                    "severity": "High",
                    "description": "Potential Cross-Site Scripting vulnerability"
                })
            
            # Check for SQLi
            sqli_url = urljoin(base_url, f"?id={self.SQLI_PAYLOAD}")
            r_sqli = requests.get(sqli_url, verify=False, timeout=self.DEFAULT_TIMEOUT)
            if "mysql" in r_sqli.text.lower() or "sql syntax" in r_sqli.text.lower():
                results.append({
                    "type": "SQLi",
                    "url": sqli_url,
                    "severity": "Critical",
                    "description": "Potential SQL Injection vulnerability"
                })
            
            # Directory brute-force
            for dir in self.DIRECTORY_LIST:
                dir_url = urljoin(base_url, dir)
                try:
                    r_dir = requests.get(dir_url, verify=False, timeout=self.DEFAULT_TIMEOUT)
                    if r_dir.status_code == 200:
                        results.append({
                            "type": "Exposed Directory",
                            "url": dir_url,
                            "severity": "Medium",
                            "description": "Accessible directory found"
                        })
                except:
                    pass
                    
        except Exception as e:
            self.logger.error(f"Web scan error for {base_url}: {e}")
        
        return results
    
    def scan_plesk(self, ip, port):
        base_url = f"https://{ip}:{port}"
        results = []
        
        try:
            # Check accessibility
            r = requests.get(base_url, verify=False, timeout=self.DEFAULT_TIMEOUT)
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "No title"
            results.append({
                "type": "Plesk Access",
                "status": r.status_code,
                "title": title,
                "url": base_url
            })
        except Exception as e:
            results.append({
                "type": "Connection Error",
                "error": str(e),
                "url": base_url
            })
        
        # Check headers
        try:
            r = requests.get(base_url, verify=False, timeout=self.DEFAULT_TIMEOUT)
            headers = r.headers
            for h in ["Server", "X-Powered-By"]:
                if h in headers:
                    vuln_info = self.check_vuln_banner(headers[h])
                    results.append({
                        "type": "Header",
                        "name": h,
                        "value": headers[h],
                        "vuln_info": vuln_info
                    })
        except:
            pass
        
        # SQLi login bypass attempt
        try:
            login_url = urljoin(base_url, "/login_up.php")
            payload = {"login_name": "admin' OR '1'='1", "passwd": "random"}
            r = requests.post(login_url, data=payload, verify=False, timeout=self.DEFAULT_TIMEOUT, allow_redirects=False)
            if r.status_code in [302, 301]:
                results.append({
                    "type": "SQLi Bypass",
                    "url": login_url,
                    "status": r.status_code,
                    "severity": "Critical",
                    "description": "Possible SQL injection login bypass"
                })
        except:
            pass
        
        # Check known paths
        for path in self.KNOWN_PATHS:
            url = urljoin(base_url, path)
            try:
                r = requests.get(url, verify=False, timeout=self.DEFAULT_TIMEOUT)
                if r.status_code == 200:
                    results.append({
                        "type": "Exposed Path",
                        "url": url,
                        "status": r.status_code,
                        "severity": "Medium",
                        "description": "Exposed or vulnerable path found"
                    })
            except:
                pass
        
        return results
    
    def run_complete_scan(self, target_url):
        start_time = datetime.now()
        
        # Auto-fix scheme if missing
        if not urlparse(target_url).scheme:
            target_url = "https://" + target_url
        
        # Parse URL and detect port
        domain, target_port = self.parse_url_and_detect_port(target_url)
        
        # Resolve IP
        ip = self.resolve_ip(domain)
        if not ip:
            raise Exception("Could not resolve IP address")
        
        # Get additional info
        geolocation = self.get_geolocation(ip)
        whois_info = self.get_whois_info(domain)
        dns_records = self.get_dns_records(domain)
        
        # Run scans
        network_results = self.run_network_scan(ip)
        plesk_results = self.scan_plesk(ip, target_port)
        web_results = self.scan_web_vulnerabilities(target_url)
        
        scan_duration = str(datetime.now() - start_time)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "scan_duration": scan_duration,
            "target_info": {
                "original_url": target_url,
                "domain": domain,
                "ip": ip,
                "port": target_port
            },
            "geolocation": geolocation,
            "whois": whois_info,
            "dns_records": dns_records,
            "network_scan": network_results,
            "plesk_scan": plesk_results,
            "web_vulnerabilities": web_results,
            "summary": {
                "open_ports": len([r for r in network_results if r['status'] == 'open']),
                "vulnerabilities_found": len([r for r in web_results if r['severity'] in ['High', 'Critical']]),
                "plesk_findings": len(plesk_results)
            }
  }
