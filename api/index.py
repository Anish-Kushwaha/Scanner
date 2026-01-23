import requests
import socket
import threading
import json
import re
import time
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
import logging
import whois
import dns.resolver

# Disable warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings()

# ================= CONFIG =================
DEFAULT_TIMEOUT = 5
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443, 8888]
BANNER_GRAB_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389]
KNOWN_PATHS = [
    "/.env", "/config.php", "/.git/config", "/plesk-stat/", "/export.tar.gz",
    "/backup.zip", "/phpinfo.php", "/test.php", "/readme.html", "/admin", "/login",
    "/robots.txt", "/sitemap.xml", "/wp-admin", "/adminer.php", "/phpmyadmin"
]
VULN_PATTERNS = {
    "Apache/2.2": "Outdated Apache version (pre-2.4), vulnerable to CVE-2017-5638",
    "PleskLin": "Potential Plesk server, check for CVE-2023-24044",
    "PHP/5.": "Outdated PHP version, may be vulnerable to multiple CVEs",
    "nginx/1.": "Outdated nginx version, check for known CVEs",
    "IIS/6.": "Outdated IIS version, vulnerable to multiple CVEs"
}
XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"
DIRECTORY_LIST = ["/admin", "/backup", "/config", "/db", "/logs", "/test", "/upload"]

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ================= UTILITY FUNCTIONS =================
def parse_url_and_detect_port(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    port = parsed.port
    if not port:
        port = 8443 if parsed.scheme == 'https' else 80
    return domain, port

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return None

def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=DEFAULT_TIMEOUT)
        data = response.json()
        if data['status'] == 'success':
            return {
                "country": data.get("country", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }
        return {"error": "Geolocation failed"}
    except Exception as e:
        return {"error": str(e)}

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar) if w.registrar else "Unknown",
            "creation_date": str(w.creation_date) if w.creation_date else "Unknown",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "Unknown"
        }
    except Exception as e:
        return {"error": str(e)}

# ================= NETWORK SCANNER =================
def scan_port(ip, port, results, rate_limit=0.01):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(DEFAULT_TIMEOUT)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = ""
                if port in BANNER_GRAB_PORTS:
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode(errors="ignore")[:100]
                    except:
                        banner = "Open"
                results.append((port, banner))
    except:
        pass
    finally:
        time.sleep(rate_limit)

def run_network_scan(ip, port_range=COMMON_PORTS):
    threads = []
    results = []
    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        thread.start()
        threads.append(thread)
    for t in threads:
        t.join()
    return [{"port": port, "status": "open", "banner": banner} for port, banner in sorted(results)]

# ================= WEB VULNERABILITY SCANNER =================
def scan_web_vulnerabilities(base_url):
    results = []
    
    try:
        r = requests.get(base_url, verify=False, timeout=DEFAULT_TIMEOUT)
        
        # Check XSS
        xss_url = urljoin(base_url, f"?test={XSS_PAYLOAD}")
        r_xss = requests.get(xss_url, verify=False, timeout=DEFAULT_TIMEOUT)
        if XSS_PAYLOAD in r_xss.text:
            results.append({"type": "XSS", "url": xss_url, "severity": "High", "found": True})
        
        # Check for exposed directories
        for dir in DIRECTORY_LIST:
            dir_url = urljoin(base_url, dir)
            try:
                r_dir = requests.get(dir_url, verify=False, timeout=DEFAULT_TIMEOUT)
                if r_dir.status_code == 200:
                    results.append({"type": "Exposed Directory", "url": dir_url, "severity": "Medium", "found": True})
            except:
                pass
                
    except Exception as e:
        results.append({"type": "Connection Error", "error": str(e)})
    
    return results

# ================= PLESK SCANNER =================
def scan_plesk(ip, port):
    results = []
    base_url = f"https://{ip}:{port}"
    
    try:
        r = requests.get(base_url, verify=False, timeout=DEFAULT_TIMEOUT)
        results.append({"type": "Plesk Access", "status": r.status_code, "url": base_url})
        
        # Check vulnerable paths
        for path in KNOWN_PATHS[:5]:  # Check first 5 paths
            url = urljoin(base_url, path)
            try:
                r_path = requests.get(url, verify=False, timeout=DEFAULT_TIMEOUT)
                if r_path.status_code == 200:
                    results.append({"type": "Exposed Path", "url": url, "status": r_path.status_code})
            except:
                pass
                
    except Exception as e:
        results.append({"type": "Connection Error", "error": str(e)})
    
    return results

# ================= API ENDPOINT (For Node.js Integration) =================
def scan_target(target_url):
    """Main scanning function that returns JSON results"""
    
    # Validate and fix URL
    if not urlparse(target_url).scheme:
        target_url = "https://" + target_url
    
    domain, target_port = parse_url_and_detect_port(target_url)
    ip = resolve_ip(domain)
    
    if not ip:
        return {"error": "Could not resolve IP"}
    
    # Run all scans
    network_results = run_network_scan(ip)
    web_results = scan_web_vulnerabilities(target_url)
    plesk_results = scan_plesk(ip, target_port)
    geolocation = get_geolocation(ip)
    whois_info = get_whois_info(domain)
    
    # Build final report
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": {
            "url": target_url,
            "domain": domain,
            "ip": ip,
            "port": target_port
        },
        "info": {
            "geolocation": geolocation,
            "whois": whois_info
        },
        "scan_results": {
            "network_scan": network_results,
            "web_vulnerabilities": web_results,
            "plesk_scan": plesk_results
        },
        "summary": {
            "open_ports": len(network_results),
            "vulnerabilities_found": len(web_results) + len(plesk_results),
            "scan_completed": True
        }
    }
    
    return report

# ================= VERCEL SERVERLESS FUNCTION =================
def handler(request):
    """Vercel serverless function handler"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            target_url = data.get('target')
            
            if not target_url:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Target URL is required'})
                }
            
            # Run the scan
            scan_results = scan_target(target_url)
            
            return {
                'statusCode': 200,
                'body': json.dumps(scan_results)
            }
        else:
            return {
                'statusCode': 405,
                'body': json.dumps({'error': 'Method not allowed'})
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

# For local testing
if __name__ == "__main__":
    # Test the scanner
    test_url = "https://example.com"
    print("Testing scanner with:", test_url)
    results = scan_target(test_url)
    print(json.dumps(results, indent=2))
