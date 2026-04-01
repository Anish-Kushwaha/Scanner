#!/usr/bin/env python3
"""
Anish Security Scanner v5 (PRO Edition)
Enhanced Recon & Vulnerability Assessment Framework
Ethical Use Only
"""

import argparse
import concurrent.futures
import json
import logging
import re
import socket
import sys
import threading
import time
import whois
from datetime import datetime
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
from bs4 import BeautifulSoup

# Optional imports (graceful fallback)
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    print(f"[!] Scapy import failed: {e}. SYN scan will not be available.")

# Disable warnings
requests.packages.urllib3.disable_warnings()

# ================= CONFIGURATION =================
DEFAULT_TIMEOUT = 5
THREAD_POOL_SIZE = 20
ASYNC_CONCURRENCY = 20
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443, 8888]
BANNER_GRAB_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389]

# Service probes (simple)
SERVICE_PROBES = {
    21: b"USER anonymous\r\n",
    22: b"SSH-2.0-",
    25: b"EHLO test\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"USER test\r\n",
    143: b"CAPABILITY\r\n",
    3306: b"\x00\x00\x00\x01",
    3389: b"\x03\x00\x00\x13",
}

# Vuln DB (simplified - expand as needed)
CVE_DB = {
    "nginx": {
        "1.18": ["CVE-2021-23017"],
        "1.20": []
    },
    "Apache": {
        "2.2": ["CVE-2017-5638"],
        "2.4": []
    },
    "OpenSSH": {
        "7.4": ["CVE-2016-6210"],
        "8.2": []
    }
}

# WAF signatures
WAF_SIGNATURES = {
    "Cloudflare": ["CF-Ray", "cloudflare"],
    "Akamai": ["X-Akamai-Transformed"],
    "AWS WAF": ["x-amzn-RequestId"],
    "Sucuri": ["X-Sucuri-ID"],
    "Wordfence": ["wordfence"],
}

# Common subdomain list (truncated for brevity)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "download", "dns", "api", "api2",
    "cdn", "app", "storage", "portal", "stats", "proxy", "gateway", "remote",
    "files", "apps", "mssql", "vps", "live", "auth", "cloud", "server", "monitor",
    "log", "database", "backup", "dashboard", "upload", "status", "help", "tools",
    "forum2", "forums", "community", "development", "staging", "stage", "stg",
    "qa", "test2", "test3", "preprod", "prod", "production", "alpha", "beta2"
]

# Directory wordlist (categorized)
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

SENSITIVE_PATTERNS = [
    r"(?i)(DB_|DATABASE_)(USERNAME|PASSWORD|HOST|NAME)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(MYSQL|POSTGRES|MONGO|REDIS)_(USER|PASS|PASSWORD|HOST|DB)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(AWS_|AZURE_|GCP_)(ACCESS_KEY|SECRET_KEY|KEY|SECRET)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(API_KEY|API_SECRET|APP_KEY|APP_SECRET)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(PASSWORD|PASSWD|PASSPHRASE)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(SECRET|SECRET_KEY)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(TOKEN|AUTH_TOKEN|BEARER)\s*[=:]\s*['\"]?([^'\"]+)"
]

XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"

# Setup logging
logging.basicConfig(filename="anish_scanner_v5.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ================= UTILITY FUNCTIONS =================
def print_banner():
    print(r"""
     в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•— в–Ҳв–Ҳв–Ҳв•—   в–Ҳв–Ҳв•—в–Ҳв–Ҳв•—в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•—в–Ҳв–Ҳв•—  в–Ҳв–Ҳв•—    в–Ҳв–Ҳв•—  в–Ҳв–Ҳв•—в–Ҳв–Ҳв•—   в–Ҳв–Ҳв•—в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•—в–Ҳв–Ҳв•—  в–Ҳв–Ҳв•—в–Ҳв–Ҳв•—    в–Ҳв–Ҳв•— в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•— в–Ҳв–Ҳв•—  в–Ҳв–Ҳв•— в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳ
    в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•—в–Ҳв–Ҳв–Ҳв–Ҳв•—  в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв•җв•җв•қв–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘    в–Ҳв–Ҳв•‘ в–Ҳв–Ҳв•”в•қв–Ҳв–Ҳв•‘   в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв•җв•җв•қв–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘    в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•—в–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•—
    в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в–Ҳв–Ҳв•— в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•—в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘    в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•”в•қ в–Ҳв–Ҳв•‘   в–Ҳв–Ҳв•‘в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•—в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘ в–Ҳв•— в–Ҳв–Ҳв•‘в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘
    в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘в•ҡв–Ҳв–Ҳв•—в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘в•ҡв•җв•җв•җв•җв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•‘    в–Ҳв–Ҳв•”в•җв–Ҳв–Ҳв•— в–Ҳв–Ҳв•‘   в–Ҳв–Ҳв•‘в•ҡв•җв•җв•җв•җв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘в–Ҳв–Ҳв–Ҳв•—в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•”в•җв•җв–Ҳв–Ҳв•‘
    в–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘ в•ҡв–Ҳв–Ҳв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘в–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘    в–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•—в•ҡв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•”в•қв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘в•ҡв–Ҳв–Ҳв–Ҳв•”в–Ҳв–Ҳв–Ҳв•”в•қв–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘в–Ҳв–Ҳв•‘  в–Ҳв–Ҳв•‘
    в•ҡв•җв•қ  в•ҡв•җв•қв•ҡв•җв•қ  в•ҡв•җв•җв•җв•қв•ҡв•җв•қв•ҡв•җв•җв•җв•җв•җв•җв•қв•ҡв•җв•қ  в•ҡв•җв•қ    в•ҡв•җв•қ  в•ҡв•җв•қ в•ҡв•җв•җв•җв•җв•җв•қ в•ҡв•җв•җв•җв•җв•җв•җв•қв•ҡв•җв•қ  в•ҡв•җв•қ в•ҡв•җв•җв•қв•ҡв•җв•җв•қ в•ҡв•җв•қ  в•ҡв•җв•қв•ҡв•җв•қ  в•ҡв•җв•қв•ҡв•җв•қ  в•ҡв•җв•қ

    Anish Security Scanner v5 (PRO Edition)
    Enhanced Reconnaissance & Vulnerability Assessment
    Ethical Use Only
    """)

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.error(f"Error resolving IP: {e}")
        return None

def parse_url_and_detect_port(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == 'https' else 80
    return domain, port

# ================= CLASSES =================
class NetworkScanner:
    """Advanced network scanner with SYN/TCP scans and service detection."""
    def __init__(self, target_ip, ports=None, stealth=False, timeout=DEFAULT_TIMEOUT):
        self.target_ip = target_ip
        self.ports = ports or COMMON_PORTS
        self.stealth = stealth
        self.timeout = timeout
        self.results = []  # list of (port, state, banner, version, cves)
        self.lock = threading.Lock()

    def scan(self):
        """Run network scan (parallel threads)."""
        logger.info(f"Starting network scan on {self.target_ip}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as executor:
            futures = [executor.submit(self._scan_port, port) for port in self.ports]
            for future in concurrent.futures.as_completed(futures):
                future.result()
        return self.results

    def _scan_port(self, port):
        """Scan a single port using SYN (if scapy) or TCP connect."""
        if SCAPY_AVAILABLE and self.stealth:
            state = self._syn_scan(port)
        else:
            state = self._tcp_connect(port)

        if state in ('open', 'open|filtered'):
            banner = self._grab_banner(port)
            version = self._detect_version(port, banner)
            cves = self._map_cves(banner, version)
            with self.lock:
                self.results.append((port, state, banner, version, cves))
                logger.info(f"Port {port}: {state} - {banner} - {version} - CVEs: {cves}")

    def _tcp_connect(self, port):
        """TCP connect scan."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    return 'open'
                else:
                    return 'closed'
        except Exception:
            return 'filtered'

    def _syn_scan(self, port):
        """SYN scan using Scapy."""
        try:
            pkt = scapy.IP(dst=self.target_ip)/scapy.TCP(dport=port, flags='S')
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                if resp.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close
                    scapy.send(scapy.IP(dst=self.target_ip)/scapy.TCP(dport=port, flags='R'), verbose=0)
                    return 'open'
                elif resp.getlayer(scapy.TCP).flags == 0x14:  # RST
                    return 'closed'
            return 'filtered'
        except Exception:
            return 'filtered'

    def _grab_banner(self, port):
        """Send a probe to get banner."""
        if port not in BANNER_GRAB_PORTS:
            return ""
        probe = SERVICE_PROBES.get(port, b"\r\n")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.target_ip, port))
                sock.send(probe)
                banner = sock.recv(1024).decode(errors='ignore').strip()
                return banner
        except Exception:
            return ""

    def _detect_version(self, port, banner):
        """Extract version from banner."""
        if port == 80 or port == 443:
            # Try to detect web server version
            if "Server:" in banner:
                match = re.search(r"Server:\s*([^\r\n]+)", banner)
                if match:
                    return match.group(1).strip()
            return "Unknown"
        elif port == 22:
            # SSH banner
            match = re.search(r"SSH-([\d.]+)", banner)
            if match:
                return f"OpenSSH {match.group(1)}"
        elif port == 21:
            # FTP banner
            return banner.split()[1] if len(banner.split()) > 1 else banner
        return "Unknown"

    def _map_cves(self, banner, version):
        """Map version to known CVEs (simplified)."""
        cves = []
        for service, versions in CVE_DB.items():
            if service.lower() in banner.lower() or service.lower() in version.lower():
                for ver, cv in versions.items():
                    if ver in version:
                        cves.extend(cv)
        return cves

class WAFDetector:
    """Detect WAF/CDN presence."""
    def __init__(self, domain):
        self.domain = domain
        self.waf = None
        self.cdn = None

    def detect(self):
        """Perform detection."""
        try:
            resp = requests.get(f"http://{self.domain}", timeout=DEFAULT_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
            headers = resp.headers
            for waf, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if any(sig in k for k in headers) or sig in resp.text:
                        self.waf = waf
                        break
                if self.waf:
                    break

            # CDN detection via ASN (simplified - could use ipinfo)
            ip = resolve_ip(self.domain)
            if ip:
                # Placeholder: you can integrate ipinfo.io or similar
                pass

        except Exception:
            pass
        return self.waf, self.cdn

class ReconEngine:
    """Reconnaissance: subdomains, reverse DNS, ASN, etc."""
    def __init__(self, domain, threads=20):
        self.domain = domain
        self.threads = threads
        self.subdomains = []
        self.results = {}

    def enumerate_subdomains(self):
        """Subdomain brute-force + certificate transparency."""
        # CT logs via crt.sh
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
            data = resp.json()
            for entry in data:
                name = entry.get('name_value')
                if name and name.endswith(self.domain):
                    self.subdomains.append(name.lower())
        except Exception:
            pass

        # Wordlist brute-force
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._check_subdomain, sub) for sub in SUBDOMAIN_WORDLIST]
            for future in concurrent.futures.as_completed(futures):
                found = future.result()
                if found:
                    self.subdomains.append(found)

        self.subdomains = list(set(self.subdomains))
        return self.subdomains

    def _check_subdomain(self, sub):
        try:
            target = f"{sub}.{self.domain}"
            ip = socket.gethostbyname(target)
            return target
        except Exception:
            return None

    def reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def asn_lookup(self, ip):
        # Placeholder: could use ipinfo.io API
        return None

    def run(self):
        self.subdomains = self.enumerate_subdomains()
        self.results['subdomains'] = self.subdomains
        return self.results

class WebScanner:
    """Web vulnerability scanner with tech detection, directory enum, JS extraction."""
    def __init__(self, target_url, session=None):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.verify = False
        self.technologies = {}
        self.results = []

    def detect_technologies(self):
        """Detect CMS, frameworks, etc."""
        try:
            resp = self.session.get(self.target_url, timeout=DEFAULT_TIMEOUT)
            headers = resp.headers
            html = resp.text

            # Simple detection
            if "wp-content" in html or "wp-includes" in html:
                self.technologies['CMS'] = "WordPress"
            elif "Joomla" in html or "joomla" in html:
                self.technologies['CMS'] = "Joomla"
            elif "Drupal" in html:
                self.technologies['CMS'] = "Drupal"

            # Frameworks
            if "react" in html or "React" in html:
                self.technologies['Framework'] = "React"
            if "angular" in html or "ng-" in html:
                self.technologies['Framework'] = "Angular"
            if "laravel" in html or "csrf-token" in html:
                self.technologies['Framework'] = "Laravel"

            # Server
            if 'Server' in headers:
                self.technologies['Server'] = headers['Server']
        except Exception:
            pass
        return self.technologies

    def extract_js_endpoints(self):
        """Extract API endpoints from JavaScript files."""
        endpoints = []
        try:
            soup = BeautifulSoup(self.session.get(self.target_url).text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                if src.startswith('http'):
                    js_url = src
                else:
                    js_url = urljoin(self.target_url, src)
                try:
                    js = self.session.get(js_url, timeout=DEFAULT_TIMEOUT).text
                    # Look for API paths
                    api_matches = re.findall(r'["\'](/api/[^"\']+)["\']', js)
                    endpoints.extend(api_matches)
                except:
                    pass
        except:
            pass
        return list(set(endpoints))

    def directory_enum(self, wordlist=None):
        """Multi-threaded directory brute-force."""
        wordlist = wordlist or COMMON_DIRECTORIES
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as executor:
            futures = [executor.submit(self._check_dir, d) for d in wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        return found

    def _check_dir(self, dir):
        try:
            url = urljoin(self.target_url, dir)
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code in (200, 403, 401):
                return url
        except:
            pass
        return None

    def file_enum(self):
        """Check for common files."""
        found = []
        for f in COMMON_FILES:
            url = urljoin(self.target_url, f)
            try:
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                    found.append(url)
                    # Check for sensitive data
                    if f.endswith(('.txt', '.php', '.env', '.sql', '.conf', '.log', '.bak', '.old', '.git', '.svn', '.yml', '.json', '.xml', '.ini')):
                        self._check_sensitive_data(resp.text, url)
            except:
                pass
        return found

    def _check_sensitive_data(self, text, source_url):
        for pattern in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                for match in matches:
                    found = ' '.join([m for m in match if m])
                    print(f"        [!] Possible sensitive info in {source_url}: {found}")
                    self.results.append({
                        "type": "Sensitive Information Disclosure",
                        "url": source_url,
                        "severity": "High",
                        "details": f"Pattern matched: {found}"
                    })
                    logger.warning(f"Sensitive data in {source_url}: {found}")

    def test_xss(self):
        """Test for reflected XSS."""
        xss_url = urljoin(self.target_url, f"?test={XSS_PAYLOAD}")
        try:
            resp = self.session.get(xss_url, timeout=DEFAULT_TIMEOUT)
            if XSS_PAYLOAD in resp.text:
                self.results.append({
                    "type": "XSS",
                    "url": xss_url,
                    "severity": "High"
                })
                logger.warning(f"XSS detected at {xss_url}")
        except:
            pass

    def test_sqli(self):
        """Test for SQL injection (simple)."""
        sqli_url = urljoin(self.target_url, f"?id={SQLI_PAYLOAD}")
        try:
            resp = self.session.get(sqli_url, timeout=DEFAULT_TIMEOUT)
            if "mysql" in resp.text.lower() or "sql syntax" in resp.text.lower():
                self.results.append({
                    "type": "SQLi",
                    "url": sqli_url,
                    "severity": "Critical"
                })
                logger.warning(f"SQLi detected at {sqli_url}")
        except:
            pass

    def run(self):
        self.detect_technologies()
        self.results.append({"type": "Technologies", "data": self.technologies})
        endpoints = self.extract_js_endpoints()
        self.results.append({"type": "JS Endpoints", "data": endpoints})
        dirs = self.directory_enum()
        for d in dirs:
            self.results.append({"type": "Exposed Directory", "url": d, "severity": "Medium"})
        files = self.file_enum()
        for f in files:
            self.results.append({"type": "Exposed File", "url": f, "severity": "Medium"})
        self.test_xss()
        self.test_sqli()
        return self.results

class VulnEngine:
    """CVE lookup and risk assessment."""
    def __init__(self, services):
        self.services = services  # list of (service_name, version)
        self.vulns = []

    def lookup_cves(self):
        for name, version in self.services:
            if name in CVE_DB:
                for ver, cves in CVE_DB[name].items():
                    if version and ver in version:
                        self.vulns.extend(cves)
        return self.vulns

    def assess_risk(self):
        if len(self.vulns) > 0:
            return "High"
        else:
            return "Low"

class ReportGenerator:
    """Generate JSON and HTML reports."""
    def __init__(self, target, scan_data):
        self.target = target
        self.data = scan_data

    def to_json(self, filename="anish_report.json"):
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)
        print(f"[+] JSON report saved to {filename}")

    def to_html(self, filename="anish_report.html"):
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Anish Scanner Report - {self.target}</title></head>
        <body>
        <h1>Security Scan Report for {self.target}</h1>
        <p>Generated: {datetime.now().isoformat()}</p>
        <pre>{json.dumps(self.data, indent=2)}</pre>
        </body>
        </html>
        """
        with open(filename, 'w') as f:
            f.write(html_template)
        print(f"[+] HTML report saved to {filename}")

class AnishScanner:
    """Orchestrator for all modules."""
    def __init__(self, target, options):
        self.target = target
        self.options = options
        self.domain, self.port = parse_url_and_detect_port(target)
        self.ip = resolve_ip(self.domain)
        self.data = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "domain": self.domain,
            "ip": self.ip,
            "port": self.port
        }

    def run(self):
        print_banner()
        if not self.ip:
            print("[!] Could not resolve IP. Exiting.")
            return

        print(f"[+] Target: {self.target}")
        print(f"[+] Domain: {self.domain}")
        print(f"[+] IP: {self.ip}")

        # 1. Reconnaissance
        recon = ReconEngine(self.domain)
        recon_data = recon.run()
        self.data['subdomains'] = recon_data.get('subdomains', [])
        print(f"[+] Found {len(self.data['subdomains'])} subdomains")

        # 2. WAF/CDN detection
        waf = WAFDetector(self.domain)
        waf_name, cdn_name = waf.detect()
        self.data['waf'] = waf_name
        self.data['cdn'] = cdn_name
        if waf_name:
            print(f"[+] WAF detected: {waf_name}")
        if cdn_name:
            print(f"[+] CDN detected: {cdn_name}")

        # 3. Network scan
        net_scanner = NetworkScanner(self.ip, ports=self.options.get('ports', COMMON_PORTS),
                                      stealth=self.options.get('stealth', False))
        network_results = net_scanner.scan()
        self.data['network'] = []
        for port, state, banner, version, cves in network_results:
            self.data['network'].append({
                "port": port,
                "state": state,
                "banner": banner,
                "version": version,
                "cves": cves
            })
            print(f"Port {port}: {state} - {banner} - {version}")

        # 4. Web scan (if web ports found)
        web_ports = [p for p, _, _, _, _ in network_results if p in [80, 443, 8080, 8443]]
        if web_ports:
            web_scanner = WebScanner(self.target)
            web_results = web_scanner.run()
            self.data['web'] = web_results
            print("[+] Web scan completed.")
        else:
            self.data['web'] = []
            print("[!] No web ports found, skipping web scan.")

        # 5. CVE mapping (from network services)
        vuln_engine = VulnEngine([(b, v) for _, _, b, v, _ in network_results if v != "Unknown"])
        cves = vuln_engine.lookup_cves()
        self.data['cves'] = cves
        self.data['risk'] = vuln_engine.assess_risk()
        print(f"[+] Risk assessment: {self.data['risk']}")

        # 6. Generate reports
        report_gen = ReportGenerator(self.target, self.data)
        report_gen.to_json()
        if self.options.get('html', False):
            report_gen.to_html()

        print("\n[+] Scan completed.")

def main():
    # Interactive mode if no arguments
    if len(sys.argv) == 1:
        print("Interactive mode (no command-line arguments provided).")
        target = input("Enter the target URL (e.g., https://example.com): ").strip()
        if not target:
            print("[!] Target URL is required.")
            return

        deep = input("Perform deep scan? (y/n): ").strip().lower() == 'y'
        stealth = input("Use stealth SYN scan? (requires scapy, may not work on Android) (y/n): ").strip().lower() == 'y'
        threads_input = input("Number of threads (default 20): ").strip()
        threads = int(threads_input) if threads_input.isdigit() else 20
        ports_input = input("Ports to scan (comma-separated, leave empty for default list): ").strip()
        ports = [int(p) for p in ports_input.split(',')] if ports_input else COMMON_PORTS
        output = input("Output format (json/html, default json): ").strip().lower()
        output = output if output in ['json', 'html'] else 'json'

        options = {
            'deep': deep,
            'threads': threads,
            'stealth': stealth,
            'ports': ports,
            'html': output == 'html'
        }
        scanner = AnishScanner(target, options)
        scanner.run()
        return

    # Otherwise, use argparse
    parser = argparse.ArgumentParser(description="Anish Security Scanner v5")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP (e.g., https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Deep scan (more thorough)")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default 20)")
    parser.add_argument("--stealth", action="store_true", help="Use stealth SYN scan (requires scapy)")
    parser.add_argument("--ports", type=str, help="Ports to scan (comma-separated)")
    parser.add_argument("--output", choices=['json', 'html'], default='json', help="Report format")
    args = parser.parse_args()

    options = {
        'deep': args.deep,
        'threads': args.threads,
        'stealth': args.stealth,
        'ports': [int(p) for p in args.ports.split(',')] if args.ports else COMMON_PORTS,
        'html': args.output == 'html'
    }

    scanner = AnishScanner(args.target, options)
    scanner.run()

if __name__ == "__main__":
    main()
