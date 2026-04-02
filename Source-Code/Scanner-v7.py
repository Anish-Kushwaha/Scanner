#!/usr/bin/env python3
"""
Anish Security Scanner v7 – True Async Intelligence Edition
Ultra‑fast, non‑blocking reconnaissance & vulnerability assessment
Ethical Use Only
"""

import asyncio
import aiohttp
import aiodns
import argparse
import json
import logging
import re
import time
import os
import sys
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
import socket

from bs4 import BeautifulSoup
import whois  # whois is sync but used only once, fine

# Disable warnings
try:
    import urllib3
    urllib3.disable_warnings()
except:
    pass

# ================= CONFIGURATION =================
DEFAULT_TIMEOUT = 5
MAX_CONCURRENT = 100           # Async semaphore limit
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443, 8888]
BANNER_GRAB_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389]

# Service probes
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
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}

# Known CDN ASNs and IP ranges (simplified, can be extended)
CDN_ASNS = {
    "Cloudflare": [13335],
    "Akamai": [16625, 20940],
    "Fastly": [54113],
    "Amazon CloudFront": [16509, 14618],
    "Google Cloud CDN": [15169],
}

# Subdomain takeover fingerprints (HTTP response)
TAKEOVER_FINGERPRINTS = {
    "github.io": ["There isn't a GitHub Pages site here", "404"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "herokuapp.com": ["No such app", "Heroku | No such app"],
    "azurewebsites.net": ["404 Web Site not found"],
    "cloudfront.net": ["The request could not be satisfied", "AccessDenied"],
    "fastly.net": ["Fastly error: unknown domain"],
    "firebaseapp.com": ["404 Not Found", "Page not found"],
    "netlify.com": ["Not Found", "Page Not Found"],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["Repository not found"],
    "gitlab.io": ["404 Not Found"],
    "vercel.app": ["The deployment could not be found"],
    "render.com": ["The page you’re looking for doesn’t exist"],
}

# Subdomain wordlist (truncated for brevity)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
    "ns2", "cpanel", "whm", "autodiscover", "m", "imap", "test",
    "dev", "admin", "blog", "support", "api", "app", "cdn", "static",
    "assets", "portal", "dashboard", "docs", "status", "monitor",
    "staging", "stage", "qa", "prod", "production", "alpha", "beta"
]

# Directory wordlist
COMMON_DIRECTORIES = [
    "/admin", "/backup", "/config", "/logs", "/test", "/upload",
    "/wp-admin", "/wp-content", "/wp-includes", "/uploads", "/files",
    "/images", "/css", "/js", "/vendor", "/assets", "/cgi-bin",
    "/.git", "/.svn", "/.env", "/phpmyadmin", "/api", "/graphql",
    "/swagger", "/redoc", "/robots.txt", "/sitemap.xml"
]

COMMON_FILES = [
    "index.php", "index.html", "login.php", "admin.php", "config.php",
    "wp-config.php", ".env", "backup.zip", "dump.sql", "error.log",
    "phpinfo.php", "readme.html", "composer.json", "package.json"
]

SENSITIVE_PATTERNS = [
    r"(?i)(DB_|DATABASE_)(USERNAME|PASSWORD|HOST|NAME)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(AWS_|AZURE_|GCP_)(ACCESS_KEY|SECRET_KEY|KEY|SECRET)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(API_KEY|API_SECRET|APP_KEY|APP_SECRET)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(PASSWORD|PASSWD|PASSPHRASE)\s*[=:]\s*['\"]?([^'\"]+)",
]

XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"

# Setup logging
logging.basicConfig(filename="anish_scanner_v7.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ================= UTILITY FUNCTIONS =================
def print_banner():
    print(r"""
     █████╗ ███╗   ██╗██╗███████╗██╗  ██╗
    ██╔══██╗████╗  ██║██║██╔════╝██║  ██║
    ███████║██╔██╗ ██║██║███████╗███████║
    ██╔══██║██║╚██╗██║██║╚════██║██╔══██║
    ██║  ██║██║ ╚████║██║███████║██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝  ╚═╝

    Anish Security Scanner v7 – True Async Intelligence Edition
    Ultra‑fast, non‑blocking reconnaissance & vulnerability assessment
    Ethical Use Only
    """)

async def resolve_ip(domain, resolver):
    """Async IP resolution using aiodns."""
    try:
        result = await resolver.gethostbyname(domain, socket.AF_INET)
        return result[0] if result else None
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
class AsyncNetworkScanner:
    """Async network scanner with proper TCP connect and banner grabbing."""
    def __init__(self, target_ip, ports=None, timeout=DEFAULT_TIMEOUT, concurrency=MAX_CONCURRENT):
        self.target_ip = target_ip
        self.ports = ports or COMMON_PORTS
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = []

    async def scan(self):
        logger.info(f"Starting async network scan on {self.target_ip}")
        tasks = [self._scan_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.results = [r for r in results if r is not None]
        return self.results

    async def _scan_port(self, port):
        async with self.semaphore:
            try:
                # Asynchronous TCP connect
                reader, writer = await asyncio.open_connection(self.target_ip, port)
                writer.close()
                await writer.wait_closed()
                state = 'open'
            except asyncio.TimeoutError:
                state = 'filtered'
            except ConnectionRefusedError:
                state = 'closed'
            except Exception:
                state = 'filtered'

            if state == 'open':
                banner = await self._grab_banner(port)
                version = self._detect_version(port, banner)
                # We'll do CVE lookup later; just return data
                return (port, state, banner, version)
            return None

    async def _grab_banner(self, port):
        if port not in BANNER_GRAB_PORTS:
            return ""
        probe = SERVICE_PROBES.get(port, b"\r\n")
        try:
            reader, writer = await asyncio.open_connection(self.target_ip, port)
            writer.write(probe)
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return banner.decode(errors='ignore').strip()
        except Exception:
            return ""

    def _detect_version(self, port, banner):
        # Improved version detection
        if port == 80 or port == 443:
            match = re.search(r"Server:\s*([^\r\n]+)", banner)
            if match:
                return match.group(1).strip()
            return "Unknown"
        elif port == 22:
            match = re.search(r"SSH-([\d.]+)", banner)
            if match:
                return f"OpenSSH {match.group(1)}"
        elif port == 21:
            parts = banner.split()
            return parts[1] if len(parts) > 1 else banner
        return "Unknown"

class WAFDetector:
    """Enhanced WAF/CDN detection with ASN and IP ranges."""
    def __init__(self, domain, session, resolver):
        self.domain = domain
        self.session = session
        self.resolver = resolver
        self.waf = None
        self.cdn = None

    async def detect(self):
        # 1. DNS CNAME detection
        try:
            cname = await self._get_cname()
            if cname:
                for cdn_domain, name in CDN_CNAMES.items():
                    if cdn_domain in cname:
                        self.cdn = name
                        break
        except:
            pass

        # 2. HTTP headers detection
        try:
            async with self.session.get(f"http://{self.domain}", timeout=HTTP_TIMEOUT) as resp:
                headers = resp.headers
                text = await resp.text()
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if any(sig in k for k in headers) or sig in text:
                            self.waf = waf
                            break
                    if self.waf:
                        break
                # CDN detection from headers
                if not self.cdn:
                    if 'CF-Cache-Status' in headers:
                        self.cdn = "Cloudflare"
                    elif 'X-Akamai-Transformed' in headers:
                        self.cdn = "Akamai"
                    elif 'X-Fastly-Request-ID' in headers:
                        self.cdn = "Fastly"
        except:
            pass

        # 3. IP ASN lookup (using ipinfo.io or similar)
        ip = await resolve_ip(self.domain, self.resolver)
        if ip:
            asn = await self._get_asn(ip)
            for cdn_name, asns in CDN_ASNS.items():
                if asn in asns:
                    self.cdn = cdn_name
                    break
        return self.waf, self.cdn

    async def _get_cname(self):
        try:
            # Use aiodns for CNAME
            result = await self.resolver.query(self.domain, 'CNAME')
            if result:
                return str(result[0].target).lower()
        except:
            pass
        return None

    async def _get_asn(self, ip):
        # Simple free API
        try:
            async with self.session.get(f"https://ipinfo.io/{ip}/json") as resp:
                data = await resp.json()
                org = data.get('org', '')
                if 'AS' in org:
                    asn = int(org.split()[0][2:])
                    return asn
        except:
            pass
        return None

class ReconEngine:
    """Async recon with subdomain enumeration and takeover detection."""
    def __init__(self, domain, session, resolver, concurrency=MAX_CONCURRENT):
        self.domain = domain
        self.session = session
        self.resolver = resolver
        self.semaphore = asyncio.Semaphore(concurrency)
        self.subdomains = []
        self.takeover_vulns = []

    async def enumerate_subdomains(self):
        # 1. Certificate transparency (crt.sh)
        try:
            async with self.session.get(f"https://crt.sh/?q=%.{self.domain}&output=json") as resp:
                data = await resp.json()
                for entry in data:
                    name = entry.get('name_value')
                    if name and name.endswith(self.domain):
                        self.subdomains.append(name.lower())
        except:
            pass

        # 2. Wordlist brute-force with async DNS
        tasks = []
        for sub in SUBDOMAIN_WORDLIST:
            tasks.append(self._check_subdomain(sub))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for found in results:
            if found:
                self.subdomains.append(found)

        self.subdomains = list(set(self.subdomains))
        return self.subdomains

    async def _check_subdomain(self, sub):
        async with self.semaphore:
            try:
                target = f"{sub}.{self.domain}"
                # Async DNS lookup
                await self.resolver.gethostbyname(target, socket.AF_INET)
                return target
            except:
                return None

    async def check_takeover(self):
        for sub in self.subdomains:
            # Get CNAME
            try:
                result = await self.resolver.query(sub, 'CNAME')
                if result:
                    cname = str(result[0].target).lower()
                    for pattern, service in TAKEOVER_SIGNATURES.items():
                        if pattern in cname:
                            # Verify with HTTP request
                            if await self._verify_takeover(sub, pattern):
                                self.takeover_vulns.append({
                                    "subdomain": sub,
                                    "cname": cname,
                                    "service": service
                                })
            except:
                pass

    async def _verify_takeover(self, subdomain, pattern):
        try:
            async with self.session.get(f"http://{subdomain}", timeout=HTTP_TIMEOUT) as resp:
                text = await resp.text()
                fingerprints = TAKEOVER_FINGERPRINTS.get(pattern, [])
                for fp in fingerprints:
                    if fp.lower() in text.lower():
                        return True
        except:
            pass
        return False

    async def run(self):
        await self.enumerate_subdomains()
        await self.check_takeover()
        return {"subdomains": self.subdomains, "takeover_vulns": self.takeover_vulns}

class WebScanner:
    """Async web scanner with tech detection, directory enumeration, and vulnerability tests."""
    def __init__(self, target_url, session, resolver):
        self.target_url = target_url.rstrip('/')
        self.session = session
        self.resolver = resolver
        self.technologies = {}
        self.results = []
        self.rate_limited = False

    async def detect_technologies(self):
        try:
            async with self.session.get(self.target_url, timeout=HTTP_TIMEOUT) as resp:
                headers = resp.headers
                html = await resp.text()
                # CMS detection
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
                if 'Server' in headers:
                    self.technologies['Server'] = headers['Server']
                # Rate limit detection
                if resp.status == 429 or 'Retry-After' in headers:
                    self.rate_limited = True
        except:
            pass
        return self.technologies

    async def extract_js_endpoints(self):
        endpoints = []
        try:
            async with self.session.get(self.target_url) as resp:
                html = await resp.text()
                soup = BeautifulSoup(html, 'html.parser')
                scripts = soup.find_all('script', src=True)
                tasks = []
                for script in scripts:
                    src = script['src']
                    js_url = urljoin(self.target_url, src)
                    tasks.append(self._fetch_js(js_url))
                js_contents = await asyncio.gather(*tasks, return_exceptions=True)
                for js in js_contents:
                    if isinstance(js, str):
                        # Enhanced regex to find various endpoints
                        # API paths, GraphQL, etc.
                        api_matches = re.findall(r'["\'](/[^"\']+)["\']', js)
                        # Filter likely endpoints
                        for match in api_matches:
                            if any(x in match for x in ['/api/', '/graphql', '/v1/', '/v2/', '/wp-json']):
                                endpoints.append(match)
        except:
            pass
        return list(set(endpoints))

    async def _fetch_js(self, url):
        try:
            async with self.session.get(url) as resp:
                return await resp.text()
        except:
            return ""

    async def directory_enum(self):
        tasks = [self._check_dir(d) for d in COMMON_DIRECTORIES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [res for res in results if res]

    async def _check_dir(self, dir):
        try:
            url = urljoin(self.target_url, dir)
            async with self.session.get(url, allow_redirects=False) as resp:
                if resp.status in (200, 403, 401):
                    return url
        except:
            pass
        return None

    async def file_enum(self):
        tasks = [self._check_file(f) for f in COMMON_FILES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [res for res in results if res]

    async def _check_file(self, f):
        url = urljoin(self.target_url, f)
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    # Check sensitive data
                    self._check_sensitive_data(text, url)
                    return url
        except:
            pass
        return None

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

    async def test_xss(self):
        xss_url = urljoin(self.target_url, f"?test={XSS_PAYLOAD}")
        try:
            async with self.session.get(xss_url) as resp:
                text = await resp.text()
                if XSS_PAYLOAD in text:
                    self.results.append({
                        "type": "XSS",
                        "url": xss_url,
                        "severity": "High"
                    })
                    logger.warning(f"XSS detected at {xss_url}")
        except:
            pass

    async def test_sqli(self):
        sqli_url = urljoin(self.target_url, f"?id={SQLI_PAYLOAD}")
        try:
            async with self.session.get(sqli_url) as resp:
                text = await resp.text()
                if "mysql" in text.lower() or "sql syntax" in text.lower():
                    self.results.append({
                        "type": "SQLi",
                        "url": sqli_url,
                        "severity": "Critical"
                    })
                    logger.warning(f"SQLi detected at {sqli_url}")
        except:
            pass

    async def run(self):
        await self.detect_technologies()
        self.results.append({"type": "Technologies", "data": self.technologies})
        endpoints = await self.extract_js_endpoints()
        self.results.append({"type": "JS Endpoints", "data": endpoints})
        dirs = await self.directory_enum()
        for d in dirs:
            self.results.append({"type": "Exposed Directory", "url": d, "severity": "Medium"})
        files = await self.file_enum()
        for f in files:
            self.results.append({"type": "Exposed File", "url": f, "severity": "Medium"})
        await self.test_xss()
        await self.test_sqli()
        return self.results

class VulnEngine:
    """CVE lookup with CPE matching and CVSS scoring."""
    def __init__(self, services, session):
        self.services = services  # list of (service_name, version)
        self.session = session
        self.vulns = []
        self.cve_cache = self._load_cache()

    def _load_cache(self):
        cache_file = "cve_cache.json"
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    if data.get('timestamp', 0) > time.time() - 86400:  # 24h TTL
                        return data.get('cves', {})
            except:
                pass
        return {}

    def _save_cache(self):
        cache_file = "cve_cache.json"
        with open(cache_file, 'w') as f:
            json.dump({'timestamp': time.time(), 'cves': self.cve_cache}, f)

    async def lookup_cves(self):
        for name, version in self.services:
            if version == "Unknown":
                continue
            # Build CPE: cpe:2.3:a:vendor:product:version
            # Very naive: extract vendor and product from name
            vendor = name.split('/')[0].lower()
            product = name.split('/')[-1].lower()
            # For Apache, it's "apache" vendor and "http_server" product, etc. We'll keep simple.
            cpe = f"cpe:2.3:a:{vendor}:{product}:{version}"
            # Check cache
            if cpe in self.cve_cache:
                self.vulns.extend(self.cve_cache[cpe])
                continue
            # Query NVD
            params = {
                'keywordSearch': cpe,
                'resultsPerPage': 20
            }
            try:
                async with self.session.get('https://services.nvd.nist.gov/rest/json/cves/2.0', params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        cves = []
                        for item in data.get('vulnerabilities', []):
                            cve = item['cve']
                            # Get CVSS score
                            metrics = cve.get('metrics', {})
                            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                            cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                            score = max(cvss_v3, cvss_v2)
                            if score >= 6.0:  # Only High severity
                                cves.append({
                                    'id': cve['id'],
                                    'cvss': score,
                                    'description': cve['descriptions'][0]['value'][:200]
                                })
                        self.cve_cache[cpe] = cves
                        self.vulns.extend(cves)
            except:
                pass
        self._save_cache()
        return self.vulns

    def assess_risk(self):
        if not self.vulns:
            return "Low"
        max_cvss = max([v['cvss'] for v in self.vulns])
        if max_cvss >= 9.0:
            return "Critical"
        elif max_cvss >= 7.0:
            return "High"
        elif max_cvss >= 4.0:
            return "Medium"
        else:
            return "Low"

class ReportGenerator:
    """Generate JSON and HTML reports."""
    def __init__(self, target, scan_data):
        self.target = target
        self.data = scan_data

    def to_json(self, filename="anish_report_v7.json"):
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)
        print(f"[+] JSON report saved to {filename}")

    def to_html(self, filename="anish_report_v7.html"):
        risk = self.data.get('risk', 'Unknown')
        color = {'Critical':'red', 'High':'orange', 'Medium':'yellow', 'Low':'green'}.get(risk, 'black')
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Anish Scanner Report - {self.target}</title>
        <style>
            body {{ font-family: Arial; margin: 20px; }}
            .risk {{ color: {color}; font-weight: bold; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
        </head>
        <body>
        <h1>Security Scan Report for {self.target}</h1>
        <p>Generated: {datetime.now().isoformat()}</p>
        <p>Risk Level: <span class="risk">{risk}</span></p>
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
        self.data = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "domain": self.domain,
            "port": self.port
        }

    async def run(self):
        print_banner()
        # Create shared objects
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, limit_per_host=MAX_CONCURRENT)
        async with aiohttp.ClientSession(connector=connector, timeout=HTTP_TIMEOUT) as session:
            resolver = aiodns.DNSResolver()
            # Resolve IP
            self.data['ip'] = await resolve_ip(self.domain, resolver)
            if not self.data['ip']:
                print("[!] Could not resolve IP. Exiting.")
                return

            print(f"[+] Target: {self.target}")
            print(f"[+] Domain: {self.domain}")
            print(f"[+] IP: {self.data['ip']}")

            # 1. WAF/CDN detection
            waf_detector = WAFDetector(self.domain, session, resolver)
            waf_name, cdn_name = await waf_detector.detect()
            self.data['waf'] = waf_name
            self.data['cdn'] = cdn_name
            if waf_name:
                print(f"[+] WAF detected: {waf_name}")
            if cdn_name:
                print(f"[+] CDN detected: {cdn_name}")

            # 2. Reconnaissance
            recon = ReconEngine(self.domain, session, resolver)
            recon_data = await recon.run()
            self.data['subdomains'] = recon_data['subdomains']
            self.data['takeover_vulns'] = recon_data['takeover_vulns']
            print(f"[+] Found {len(self.data['subdomains'])} subdomains")
            if self.data['takeover_vulns']:
                print("[+] Potential subdomain takeover vulnerabilities:")
                for tv in self.data['takeover_vulns']:
                    print(f"    {tv['subdomain']} -> {tv['service']}")

            # 3. Network scan (skip if CDN and not forced)
            if cdn_name and not self.options.get('force_network', False):
                print("[!] CDN detected. Skipping deep network scan (use --force-network to override).")
                network_results = []
            else:
                net_scanner = AsyncNetworkScanner(self.data['ip'], ports=self.options.get('ports', COMMON_PORTS))
                network_results = await net_scanner.scan()
                self.data['network'] = []
                for port, state, banner, version in network_results:
                    self.data['network'].append({
                        "port": port,
                        "state": state,
                        "banner": banner,
                        "version": version
                    })
                    print(f"Port {port}: {state} - {banner} - {version}")

            # 4. Web scan (if web ports found or forced)
            web_ports = [p for p, _, _, _ in network_results if p in [80, 443, 8080, 8443]] if network_results else []
            if web_ports or self.options.get('force_web', False):
                web_scanner = WebScanner(self.target, session, resolver)
                web_results = await web_scanner.run()
                self.data['web'] = web_results
                print("[+] Web scan completed.")
            else:
                self.data['web'] = []
                print("[!] No web ports found, skipping web scan.")

            # 5. CVE mapping
            services = [(b, v) for _, _, b, v in network_results]
            vuln_engine = VulnEngine(services, session)
            cves = await vuln_engine.lookup_cves()
            self.data['cves'] = cves
            self.data['risk'] = vuln_engine.assess_risk()
            print(f"[+] Risk assessment: {self.data['risk']}")

            # 6. Reports
            report_gen = ReportGenerator(self.target, self.data)
            report_gen.to_json()
            if self.options.get('html', False):
                report_gen.to_html()

        print("\n[+] Scan completed.")

def main():
    parser = argparse.ArgumentParser(description="Anish Security Scanner v7")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP (e.g., https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Deep scan (more thorough)")
    parser.add_argument("--stealth", action="store_true", help="Stealth SYN scan (not available in async mode)")
    parser.add_argument("--ports", type=str, help="Ports to scan (comma-separated)")
    parser.add_argument("--output", choices=['json', 'html'], default='json', help="Report format")
    parser.add_argument("--force-network", action="store_true", help="Force network scan even if CDN detected")
    parser.add_argument("--force-web", action="store_true", help="Force web scan even if no web ports found")
    args = parser.parse_args()

    options = {
        'deep': args.deep,
        'stealth': args.stealth,
        'ports': [int(p) for p in args.ports.split(',')] if args.ports else COMMON_PORTS,
        'html': args.output == 'html',
        'force_network': args.force_network,
        'force_web': args.force_web
    }

    scanner = AnishScanner(args.target, options)
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()
