#!/usr/bin/env python3
"""
Anish Security Scanner v8 – Ultimate Intelligence Edition
Fully async, adaptive, stealthy, and intelligent
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
import random
import socket
from datetime import datetime
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import whois

# Optional Scapy for stealth and OS detection
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# Disable warnings
try:
    import urllib3
    urllib3.disable_warnings()
except:
    pass

# ================= CONFIGURATION =================
DEFAULT_TIMEOUT = 5
INITIAL_CONCURRENCY = 100
MAX_CONCURRENT = 200
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

# WAF signatures
WAF_SIGNATURES = {
    "Cloudflare": ["CF-Ray", "cloudflare", "__cfduid"],
    "Akamai": ["X-Akamai-Transformed", "X-Akamai-Request-ID"],
    "AWS WAF": ["x-amzn-RequestId", "AWSALB"],
    "Sucuri": ["X-Sucuri-ID", "X-Sucuri-Cache"],
    "Wordfence": ["wordfence", "wfvt_"],
    "Imperva": ["X-Iinfo", "X-Cdn"],
    "F5 BIG-IP": ["X-WA-Info", "X-Cnection"],
}

# CDN detection via CNAME
CDN_CNAMES = {
    "cloudflare.com": "Cloudflare",
    "cloudfront.net": "AWS CloudFront",
    "akamai.net": "Akamai",
    "fastly.net": "Fastly",
    "edgecastcdn.net": "Verizon Edgecast",
    "azureedge.net": "Azure CDN",
}

# CDN ASNs
CDN_ASNS = {
    "Cloudflare": [13335],
    "Akamai": [16625, 20940],
    "Fastly": [54113],
    "Amazon CloudFront": [16509, 14618],
}

# Subdomain takeover fingerprints
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

# Subdomain wordlist
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

# Service to CPE mapping for accurate CVE matching
SERVICE_CPE_MAP = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "php": ("php", "php"),
}

# OS fingerprinting using TCP SYN response (TTL, window size)
OS_FINGERPRINTS = {
    (64, 5840): "Linux 2.6.x / 3.x",
    (64, 8192): "Linux 4.x",
    (128, 8192): "Windows 10 / Server 2016",
    (128, 64240): "Windows 7 / 2008",
    (64, 16384): "FreeBSD",
    (255, 4128): "Cisco IOS",
    (64, 65535): "Mac OS X",
}

# User agents for web stealth
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
]

# Setup logging
logging.basicConfig(filename="anish_scanner_v8.log", level=logging.INFO,
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

    Anish Security Scanner v8 – Ultimate Intelligence Edition
    Fully async, adaptive, stealthy, and intelligent
    Ethical Use Only
    """)

async def resolve_ip(domain, resolver):
    try:
        # Try async DNS first
        result = await resolver.gethostbyname(domain.lower(), socket.AF_INET)
        return result[0] if result else None
    except Exception:
        try:
            # Fallback to system DNS (VERY IMPORTANT)
            return socket.gethostbyname(domain.lower())
        except Exception as e:
            logger.error(f"DNS resolution failed: {e}")
            return None

def parse_url_and_detect_port(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == 'https' else 80
    return domain, port

def load_profile(target):
    """Load previous scan profile for intelligence."""
    profile_file = "target_profiles.json"
    if os.path.exists(profile_file):
        try:
            with open(profile_file, 'r') as f:
                profiles = json.load(f)
                return profiles.get(target, {})
        except:
            pass
    return {}

def save_profile(target, data):
    """Save current scan profile."""
    profile_file = "target_profiles.json"
    profiles = {}
    if os.path.exists(profile_file):
        try:
            with open(profile_file, 'r') as f:
                profiles = json.load(f)
        except:
            pass
    profiles[target] = data
    with open(profile_file, 'w') as f:
        json.dump(profiles, f, indent=4)

# ================= RATE LIMITER =================
class RateLimiter:
    """Adaptive rate limiter that reduces concurrency on 429."""
    def __init__(self, initial_concurrency=INITIAL_CONCURRENCY):
        self.concurrency = initial_concurrency
        self.semaphore = asyncio.Semaphore(initial_concurrency)
        self.backoff_factor = 1.0
        self.last_429 = 0
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            await self.semaphore.acquire()

    def release(self):
        self.semaphore.release()

    async def on_429(self):
        async with self.lock:
            now = time.time()
            if now - self.last_429 < 30:  # multiple 429s in a short time
                # Reduce concurrency
                self.concurrency = max(1, self.concurrency // 2)
                self.semaphore = asyncio.Semaphore(self.concurrency)
                self.backoff_factor *= 2
            self.last_429 = now
            # Wait before allowing more requests
            await asyncio.sleep(self.backoff_factor)

# ================= NETWORK SCANNER (Async + Stealth) =================
class AsyncNetworkScanner:
    def __init__(self, target_ip, ports=None, timeout=DEFAULT_TIMEOUT, stealth=False):
        self.target_ip = target_ip
        self.ports = ports or COMMON_PORTS
        self.timeout = timeout
        self.stealth = stealth and SCAPY_AVAILABLE
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        self.results = []

    async def scan(self):
        logger.info(f"Starting network scan on {self.target_ip}")
        tasks = [self._scan_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.results = [r for r in results if r is not None]
        return self.results

    async def _scan_port(self, port):
        async with self.semaphore:
            if self.stealth:
                # SYN scan using Scapy (blocking, run in thread)
                state = await asyncio.get_event_loop().run_in_executor(None, self._syn_scan, port)
                if state != 'open':
                    return None
            else:
                # TCP connect
                try:
                    reader, writer = await asyncio.open_connection(self.target_ip, port)
                    writer.close()
                    await writer.wait_closed()
                    state = 'open'
                except (asyncio.TimeoutError, ConnectionRefusedError):
                    return None
                except Exception:
                    return None

            # Grab banner and detect version
            banner = await self._grab_banner(port)
            version = self._detect_version(port, banner)
            os_info = await self._detect_os(port) if SCAPY_AVAILABLE else {}
            return (port, state, banner, version, os_info)

    def _syn_scan(self, port):
        try:
            pkt = scapy.IP(dst=self.target_ip) / scapy.TCP(dport=port, flags='S', sport=random.randint(1024, 65535))
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
            if resp and resp.haslayer(scapy.TCP):
                if resp.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close
                    scapy.send(scapy.IP(dst=self.target_ip) / scapy.TCP(dport=port, flags='R'), verbose=0)
                    return 'open'
            return 'closed'
        except Exception:
            return 'closed'

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
        # Improved version extraction
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

    async def _detect_os(self, port):
        """Detect OS using TCP SYN response (requires Scapy)."""
        try:
            pkt = scapy.IP(dst=self.target_ip) / scapy.TCP(dport=port, flags='S')
            resp = await asyncio.get_event_loop().run_in_executor(None, scapy.sr1, pkt, self.timeout, 0)
            if resp and resp.haslayer(scapy.TCP):
                ttl = resp.ttl
                window = resp.getlayer(scapy.TCP).window
                for (ttl_range, win_range), os_name in OS_FINGERPRINTS.items():
                    if abs(ttl - ttl_range) < 10 and abs(window - win_range) < 1000:
                        return {"os": os_name, "ttl": ttl, "window": window}
            return {"os": "Unknown", "ttl": None, "window": None}
        except Exception:
            return {"os": "Unknown", "ttl": None, "window": None}

# ================= WAF/CDN DETECTOR =================
class WAFDetector:
    def __init__(self, domain, session, resolver):
        self.domain = domain
        self.session = session
        self.resolver = resolver
        self.waf = None
        self.cdn = None

    async def detect(self):
        # DNS CNAME
        try:
            cname = await self._get_cname()
            if cname:
                for cdn_domain, name in CDN_CNAMES.items():
                    if cdn_domain in cname:
                        self.cdn = name
                        break
        except:
            pass

        # HTTP headers
        try:
            async with self.session.get(f"http://{self.domain}", timeout=5) as resp:
                headers = resp.headers
                text = await resp.text()
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if any(sig in k for k in headers) or sig in text:
                            self.waf = waf
                            break
                    if self.waf:
                        break
                if not self.cdn:
                    if 'CF-Cache-Status' in headers:
                        self.cdn = "Cloudflare"
                    elif 'X-Akamai-Transformed' in headers:
                        self.cdn = "Akamai"
        except:
            pass

        # ASN lookup (ipinfo.io)
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
            result = await self.resolver.query(self.domain, 'CNAME')
            if result:
                return str(result[0].target).lower()
        except:
            pass
        return None

    async def _get_asn(self, ip):
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

# ================= RECON ENGINE (Subdomains + Takeover) =================
class ReconEngine:
    def __init__(self, domain, session, resolver, concurrency=MAX_CONCURRENT):
        self.domain = domain
        self.session = session
        self.resolver = resolver
        self.semaphore = asyncio.Semaphore(concurrency)
        self.subdomains = []
        self.takeover_vulns = []

    async def enumerate_subdomains(self):
        # Certificate transparency
        try:
            async with self.session.get(f"https://crt.sh/?q=%.{self.domain}&output=json") as resp:
                data = await resp.json()
                for entry in data:
                    name = entry.get('name_value')
                    if name and name.endswith(self.domain):
                        self.subdomains.append(name.lower())
        except:
            pass

        # Wordlist brute-force
        tasks = [self._check_subdomain(sub) for sub in SUBDOMAIN_WORDLIST]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for found in results:
            if found:
                self.subdomains.append(found)
        self.subdomains = list(set(self.subdomains))

    async def _check_subdomain(self, sub):
        async with self.semaphore:
            try:
                target = f"{sub}.{self.domain}"
                await self.resolver.gethostbyname(target, socket.AF_INET)
                return target
            except:
                return None

    async def check_takeover(self):
        for sub in self.subdomains:
            try:
                result = await self.resolver.query(sub, 'CNAME')
                if result:
                    cname = str(result[0].target).lower()
                    for pattern, service in TAKEOVER_FINGERPRINTS.items():
                        if pattern in cname:
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
            async with self.session.get(f"http://{subdomain}", timeout=5) as resp:
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

# ================= WEB SCANNER (with Stealth) =================
class WebScanner:
    def __init__(self, target_url, session, resolver, stealth=False):
        self.target_url = target_url.rstrip('/')
        self.session = session
        self.resolver = resolver
        self.stealth = stealth
        self.technologies = {}
        self.results = []
        self.rate_limiter = RateLimiter()
        self.user_agent_cycle = 0

    async def _request(self, url, **kwargs):
        """Perform a request with stealth and rate limiting."""
        await self.rate_limiter.acquire()
        try:
            if self.stealth:
                # Random user agent and delay
                ua = random.choice(USER_AGENTS)
                kwargs['headers'] = kwargs.get('headers', {})
                kwargs['headers']['User-Agent'] = ua
                await asyncio.sleep(random.uniform(0.1, 0.5))
            async with self.session.get(url, **kwargs) as resp:
                if resp.status == 429:
                    await self.rate_limiter.on_429()
                return resp
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None
        finally:
            self.rate_limiter.release()

    async def detect_technologies(self):
        resp = await self._request(self.target_url)
        if not resp:
            return
        headers = resp.headers
        html = await resp.text()
        # CMS
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
        self.results.append({"type": "Technologies", "data": self.technologies})

    async def extract_js_endpoints(self):
        endpoints = []
        resp = await self._request(self.target_url)
        if not resp:
            return endpoints
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
                # Find API endpoints
                matches = re.findall(r'["\'](/[^"\']+)["\']', js)
                for m in matches:
                    if any(x in m for x in ['/api/', '/graphql', '/v1/', '/v2/', '/wp-json']):
                        endpoints.append(m)
        return list(set(endpoints))

    async def _fetch_js(self, url):
        resp = await self._request(url)
        if resp:
            return await resp.text()
        return ""

    async def directory_enum(self):
        tasks = [self._check_dir(d) for d in COMMON_DIRECTORIES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [res for res in results if res]

    async def _check_dir(self, dir):
        url = urljoin(self.target_url, dir)
        resp = await self._request(url, allow_redirects=False)
        if resp and resp.status in (200, 403, 401):
            return url
        return None

    async def file_enum(self):
        tasks = [self._check_file(f) for f in COMMON_FILES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [res for res in results if res]

    async def _check_file(self, f):
        url = urljoin(self.target_url, f)
        resp = await self._request(url)
        if resp and resp.status == 200:
            text = await resp.text()
            self._check_sensitive_data(text, url)
            return url
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
        resp = await self._request(xss_url)
        if resp:
            text = await resp.text()
            if XSS_PAYLOAD in text:
                self.results.append({
                    "type": "XSS",
                    "url": xss_url,
                    "severity": "High"
                })
                logger.warning(f"XSS detected at {xss_url}")

    async def test_sqli(self):
        sqli_url = urljoin(self.target_url, f"?id={SQLI_PAYLOAD}")
        resp = await self._request(sqli_url)
        if resp:
            text = await resp.text()
            if "mysql" in text.lower() or "sql syntax" in text.lower():
                self.results.append({
                    "type": "SQLi",
                    "url": sqli_url,
                    "severity": "Critical"
                })
                logger.warning(f"SQLi detected at {sqli_url}")

    async def run(self):
        await self.detect_technologies()
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

# ================= VULNERABILITY ENGINE (Accurate CVE) =================
class VulnEngine:
    def __init__(self, services, session):
        self.services = services  # list of (banner, version)
        self.session = session
        self.vulns = []
        self.cve_cache = self._load_cache()

    def _load_cache(self):
        cache_file = "cve_cache.json"
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    if data.get('timestamp', 0) > time.time() - 86400:
                        return data.get('cves', {})
            except:
                pass
        return {}

    def _save_cache(self):
        cache_file = "cve_cache.json"
        with open(cache_file, 'w') as f:
            json.dump({'timestamp': time.time(), 'cves': self.cve_cache}, f)

    async def lookup_cves(self):
        for banner, version in self.services:
            if version == "Unknown":
                continue
            # Map service to CPE vendor:product
            service_key = banner.split('/')[0].lower()
            if service_key in SERVICE_CPE_MAP:
                vendor, product = SERVICE_CPE_MAP[service_key]
            else:
                # Fallback: assume vendor = product = service_key
                vendor = product = service_key
            cpe = f"cpe:2.3:a:{vendor}:{product}:{version}"
            # Extract exact version number (e.g., 1.18.0)
            ver_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
            if ver_match:
                exact_version = ver_match.group(1)
                cpe = f"cpe:2.3:a:{vendor}:{product}:{exact_version}"
            # Check cache
            if cpe in self.cve_cache:
                self.vulns.extend(self.cve_cache[cpe])
                continue
            # Query NVD
            params = {'keywordSearch': cpe, 'resultsPerPage': 20}
            try:
                async with self.session.get('https://services.nvd.nist.gov/rest/json/cves/2.0', params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        cves = []
                        for item in data.get('vulnerabilities', []):
                            cve = item['cve']
                            metrics = cve.get('metrics', {})
                            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                            cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                            score = max(cvss_v3, cvss_v2)
                            if score >= 6.0:
                                cves.append({
                                    'id': cve['id'],
                                    'cvss': score,
                                    'description': cve['descriptions'][0]['value'][:200]
                                })
                        self.cve_cache[cpe] = cves
                        self.vulns.extend(cves)
            except Exception as e:
                logger.error(f"CVE lookup error: {e}")
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

# ================= REPORT GENERATOR (with profiling) =================
class ReportGenerator:
    def __init__(self, target, scan_data, previous_profile):
        self.target = target
        self.data = scan_data
        self.previous = previous_profile

    def to_json(self, filename="anish_report_v8.json"):
        # Add diff if previous profile exists
        if self.previous:
            diff = self._compute_diff()
            self.data['changes'] = diff
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)
        print(f"[+] JSON report saved to {filename}")
        # Save profile for future scans
        profile = {k: v for k, v in self.data.items() if k in ['network', 'web', 'subdomains', 'technologies']}
        profile['timestamp'] = datetime.now().isoformat()
        save_profile(self.target, profile)

    def to_html(self, filename="anish_report_v8.html"):
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

    def _compute_diff(self):
        diff = {}
        # Compare network ports
        new_ports = []
        old_ports = [p['port'] for p in self.previous.get('network', [])]
        current_ports = [p['port'] for p in self.data.get('network', [])]
        for p in current_ports:
            if p not in old_ports:
                new_ports.append(p)
        if new_ports:
            diff['new_ports'] = new_ports
        # Compare technologies
        old_tech = self.previous.get('technologies', {})
        new_tech = self.data.get('technologies', {})
        if new_tech != old_tech:
            diff['technology_changes'] = new_tech
        return diff

# ================= MAIN SCANNER =================
class AnishScanner:
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
        self.previous_profile = load_profile(target)

    async def run(self):
        print_banner()
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, limit_per_host=MAX_CONCURRENT)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)) as session:
            resolver = aiodns.DNSResolver()
            ip = await resolve_ip(self.domain, resolver)
            if not ip:
                print("[!] Could not resolve IP. Exiting.")
                return
            self.data['ip'] = ip
            print(f"[+] Target: {self.target}")
            print(f"[+] Domain: {self.domain}")
            print(f"[+] IP: {ip}")

            # 1. WAF/CDN
            waf = WAFDetector(self.domain, session, resolver)
            waf_name, cdn_name = await waf.detect()
            self.data['waf'] = waf_name
            self.data['cdn'] = cdn_name
            if waf_name:
                print(f"[+] WAF detected: {waf_name}")
            if cdn_name:
                print(f"[+] CDN detected: {cdn_name}")

            # 2. Recon
            recon = ReconEngine(self.domain, session, resolver)
            recon_data = await recon.run()
            self.data['subdomains'] = recon_data['subdomains']
            self.data['takeover_vulns'] = recon_data['takeover_vulns']
            print(f"[+] Found {len(self.data['subdomains'])} subdomains")
            if self.data['takeover_vulns']:
                print("[+] Potential subdomain takeover vulnerabilities:")
                for tv in self.data['takeover_vulns']:
                    print(f"    {tv['subdomain']} -> {tv['service']}")

            # 3. Network scan
            if cdn_name and not self.options.get('force_network', False):
                print("[!] CDN detected. Skipping deep network scan (use --force-network to override).")
                network_results = []
            else:
                net_scanner = AsyncNetworkScanner(ip, ports=self.options.get('ports', COMMON_PORTS),
                                                   stealth=self.options.get('stealth', False))
                network_results = await net_scanner.scan()
                self.data['network'] = []
                for port, state, banner, version, os_info in network_results:
                    self.data['network'].append({
                        "port": port,
                        "state": state,
                        "banner": banner,
                        "version": version,
                        "os": os_info
                    })
                    print(f"Port {port}: {state} - {banner} - {version}")

            # 4. Web scan
            web_ports = [p for p, _, _, _, _ in network_results if p in [80, 443, 8080, 8443]] if network_results else []
            if web_ports or self.options.get('force_web', False):
                web_scanner = WebScanner(self.target, session, resolver, stealth=self.options.get('stealth', False))
                web_results = await web_scanner.run()
                self.data['web'] = web_results
                print("[+] Web scan completed.")
            else:
                self.data['web'] = []
                print("[!] No web ports found, skipping web scan.")

            # 5. CVE mapping
            services = [(b, v) for _, _, b, v, _ in network_results]
            vuln_engine = VulnEngine(services, session)
            cves = await vuln_engine.lookup_cves()
            self.data['cves'] = cves
            self.data['risk'] = vuln_engine.assess_risk()
            print(f"[+] Risk assessment: {self.data['risk']}")

            # 6. Reports
            report_gen = ReportGenerator(self.target, self.data, self.previous_profile)
            report_gen.to_json()
            if self.options.get('html', False):
                report_gen.to_html()

        print("\n[+] Scan completed.")

def main():
    parser = argparse.ArgumentParser(description="Anish Security Scanner v8")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP (e.g., https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Deep scan (more thorough)")
    parser.add_argument("--stealth", action="store_true", help="Use stealth mode (SYN scan, random delays)")
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

    if args.stealth and not SCAPY_AVAILABLE:
        print("[!] Scapy not available. Stealth mode disabled. Falling back to TCP connect.")
        options['stealth'] = False

    scanner = AnishScanner(args.target, options)
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()
