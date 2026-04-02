#!/usr/bin/env python3
"""
Anish Security Scanner v9 – Production Intelligence Edition
High‑performance, accurate, async reconnaissance & vulnerability assessment
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

# Disable warnings
try:
    import urllib3
    urllib3.disable_warnings()
except:
    pass

# ================= CONFIGURATION =================
DEFAULT_TIMEOUT = 5
INITIAL_CONCURRENCY = 50          # Conservative start
MAX_CONCURRENT = 100
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443, 8888]
BANNER_GRAB_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389]

# Service probes (enhanced)
SERVICE_PROBES = {
    21: b"USER anonymous\r\n",
    22: b"SSH-2.0-",
    25: b"EHLO test\r\n",
    80: b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n",
    443: b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n",
    110: b"USER test\r\n",
    143: b"CAPABILITY\r\n",
    3306: b"\x00\x00\x00\x01",
    3389: b"\x03\x00\x00\x13",
    8080: b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n",
    8443: b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n",
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

# Subdomain wordlist (expanded)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1",
    "ns2", "cpanel", "whm", "autodiscover", "m", "imap", "test",
    "dev", "admin", "blog", "support", "api", "app", "cdn", "static",
    "assets", "portal", "dashboard", "docs", "status", "monitor",
    "staging", "stage", "qa", "prod", "production", "alpha", "beta",
    "backend", "frontend", "mobile", "vpn", "remote", "exchange", "owa",
    "sharepoint", "jenkins", "gitlab", "grafana", "prometheus", "kibana"
]

# Directory wordlist (expanded)
COMMON_DIRECTORIES = [
    "/admin", "/backup", "/config", "/logs", "/test", "/upload",
    "/wp-admin", "/wp-content", "/wp-includes", "/uploads", "/files",
    "/images", "/css", "/js", "/vendor", "/assets", "/cgi-bin",
    "/.git", "/.svn", "/.env", "/phpmyadmin", "/api", "/graphql",
    "/swagger", "/redoc", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info", "/health", "/metrics",
    "/debug", "/_profiler", "/_debugbar", "/phpinfo.php", "/info.php"
]

COMMON_FILES = [
    "index.php", "index.html", "login.php", "admin.php", "config.php",
    "wp-config.php", ".env", "backup.zip", "dump.sql", "error.log",
    "phpinfo.php", "readme.html", "composer.json", "package.json",
    "robots.txt", "crossdomain.xml", "clientaccesspolicy.xml"
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

# OS fingerprinting using TCP SYN response (TTL, window size) – no Scapy required
# Use SYN scan results or fallback to HTTP Server header analysis
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
logging.basicConfig(filename="anish_scanner_v9.log", level=logging.INFO,
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

    Anish Security Scanner v9 – Production Intelligence Edition
    High‑performance, accurate, async reconnaissance & vulnerability assessment
    Ethical Use Only
    """)

async def resolve_ip(domain, resolver):
    """Robust DNS resolution with fallback chain."""
    # Normalize domain
    domain = domain.lower().strip()
    # Remove scheme and path
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://')[1].split('/')[0]
    # Remove port
    if ':' in domain:
        domain = domain.split(':')[0]
    # Try aiodns first
    try:
        result = await resolver.gethostbyname(domain, socket.AF_INET)
        if result:
            return result[0]
    except:
        pass
    # Fallback to socket.getaddrinfo (async but blocking in executor)
    try:
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(domain, 80, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if info:
            return info[0][4][0]
    except:
        pass
    # Last resort: socket.gethostbyname (sync)
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.error(f"DNS resolution failed for {domain}: {e}")
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

# ================= RATE LIMITER (Global Adaptive) =================
class GlobalRateLimiter:
    """Adaptive global rate limiter that reduces concurrency on failures."""
    def __init__(self, initial_concurrency=INITIAL_CONCURRENCY):
        self.concurrency = initial_concurrency
        self.semaphore = asyncio.Semaphore(initial_concurrency)
        self.failure_count = 0
        self.success_count = 0
        self.last_adjust = time.time()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            await self.semaphore.acquire()

    def release(self, success=True):
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1
        self.semaphore.release()
        # Periodically adjust concurrency
        now = time.time()
        if now - self.last_adjust > 10:
            self._adjust_concurrency()

    def _adjust_concurrency(self):
        total = self.success_count + self.failure_count
        if total > 20:
            failure_rate = self.failure_count / total
            if failure_rate > 0.3:  # >30% failures
                self.concurrency = max(1, self.concurrency // 2)
                self.semaphore = asyncio.Semaphore(self.concurrency)
                logger.info(f"Reducing concurrency to {self.concurrency} due to {failure_rate*100:.1f}% failures")
            elif failure_rate < 0.1 and self.concurrency < MAX_CONCURRENT:
                self.concurrency = min(MAX_CONCURRENT, int(self.concurrency * 1.2))
                self.semaphore = asyncio.Semaphore(self.concurrency)
                logger.info(f"Increasing concurrency to {self.concurrency}")
        self.success_count = 0
        self.failure_count = 0
        self.last_adjust = time.time()

# ================= NETWORK SCANNER (Accurate Port States) =================
class AsyncNetworkScanner:
    def __init__(self, target_ip, ports=None, timeout=DEFAULT_TIMEOUT, stealth=False):
        self.target_ip = target_ip
        self.ports = ports or COMMON_PORTS
        self.timeout = timeout
        self.stealth = False  # SYN scan not reliable without root; always use TCP connect
        self.rate_limiter = None  # Will be set by main
        self.results = []

    def set_rate_limiter(self, rate_limiter):
        self.rate_limiter = rate_limiter

    async def scan(self):
        logger.info(f"Starting network scan on {self.target_ip}")
        tasks = [self._scan_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        self.results = [r for r in results if r is not None]
        return self.results

    async def _scan_port(self, port):
        await self.rate_limiter.acquire()
        try:
            # Use asyncio.open_connection with timeout
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                state = 'open'
                success = True
            except asyncio.TimeoutError:
                state = 'filtered'
                success = False
            except ConnectionRefusedError:
                state = 'closed'
                success = True
            except Exception:
                state = 'filtered'
                success = False

            if state == 'open':
                # Grab banner and detect service
                service, banner, version, os_hint = await self._detect_service(port)
                # HTTP specific enrichment
                http_info = {}
                if service == 'http' and port in [80, 443, 8080, 8443]:
                    http_info = await self._http_probe(port)
                result = {
                    "port": port,
                    "state": state,
                    "service": service,
                    "banner": banner,
                    "version": version,
                    "os_hint": os_hint,
                    "http": http_info
                }
                self.rate_limiter.release(success=True)
                return result
            else:
                self.rate_limiter.release(success=success)
                return None
        except Exception as e:
            logger.error(f"Port scan error {port}: {e}")
            self.rate_limiter.release(success=False)
            return None

    async def _detect_service(self, port):
        """Probe port to identify service and version."""
        probe = SERVICE_PROBES.get(port, b"\r\n")
        # For HTTP, inject Host header
        if port in [80, 443, 8080, 8443]:
            # We'll handle HTTP separately
            pass
        try:
            reader, writer = await asyncio.open_connection(self.target_ip, port)
            if probe:
                writer.write(probe)
                await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            banner_str = banner.decode(errors='ignore').strip()
            # Simple service detection
            if port == 22 and "SSH" in banner_str:
                service = "ssh"
                version = re.search(r"SSH-([\d.]+)", banner_str)
                version = version.group(1) if version else "Unknown"
            elif port == 21 and "FTP" in banner_str:
                service = "ftp"
                version = banner_str.split()[1] if len(banner_str.split()) > 1 else "Unknown"
            elif port in [80, 443, 8080, 8443]:
                service = "http"
                version = "Unknown"
            elif port == 25 and "SMTP" in banner_str:
                service = "smtp"
                version = "Unknown"
            else:
                service = "unknown"
                version = "Unknown"
            # OS hint from banner (simple)
            os_hint = {}
            if "Linux" in banner_str:
                os_hint["os"] = "Linux"
            elif "Windows" in banner_str:
                os_hint["os"] = "Windows"
            else:
                os_hint["os"] = "Unknown"
            return service, banner_str, version, os_hint
        except Exception:
            return "unknown", "", "Unknown", {"os": "Unknown"}

    async def _http_probe(self, port):
        """Send a proper HTTP GET request and parse response."""
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{self.target_ip}:{port}/"
        try:
            # Use a separate session to avoid sharing the main one? We'll create a temp one.
            connector = aiohttp.TCPConnector(verify_ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=5, allow_redirects=True) as resp:
                    headers = resp.headers
                    text = await resp.text()
                    # Extract info
                    title = ""
                    soup = BeautifulSoup(text, 'html.parser')
                    if soup.title:
                        title = soup.title.string.strip()
                    server = headers.get('Server', 'Unknown')
                    powered_by = headers.get('X-Powered-By', '')
                    status = resp.status
                    # Security headers
                    security = {
                        "csp": headers.get('Content-Security-Policy', 'Missing'),
                        "hsts": headers.get('Strict-Transport-Security', 'Missing'),
                        "xframe": headers.get('X-Frame-Options', 'Missing'),
                        "xcontent": headers.get('X-Content-Type-Options', 'Missing')
                    }
                    return {
                        "status_code": status,
                        "server": server,
                        "powered_by": powered_by,
                        "title": title,
                        "security_headers": security,
                        "content_length": len(text)
                    }
        except Exception as e:
            logger.error(f"HTTP probe failed for port {port}: {e}")
            return {}

# ================= WAF/CDN DETECTOR (Non‑blocking) =================
class WAFDetector:
    def __init__(self, domain, session):
        self.domain = domain
        self.session = session
        self.waf = None
        self.cdn = None

    async def detect(self):
        # DNS CNAME
        try:
            resolver = aiodns.DNSResolver()
            result = await resolver.query(self.domain, 'CNAME')
            if result:
                cname = str(result[0].target).lower()
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
        return self.waf, self.cdn

# ================= RECON ENGINE (Robust Subdomain Enumeration) =================
class ReconEngine:
    def __init__(self, domain, session, rate_limiter, concurrency=MAX_CONCURRENT):
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
        self.semaphore = asyncio.Semaphore(concurrency)
        self.subdomains = []
        self.takeover_vulns = []

    async def enumerate_subdomains(self):
        # Certificate transparency (crt.sh)
        try:
            await self.rate_limiter.acquire()
            async with self.session.get(f"https://crt.sh/?q=%.{self.domain}&output=json") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get('name_value')
                        if name and name.endswith(self.domain):
                            # Some entries have multiple names separated by newline
                            for n in name.split('\n'):
                                n = n.lower().strip()
                                if n.endswith(self.domain):
                                    self.subdomains.append(n)
            self.rate_limiter.release(success=True)
        except Exception as e:
            self.rate_limiter.release(success=False)
            logger.error(f"crt.sh error: {e}")

        # DNS brute-force
        tasks = [self._check_subdomain(sub) for sub in SUBDOMAIN_WORDLIST]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for found in results:
            if found:
                self.subdomains.append(found)
        self.subdomains = list(set(self.subdomains))

    async def _check_subdomain(self, sub):
        await self.semaphore.acquire()
        try:
            target = f"{sub}.{self.domain}"
            # Use async DNS lookup
            resolver = aiodns.DNSResolver()
            await resolver.gethostbyname(target, socket.AF_INET)
            return target
        except:
            return None
        finally:
            self.semaphore.release()

    async def check_takeover(self):
        for sub in self.subdomains:
            try:
                resolver = aiodns.DNSResolver()
                result = await resolver.query(sub, 'CNAME')
                if result:
                    cname = str(result[0].target).lower()
                    for pattern, service in TAKEOVER_FINGERPRINTS.items():
                        if pattern in cname:
                            if await self._verify_takeover(sub, pattern):
                                self.takeover_vulns.append({
                                    "subdomain": sub,
                                    "cname": cname,
                                    "service": service,
                                    "risk": "High",
                                    "confidence": 90
                                })
            except:
                pass

    async def _verify_takeover(self, subdomain, pattern):
        try:
            await self.rate_limiter.acquire()
            async with self.session.get(f"http://{subdomain}", timeout=5) as resp:
                text = await resp.text()
                fingerprints = TAKEOVER_FINGERPRINTS.get(pattern, [])
                for fp in fingerprints:
                    if fp.lower() in text.lower():
                        return True
            return False
        except:
            return False
        finally:
            self.rate_limiter.release(success=True)

    async def run(self):
        await self.enumerate_subdomains()
        await self.check_takeover()
        return {"subdomains": self.subdomains, "takeover_vulns": self.takeover_vulns}

# ================= WEB SCANNER (Deep Analysis) =================
class WebScanner:
    def __init__(self, target_url, session, rate_limiter, stealth=False):
        self.target_url = target_url.rstrip('/')
        self.session = session
        self.rate_limiter = rate_limiter
        self.stealth = stealth
        self.technologies = {}
        self.results = []
        self.cookies = []

    async def _request(self, url, **kwargs):
        await self.rate_limiter.acquire()
        try:
            if self.stealth:
                ua = random.choice(USER_AGENTS)
                kwargs['headers'] = kwargs.get('headers', {})
                kwargs['headers']['User-Agent'] = ua
                await asyncio.sleep(random.uniform(0.1, 0.3))
            async with self.session.get(url, **kwargs) as resp:
                if resp.status == 429:
                    # Signal rate limit to global limiter (will be handled by failure count)
                    raise Exception("Rate limited")
                return resp
        except Exception as e:
            self.rate_limiter.release(success=False)
            raise e
        else:
            self.rate_limiter.release(success=True)
            return resp

    async def analyze_headers(self, url):
        resp = await self._request(url)
        headers = resp.headers
        security = {
            "Content-Security-Policy": headers.get('Content-Security-Policy', 'Missing'),
            "Strict-Transport-Security": headers.get('Strict-Transport-Security', 'Missing'),
            "X-Frame-Options": headers.get('X-Frame-Options', 'Missing'),
            "X-Content-Type-Options": headers.get('X-Content-Type-Options', 'Missing'),
            "Referrer-Policy": headers.get('Referrer-Policy', 'Missing'),
            "Permissions-Policy": headers.get('Permissions-Policy', 'Missing')
        }
        # Cookie analysis
        cookies = []
        for cookie in self.session.cookie_jar:
            cookies.append({
                "name": cookie.key,
                "secure": cookie.secure,
                "http_only": cookie.httponly,
                "domain": cookie.domain
            })
        return security, cookies

    async def detect_technologies(self, url):
        resp = await self._request(url)
        html = await resp.text()
        headers = resp.headers
        tech = {}
        # CMS
        if "wp-content" in html or "wp-includes" in html:
            tech['CMS'] = "WordPress"
        elif "Joomla" in html or "joomla" in html:
            tech['CMS'] = "Joomla"
        elif "Drupal" in html:
            tech['CMS'] = "Drupal"
        # Frameworks
        if "react" in html or "React" in html:
            tech['Framework'] = "React"
        if "angular" in html or "ng-" in html:
            tech['Framework'] = "Angular"
        if "laravel" in html or "csrf-token" in html:
            tech['Framework'] = "Laravel"
        if 'Server' in headers:
            tech['Server'] = headers['Server']
        if 'X-Powered-By' in headers:
            tech['PoweredBy'] = headers['X-Powered-By']
        return tech

    async def extract_js_endpoints(self, url):
        endpoints = []
        resp = await self._request(url)
        html = await resp.text()
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script', src=True)
        tasks = []
        for script in scripts:
            src = script['src']
            js_url = urljoin(url, src)
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
        try:
            resp = await self._request(url)
            return await resp.text()
        except:
            return ""

    async def directory_enum(self, base_url, wordlist=None, depth=0, max_depth=1):
        if depth > max_depth:
            return []
        wordlist = wordlist or COMMON_DIRECTORIES
        found = []
        tasks = [self._check_dir(base_url, d) for d in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if res:
                found.append(res)
                # Recursively explore deeper if requested
                if max_depth > depth + 1:
                    deeper = await self.directory_enum(res, COMMON_DIRECTORIES, depth+1, max_depth)
                    found.extend(deeper)
        return found

    async def _check_dir(self, base_url, dir):
        url = urljoin(base_url, dir)
        try:
            resp = await self._request(url, allow_redirects=False)
            if resp.status in (200, 403, 401):
                return url
        except:
            pass
        return None

    async def file_enum(self, base_url):
        found = []
        tasks = [self._check_file(base_url, f) for f in COMMON_FILES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if res:
                found.append(res)
        return found

    async def _check_file(self, base_url, f):
        url = urljoin(base_url, f)
        try:
            resp = await self._request(url)
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
                        "confidence": 80,
                        "details": f"Pattern matched: {found}"
                    })
                    logger.warning(f"Sensitive data in {source_url}: {found}")

    async def test_xss(self, base_url):
        xss_url = urljoin(base_url, f"?test={XSS_PAYLOAD}")
        try:
            resp = await self._request(xss_url)
            text = await resp.text()
            if XSS_PAYLOAD in text:
                self.results.append({
                    "type": "XSS",
                    "url": xss_url,
                    "severity": "High",
                    "confidence": 70,
                    "details": "Reflected XSS payload found in response"
                })
                logger.warning(f"XSS detected at {xss_url}")
        except:
            pass

    async def test_sqli(self, base_url):
        sqli_url = urljoin(base_url, f"?id={SQLI_PAYLOAD}")
        try:
            resp = await self._request(sqli_url)
            text = await resp.text()
            if "mysql" in text.lower() or "sql syntax" in text.lower():
                self.results.append({
                    "type": "SQLi",
                    "url": sqli_url,
                    "severity": "Critical",
                    "confidence": 60,
                    "details": "SQL error message detected"
                })
                logger.warning(f"SQLi detected at {sqli_url}")
        except:
            pass

    async def run(self):
        base = self.target_url
        # Headers and cookies
        security_headers, cookies = await self.analyze_headers(base)
        self.results.append({"type": "Security Headers", "data": security_headers})
        if cookies:
            self.results.append({"type": "Cookies", "data": cookies})
        # Technologies
        tech = await self.detect_technologies(base)
        self.results.append({"type": "Technologies", "data": tech})
        # JS endpoints
        endpoints = await self.extract_js_endpoints(base)
        self.results.append({"type": "JS Endpoints", "data": endpoints})
        # Directory enumeration (depth 1)
        dirs = await self.directory_enum(base, max_depth=1)
        for d in dirs:
            self.results.append({"type": "Exposed Directory", "url": d, "severity": "Medium", "confidence": 90})
        # Files
        files = await self.file_enum(base)
        for f in files:
            self.results.append({"type": "Exposed File", "url": f, "severity": "Medium", "confidence": 85})
        # Vulnerability tests
        await self.test_xss(base)
        await self.test_sqli(base)
        return self.results

# ================= VULNERABILITY ENGINE (Accurate CVE) =================
class VulnEngine:
    def __init__(self, services, session):
        self.services = services  # list of (service, version)
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
        for service, version in self.services:
            if version == "Unknown":
                continue
            # Map service to CPE vendor:product
            service_key = service.lower()
            if service_key in SERVICE_CPE_MAP:
                vendor, product = SERVICE_CPE_MAP[service_key]
            else:
                vendor = product = service_key
            # Extract exact version number
            ver_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
            exact_version = ver_match.group(1) if ver_match else version
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

# ================= REPORT GENERATOR (Enriched JSON) =================
class ReportGenerator:
    def __init__(self, target, scan_data, previous_profile):
        self.target = target
        self.data = scan_data
        self.previous = previous_profile

    def to_json(self, filename="anish_report_v9.json"):
        if self.previous:
            diff = self._compute_diff()
            self.data['changes'] = diff
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)
        print(f"[+] JSON report saved to {filename}")
        # Save profile
        profile = {k: v for k, v in self.data.items() if k in ['network', 'web', 'subdomains']}
        profile['timestamp'] = datetime.now().isoformat()
        save_profile(self.target, profile)

    def to_html(self, filename="anish_report_v9.html"):
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
        old_ports = {p['port']: p for p in self.previous.get('network', [])}
        new_ports = {p['port']: p for p in self.data.get('network', [])}
        added = [p for p in new_ports if p not in old_ports]
        removed = [p for p in old_ports if p not in new_ports]
        if added:
            diff['new_ports'] = added
        if removed:
            diff['removed_ports'] = removed
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
        # Global rate limiter
        rate_limiter = GlobalRateLimiter()
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, limit_per_host=MAX_CONCURRENT, ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)) as session:
            # Resolve IP
            resolver = aiodns.DNSResolver()
            ip = await resolve_ip(self.domain, resolver)
            if not ip:
                print("[!] Could not resolve IP. Exiting.")
                return
            self.data['ip'] = ip
            print(f"[+] Target: {self.target}")
            print(f"[+] Domain: {self.domain}")
            print(f"[+] IP: {ip}")

            # WAF/CDN detection (non‑blocking)
            waf = WAFDetector(self.domain, session)
            waf_name, cdn_name = await waf.detect()
            self.data['waf'] = waf_name
            self.data['cdn'] = cdn_name
            if waf_name:
                print(f"[+] WAF detected: {waf_name}")
            if cdn_name:
                print(f"[+] CDN detected: {cdn_name} (scan continues)")

            # Recon (subdomains, takeover)
            recon = ReconEngine(self.domain, session, rate_limiter)
            recon_data = await recon.run()
            self.data['subdomains'] = recon_data['subdomains']
            self.data['takeover_vulns'] = recon_data['takeover_vulns']
            print(f"[+] Found {len(self.data['subdomains'])} subdomains")
            if self.data['takeover_vulns']:
                print("[+] Potential subdomain takeover vulnerabilities:")
                for tv in self.data['takeover_vulns']:
                    print(f"    {tv['subdomain']} -> {tv['service']}")

            # Network scan (even if CDN, we still scan)
            net_scanner = AsyncNetworkScanner(ip, ports=self.options.get('ports', COMMON_PORTS))
            net_scanner.set_rate_limiter(rate_limiter)
            network_results = await net_scanner.scan()
            self.data['network'] = []
            for res in network_results:
                self.data['network'].append(res)
                # Rich output
                print(f"Port {res['port']}:")
                print(f"  Status: {res['state']}")
                print(f"  Service: {res['service']}")
                if res['service'] == 'http':
                    http = res.get('http', {})
                    print(f"  Server: {http.get('server', 'Unknown')}")
                    print(f"  Title: {http.get('title', 'No title')}")
                    print(f"  Status Code: {http.get('status_code', 'N/A')}")
                    print(f"  Security Headers: {http.get('security_headers', {})}")
                else:
                    print(f"  Banner: {res['banner'][:100]}")
                    print(f"  Version: {res['version']}")
                print()

            # Web scan (if any HTTP ports found)
            web_ports = [r for r in network_results if r['service'] == 'http']
            if web_ports or self.options.get('force_web', False):
                # Use the first HTTP port as base URL
                scheme = "https" if any(p['port'] == 443 for p in web_ports) else "http"
                port = web_ports[0]['port'] if web_ports else 80
                base_url = f"{scheme}://{self.domain}:{port}"
                web_scanner = WebScanner(base_url, session, rate_limiter, stealth=self.options.get('stealth', False))
                web_results = await web_scanner.run()
                self.data['web'] = web_results
                print("[+] Web scan completed.")
            else:
                self.data['web'] = []
                print("[!] No HTTP ports found, skipping web scan.")

            # CVE mapping
            services = [(r['service'], r['version']) for r in network_results if r['version'] != "Unknown"]
            vuln_engine = VulnEngine(services, session)
            cves = await vuln_engine.lookup_cves()
            self.data['cves'] = cves
            self.data['risk'] = vuln_engine.assess_risk()
            print(f"[+] Risk assessment: {self.data['risk']}")

            # Reports
            report_gen = ReportGenerator(self.target, self.data, self.previous_profile)
            report_gen.to_json()
            if self.options.get('html', False):
                report_gen.to_html()

        print("\n[+] Scan completed.")

def main():
    parser = argparse.ArgumentParser(description="Anish Security Scanner v9")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP (e.g., https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Deep scan (more thorough – enables directory recursion)")
    parser.add_argument("--stealth", action="store_true", help="Use stealth mode (random delays, user‑agent rotation)")
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
