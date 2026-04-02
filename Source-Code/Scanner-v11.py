#!/usr/bin/env python3
"""
Anish Security Scanner v11 – Ultimate Production Edition
Fully async, accurate, intelligent, and production‑grade
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
from collections import defaultdict

from bs4 import BeautifulSoup
import whois

# Disable SSL warnings (for compatibility)
try:
    import urllib3
    urllib3.disable_warnings()
except:
    pass

# ================= CONFIGURATION =================
DEFAULT_TIMEOUT = 5
INITIAL_CONCURRENCY = 30
MAX_CONCURRENT = 100
FAST_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888,9000,27017]
FULL_PORTS = list(range(1, 65536))

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

# User agents for web stealth
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
]

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
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

    Anish Security Scanner v11 – Ultimate Production Edition
    Fully async, accurate, intelligent, and production‑grade
    Ethical Use Only
    """)

# ================= DNS RESOLVER (Robust Fallback) =================
class DNSResolver:
    def __init__(self):
        self.aiodns_resolver = aiodns.DNSResolver()
    
    async def resolve_ip(self, domain):
        """Resolve domain to IP with fallback chain."""
        domain = domain.lower().strip()
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://')[1].split('/')[0]
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Try aiodns
        try:
            result = await self.aiodns_resolver.gethostbyname(domain, socket.AF_INET)
            if result:
                return result[0]
        except Exception as e:
            logger.debug(f"aiodns failed for {domain}: {e}")
        
        # Fallback to getaddrinfo
        try:
            loop = asyncio.get_event_loop()
            info = await loop.getaddrinfo(domain, 80, family=socket.AF_INET, type=socket.SOCK_STREAM)
            if info:
                return info[0][4][0]
        except Exception as e:
            logger.debug(f"getaddrinfo failed for {domain}: {e}")
        
        # Last resort: socket.gethostbyname in executor
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            return ip
        except Exception as e:
            logger.error(f"DNS resolution failed for {domain}: {e}")
            return None

# ================= GLOBAL RATE LIMITER (Adaptive) =================
class RateLimiter:
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
        # Periodic adjustment
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

# ================= PORT SCANNER (Accurate States + Chunking) =================
class PortScanner:
    def __init__(self, target_ip, ports, rate_limiter, timeout=DEFAULT_TIMEOUT, retries=2):
        self.target_ip = target_ip
        self.ports = ports
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.retries = retries
    
    async def scan(self):
        results = []
        # Chunk to avoid 65k simultaneous tasks
        chunk_size = 1000
        for i in range(0, len(self.ports), chunk_size):
            chunk = self.ports[i:i+chunk_size]
            tasks = [self._scan_port(port) for port in chunk]
            chunk_results = await asyncio.gather(*tasks, return_exceptions=True)
            results.extend([r for r in chunk_results if r is not None])
        return results
    
    async def _scan_port(self, port):
        await self.rate_limiter.acquire()
        success = False
        try:
            for attempt in range(self.retries):
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target_ip, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    state = 'open'
                    success = True
                    break
                except asyncio.TimeoutError:
                    state = 'filtered'
                    continue
                except ConnectionRefusedError:
                    state = 'closed'
                    success = True
                    break
                except Exception:
                    state = 'filtered'
                    continue
            else:
                # All retries failed, state remains filtered but success=False
                self.rate_limiter.release(success=False)
                return None
            
            if state == 'open':
                self.rate_limiter.release(success=True)
                return {"port": port, "state": state}
            else:
                self.rate_limiter.release(success=success)
                return None
        except Exception as e:
            self.rate_limiter.release(success=False)
            logger.error(f"Port scan error {port}: {e}")
            return None

# ================= SERVICE DETECTOR (Uses Domain, Reuses Session) =================
class ServiceDetector:
    def __init__(self, target_ip, domain, session, rate_limiter, timeout=DEFAULT_TIMEOUT):
        self.target_ip = target_ip
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.service_cache = {}
    
    async def detect(self, port):
        if port in self.service_cache:
            return self.service_cache[port]
        
        await self.rate_limiter.acquire()
        success = False
        try:
            service_info = await self._probe(port)
            success = True
            self.service_cache[port] = service_info
            return service_info
        finally:
            self.rate_limiter.release(success=success)
    
    async def _probe(self, port):
        # Determine service by port (baseline)
        service_name = self._port_to_service(port)
        banner = ""
        version = "Unknown"
        
        # Protocol-specific probing
        if port in [80, 443, 8080, 8443]:
            http_info = await self._http_probe(port)
            if http_info:
                service_name = "http"
                banner = http_info.get("server", "")
                version = http_info.get("version", "Unknown")
                return {
                    "service": service_name,
                    "banner": banner,
                    "version": version,
                    "http": http_info
                }
        elif port == 22:
            banner = await self._generic_probe(port, b"SSH-2.0-")
            if "SSH" in banner:
                service_name = "ssh"
                match = re.search(r"SSH-([\d.]+)", banner)
                version = match.group(1) if match else "Unknown"
        elif port == 21:
            banner = await self._generic_probe(port, b"USER anonymous\r\n")
            if "FTP" in banner:
                service_name = "ftp"
                parts = banner.split()
                version = parts[1] if len(parts) > 1 else "Unknown"
        elif port == 25:
            banner = await self._generic_probe(port, b"EHLO test\r\n")
            if "SMTP" in banner:
                service_name = "smtp"
                version = "Unknown"
        elif port == 3306:
            banner = await self._generic_probe(port, b"\x00\x00\x00\x01")
            if "mysql" in banner.lower():
                service_name = "mysql"
                match = re.search(r"(\d+\.\d+\.\d+)", banner)
                version = match.group(1) if match else "Unknown"
        
        return {
            "service": service_name,
            "banner": banner[:200],
            "version": version,
            "http": {}
        }
    
    async def _generic_probe(self, port, probe):
        try:
            reader, writer = await asyncio.open_connection(self.target_ip, port)
            if probe:
                writer.write(probe)
                await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            return banner.decode(errors='ignore').strip()
        except:
            return ""
    
    async def _http_probe(self, port):
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{self.domain}:{port}/"
        headers = {"Host": self.domain}
        try:
            async with self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True, ssl=False) as resp:
                headers_dict = resp.headers
                text = await resp.text()
                title = ""
                soup = BeautifulSoup(text, 'html.parser')
                if soup.title:
                    title = soup.title.string.strip()
                server = headers_dict.get('Server', 'Unknown')
                powered_by = headers_dict.get('X-Powered-By', '')
                version = "Unknown"
                if "nginx" in server.lower():
                    match = re.search(r"nginx/([\d.]+)", server)
                    version = match.group(1) if match else "Unknown"
                elif "Apache" in server:
                    match = re.search(r"Apache/([\d.]+)", server)
                    version = match.group(1) if match else "Unknown"
                return {
                    "status_code": resp.status,
                    "server": server,
                    "powered_by": powered_by,
                    "title": title,
                    "version": version,
                    "content_length": len(text),
                    "redirect_url": str(resp.url) if resp.url != url else None
                }
        except Exception as e:
            logger.debug(f"HTTP probe failed for port {port}: {e}")
            return None
    
    def _port_to_service(self, port):
        mapping = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
            1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-proxy",
            8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 27017: "mongodb"
        }
        return mapping.get(port, "unknown")

# ================= WEB INTELLIGENCE ENGINE =================
class WebIntelligence:
    def __init__(self, domain, session, rate_limiter):
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
        self.base_url = f"http://{domain}"
        self.https_url = f"https://{domain}"
    
    async def analyze(self):
        results = {}
        for url in [self.https_url, self.base_url]:
            await self.rate_limiter.acquire()
            success = False
            try:
                async with self.session.get(url, timeout=5, allow_redirects=True, ssl=False) as resp:
                    headers = resp.headers
                    text = await resp.text()
                    status = resp.status
                    final_url = str(resp.url)
                    title = ""
                    soup = BeautifulSoup(text, 'html.parser')
                    if soup.title:
                        title = soup.title.string.strip()
                    server = headers.get('Server', 'Unknown')
                    powered_by = headers.get('X-Powered-By', '')
                    security = {
                        "csp": headers.get('Content-Security-Policy', 'Missing'),
                        "hsts": headers.get('Strict-Transport-Security', 'Missing'),
                        "xframe": headers.get('X-Frame-Options', 'Missing'),
                        "xcontent": headers.get('X-Content-Type-Options', 'Missing'),
                        "referrer": headers.get('Referrer-Policy', 'Missing')
                    }
                    cookies = []
                    for cookie in self.session.cookie_jar:
                        cookies.append({
                            "name": cookie.key,
                            "secure": cookie.secure,
                            "http_only": cookie.httponly,
                            "domain": cookie.domain
                        })
                    results = {
                        "url": final_url,
                        "status_code": status,
                        "title": title,
                        "server": server,
                        "powered_by": powered_by,
                        "security_headers": security,
                        "cookies": cookies,
                        "content_length": len(text)
                    }
                    success = True
                    break
            except Exception as e:
                logger.debug(f"Web analysis failed for {url}: {e}")
            finally:
                self.rate_limiter.release(success=success)
        return results

# ================= FINGERPRINTING ENGINE =================
class Fingerprinter:
    def __init__(self, session, rate_limiter):
        self.session = session
        self.rate_limiter = rate_limiter
    
    async def detect_cms(self, url, html):
        cms = None
        if "wp-content" in html or "wp-includes" in html:
            cms = "WordPress"
        elif "Joomla" in html or "joomla" in html:
            cms = "Joomla"
        elif "Drupal" in html:
            cms = "Drupal"
        return cms
    
    async def detect_frameworks(self, html):
        frameworks = []
        if "react" in html or "React" in html:
            frameworks.append("React")
        if "angular" in html or "ng-" in html:
            frameworks.append("Angular")
        if "laravel" in html or "csrf-token" in html:
            frameworks.append("Laravel")
        return frameworks
    
    async def detect_cdn(self, domain):
        resolver = aiodns.DNSResolver()
        try:
            result = await resolver.query(domain, 'CNAME')
            if result:
                cname = str(result[0].target).lower()
                for cdn_domain, name in CDN_CNAMES.items():
                    if cdn_domain in cname:
                        return name
        except:
            pass
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(f"http://{domain}", timeout=5) as resp:
                headers = resp.headers
                if 'CF-Cache-Status' in headers:
                    return "Cloudflare"
                elif 'X-Akamai-Transformed' in headers:
                    return "Akamai"
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(success=success)
        return None
    
    async def detect_waf(self, domain):
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(f"http://{domain}", timeout=5) as resp:
                headers = resp.headers
                text = await resp.text()
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if any(sig in k for k in headers) or sig in text:
                            return waf
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(success=success)
        return None

# ================= SUBDOMAIN ENUMERATION (Multiple Sources) =================
class SubdomainEnumerator:
    def __init__(self, domain, session, rate_limiter):
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(50)
    
    async def enumerate(self):
        subdomains = set()
        # Source 1: crt.sh
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(f"https://crt.sh/?q=%.{self.domain}&output=json") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get('name_value')
                        if name:
                            for n in name.split('\n'):
                                n = n.lower().strip()
                                if n.endswith(self.domain):
                                    subdomains.add(n)
            success = True
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        finally:
            self.rate_limiter.release(success=success)
        
        # Source 2: bufferover.run
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(f"https://dns.bufferover.run/dns?q=.{self.domain}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get('FDNS_A', []):
                        if isinstance(item, list) and len(item) > 1:
                            sub = item[1].lower()
                            if sub.endswith(self.domain):
                                subdomains.add(sub)
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(success=success)
        
        # Source 3: hackertarget
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}") as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        if ',' in line:
                            sub = line.split(',')[0].lower()
                            if sub.endswith(self.domain):
                                subdomains.add(sub)
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(success=success)
        
        # Wordlist brute-force
        tasks = [self._check_subdomain(sub) for sub in SUBDOMAIN_WORDLIST]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for found in results:
            if found:
                subdomains.add(found)
        
        return list(subdomains)
    
    async def _check_subdomain(self, sub):
        async with self.semaphore:
            try:
                target = f"{sub}.{self.domain}"
                await self.resolver.gethostbyname(target, socket.AF_INET)
                return target
            except:
                return None

# ================= DIRECTORY ENUMERATION (Fixed Recursion) =================
class DirectoryEnumerator:
    def __init__(self, base_url, session, rate_limiter, max_depth=1):
        self.base_url = base_url.rstrip('/')
        self.session = session
        self.rate_limiter = rate_limiter
        self.max_depth = max_depth
        self.visited = set()
    
    async def enumerate(self, wordlist=None, depth=0):
        if depth > self.max_depth:
            return []
        wordlist = wordlist or COMMON_DIRECTORIES
        tasks = [self._check_path(path, depth) for path in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = []
        for res in results:
            if res:
                found.append(res)
                if self.max_depth > depth + 1:
                    # Create a new enumerator for the deeper directory
                    deeper_enum = DirectoryEnumerator(res['url'], self.session, self.rate_limiter, self.max_depth)
                    deeper = await deeper_enum.enumerate(wordlist, depth+1)
                    found.extend(deeper)
        return found
    
    async def _check_path(self, path, depth):
        url = urljoin(self.base_url, path)
        if url in self.visited:
            return None
        self.visited.add(url)
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(url, allow_redirects=False, timeout=5) as resp:
                if resp.status in (200, 403, 401):
                    return {"url": url, "status": resp.status, "depth": depth}
            return None
        except:
            return None
        finally:
            self.rate_limiter.release(success=success)

# ================= VULNERABILITY ENGINE (Realistic Detection) =================
class VulnerabilityEngine:
    def __init__(self, session, rate_limiter):
        self.session = session
        self.rate_limiter = rate_limiter
    
    async def test_xss(self, url):
        # Baseline
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(url, timeout=5) as resp:
                baseline = await resp.text()
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(success=success)
        if not success:
            return None
        
        # Injected
        xss_url = urljoin(url, f"?test={XSS_PAYLOAD}")
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(xss_url, timeout=5) as resp:
                injected = await resp.text()
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(success=success)
        if not success:
            return None
        
        if XSS_PAYLOAD in injected and XSS_PAYLOAD not in baseline:
            return {
                "type": "Reflected XSS",
                "url": xss_url,
                "severity": "High",
                "confidence": 70,
                "details": "Payload reflected in response"
            }
        return None
    
    async def test_sqli(self, url):
        sqli_url = urljoin(url, f"?id={SQLI_PAYLOAD}")
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get(sqli_url, timeout=5) as resp:
                text = await resp.text()
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(success=success)
        if not success:
            return None
        
        error_patterns = ["mysql", "sql syntax", "microsoft ole db", "postgresql error", "oracle.jdbc"]
        for pattern in error_patterns:
            if pattern in text.lower():
                return {
                    "type": "SQL Injection (Error-based)",
                    "url": sqli_url,
                    "severity": "Critical",
                    "confidence": 60,
                    "details": f"SQL error message containing '{pattern}'"
                }
        return None

# ================= CVE LOOKUP (Optional, with Limit) =================
class CVELookup:
    def __init__(self, session, rate_limiter):
        self.session = session
        self.rate_limiter = rate_limiter
        self.cache = self._load_cache()
    
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
            json.dump({'timestamp': time.time(), 'cves': self.cache}, f)
    
    async def lookup(self, service, version):
        if version == "Unknown":
            return []
        service_key = service.lower()
        if service_key in SERVICE_CPE_MAP:
            vendor, product = SERVICE_CPE_MAP[service_key]
        else:
            vendor = product = service_key
        ver_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
        exact_version = ver_match.group(1) if ver_match else version
        cpe = f"cpe:2.3:a:{vendor}:{product}:{exact_version}"
        
        if cpe in self.cache:
            return self.cache[cpe]
        
        params = {"cpeName": cpe, "resultsPerPage": 20}
        await self.rate_limiter.acquire()
        success = False
        try:
            async with self.session.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params) as resp:
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
                    self.cache[cpe] = cves
                    return cves
            success = True
        except Exception as e:
            logger.error(f"CVE lookup error: {e}")
        finally:
            self.rate_limiter.release(success=success)
        return []

# ================= REPORT GENERATOR (Structured) =================
class ReportGenerator:
    def __init__(self, target, data):
        self.target = target
        self.data = data
    
    def to_json(self, filename="anish_report_v11.json"):
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)
        print(f"[+] JSON report saved to {filename}")
    
    def to_html(self, filename="anish_report_v11.html"):
        risk = self.data.get('risk_score', 'Unknown')
        color = {'Critical':'red', 'High':'orange', 'Medium':'yellow', 'Low':'green'}.get(risk, 'black')
        html = f"""
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
            f.write(html)
        print(f"[+] HTML report saved to {filename}")

# ================= MAIN SCANNER ORCHESTRATOR =================
class AnishScanner:
    def __init__(self, target, options):
        self.target = target
        self.options = options
        self.domain, self.port = self._parse_target(target)
        self.data = {
            "target": target,
            "domain": self.domain,
            "scan_time": datetime.now().isoformat(),
            "network": [],
            "web": {},
            "vulnerabilities": [],
            "risk_score": "Low"
        }
    
    def _parse_target(self, target):
        parsed = urlparse(target)
        domain = parsed.netloc.split(':')[0]
        port = parsed.port
        if not port:
            port = 443 if parsed.scheme == 'https' else 80
        return domain, port
    
    async def run(self):
        print_banner()
        rate_limiter = RateLimiter()
        # Global session with timeout
        timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, limit_per_host=MAX_CONCURRENT, ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            dns = DNSResolver()
            ip = await dns.resolve_ip(self.domain)
            if not ip:
                print("[!] Could not resolve IP. Exiting.")
                return
            self.data['ip'] = ip
            print(f"[+] Target: {self.target}")
            print(f"[+] Domain: {self.domain}")
            print(f"[+] IP: {ip}")
            
            # Determine port list based on mode
            if self.options.get('mode') == 'fast':
                ports = FAST_PORTS
            elif self.options.get('mode') == 'full':
                ports = FULL_PORTS
            else:
                ports = COMMON_PORTS
            
            # Port scanning
            port_scanner = PortScanner(ip, ports, rate_limiter)
            open_ports = await port_scanner.scan()
            print(f"[+] Found {len(open_ports)} open ports")
            
            # Service detection on open ports (pass domain and session)
            service_detector = ServiceDetector(ip, self.domain, session, rate_limiter)
            service_results = []
            for p in open_ports:
                service = await service_detector.detect(p['port'])
                service_results.append({
                    "port": p['port'],
                    "state": p['state'],
                    "service": service.get("service", "unknown"),
                    "banner": service.get("banner", ""),
                    "version": service.get("version", "Unknown"),
                    "http": service.get("http", {})
                })
                print(f"Port {p['port']}: {p['state']} - {service.get('service', 'unknown')}")
                if service.get('http'):
                    http = service['http']
                    print(f"  Server: {http.get('server', 'Unknown')}")
                    print(f"  Title: {http.get('title', 'No title')}")
                    print(f"  Status: {http.get('status_code', 'N/A')}")
            self.data['network'] = service_results
            
            # Web intelligence (if HTTP ports exist)
            http_ports = [r for r in service_results if r['service'] == 'http']
            if http_ports or self.options.get('web_only') or self.options.get('recon_only'):
                web_intel = WebIntelligence(self.domain, session, rate_limiter)
                web_data = await web_intel.analyze()
                self.data['web'] = web_data
                print("[+] Web intelligence gathered")
                
                # Fingerprinting
                fingerprinter = Fingerprinter(session, rate_limiter)
                if web_data:
                    try:
                        await rate_limiter.acquire()
                        async with session.get(web_data['url'], timeout=5, ssl=False) as resp:
                            html = await resp.text()
                        rate_limiter.release(success=True)
                        cms = await fingerprinter.detect_cms(web_data['url'], html)
                        frameworks = await fingerprinter.detect_frameworks(html)
                        if cms:
                            self.data['web']['cms'] = cms
                        if frameworks:
                            self.data['web']['frameworks'] = frameworks
                        cdn = await fingerprinter.detect_cdn(self.domain)
                        waf = await fingerprinter.detect_waf(self.domain)
                        if cdn:
                            self.data['web']['cdn'] = cdn
                        if waf:
                            self.data['web']['waf'] = waf
                    except Exception as e:
                        rate_limiter.release(success=False)
                        logger.debug(f"Fingerprinting error: {e}")
                
                # Subdomain enumeration (recon only or full)
                if self.options.get('recon_only') or not self.options.get('web_only'):
                    sub_enum = SubdomainEnumerator(self.domain, session, rate_limiter)
                    subdomains = await sub_enum.enumerate()
                    self.data['subdomains'] = subdomains
                    print(f"[+] Found {len(subdomains)} subdomains")
                
                # Directory enumeration (if deep or recon_only)
                if self.options.get('deep') and web_data:
                    dir_enum = DirectoryEnumerator(web_data['url'], session, rate_limiter, max_depth=1)
                    dirs = await dir_enum.enumerate()
                    self.data['directories'] = dirs
                    print(f"[+] Found {len(dirs)} accessible directories")
                
                # Vulnerability tests (if web_only or full)
                if not self.options.get('recon_only') and web_data:
                    vuln_engine = VulnerabilityEngine(session, rate_limiter)
                    xss = await vuln_engine.test_xss(web_data['url'])
                    if xss:
                        self.data['vulnerabilities'].append(xss)
                    sqli = await vuln_engine.test_sqli(web_data['url'])
                    if sqli:
                        self.data['vulnerabilities'].append(sqli)
            
            # CVE Lookup (optional, limit to top 5 services)
            if self.options.get('cve'):
                cve_lookup = CVELookup(session, rate_limiter)
                all_cves = []
                # Limit to first 5 services to avoid too many API calls
                for svc in service_results[:5]:
                    if svc['version'] != "Unknown":
                        cves = await cve_lookup.lookup(svc['service'], svc['version'])
                        if cves:
                            all_cves.extend(cves)
                self.data['cves'] = all_cves
            else:
                self.data['cves'] = []
            
            # Risk scoring
            if any(v['severity'] == 'Critical' for v in self.data['vulnerabilities']) or any(c.get('cvss', 0) >= 9 for c in self.data.get('cves', [])):
                self.data['risk_score'] = "Critical"
            elif any(v['severity'] == 'High' for v in self.data['vulnerabilities']) or any(c.get('cvss', 0) >= 7 for c in self.data.get('cves', [])):
                self.data['risk_score'] = "High"
            elif any(v['severity'] == 'Medium' for v in self.data['vulnerabilities']) or any(c.get('cvss', 0) >= 4 for c in self.data.get('cves', [])):
                self.data['risk_score'] = "Medium"
            else:
                self.data['risk_score'] = "Low"
            
            # Report
            report = ReportGenerator(self.target, self.data)
            report.to_json()
            if self.options.get('html'):
                report.to_html()
        
        print("\n[+] Scan completed.")

# ================= CLI ENTRY POINT =================
def main():
    parser = argparse.ArgumentParser(description="Anish Security Scanner v11")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP")
    parser.add_argument("--fast", action="store_true", help="Fast scan (top 20 ports)")
    parser.add_argument("--full", action="store_true", help="Full scan (1-65535 ports)")
    parser.add_argument("--web-only", action="store_true", help="Only web intelligence")
    parser.add_argument("--recon-only", action="store_true", help="Only subdomain enumeration")
    parser.add_argument("--deep", action="store_true", help="Deep scan (directory recursion)")
    parser.add_argument("--cve", action="store_true", help="Enable CVE lookup (NVD API)")
    parser.add_argument("--output", choices=['json', 'html'], default='json', help="Report format")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine mode
    if args.fast:
        mode = 'fast'
    elif args.full:
        mode = 'full'
    else:
        mode = 'common'
    
    options = {
        'mode': mode,
        'web_only': args.web_only,
        'recon_only': args.recon_only,
        'deep': args.deep,
        'cve': args.cve,
        'html': args.output == 'html'
    }
    
    scanner = AnishScanner(args.target, options)
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()
