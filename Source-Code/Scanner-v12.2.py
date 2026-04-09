#!/usr/bin/env python3
"""
Anish Security Framework v12 – Advanced Modular Edition
High-performance, persistent async reconnaissance & vulnerability assessment engine.
Ethical Use Only - Ensure explicit authorization before scanning.
"""

import asyncio
import aiohttp
import aiodns
import argparse
import json
import logging
import re
import time
import socket
import sqlite3
import os
import random
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

try:
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    pass

# ================= CONFIGURATION & CONSTANTS =================
VERSION = "12.0"
MAX_CONCURRENT = 100
DEFAULT_TIMEOUT = 10
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

# API Keys (Set these in environment variables or hardcode for OSINT integration)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")

# Extended Regex for deep JS & Source scanning
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Stripe Standard API": r"sk_live_[0-9a-zA-Z]{24}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36}",
    "Generic Password": r"(?i)(password|passwd|secret|api_key)\s*[:=]\s*['\"]([^'\"]+)['\"]"
}

# Cloud Bucket Permutations
CLOUD_ENV_WORDS = ["dev", "prod", "staging", "test", "qa", "backup", "assets", "static", "media", "public", "private"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Anish-Advanced-Scanner/12.0"
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ScannerV12")

# ================= DATABASE ENGINE =================
class DatabaseManager:
    """Handles SQLite persistence for tracking state across multiple scans."""
    def __init__(self, db_name="anish_recon.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self._init_tables()

    def _init_tables(self):
        self.cursor.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                ip TEXT,
                last_scanned TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                subdomain TEXT UNIQUE,
                ip TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            );
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                ip TEXT,
                port INTEGER,
                service TEXT,
                banner TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                type TEXT,
                severity TEXT,
                details TEXT,
                url TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            );
        """)
        self.conn.commit()

    def log_target(self, domain, ip):
        self.cursor.execute("""
            INSERT INTO targets (domain, ip, last_scanned) 
            VALUES (?, ?, ?) 
            ON CONFLICT(domain) DO UPDATE SET ip=excluded.ip, last_scanned=excluded.last_scanned
        """, (domain, ip, datetime.now().isoformat()))
        self.conn.commit()
        return self.cursor.lastrowid

    def log_vuln(self, target_id, v_type, severity, details, url=""):
        self.cursor.execute("""
            INSERT INTO vulnerabilities (target_id, type, severity, details, url)
            VALUES (?, ?, ?, ?, ?)
        """, (target_id, v_type, severity, details, url))
        self.conn.commit()

# ================= CLOUD ENUMERATION MODULE =================
class CloudEnumModule:
    """Hunts for exposed S3, Azure, and GCP buckets."""
    def __init__(self, domain, session, semaphore):
        self.domain = domain.split('.')[0] # Extract base name
        self.session = session
        self.semaphore = semaphore
        self.findings = []

    def generate_permutations(self):
        perms = [self.domain]
        for env in CLOUD_ENV_WORDS:
            perms.extend([f"{self.domain}-{env}", f"{self.domain}_{env}", f"{env}-{self.domain}"])
        return perms

    async def check_s3(self, bucket_name):
        url = f"https://{bucket_name}.s3.amazonaws.com"
        await self.semaphore.acquire()
        try:
            async with self.session.get(url, timeout=5) as resp:
                text = await resp.text()
                if resp.status == 200 and "ListBucketResult" in text:
                    self.findings.append({"provider": "AWS S3", "url": url, "status": "Open", "severity": "Critical"})
                elif resp.status == 403:
                    self.findings.append({"provider": "AWS S3", "url": url, "status": "Protected", "severity": "Info"})
        except Exception:
            pass
        finally:
            self.semaphore.release()

    async def run(self):
        print("[*] Starting Cloud Bucket Enumeration...")
        permutations = self.generate_permutations()
        tasks = [self.check_s3(bucket) for bucket in permutations]
        await asyncio.gather(*tasks)
        return self.findings

# ================= ASYNC WEB CRAWLER & ANALYZER =================
class DeepWebCrawler:
    """Asynchronous BFS Crawler with Secret Extraction and CORS checking."""
    def __init__(self, start_url, session, max_depth=2, max_pages=50):
        self.start_url = start_url.rstrip('/')
        self.domain = urlparse(start_url).netloc
        self.session = session
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.queue = asyncio.Queue()
        self.queue.put_nowait((self.start_url, 0))
        self.findings = []
        self.js_files = set()
        self.semaphore = asyncio.Semaphore(20) # Crawler specific limit

    async def _fetch(self, url):
        await self.semaphore.acquire()
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            async with self.session.get(url, headers=headers, timeout=7, allow_redirects=True) as resp:
                return resp.status, resp.headers, await resp.text()
        except Exception:
            return None, None, None
        finally:
            self.semaphore.release()

    async def analyze_content(self, url, html):
        """Extract links, JS files, and scan for secrets."""
        soup = BeautifulSoup(html, 'html.parser')
        
        # 1. Extract internal links for crawler queue
        links = soup.find_all('a', href=True)
        new_urls = []
        for link in links:
            href = link['href']
            full_url = urljoin(url, href).split('#')[0]
            if self.domain in full_url and full_url not in self.visited:
                new_urls.append(full_url)

        # 2. Extract JS files for deep scanning
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            js_url = urljoin(url, script['src'])
            if js_url not in self.js_files:
                self.js_files.add(js_url)
                asyncio.create_task(self.scan_js_for_secrets(js_url))

        # 3. Quick HTML Regex scan
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, html)
            if matches:
                self.findings.append({
                    "type": "Secret Leak",
                    "severity": "Critical",
                    "details": f"Found {name} pattern match.",
                    "url": url
                })

        return new_urls

    async def scan_js_for_secrets(self, js_url):
        status, headers, text = await self._fetch(js_url)
        if text:
            for name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, text)
                if matches:
                    self.findings.append({
                        "type": "Hardcoded Credential",
                        "severity": "Critical",
                        "details": f"Found {name} in JavaScript.",
                        "url": js_url
                    })

    async def check_cors_and_headers(self, url):
        """Active tests against specific endpoints."""
        headers = {"Origin": "https://evil.com"}
        await self.semaphore.acquire()
        try:
            async with self.session.get(url, headers=headers, timeout=5) as resp:
                if resp.headers.get('Access-Control-Allow-Origin') == 'https://evil.com':
                    self.findings.append({
                        "type": "CORS Misconfiguration",
                        "severity": "High",
                        "details": "Reflects arbitrary origin.",
                        "url": url
                    })
        except Exception:
            pass
        finally:
            self.semaphore.release()

    async def crawl(self):
        print(f"[*] Initiating Deep Web Crawl on {self.start_url} (Max Depth: {self.max_depth})")
        
        # Initial Header Check
        await self.check_cors_and_headers(self.start_url)

        pages_scanned = 0
        workers = []

        async def worker():
            nonlocal pages_scanned
            while not self.queue.empty() and pages_scanned < self.max_pages:
                current_url, depth = await self.queue.get()
                
                if current_url in self.visited or depth > self.max_depth:
                    self.queue.task_done()
                    continue
                
                self.visited.add(current_url)
                pages_scanned += 1
                
                status, headers, html = await self._fetch(current_url)
                if html and status == 200:
                    new_urls = await self.analyze_content(current_url, html)
                    for n_url in new_urls:
                        self.queue.put_nowait((n_url, depth + 1))
                
                self.queue.task_done()

        # Spawn 5 concurrent crawler workers
        for _ in range(5):
            workers.append(asyncio.create_task(worker()))
            
        await self.queue.join()
        for w in workers:
            w.cancel()
            
        print(f"[+] Crawl finished. Scanned {pages_scanned} pages. Found {len(self.js_files)} JS files.")
        return self.findings

# ================= OSINT ENGINE (Stubs) =================
class OSINTEngine:
    @staticmethod
    async def query_shodan(ip, session):
        if not SHODAN_API_KEY:
            return {"error": "No API Key"}
        print(f"[*] Querying Shodan for {ip}...")
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        try:
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception as e:
            logger.error(f"Shodan API Error: {e}")
        return {}

# ================= CORE ORCHESTRATOR =================
class AnishScannerFramework:
    def __init__(self, target):
        self.target = target
        parsed = urlparse(target if target.startswith('http') else f"http://{target}")
        self.domain = parsed.netloc.split(':')[0]
        self.db = DatabaseManager()
        self.target_id = None
        self.results = {"domain": self.domain, "timestamp": datetime.now().isoformat()}

    def display_banner(self):
        print(r"""
     █████╗ ███╗   ██╗██╗███████╗██╗  ██╗   ██╗██████╗ 
    ██╔══██╗████╗  ██║██║██╔════╝██║  ██║   ██║╚════██╗
    ███████║██╔██╗ ██║██║███████╗███████║   ██║ █████╔╝
    ██╔══██║██║╚██╗██║██║╚════██║██╔══██║   ██║██╔═══╝ 
    ██║  ██║██║ ╚████║██║███████║██║  ██║   ██║███████╗
    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝╚══════╝
    Anish Security Framework v12 – Advanced Modular Edition
        """)

    async def resolve(self):
        resolver = aiodns.DNSResolver()
        try:
            result = await resolver.query(self.domain, 'A')
            return result[0].host
        except Exception:
            return socket.gethostbyname(self.domain)

    async def execute(self):
        self.display_banner()
        
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, ssl=False)
        timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            ip = await self.resolve()
            if not ip:
                print("[-] Target resolution failed. Exiting.")
                return
            
            print(f"[+] Target IP: {ip}")
            self.results['ip'] = ip
            self.target_id = self.db.log_target(self.domain, ip)

            # Phase 1: OSINT Integration
            shodan_data = await OSINTEngine.query_shodan(ip, session)
            if "ports" in shodan_data:
                print(f"[+] Shodan found open ports: {shodan_data['ports']}")
                self.results['osint'] = shodan_data

            # Phase 2: Cloud Asset Enum
            cloud_enum = CloudEnumModule(self.domain, session, semaphore)
            cloud_results = await cloud_enum.run()
            self.results['cloud'] = cloud_results
            for c in cloud_results:
                print(f"    - [{c['severity']}] {c['provider']}: {c['url']} ({c['status']})")
                self.db.log_vuln(self.target_id, "Exposed Bucket", c['severity'], f"{c['provider']} - {c['status']}", c['url'])

            # Phase 3: Deep Web Application Analysis
            base_url = self.target if self.target.startswith('http') else f"https://{self.domain}"
            crawler = DeepWebCrawler(base_url, session, max_depth=2, max_pages=100)
            web_vulns = await crawler.crawl()
            self.results['web_vulns'] = web_vulns
            
            if web_vulns:
                print("\n[!] Web Application Vulnerabilities Detected:")
                for v in web_vulns:
                    print(f"    - [{v['severity']}] {v['type']} at {v['url']}")
                    self.db.log_vuln(self.target_id, v['type'], v['severity'], v['details'], v['url'])
            else:
                print("\n[+] No immediate critical web vulns detected during crawl.")

        self.generate_report()

    def generate_report(self):
        filename = f"framework_report_{self.domain}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"\n[+] Framework Execution Complete. Intelligence saved to SQLite DB and {filename}")

def main():
    parser = argparse.ArgumentParser(description="Anish Security Framework v12")
    parser.add_argument("-t", "--target", required=True, help="Target URL or domain (e.g., https://example.com)")
    args = parser.parse_args()

    framework = AnishScannerFramework(args.target)
    asyncio.run(framework.execute())

if __name__ == "__main__":
    main()
