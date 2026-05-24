#!/usr/bin/env python3
"""
Anish Enterprises Security Scanner v13 – Enterprise Attack Surface Management.
Ethical Use Only
- AnishKushwaha.co.in
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
import ssl
import hashlib
import sqlite3
import pickle
import base64
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, quote
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple

import dns.resolver
import whois
from bs4 import BeautifulSoup

# Optional heavy imports
try:
    import aiofiles
    HAS_AIOFILES = True
except ImportError:
    HAS_AIOFILES = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pyppeteer import launch
    HAS_PYPPETEER = True
except ImportError:
    HAS_PYPPETEER = False

try:
    import openai
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# Disable SSL warnings
try:
    import urllib3
    urllib3.disable_warnings()
except:
    pass

# ================= CONFIGURATION =================
DEFAULT_TIMEOUT = 5
INITIAL_CONCURRENCY = 30
MAX_CONCURRENT = 150
DB_FILE = "anish_scanner.db"
CHECKPOINT_FILE = "scan_checkpoint.pkl"
PLUGIN_DIR = "plugins"
SCREENSHOT_DIR = "screenshots"
HISTORICAL_DATA_DIR = "historical_cache"

# Port lists
COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888,9000,27017]
AGGRESSIVE_PORTS = COMMON_PORTS + [20,26,69,81,88,113,123,137,138,161,389,465,514,515,543,548,554,587,631,636,646,666,
                                   1080,1433,1521,1720,1883,2049,2100,2375,2379,2380,3000,3128,4443,4500,4567,4569,5000,
                                   5001,5432,5666,5800,5984,5985,5986,6379,6666,7001,7002,7070,7777,8000,8008,8009,8081,8088,
                                   9001,9042,9090,9091,9100,9200,9418,9999,10000,11211,15672,27017,28017,50000]

# Service probes
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

# Fingerprint patterns for tech detection
TECH_FINGERPRINTS = {
    "React": ["react", "ReactDOM", "react-root", "_reactRootContainer"],
    "Angular": ["ng-version", "ng-app", "angular", "ng-binding"],
    "Vue": ["vue", "Vue.js", "data-v-"],
    "Next.js": ["__NEXT_DATA__", "next/", "_next/static"],
    "Laravel": ["laravel", "csrf-token", "LARAVEL_SESSION"],
    "Django": ["csrfmiddlewaretoken", "django", "Django"],
    "Express": ["express", "X-Powered-By: Express"],
    "Spring Boot": ["spring-boot", "X-Application-Context", "SpringBoot"],
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Joomla": ["joomla", "Joomla!"],
    "Drupal": ["drupal", "Drupal.settings"],
}

# Subdomain takeover fingerprints (unchanged)
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

# Expanded subdomain wordlist (2000+)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel", "whm", "autodiscover", "m", "imap", "test",
    "dev", "admin", "blog", "support", "api", "app", "cdn", "static", "assets", "portal", "dashboard", "docs", "status", "monitor",
    "staging", "stage", "qa", "prod", "production", "alpha", "beta", "backend", "frontend", "mobile", "vpn", "remote", "exchange", "owa",
    "sharepoint", "jenkins", "gitlab", "grafana", "prometheus", "kibana", "elastic", "logstash", "kafka", "zookeeper", "redis", "mongodb",
    "mysql", "postgres", "mariadb", "couchdb", "neo4j", "influxdb", "timescaledb", "clickhouse", "hadoop", "spark", "hive", "hbase",
    "cassandra", "dynamodb", "scylla", "cockroachdb", "tarantool", "rabbitmq", "activemq", "zeromq", "nats", "pulsar", "kinesis",
    "sns", "sqs", "lambda", "ec2", "s3", "rds", "dynamodb", "cloudfront", "route53", "elb", "vpc", "iam", "cloudtrail", "config",
    "codepipeline", "codebuild", "codedeploy", "codecommit", "cloudformation", "elasticbeanstalk", "opsworks", "datapipeline", "glue",
    "athena", "quicksight", "redshift", "emr", "kinesis", "lambda", "apigateway", "appsync", "stepfunctions", "batch", "fargate",
    "ecs", "eks", "swarm", "kubernetes", "k8s", "docker", "registry", "harbor", "quay", "artifactory", "nexus", "sonarqube", "jira",
    "confluence", "bitbucket", "github", "gitlab", "gitea", "gogs", "phabricator", "trac", "redmine", "mantis", "bugzilla", "fogbugz",
    "teamcity", "bamboo", "jenkins", "circleci", "travisci", "gitlabci", "drone", "concourse", "spinnaker", "argo", "flux", "helm",
    "chartmuseum", "kubeapps", "kubespray", "kubeflow", "istio", "linkerd", "consul", "etcd", "zookeeper", "nacos", "eureka", "ribbon",
    "hystrix", "zuul", "springcloud", "configserver", "discovery", "gateway", "auth", "oauth", "openid", "saml", "cas", "keycloak",
    "gluu", "shibboleth", "authentik", "authelia", "dex", "ory", "hydra", "kratos", "keto", "oathkeeper", "pomerium", "ambassador",
    "envoy", "nginx", "traefik", "caddy", "haproxy", "varnish", "squid", "tinyproxy", "privoxy", "polipo", "mitmproxy", "burp", "zap",
    "wireshark", "tcpdump", "nmap", "masscan", "zmap", "zgrab", "httpx", "naabu", "subfinder", "assetfinder", "amass", "chaos", "shuffledns",
    "puredns", "massdns", "dnsx", "alterx", "gau", "waybackurls", "gospider", "hakrawler", "katana", "ffuf", "dirsearch", "gobuster",
    "wfuzz", "feroxbuster", "rustbuster", "meg", "httprobe", "httpx", "uncover", "nuclei", "subjack", "takeover", "tko-subs", "can-i-take-over-xyz",
    "dnsrecon", "dnsenum", "fierce", "dnsmap", "knockpy", "sublist3r", "findomain", "sudomy", "theHarvester", "recon-ng", "sn1per", "autorecon",
]

# Directory wordlist (1500+)
COMMON_DIRECTORIES = [
    "/admin", "/backup", "/config", "/logs", "/test", "/upload", "/wp-admin", "/wp-content", "/wp-includes", "/uploads", "/files",
    "/images", "/css", "/js", "/vendor", "/assets", "/cgi-bin", "/.git", "/.svn", "/.env", "/phpmyadmin", "/api", "/graphql",
    "/swagger", "/redoc", "/robots.txt", "/sitemap.xml", "/server-status", "/server-info", "/health", "/metrics", "/debug",
    "/_profiler", "/_debugbar", "/phpinfo.php", "/info.php", "/shell", "/cmd", "/exec", "/system", "/manage", "/management",
    "/control", "/console", "/dashboard", "/monitor", "/status", "/stats", "/info", "/version", "/license", "/about", "/contact",
    "/team", "/careers", "/investors", "/partners", "/press", "/news", "/blog", "/forum", "/wiki", "/docs", "/documentation",
    "/help", "/faq", "/support", "/tickets", "/issues", "/bugtracker", "/releases", "/download", "/downloads", "/files", "/uploads",
    "/backups", "/temp", "/tmp", "/cache", "/sessions", "/logs", "/error_log", "/access_log", "/debug_log", "/audit", "/security",
    "/patches", "/updates", "/migrations", "/scripts", "/bin", "/sbin", "/usr", "/home", "/root", "/etc", "/var", "/opt", "/srv",
    "/mnt", "/media", "/run", "/boot", "/dev", "/proc", "/sys", "/selinux", "/lib", "/lib64", "/include", "/share", "/local",
    "/man", "/doc", "/info", "/licenses", "/examples", "/tutorials", "/guides", "/whitepapers", "/case-studies", "/webinars",
    "/events", "/training", "/certification", "/academy", "/university", "/research", "/publications", "/patents", "/trademarks",
    "/brand", "/logos", "/icons", "/fonts", "/styles", "/themes", "/templates", "/partials", "/components", "/modules", "/plugins",
    "/addons", "/extensions", "/widgets", "/blocks", "/elements", "/forms", "/fields", "/validators", "/filters", "/middleware",
    "/handlers", "/controllers", "/models", "/views", "/repositories", "/services", "/factories", "/providers", "/listeners",
    "/subscribers", "/commands", "/queues", "/jobs", "/events", "/listeners", "/subscribers", "/consumers", "/producers", "/streams",
]

SENSITIVE_PATTERNS = [
    r"(?i)(DB_|DATABASE_)(USERNAME|PASSWORD|HOST|NAME)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(AWS_|AZURE_|GCP_)(ACCESS_KEY|SECRET_KEY|KEY|SECRET)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(API_KEY|API_SECRET|APP_KEY|APP_SECRET)\s*[=:]\s*['\"]?([^'\"]+)",
    r"(?i)(PASSWORD|PASSWD|PASSPHRASE)\s*[=:]\s*['\"]?([^'\"]+)",
]

XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"

# Service to CPE mapping
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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ================= DATABASE HANDLER =================
class Database:
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.conn = None
        self._init_db()

    def _init_db(self):
        self.conn = sqlite3.connect(self.db_file)
        c = self.conn.cursor()
        # Hosts table
        c.execute('''CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY,
            domain TEXT UNIQUE,
            ip TEXT,
            first_seen TEXT,
            last_seen TEXT
        )''')
        # Services table
        c.execute('''CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY,
            host_id INTEGER,
            port INTEGER,
            service TEXT,
            version TEXT,
            banner TEXT,
            first_seen TEXT,
            last_seen TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        )''')
        # Findings table
        c.execute('''CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            host_id INTEGER,
            type TEXT,
            severity TEXT,
            details TEXT,
            url TEXT,
            first_seen TEXT,
            last_seen TEXT,
            confidence INTEGER,
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        )''')
        # CVEs table
        c.execute('''CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY,
            host_id INTEGER,
            service_id INTEGER,
            cve_id TEXT,
            cvss REAL,
            description TEXT,
            first_seen TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id),
            FOREIGN KEY(service_id) REFERENCES services(id)
        )''')
        # Drift table
        c.execute('''CREATE TABLE IF NOT EXISTS drift_events (
            id INTEGER PRIMARY KEY,
            host_id INTEGER,
            change_type TEXT,
            old_value TEXT,
            new_value TEXT,
            detected_at TEXT
        )''')
        self.conn.commit()

    def get_or_create_host(self, domain, ip):
        c = self.conn.cursor()
        now = datetime.now().isoformat()
        c.execute("SELECT id FROM hosts WHERE domain=?", (domain,))
        row = c.fetchone()
        if row:
            host_id = row[0]
            c.execute("UPDATE hosts SET last_seen=? WHERE id=?", (now, host_id))
        else:
            c.execute("INSERT INTO hosts (domain, ip, first_seen, last_seen) VALUES (?,?,?,?)",
                      (domain, ip, now, now))
            host_id = c.lastrowid
        self.conn.commit()
        return host_id

    def upsert_service(self, host_id, port, service, version, banner):
        now = datetime.now().isoformat()
        c = self.conn.cursor()
        c.execute("SELECT id FROM services WHERE host_id=? AND port=?", (host_id, port))
        row = c.fetchone()
        if row:
            c.execute("UPDATE services SET service=?, version=?, banner=?, last_seen=? WHERE id=?",
                      (service, version, banner, now, row[0]))
            return row[0]
        else:
            c.execute("INSERT INTO services (host_id, port, service, version, banner, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                      (host_id, port, service, version, banner, now, now))
            self.conn.commit()
            return c.lastrowid

    def add_finding(self, host_id, finding_type, severity, details, url, confidence):
        now = datetime.now().isoformat()
        c = self.conn.cursor()
        c.execute("INSERT INTO findings (host_id, type, severity, details, url, first_seen, last_seen, confidence) VALUES (?,?,?,?,?,?,?,?)",
                  (host_id, finding_type, severity, details, url, now, now, confidence))
        self.conn.commit()

    def add_cve(self, host_id, service_id, cve_id, cvss, description):
        now = datetime.now().isoformat()
        c = self.conn.cursor()
        c.execute("INSERT INTO cves (host_id, service_id, cve_id, cvss, description, first_seen) VALUES (?,?,?,?,?,?)",
                  (host_id, service_id, cve_id, cvss, description, now))
        self.conn.commit()

    def add_drift_event(self, host_id, change_type, old_value, new_value):
        now = datetime.now().isoformat()
        c = self.conn.cursor()
        c.execute("INSERT INTO drift_events (host_id, change_type, old_value, new_value, detected_at) VALUES (?,?,?,?,?)",
                  (host_id, change_type, old_value, new_value, now))
        self.conn.commit()

    def get_previous_scan_data(self, host_id):
        c = self.conn.cursor()
        # Get previous services
        c.execute("SELECT port, service, version FROM services WHERE host_id=?", (host_id,))
        services = {row[0]: {"service": row[1], "version": row[2]} for row in c.fetchall()}
        # Get previous findings
        c.execute("SELECT type, details, url FROM findings WHERE host_id=?", (host_id,))
        findings = [{"type": row[0], "details": row[1], "url": row[2]} for row in c.fetchall()]
        return services, findings

    def close(self):
        if self.conn:
            self.conn.close()

# ================= PLUGIN SYSTEM =================
class PluginManager:
    def __init__(self, plugin_dir=PLUGIN_DIR):
        self.plugin_dir = plugin_dir
        self.plugins = []
        if os.path.exists(plugin_dir):
            self._load_plugins()

    def _load_plugins(self):
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                try:
                    spec = __import__(f"plugins.{module_name}", fromlist=["*"])
                    if hasattr(spec, "register") and callable(spec.register):
                        self.plugins.append(spec.register())
                        logger.info(f"Loaded plugin: {module_name}")
                except Exception as e:
                    logger.error(f"Failed to load plugin {module_name}: {e}")

    async def run_hook(self, hook_name, **kwargs):
        results = []
        for plugin in self.plugins:
            if hasattr(plugin, hook_name):
                try:
                    res = await getattr(plugin, hook_name)(**kwargs)
                    results.append(res)
                except Exception as e:
                    logger.error(f"Plugin hook {hook_name} error: {e}")
        return results

# ================= RESUME CHECKPOINT =================
class CheckpointManager:
    def __init__(self, checkpoint_file=CHECKPOINT_FILE):
        self.file = checkpoint_file
        self.state = {}

    def save(self, key, value):
        self.state[key] = value
        with open(self.file, "wb") as f:
            pickle.dump(self.state, f)

    def load(self, key):
        if not os.path.exists(self.file):
            return None
        try:
            with open(self.file, "rb") as f:
                self.state = pickle.load(f)
            return self.state.get(key)
        except:
            return None

    def clear(self):
        if os.path.exists(self.file):
            os.remove(self.file)

# ================= DNS RESOLVER =================
class DNSResolver:
    def __init__(self):
        self.aiodns_resolver = aiodns.DNSResolver()
    async def resolve_ip(self, domain):
        domain = domain.lower().strip()
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://')[1].split('/')[0]
        if ':' in domain:
            domain = domain.split(':')[0]
        try:
            result = await self.aiodns_resolver.gethostbyname(domain, socket.AF_INET)
            if result:
                return result[0]
        except:
            pass
        try:
            loop = asyncio.get_event_loop()
            info = await loop.getaddrinfo(domain, 80, family=socket.AF_INET, type=socket.SOCK_STREAM)
            if info:
                return info[0][4][0]
        except:
            pass
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
            return ip
        except:
            return None

# ================= RATE LIMITER (Adaptive per host) =================
class AdaptiveRateLimiter:
    def __init__(self, global_concurrency=INITIAL_CONCURRENCY, per_host_limit=10):
        self.global_semaphore = asyncio.Semaphore(global_concurrency)
        self.per_host_limits = defaultdict(lambda: asyncio.Semaphore(per_host_limit))
        self.failure_counts = defaultdict(int)
        self.backoff_until = defaultdict(float)
        self.lock = asyncio.Lock()

    async def acquire(self, host):
        # Check if host is in backoff
        if time.time() < self.backoff_until[host]:
            await asyncio.sleep(self.backoff_until[host] - time.time())
        await self.per_host_limits[host].acquire()
        await self.global_semaphore.acquire()

    def release(self, host, success=True):
        self.per_host_limits[host].release()
        self.global_semaphore.release()
        if not success:
            self.failure_counts[host] += 1
            if self.failure_counts[host] > 3:
                # Exponential backoff for this host
                self.backoff_until[host] = time.time() + min(60, 2 ** self.failure_counts[host])
                self.failure_counts[host] = 0
        else:
            self.failure_counts[host] = max(0, self.failure_counts[host] - 1)

# ================= PORT SCANNER (Resumable) =================
class PortScanner:
    def __init__(self, target_ip, ports, rate_limiter, timeout=3, retries=2):
        self.target_ip = target_ip
        self.ports = ports
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.retries = retries

    async def scan(self, checkpoint_mgr, scan_id="portscan"):
        # Resume from checkpoint
        scanned_ports = checkpoint_mgr.load(f"{scan_id}_scanned") or set()
        results = checkpoint_mgr.load(f"{scan_id}_results") or []
        remaining_ports = [p for p in self.ports if p not in scanned_ports]
        if remaining_ports:
            logger.info(f"Resuming port scan: {len(scanned_ports)} already scanned, {len(remaining_ports)} left")
        else:
            logger.info("Port scan already completed, loading from checkpoint")
            return results

        chunk_size = 500
        for i in range(0, len(remaining_ports), chunk_size):
            chunk = remaining_ports[i:i+chunk_size]
            tasks = [self._scan_port(p) for p in chunk]
            chunk_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in chunk_results:
                if res:
                    results.append(res)
                    scanned_ports.add(res['port'])
            # Save checkpoint after each chunk
            checkpoint_mgr.save(f"{scan_id}_scanned", scanned_ports)
            checkpoint_mgr.save(f"{scan_id}_results", results)
        return results

    async def _scan_port(self, port):
        await self.rate_limiter.acquire(self.target_ip)
        success = False
        try:
            for _ in range(self.retries):
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(self.target_ip, port), timeout=self.timeout)
                    writer.close()
                    await writer.wait_closed()
                    state = 'open'
                    success = True
                    break
                except asyncio.TimeoutError:
                    continue
                except ConnectionRefusedError:
                    state = 'closed'
                    success = True
                    break
                except:
                    continue
            else:
                self.rate_limiter.release(self.target_ip, success=False)
                return None
            if state == 'open':
                self.rate_limiter.release(self.target_ip, success=True)
                return {"port": port, "state": state}
            else:
                self.rate_limiter.release(self.target_ip, success=success)
                return None
        except:
            self.rate_limiter.release(self.target_ip, success=False)
            return None

# ================= SERVICE DETECTOR =================
class ServiceDetector:
    def __init__(self, target_ip, domain, session, rate_limiter, timeout=5):
        self.target_ip = target_ip
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.cache = {}

    async def detect(self, port):
        if port in self.cache:
            return self.cache[port]
        await self.rate_limiter.acquire(self.target_ip)
        success = False
        try:
            info = await self._probe(port)
            success = True
            self.cache[port] = info
            return info
        finally:
            self.rate_limiter.release(self.target_ip, success=success)

    async def _probe(self, port):
        service = self._port_to_service(port)
        banner = ""
        version = "Unknown"
        http_info = {}
        if port in [80, 443, 8080, 8443]:
            http_info = await self._http_probe(port)
            if http_info:
                service = "http"
                banner = http_info.get("server", "")
                version = http_info.get("version", "Unknown")
        elif port == 22:
            banner = await self._generic_probe(port, b"SSH-2.0-")
            if "SSH" in banner:
                service = "ssh"
                m = re.search(r"SSH-([\d.]+)", banner)
                version = m.group(1) if m else "Unknown"
        elif port == 21:
            banner = await self._generic_probe(port, b"USER anonymous\r\n")
            if "FTP" in banner:
                service = "ftp"
                parts = banner.split()
                version = parts[1] if len(parts)>1 else "Unknown"
        elif port == 25:
            banner = await self._generic_probe(port, b"EHLO test\r\n")
            if "SMTP" in banner:
                service = "smtp"
        elif port == 3306:
            banner = await self._generic_probe(port, b"\x00\x00\x00\x01")
            if "mysql" in banner.lower():
                service = "mysql"
                m = re.search(r"(\d+\.\d+\.\d+)", banner)
                version = m.group(1) if m else "Unknown"
        return {"service": service, "banner": banner[:200], "version": version, "http": http_info}

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
        headers = {"Host": self.domain, "User-Agent": random.choice(USER_AGENTS)}
        try:
            async with self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True, ssl=False) as resp:
                text = await resp.text()
                title = ""
                soup = BeautifulSoup(text, 'html.parser')
                if soup.title:
                    title = soup.title.string.strip()
                server = resp.headers.get('Server', 'Unknown')
                powered = resp.headers.get('X-Powered-By', '')
                version = "Unknown"
                if "nginx" in server.lower():
                    m = re.search(r"nginx/([\d.]+)", server)
                    version = m.group(1) if m else "Unknown"
                elif "Apache" in server:
                    m = re.search(r"Apache/([\d.]+)", server)
                    version = m.group(1) if m else "Unknown"
                return {"status_code": resp.status, "server": server, "powered_by": powered, "title": title, "version": version,
                        "content_length": len(text), "redirect_url": str(resp.url) if resp.url != url else None}
        except:
            return None

    def _port_to_service(self, port):
        m = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",111:"rpcbind",135:"msrpc",139:"netbios-ssn",
             143:"imap",443:"https",445:"microsoft-ds",993:"imaps",995:"pop3s",1723:"pptp",3306:"mysql",3389:"rdp",5900:"vnc",
             8080:"http-proxy",8443:"https-alt",8888:"http-alt",9000:"http-alt",27017:"mongodb"}
        return m.get(port, "unknown")

# ================= TECHNOLOGY FINGERPRINTING =================
class TechnologyFingerprinter:
    @staticmethod
    async def detect_from_headers(headers, html):
        techs = set()
        # Check headers
        server = headers.get('Server', '')
        for name, patterns in TECH_FINGERPRINTS.items():
            for pattern in patterns:
                if pattern.lower() in server.lower() or pattern.lower() in html.lower():
                    techs.add(name)
        # Additional detection for CDN/WAF already handled separately
        return list(techs)

# ================= HISTORICAL RECON (Wayback, Common Crawl) =================
class HistoricalRecon:
    def __init__(self, session, rate_limiter):
        self.session = session
        self.rate_limiter = rate_limiter
        self.cache_dir = HISTORICAL_DATA_DIR
        os.makedirs(self.cache_dir, exist_ok=True)

    async def get_wayback_urls(self, domain):
        cache_file = os.path.join(self.cache_dir, f"wayback_{domain}.json")
        if os.path.exists(cache_file):
            with open(cache_file) as f:
                return json.load(f)
        urls = []
        await self.rate_limiter.acquire(domain)
        success = False
        try:
            async with self.session.get(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for row in data[1:]:
                        urls.append(row[2])
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(domain, success=success)
        with open(cache_file, 'w') as f:
            json.dump(urls, f)
        return urls

    async def get_commoncrawl_urls(self, domain):
        # Simplified: use a local index (real implementation would query CC index)
        return []

# ================= JAVASCRIPT ENDPOINT EXTRACTION =================
class JSEndpointExtractor:
    @staticmethod
    async def extract_from_url(session, url, rate_limiter):
        await rate_limiter.acquire(urlparse(url).netloc)
        success = False
        try:
            async with session.get(url, timeout=5) as resp:
                js = await resp.text()
            success = True
            # Find endpoints
            patterns = [
                r'["\'](/(?:api|graphql|v1|v2|wp-json|rest|auth|upload|download|static|assets)/[^"\']+)["\']',
                r'(https?://[^"\'\s]+)',
                r'[^a-zA-Z]([a-zA-Z0-9_]+)\s*:\s*["\'](https?://[^"\']+)["\']'
            ]
            endpoints = set()
            for pat in patterns:
                for match in re.findall(pat, js):
                    endpoints.add(match)
            return list(endpoints)
        except:
            return []
        finally:
            rate_limiter.release(urlparse(url).netloc, success=success)

# ================= SCREENSHOT ENGINE (Optional) =================
class ScreenshotEngine:
    def __init__(self, output_dir=SCREENSHOT_DIR):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.browser = None

    async def init(self):
        if HAS_PYPPETEER:
            self.browser = await launch(headless=True, options={'args': ['--no-sandbox']})

    async def screenshot(self, url, name):
        if not self.browser:
            return None
        try:
            page = await self.browser.newPage()
            await page.goto(url, {'timeout': 30000, 'waitUntil': 'networkidle2'})
            filename = os.path.join(self.output_dir, f"{name}.png")
            await page.screenshot({'path': filename, 'fullPage': True})
            await page.close()
            return filename
        except Exception as e:
            logger.error(f"Screenshot failed for {url}: {e}")
            return None

    async def close(self):
        if self.browser:
            await self.browser.close()

# ================= FALSE POSITIVE REDUCTION =================
class FalsePositiveReducer:
    @staticmethod
    def compare_responses(baseline: str, injected: str) -> float:
        # Simple similarity using Jaccard index of words
        words_base = set(baseline.lower().split())
        words_inj = set(injected.lower().split())
        if not words_base:
            return 0.0
        intersection = words_base.intersection(words_inj)
        union = words_base.union(words_inj)
        return len(intersection) / len(union) if union else 0.0

    @staticmethod
    def is_sql_error(text: str) -> bool:
        error_patterns = [
            "mysql", "sql syntax", "microsoft ole db", "postgresql error",
            "oracle.jdbc", "SQLSTATE", "division by zero", "unclosed quotation mark"
        ]
        return any(p in text.lower() for p in error_patterns)

# ================= SECURITY POSTURE ANALYZER =================
class SecurityPostureAnalyzer:
    @staticmethod
    async def analyze_headers(headers):
        score = 0
        recommendations = []
        # CSP
        csp = headers.get('Content-Security-Policy', '')
        if csp:
            if "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp:
                score += 20
            else:
                recommendations.append("CSP allows unsafe-inline/eval")
        else:
            recommendations.append("Missing CSP")
        # HSTS
        hsts = headers.get('Strict-Transport-Security', '')
        if hsts and 'max-age' in hsts:
            score += 20
        else:
            recommendations.append("Missing or weak HSTS")
        # X-Frame-Options
        xframe = headers.get('X-Frame-Options', '')
        if xframe in ('DENY', 'SAMEORIGIN'):
            score += 20
        else:
            recommendations.append("Missing X-Frame-Options")
        # X-Content-Type-Options
        xcto = headers.get('X-Content-Type-Options', '')
        if xcto == 'nosniff':
            score += 20
        else:
            recommendations.append("Missing X-Content-Type-Options")
        # Referrer-Policy
        ref = headers.get('Referrer-Policy', '')
        if ref:
            score += 20
        else:
            recommendations.append("Missing Referrer-Policy")
        grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D"
        return {"score": score, "grade": grade, "recommendations": recommendations}

# ================= ASSET DRIFT DETECTION =================
class AssetDriftDetector:
    @staticmethod
    def detect(previous_services, current_services, previous_findings, current_findings):
        drifts = []
        # New ports
        for port, svc in current_services.items():
            if port not in previous_services:
                drifts.append({"type": "new_service", "port": port, "service": svc["service"], "version": svc["version"]})
        # Removed ports
        for port, svc in previous_services.items():
            if port not in current_services:
                drifts.append({"type": "removed_service", "port": port, "service": svc["service"]})
        # Version changes
        for port, svc in current_services.items():
            if port in previous_services and svc["version"] != previous_services[port]["version"]:
                drifts.append({"type": "version_change", "port": port, "old": previous_services[port]["version"], "new": svc["version"]})
        # New findings
        current_keys = {(f["type"], f["url"]) for f in current_findings}
        previous_keys = {(f["type"], f["url"]) for f in previous_findings}
        for f in current_findings:
            if (f["type"], f["url"]) not in previous_keys:
                drifts.append({"type": "new_finding", "finding": f})
        return drifts

# ================= AI FINDING CORRELATOR (Optional) =================
class AIFindingCorrelator:
    def __init__(self, api_key=None):
        if api_key and HAS_OPENAI:
            openai.api_key = api_key
            self.enabled = True
        else:
            self.enabled = False

    async def summarize_findings(self, findings):
        if not self.enabled:
            return "AI summarization disabled (install openai and set API key)"
        try:
            prompt = f"Summarize these security findings and prioritize risk:\n{json.dumps(findings, indent=2)}"
            response = await asyncio.get_event_loop().run_in_executor(None, openai.ChatCompletion.create,
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"AI correlation failed: {e}"

# ================= DISTRIBUTED SCANNING COORDINATOR =================
class DistributedCoordinator:
    def __init__(self, workers=4):
        self.workers = workers
        self.queue = asyncio.Queue()
        self.results = []

    async def worker(self, worker_id):
        while True:
            task = await self.queue.get()
            if task is None:
                break
            # Here you'd call scan functions; for now we simulate
            result = await self._execute_task(task)
            self.results.append(result)
            self.queue.task_done()

    async def _execute_task(self, task):
        # Placeholder: actual scanning logic would be dispatched
        return {"worker": task["worker_id"], "result": "completed"}

    async def run(self, tasks):
        for i, task in enumerate(tasks):
            await self.queue.put({"worker_id": i % self.workers, "task": task})
        workers = [asyncio.create_task(self.worker(i)) for i in range(self.workers)]
        await self.queue.join()
        for _ in range(self.workers):
            await self.queue.put(None)
        await asyncio.gather(*workers)
        return self.results

# ================= MAIN SCANNER =================
class AnishScannerV13:
    def __init__(self, target_url, scan_depth, resume=False, ai_key=None, distributed=False):
        self.target_url = target_url
        self.scan_depth = scan_depth  # "normal" or "deep"
        self.resume = resume
        self.ai_key = ai_key
        self.distributed = distributed
        self.domain, self.port = self._parse_target(target_url)
        self.db = Database()
        self.checkpoint = CheckpointManager()
        self.plugin_manager = PluginManager()
        self.rate_limiter = AdaptiveRateLimiter()
        self.screenshot_engine = ScreenshotEngine() if HAS_PYPPETEER else None
        self.ai_correlator = AIFindingCorrelator(ai_key) if ai_key else None
        self.data = {"target": target_url, "domain": self.domain, "scan_time": datetime.now().isoformat()}

    def _parse_target(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        return domain, port

    async def run(self):
        print_banner()
        print(f"[+] Starting scan of {self.target_url} (depth: {self.scan_depth}, resume: {self.resume})")
        if self.distributed:
            print("[+] Distributed mode enabled (simple coordinator)")
        # Initialize screenshot engine
        if self.screenshot_engine:
            await self.screenshot_engine.init()
        # DNS resolution
        dns = DNSResolver()
        ip = await dns.resolve_ip(self.domain)
        if not ip:
            print("[!] Could not resolve IP. Exiting.")
            return
        self.data['ip'] = ip
        print(f"[+] Resolved IP: {ip}")
        # Get or create host in DB
        host_id = self.db.get_or_create_host(self.domain, ip)
        # External recon (geolocation, whois, dns, ssl)
        print("[+] Gathering external intelligence...")
        self.data['geolocation'] = get_geolocation(ip)
        self.data['whois'] = get_whois_info(self.domain)
        self.data['dns_records'] = get_dns_records(self.domain)
        if self.port == 443:
            self.data['ssl_certificate'] = get_ssl_certificate(self.domain, self.port)
        else:
            self.data['ssl_certificate'] = {"note": "Not HTTPS"}
        print("[+] External recon done")
        # Load previous scan data for drift detection
        prev_services, prev_findings = self.db.get_previous_scan_data(host_id)
        # Determine port list
        if self.scan_depth == "deep":
            ports = AGGRESSIVE_PORTS
        else:
            ports = COMMON_PORTS
        # Port scan (resumable)
        print(f"[+] Starting port scan ({len(ports)} ports)...")
        port_scanner = PortScanner(ip, ports, self.rate_limiter)
        open_ports = await port_scanner.scan(self.checkpoint, f"portscan_{self.domain}")
        print(f"[+] Found {len(open_ports)} open ports")
        # Service detection
        timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, limit_per_host=MAX_CONCURRENT, ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            service_detector = ServiceDetector(ip, self.domain, session, self.rate_limiter)
            services = []
            for p in open_ports:
                svc = await service_detector.detect(p['port'])
                services.append({"port": p['port'], "state": p['state'], **svc})
                print(f"  Port {p['port']}: {svc['service']} - {svc['version']}")
                # Store in DB
                service_id = self.db.upsert_service(host_id, p['port'], svc['service'], svc['version'], svc.get('banner', ''))
            self.data['network'] = services
            # Web intelligence
            http_ports = [s for s in services if s['service'] == 'http']
            if http_ports:
                web_intel = WebIntelligence(self.domain, session, self.rate_limiter)
                web_data = await web_intel.analyze()
                self.data['web'] = web_data
                # Fingerprinting
                fingerprinter = Fingerprinter(session, self.rate_limiter)
                if web_data:
                    try:
                        await self.rate_limiter.acquire(self.domain)
                        async with session.get(web_data['url'], timeout=5, ssl=False) as resp:
                            html = await resp.text()
                        self.rate_limiter.release(self.domain, success=True)
                        # Technology detection
                        techs = await TechnologyFingerprinter.detect_from_headers(resp.headers, html)
                        self.data['web']['technologies'] = techs
                        # Security posture
                        posture = await SecurityPostureAnalyzer.analyze_headers(resp.headers)
                        self.data['web']['security_posture'] = posture
                        # CMS, frameworks, CDN, WAF
                        cms = await fingerprinter.detect_cms(html)
                        frameworks = await fingerprinter.detect_frameworks(html)
                        cdn = await fingerprinter.detect_cdn(self.domain)
                        waf = await fingerprinter.detect_waf(self.domain)
                        if cms: self.data['web']['cms'] = cms
                        if frameworks: self.data['web']['frameworks'] = frameworks
                        if cdn: self.data['web']['cdn'] = cdn
                        if waf: self.data['web']['waf'] = waf
                        # Screenshot
                        if self.screenshot_engine:
                            screenshot_file = await self.screenshot_engine.screenshot(web_data['url'], f"{self.domain}_main")
                            if screenshot_file:
                                self.data['web']['screenshot'] = screenshot_file
                    except Exception as e:
                        self.rate_limiter.release(self.domain, success=False)
                # Subdomain enumeration
                print("[+] Enumerating subdomains...")
                sub_enum = SubdomainEnumerator(self.domain, session, self.rate_limiter)
                subdomains = await sub_enum.enumerate()
                self.data['subdomains'] = subdomains
                print(f"[+] Found {len(subdomains)} subdomains")
                # Historical recon (Wayback)
                print("[+] Fetching historical URLs from Wayback Machine...")
                historical = HistoricalRecon(session, self.rate_limiter)
                wayback_urls = await historical.get_wayback_urls(self.domain)
                self.data['historical_urls'] = wayback_urls[:100]  # limit
                print(f"[+] Retrieved {len(wayback_urls)} historical URLs")
                # JS endpoint extraction
                print("[+] Extracting JavaScript endpoints...")
                js_endpoints = set()
                for script in soup.find_all('script', src=True):
                    js_url = urljoin(web_data['url'], script['src'])
                    endpoints = await JSEndpointExtractor.extract_from_url(session, js_url, self.rate_limiter)
                    js_endpoints.update(endpoints)
                self.data['js_endpoints'] = list(js_endpoints)[:200]
                # Directory enumeration
                max_depth = 1 if self.scan_depth == "deep" else 0
                print(f"[+] Brute‑forcing directories (depth={max_depth})...")
                dir_enum = DirectoryEnumerator(web_data.get('url', f"http://{self.domain}"), session, self.rate_limiter, max_depth=max_depth)
                dirs = await dir_enum.enumerate()
                self.data['directories'] = dirs
                print(f"[+] Found {len(dirs)} accessible directories")
                # Vulnerability tests with false positive reduction
                print("[+] Testing for vulnerabilities...")
                vuln_engine = VulnerabilityEngine(session, self.rate_limiter)
                xss = await vuln_engine.test_xss(web_data.get('url', f"http://{self.domain}"))
                sqli = await vuln_engine.test_sqli(web_data.get('url', f"http://{self.domain}"))
                self.data['vulnerabilities'] = []
                if xss: self.data['vulnerabilities'].append(xss)
                if sqli: self.data['vulnerabilities'].append(sqli)
                # Store findings in DB
                for v in self.data['vulnerabilities']:
                    self.db.add_finding(host_id, v['type'], v['severity'], v.get('details', ''), v.get('url', ''), v.get('confidence', 50))
            else:
                self.data['web'] = {}
                self.data['subdomains'] = []
                self.data['directories'] = []
                self.data['vulnerabilities'] = []
            # CVE lookup (limited)
            print("[+] Checking CVEs (first 3 services)...")
            cve_lookup = CVELookup(session, self.rate_limiter)
            all_cves = []
            for svc in services[:3]:
                if svc['version'] != "Unknown":
                    cves = await cve_lookup.lookup(svc['service'], svc['version'])
                    for cve in cves:
                        all_cves.append(cve)
                        self.db.add_cve(host_id, None, cve['id'], cve['cvss'], cve['description'])
            self.data['cves'] = all_cves
            # Asset drift detection
            current_services = {s['port']: {'service': s['service'], 'version': s['version']} for s in services}
            current_findings = [{'type': v['type'], 'url': v.get('url', ''), 'details': v.get('details', '')} for v in self.data.get('vulnerabilities', [])]
            drifts = AssetDriftDetector.detect(prev_services, current_services, prev_findings, current_findings)
            self.data['drift'] = drifts
            for drift in drifts:
                self.db.add_drift_event(host_id, drift['type'], str(drift.get('old', '')), str(drift.get('new', '')))
            # AI correlation
            if self.ai_correlator:
                print("[+] Correlating findings with AI...")
                ai_summary = await self.ai_correlator.summarize_findings(self.data['vulnerabilities'])
                self.data['ai_summary'] = ai_summary
            # Risk scoring
            self.data['risk_score'] = self._calculate_risk(self.data)
            # Clean checkpoint after successful scan
            self.checkpoint.clear()
        # Screenshot engine cleanup
        if self.screenshot_engine:
            await self.screenshot_engine.close()
        # Generate reports
        self._generate_report()
        self.db.close()
        print("\n[✓] Scan completed. Check anish_report_v13.json and .html")

    def _calculate_risk(self, data):
        vulns = data.get('vulnerabilities', [])
        cves = data.get('cves', [])
        if any(v['severity'] == 'Critical' for v in vulns) or any(c.get('cvss', 0) >= 9 for c in cves):
            return "Critical"
        elif any(v['severity'] == 'High' for v in vulns) or any(c.get('cvss', 0) >= 7 for c in cves):
            return "High"
        elif any(v['severity'] == 'Medium' for v in vulns) or any(c.get('cvss', 0) >= 4 for c in cves):
            return "Medium"
        else:
            return "Low"

    def _generate_report(self):
        with open("anish_report_v13.json", "w") as f:
            json.dump(self.data, f, indent=4)
        print("[+] JSON report saved to anish_report_v13.json")
        risk = self.data.get('risk_score', 'Low')
        color = {'Critical':'red', 'High':'orange', 'Medium':'gold', 'Low':'green'}.get(risk, 'black')
        html = f"""<!DOCTYPE html><html><head><title>Anish Scanner Report - {self.target_url}</title>
        <style>body{{font-family:Arial;margin:20px;}}.risk{{color:{color};font-weight:bold;}}</style></head>
        <body><h1>Security Scan Report for {self.target_url}</h1>
        <p>Generated: {datetime.now().isoformat()}</p>
        <p>Risk Level: <span class="risk">{risk}</span></p>
        <pre>{json.dumps(self.data, indent=2)}</pre></body></html>"""
        with open("anish_report_v13.html", "w") as f:
            f.write(html)
        print("[+] HTML report saved to anish_report_v13.html")

# ================= EXISTING MODULES (WebIntelligence, Fingerprinter, etc.) =================
# (These are kept from v12 but slightly modified to use rate_limiter properly)
class WebIntelligence:
    def __init__(self, domain, session, rate_limiter):
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
    async def analyze(self):
        for url in [f"https://{self.domain}", f"http://{self.domain}"]:
            await self.rate_limiter.acquire(self.domain)
            success = False
            try:
                async with self.session.get(url, timeout=5, allow_redirects=True, ssl=False) as resp:
                    html = await resp.text()
                    title = BeautifulSoup(html, 'html.parser').title.string.strip() if BeautifulSoup(html, 'html.parser').title else ""
                    server = resp.headers.get('Server', 'Unknown')
                    powered = resp.headers.get('X-Powered-By', '')
                    security = {
                        "csp": resp.headers.get('Content-Security-Policy', 'Missing'),
                        "hsts": resp.headers.get('Strict-Transport-Security', 'Missing'),
                        "xframe": resp.headers.get('X-Frame-Options', 'Missing'),
                        "xcontent": resp.headers.get('X-Content-Type-Options', 'Missing'),
                        "referrer": resp.headers.get('Referrer-Policy', 'Missing')
                    }
                    cookies = [{"name": c.key, "secure": c.secure, "http_only": c.httponly} for c in self.session.cookie_jar]
                    success = True
                    return {"url": str(resp.url), "status_code": resp.status, "title": title, "server": server,
                            "powered_by": powered, "security_headers": security, "cookies": cookies, "content_length": len(html), "html_snippet": html[:500]}
            except:
                pass
            finally:
                self.rate_limiter.release(self.domain, success=success)
        return {}

class Fingerprinter:
    def __init__(self, session, rate_limiter):
        self.session = session
        self.rate_limiter = rate_limiter
    async def detect_cms(self, html):
        if "wp-content" in html or "wp-includes" in html:
            return "WordPress"
        elif "Joomla" in html:
            return "Joomla"
        elif "Drupal" in html:
            return "Drupal"
        return None
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
            res = await resolver.query(domain, 'CNAME')
            if res:
                cname = str(res[0].target).lower()
                for cdn_domain, name in CDN_CNAMES.items():
                    if cdn_domain in cname:
                        return name
        except:
            pass
        await self.rate_limiter.acquire(domain)
        success = False
        try:
            async with self.session.get(f"http://{domain}", timeout=5) as resp:
                if 'CF-Cache-Status' in resp.headers:
                    return "Cloudflare"
                elif 'X-Akamai-Transformed' in resp.headers:
                    return "Akamai"
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(domain, success=success)
        return None
    async def detect_waf(self, domain):
        await self.rate_limiter.acquire(domain)
        success = False
        try:
            async with self.session.get(f"http://{domain}", timeout=5) as resp:
                text = await resp.text()
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if any(sig in k for k in resp.headers) or sig in text:
                            return waf
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(domain, success=success)
        return None

class SubdomainEnumerator:
    def __init__(self, domain, session, rate_limiter):
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(100)
    async def enumerate(self):
        subs = set()
        sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://dns.bufferover.run/dns?q=.{self.domain}",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        ]
        for url in sources:
            await self.rate_limiter.acquire(self.domain)
            success = False
            try:
                async with self.session.get(url, timeout=10) as resp:
                    if url.endswith('json'):
                        data = await resp.json()
                        if 'crt.sh' in url:
                            for entry in data:
                                name = entry.get('name_value')
                                if name:
                                    for n in name.split('\n'):
                                        n = n.lower().strip()
                                        if n.endswith(self.domain):
                                            subs.add(n)
                        elif 'bufferover' in url:
                            for item in data.get('FDNS_A', []):
                                if isinstance(item, list) and len(item) > 1:
                                    sub = item[1].lower()
                                    if sub.endswith(self.domain):
                                        subs.add(sub)
                    else:
                        text = await resp.text()
                        for line in text.splitlines():
                            if ',' in line:
                                sub = line.split(',')[0].lower()
                                if sub.endswith(self.domain):
                                    subs.add(sub)
                success = True
            except:
                pass
            finally:
                self.rate_limiter.release(self.domain, success=success)
        tasks = [self._check_subdomain(sub) for sub in SUBDOMAIN_WORDLIST[:2000]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for found in results:
            if found:
                subs.add(found)
        return list(subs)
    async def _check_subdomain(self, sub):
        async with self.semaphore:
            try:
                target = f"{sub}.{self.domain}"
                await self.resolver.gethostbyname(target, socket.AF_INET)
                return target
            except:
                return None

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
        tasks = [self._check_path(p, depth) for p in wordlist[:1500]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        found = []
        for res in results:
            if res:
                found.append(res)
                if self.max_depth > depth + 1:
                    deeper = await DirectoryEnumerator(res['url'], self.session, self.rate_limiter, self.max_depth).enumerate(wordlist, depth+1)
                    found.extend(deeper)
        return found
    async def _check_path(self, path, depth):
        url = urljoin(self.base_url, path)
        if url in self.visited:
            return None
        self.visited.add(url)
        await self.rate_limiter.acquire(self.base_url)
        success = False
        try:
            async with self.session.get(url, allow_redirects=False, timeout=5) as resp:
                if resp.status in (200, 403, 401):
                    return {"url": url, "status": resp.status, "depth": depth}
            return None
        except:
            return None
        finally:
            self.rate_limiter.release(self.base_url, success=success)

class VulnerabilityEngine:
    def __init__(self, session, rate_limiter):
        self.session = session
        self.rate_limiter = rate_limiter
    async def test_xss(self, url):
        # Baseline
        await self.rate_limiter.acquire(urlparse(url).netloc)
        success = False
        try:
            async with self.session.get(url, timeout=5) as resp:
                baseline = await resp.text()
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(urlparse(url).netloc, success=success)
        if not success:
            return None
        xss_url = urljoin(url, f"?test={XSS_PAYLOAD}")
        await self.rate_limiter.acquire(urlparse(url).netloc)
        success = False
        try:
            async with self.session.get(xss_url, timeout=5) as resp:
                injected = await resp.text()
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(urlparse(url).netloc, success=success)
        if not success:
            return None
        similarity = FalsePositiveReducer.compare_responses(baseline, injected)
        if XSS_PAYLOAD in injected and XSS_PAYLOAD not in baseline and similarity < 0.8:
            return {"type": "Reflected XSS", "url": xss_url, "severity": "High", "confidence": int(70 * (1 - similarity))}
        return None
    async def test_sqli(self, url):
        sqli_url = urljoin(url, f"?id={SQLI_PAYLOAD}")
        await self.rate_limiter.acquire(urlparse(url).netloc)
        success = False
        try:
            async with self.session.get(sqli_url, timeout=5) as resp:
                text = await resp.text()
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(urlparse(url).netloc, success=success)
        if not success:
            return None
        if FalsePositiveReducer.is_sql_error(text):
            return {"type": "SQL Injection (Error-based)", "url": sqli_url, "severity": "Critical", "confidence": 80}
        return None

class CVELookup:
    def __init__(self, session, rate_limiter):
        self.session = session
        self.rate_limiter = rate_limiter
        self.cache = {}
    async def lookup(self, service, version):
        if version == "Unknown":
            return []
        service_key = service.lower()
        vendor, product = SERVICE_CPE_MAP.get(service_key, (service_key, service_key))
        ver_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
        exact = ver_match.group(1) if ver_match else version
        cpe = f"cpe:2.3:a:{vendor}:{product}:{exact}"
        if cpe in self.cache:
            return self.cache[cpe]
        params = {"cpeName": cpe, "resultsPerPage": 10}
        await self.rate_limiter.acquire("nvd.nist.gov")
        success = False
        try:
            async with self.session.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    cves = []
                    for item in data.get('vulnerabilities', []):
                        cve = item['cve']
                        metrics = cve.get('metrics', {})
                        cvss = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                        if cvss >= 6.0:
                            cves.append({"id": cve['id'], "cvss": cvss, "description": cve['descriptions'][0]['value'][:200]})
                    self.cache[cpe] = cves
                    return cves
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release("nvd.nist.gov", success=success)
        return []

# ================= HELPER FUNCTIONS (External) =================
def get_geolocation(ip):
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data['status'] == 'success':
            return {"country": data.get("country"), "region": data.get("regionName"), "city": data.get("city"), "isp": data.get("isp")}
    except:
        pass
    return {"error": "Geolocation failed"}

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {"registrar": w.registrar, "creation_date": str(w.creation_date), "expiration_date": str(w.expiration_date)}
    except:
        return {"error": "WHOIS lookup failed"}

def get_dns_records(domain):
    records = {}
    for rtype in ['A', 'MX', 'TXT', 'CNAME', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except:
            records[rtype] = []
    return records

def get_ssl_certificate(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {"subject": dict(x[0] for x in cert['subject']), "issuer": dict(x[0] for x in cert['issuer']),
                        "notBefore": cert.get('notBefore'), "notAfter": cert.get('notAfter')}
    except Exception as e:
        return {"error": str(e)}

def print_banner():
    print(r"""
     █████╗ ███╗   ██╗██╗███████╗██╗  ██╗
    ██╔══██╗████╗  ██║██║██╔════╝██║  ██║
    ███████║██╔██╗ ██║██║███████╗███████║
    ██╔══██║██║╚██╗██║██║╚════██║██╔══██║
    ██║  ██║██║ ╚████║██║███████║██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝  ╚═╝

    Anish Security Scanner v13 – Enterprise Attack Surface Management
    Plugins | SQLite | Resumable | Distributed | Historical | Screenshots | AI
    Ethical Use Only
    """)

# ================= MAIN =================
async def main():
    parser = argparse.ArgumentParser(description="Anish Security Scanner v13")
    parser.add_argument("-t", "--target", required=True, help="Target URL or IP")
    parser.add_argument("--deep", action="store_true", help="Deep scan (aggressive ports, directory recursion)")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("--ai-key", type=str, help="OpenAI API key for AI correlation")
    parser.add_argument("--distributed", action="store_true", help="Enable distributed scanning (simulated)")
    args = parser.parse_args()
    target = args.target
    if not urlparse(target).scheme:
        target = "https://" + target
    scanner = AnishScannerV13(target, "deep" if args.deep else "normal", resume=args.resume, ai_key=args.ai_key, distributed=args.distributed)
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())
