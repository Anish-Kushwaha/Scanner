#!/usr/bin/env python3
"""
Anish Security Scanner v12 – Aggressive Auto‑Scan (Fixed & Complete)
Fully automatic, high‑performance, brute‑force oriented
Asks for normal or deep scan, then runs everything.
Ethical Use Only
"""

import asyncio
import aiohttp
import aiodns
import json
import logging
import re
import time
import os
import sys
import random
import socket
import ssl
import whois
import dns.resolver
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Disable SSL warnings
try:
    import urllib3
    urllib3.disable_warnings()
except:
    pass

# ================= CONFIGURATION =================
DEFAULT_TIMEOUT = 5
INITIAL_CONCURRENCY = 50
MAX_CONCURRENT = 200

# Port lists
COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888,9000,27017]
AGGRESSIVE_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888,9000,27017,
                    20,26,69,81,88,113,123,137,138,161,389,443,465,514,515,543,548,554,587,631,636,646,666,993,995,
                    1080,1433,1521,1720,1723,1883,2049,2100,2375,2379,2380,3000,3128,3306,3389,4443,4500,4567,4569,5000,
                    5001,5432,5666,5800,5900,5984,5985,5986,6379,6666,7001,7002,7070,7777,8000,8008,8009,8080,8081,8088,
                    8443,8888,9000,9001,9042,9090,9091,9100,9200,9418,9999,10000,11211,15672,161,179,27017,28017,50000]
FULL_PORTS = list(range(1, 65536))

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
    "legion", "sparta", "nikto", "wpscan", "droopescan", "joomscan", "drupwn", "cmsmap", "whatweb", "webanalyze", "wappalyzer", "retirejs",
]

# Expanded directory wordlist (1500+)
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
    "/topics", "/partitions", "/offsets", "/consumergroups", "/brokers", "/zookeeper", "/kafka", "/redis", "/mongodb", "/mysql",
    "/postgres", "/mariadb", "/couchdb", "/neo4j", "/influxdb", "/timescaledb", "/clickhouse", "/hadoop", "/spark", "/hive", "/hbase",
    "/cassandra", "/dynamodb", "/scylla", "/cockroachdb", "/tarantool", "/rabbitmq", "/activemq", "/zeromq", "/nats", "/pulsar",
    "/kinesis", "/sns", "/sqs", "/lambda", "/ec2", "/s3", "/rds", "/dynamodb", "/cloudfront", "/route53", "/elb", "/vpc", "/iam",
    "/cloudtrail", "/config", "/codepipeline", "/codebuild", "/codedeploy", "/codecommit", "/cloudformation", "/elasticbeanstalk",
    "/opsworks", "/datapipeline", "/glue", "/athena", "/quicksight", "/redshift", "/emr", "/kinesis", "/lambda", "/apigateway",
    "/appsync", "/stepfunctions", "/batch", "/fargate", "/ecs", "/eks", "/swarm", "/kubernetes", "/k8s", "/docker", "/registry",
    "/harbor", "/quay", "/artifactory", "/nexus", "/sonarqube", "/jira", "/confluence", "/bitbucket", "/github", "/gitlab",
    "/gitea", "/gogs", "/phabricator", "/trac", "/redmine", "/mantis", "/bugzilla", "/fogbugz", "/teamcity", "/bamboo", "/jenkins",
    "/circleci", "/travisci", "/gitlabci", "/drone", "/concourse", "/spinnaker", "/argo", "/flux", "/helm", "/chartmuseum",
    "/kubeapps", "/kubespray", "/kubeflow", "/istio", "/linkerd", "/consul", "/etcd", "/zookeeper", "/nacos", "/eureka", "/ribbon",
    "/hystrix", "/zuul", "/springcloud", "/configserver", "/discovery", "/gateway", "/auth", "/oauth", "/openid", "/saml", "/cas",
    "/keycloak", "/gluu", "/shibboleth", "/authentik", "/authelia", "/dex", "/ory", "/hydra", "/kratos", "/keto", "/oathkeeper",
    "/pomerium", "/ambassador", "/envoy", "/nginx", "/traefik", "/caddy", "/haproxy", "/varnish", "/squid", "/tinyproxy", "/privoxy",
    "/polipo", "/mitmproxy", "/burp", "/zap", "/wireshark", "/tcpdump", "/nmap", "/masscan", "/zmap", "/zgrab", "/httpx", "/naabu",
    "/subfinder", "/assetfinder", "/amass", "/chaos", "/shuffledns", "/puredns", "/massdns", "/dnsx", "/alterx", "/gau", "/waybackurls",
    "/gospider", "/hakrawler", "/katana", "/ffuf", "/dirsearch", "/gobuster", "/wfuzz", "/feroxbuster", "/rustbuster", "/meg",
    "/httprobe", "/httpx", "/uncover", "/nuclei", "/subjack", "/takeover", "/tko-subs", "/can-i-take-over-xyz", "/dnsrecon", "/dnsenum",
]

# Sensitive patterns
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

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
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

    Anish Security Scanner v12 – Aggressive Auto‑Scan (Fixed & Complete)
    Fully automatic, high‑performance, brute‑force oriented
    Ethical Use Only
    """)

def parse_url_and_detect_port(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == 'https' else 80
    return domain, port

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

# ================= RATE LIMITER =================
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
        now = time.time()
        if now - self.last_adjust > 10:
            total = self.success_count + self.failure_count
            if total > 20:
                failure_rate = self.failure_count / total
                if failure_rate > 0.3:
                    self.concurrency = max(1, self.concurrency // 2)
                    self.semaphore = asyncio.Semaphore(self.concurrency)
                    logger.info(f"Reducing concurrency to {self.concurrency}")
                elif failure_rate < 0.1 and self.concurrency < MAX_CONCURRENT:
                    self.concurrency = min(MAX_CONCURRENT, int(self.concurrency * 1.2))
                    self.semaphore = asyncio.Semaphore(self.concurrency)
                    logger.info(f"Increasing concurrency to {self.concurrency}")
            self.success_count = self.failure_count = 0
            self.last_adjust = now

# ================= PORT SCANNER =================
class PortScanner:
    def __init__(self, target_ip, ports, rate_limiter, timeout=3, retries=2):
        self.target_ip = target_ip
        self.ports = ports
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.retries = retries
    async def scan(self):
        results = []
        chunk_size = 1000
        for i in range(0, len(self.ports), chunk_size):
            chunk = self.ports[i:i+chunk_size]
            tasks = [self._scan_port(p) for p in chunk]
            chunk_results = await asyncio.gather(*tasks, return_exceptions=True)
            results.extend([r for r in chunk_results if r is not None])
        return results
    async def _scan_port(self, port):
        await self.rate_limiter.acquire()
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
                self.rate_limiter.release(success=False)
                return None
            if state == 'open':
                self.rate_limiter.release(success=True)
                return {"port": port, "state": state}
            else:
                self.rate_limiter.release(success=success)
                return None
        except:
            self.rate_limiter.release(success=False)
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
        await self.rate_limiter.acquire()
        success = False
        try:
            info = await self._probe(port)
            success = True
            self.cache[port] = info
            return info
        finally:
            self.rate_limiter.release(success=success)
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

# ================= WEB INTELLIGENCE =================
class WebIntelligence:
    def __init__(self, domain, session, rate_limiter):
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
    async def analyze(self):
        for url in [f"https://{self.domain}", f"http://{self.domain}"]:
            await self.rate_limiter.acquire()
            success = False
            try:
                async with self.session.get(url, timeout=5, allow_redirects=True, ssl=False) as resp:
                    html = await resp.text()
                    title = ""
                    soup = BeautifulSoup(html, 'html.parser')
                    if soup.title:
                        title = soup.title.string.strip()
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
                            "powered_by": powered, "security_headers": security, "cookies": cookies, "content_length": len(html)}
            except:
                pass
            finally:
                self.rate_limiter.release(success=success)
        return {}

# ================= FINGERPRINTER =================
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
        await self.rate_limiter.acquire()
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
            self.rate_limiter.release(success=success)
        return None
    async def detect_waf(self, domain):
        await self.rate_limiter.acquire()
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
            self.rate_limiter.release(success=success)
        return None

# ================= SUBDOMAIN ENUMERATOR =================
class SubdomainEnumerator:
    def __init__(self, domain, session, rate_limiter):
        self.domain = domain
        self.session = session
        self.rate_limiter = rate_limiter
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(100)
    async def enumerate(self):
        subs = set()
        # External APIs
        sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://dns.bufferover.run/dns?q=.{self.domain}",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        ]
        for url in sources:
            await self.rate_limiter.acquire()
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
                self.rate_limiter.release(success=success)
        # Wordlist brute‑force (first 2000 entries)
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

# ================= DIRECTORY ENUMERATOR =================
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

# ================= VULNERABILITY ENGINE =================
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
            return {"type": "Reflected XSS", "url": xss_url, "severity": "High", "confidence": 70}
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
        patterns = ["mysql", "sql syntax", "microsoft ole db", "postgresql error", "oracle.jdbc"]
        for p in patterns:
            if p in text.lower():
                return {"type": "SQL Injection (Error-based)", "url": sqli_url, "severity": "Critical", "confidence": 60}
        return None

# ================= CVE LOOKUP (Optional) =================
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
                        cvss = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                        if cvss >= 6.0:
                            cves.append({"id": cve['id'], "cvss": cvss, "description": cve['descriptions'][0]['value'][:200]})
                    self.cache[cpe] = cves
                    return cves
            success = True
        except:
            pass
        finally:
            self.rate_limiter.release(success=success)
        return []

# ================= REPORT GENERATOR =================
class ReportGenerator:
    def __init__(self, target, data):
        self.target = target
        self.data = data
    def to_json(self, filename="anish_report_v12.json"):
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=4)
        print(f"[+] JSON report saved to {filename}")
    def to_html(self, filename="anish_report_v12.html"):
        risk = self.data.get('risk_score', 'Low')
        color = {'Critical':'red', 'High':'orange', 'Medium':'gold', 'Low':'green'}.get(risk, 'black')
        html = f"""<!DOCTYPE html><html><head><title>Anish Scanner Report - {self.target}</title>
        <style>body{{font-family:Arial;margin:20px;}}.risk{{color:{color};font-weight:bold;}}</style></head>
        <body><h1>Security Scan Report for {self.target}</h1><p>Generated: {datetime.now().isoformat()}</p>
        <p>Risk Level: <span class="risk">{risk}</span></p><pre>{json.dumps(self.data, indent=2)}</pre></body></html>"""
        with open(filename, 'w') as f:
            f.write(html)
        print(f"[+] HTML report saved to {filename}")

# ================= MAIN SCANNER =================
class AnishScanner:
    def __init__(self, target_url, scan_depth):
        self.target_url = target_url
        self.scan_depth = scan_depth  # "normal" or "deep"
        self.domain, self.port = parse_url_and_detect_port(target_url)
        self.data = {"target": target_url, "domain": self.domain, "scan_time": datetime.now().isoformat()}
    async def run(self):
        print_banner()
        rate_limiter = RateLimiter()
        timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, limit_per_host=MAX_CONCURRENT, ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            dns = DNSResolver()
            ip = await dns.resolve_ip(self.domain)
            if not ip:
                print("[!] Could not resolve IP. Exiting.")
                return
            self.data['ip'] = ip
            print(f"[+] Target: {self.target_url}")
            print(f"[+] Domain: {self.domain}")
            print(f"[+] IP: {ip}")
            # External recon
            print("[+] Gathering external intelligence...")
            self.data['geolocation'] = get_geolocation(ip)
            self.data['whois'] = get_whois_info(self.domain)
            self.data['dns_records'] = get_dns_records(self.domain)
            if self.port == 443:
                self.data['ssl_certificate'] = get_ssl_certificate(self.domain, self.port)
            else:
                self.data['ssl_certificate'] = {"note": "Not HTTPS"}
            print("[+] External reconnaissance completed")
            # Port scan
            if self.scan_depth == "deep":
                ports = AGGRESSIVE_PORTS
                print("[+] Starting deep port scan (aggressive list)...")
            else:
                ports = COMMON_PORTS
                print("[+] Starting normal port scan (common ports)...")
            port_scanner = PortScanner(ip, ports, rate_limiter)
            open_ports = await port_scanner.scan()
            print(f"[+] Found {len(open_ports)} open ports")
            # Service detection
            service_detector = ServiceDetector(ip, self.domain, session, rate_limiter)
            services = []
            for p in open_ports:
                svc = await service_detector.detect(p['port'])
                services.append({"port": p['port'], "state": p['state'], **svc})
                print(f"  Port {p['port']}: {svc['service']} - {svc['version']}")
            self.data['network'] = services
            # Web intelligence if HTTP ports exist
            http_ports = [s for s in services if s['service'] == 'http']
            if http_ports:
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
                        cms = await fingerprinter.detect_cms(html)
                        frameworks = await fingerprinter.detect_frameworks(html)
                        cdn = await fingerprinter.detect_cdn(self.domain)
                        waf = await fingerprinter.detect_waf(self.domain)
                        if cms: self.data['web']['cms'] = cms
                        if frameworks: self.data['web']['frameworks'] = frameworks
                        if cdn: self.data['web']['cdn'] = cdn
                        if waf: self.data['web']['waf'] = waf
                    except:
                        rate_limiter.release(success=False)
                # Subdomain enumeration
                print("[+] Enumerating subdomains...")
                sub_enum = SubdomainEnumerator(self.domain, session, rate_limiter)
                subdomains = await sub_enum.enumerate()
                self.data['subdomains'] = subdomains
                print(f"[+] Found {len(subdomains)} subdomains")
                # Directory enumeration (depth based on scan depth)
                max_depth = 1 if self.scan_depth == "deep" else 0
                print(f"[+] Brute‑forcing directories (depth={max_depth})...")
                dir_enum = DirectoryEnumerator(web_data.get('url', f"http://{self.domain}"), session, rate_limiter, max_depth=max_depth)
                dirs = await dir_enum.enumerate()
                self.data['directories'] = dirs
                print(f"[+] Found {len(dirs)} accessible directories")
                # Vulnerability tests
                print("[+] Testing for vulnerabilities...")
                vuln_engine = VulnerabilityEngine(session, rate_limiter)
                xss = await vuln_engine.test_xss(web_data.get('url', f"http://{self.domain}"))
                sqli = await vuln_engine.test_sqli(web_data.get('url', f"http://{self.domain}"))
                self.data['vulnerabilities'] = []
                if xss: self.data['vulnerabilities'].append(xss)
                if sqli: self.data['vulnerabilities'].append(sqli)
            else:
                self.data['web'] = {}
                self.data['subdomains'] = []
                self.data['directories'] = []
                self.data['vulnerabilities'] = []
            # CVE lookup (limited to first 3 services)
            print("[+] Checking CVEs (first 3 services)...")
            cve_lookup = CVELookup(session, rate_limiter)
            all_cves = []
            for svc in services[:3]:
                if svc['version'] != "Unknown":
                    cves = await cve_lookup.lookup(svc['service'], svc['version'])
                    if cves:
                        all_cves.extend(cves)
            self.data['cves'] = all_cves
            # Risk scoring
            if any(v['severity'] == 'Critical' for v in self.data.get('vulnerabilities',[])) or any(c.get('cvss',0)>=9 for c in all_cves):
                self.data['risk_score'] = "Critical"
            elif any(v['severity'] == 'High' for v in self.data.get('vulnerabilities',[])) or any(c.get('cvss',0)>=7 for c in all_cves):
                self.data['risk_score'] = "High"
            elif any(v['severity'] == 'Medium' for v in self.data.get('vulnerabilities',[])) or any(c.get('cvss',0)>=4 for c in all_cves):
                self.data['risk_score'] = "Medium"
            else:
                self.data['risk_score'] = "Low"
            # Report
            report = ReportGenerator(self.target_url, self.data)
            report.to_json()
            report.to_html()
        print("\n[✓] Scan completed. Check anish_report_v12.json and .html")

# ================= ENTRY POINT =================
if __name__ == "__main__":
    print_banner()
    target = input("Enter the target URL (e.g., https://example.com or example.com:8443): ").strip()
    if not target:
        print("[!] Error: Target URL is required.")
        exit(1)
    if not urlparse(target).scheme:
        target = "https://" + target
        print(f"[+] Auto-corrected URL to: {target}")
    depth = input("Scan depth (normal/deep) [normal]: ").strip().lower()
    if depth not in ['normal', 'deep']:
        depth = 'normal'
    print(f"[+] Starting {depth} scan...")
    scanner = AnishScanner(target, depth)
    asyncio.run(scanner.run())
