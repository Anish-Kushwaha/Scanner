#!/usr/bin/env python3
"""
Scanner Platform Engine
A scoped, authorization-gated network and web security assessment worker.

This engine performs bounded discovery and non-destructive configuration checks.
It does not exploit vulnerabilities, brute-force credentials, evade controls, or
run arbitrary user-supplied scanner arguments.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html.parser
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


VERSION = "5.0.0"
USER_AGENT = f"Anish-Scanner/{VERSION} (+authorized-security-assessment)"
MAX_TARGETS = 256
MAX_HTTP_BODY = 512_000
MAX_CRAWL_PAGES = 30
MAX_CRAWL_DEPTH = 2
HTTP_TIMEOUT = 8
NMAP_TIMEOUT = 360
SAFE_PATHS = (
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/openapi.json", "/swagger.json", "/api-docs",
)


class ScopeError(ValueError):
    pass


class ToolError(RuntimeError):
    pass


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    category: str
    asset: str
    description: str
    evidence: str
    remediation: str
    status: str = "new"
    cve: str | None = None


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_allowlist() -> tuple[set[str], list[ipaddress._BaseNetwork]]:
    raw = os.environ.get("SCANNER_ALLOWED_TARGETS", "")
    hosts: set[str] = set()
    networks: list[ipaddress._BaseNetwork] = []
    for entry in raw.split(","):
        item = entry.strip().lower()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            host = item.rstrip(".")
            if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9.-]+", host):
                raise ScopeError(f"Invalid entry in SCANNER_ALLOWED_TARGETS: {item}")
            hosts.add(host)
    if not hosts and not networks:
        raise ScopeError(
            "No authorized scope configured. Set SCANNER_ALLOWED_TARGETS to exact "
            "hostnames, IP addresses, or explicitly authorized CIDRs."
        )
    return hosts, networks


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw or len(raw) > 2048 or any(ord(c) < 33 for c in raw):
        raise ScopeError("Target is empty, too long, or contains control characters.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Only valid HTTP(S) URLs or hostnames are accepted.")
    if parsed.username or parsed.password:
        raise ScopeError("Credentials embedded in URLs are not accepted.")
    if parsed.port not in (None, 80, 443):
        raise ScopeError("Web checks use standard ports 80 and 443 only.")
    host = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeError("Invalid internationalized hostname.") from exc
    return urllib.parse.urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", ""))


def is_in_scope(host: str, allow_hosts: set[str], networks: list[ipaddress._BaseNetwork]) -> bool:
    normalized = host.rstrip(".").lower()
    if normalized in allow_hosts:
        return True
    try:
        address = ipaddress.ip_address(normalized)
        return any(address.version == n.version and address in n for n in networks)
    except ValueError:
        return False


def resolve_target(host: str, allow_hosts: set[str], networks: list[ipaddress._BaseNetwork]) -> list[str]:
    if not is_in_scope(host, allow_hosts, networks):
        raise ScopeError(f"{host} is not explicitly present in the authorized target allowlist.")
    try:
        literal = ipaddress.ip_address(host)
        return [str(literal)]
    except ValueError:
        try:
            answers = sorted({row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
        except socket.gaierror as exc:
            raise ToolError(f"DNS resolution failed for {host}: {exc}") from exc
        if not answers:
            raise ToolError(f"No DNS answers found for {host}.")
        if networks:
            # A hostname explicitly allowlisted by name remains in scope; a CIDR-only
            # authorization must also contain every resolved address.
            if host not in allow_hosts and any(
                not any(ipaddress.ip_address(a) in n for n in networks if ipaddress.ip_address(a).version == n.version)
                for a in answers
            ):
                raise ScopeError("At least one resolved address falls outside the authorized CIDR scope.")
        return answers


def add_finding(findings: list[Finding], title: str, severity: str, confidence: str,
                category: str, asset: str, description: str, evidence: str, remediation: str,
                cve: str | None = None) -> None:
    key = f"{title}|{asset}|{evidence}"
    fid = str(uuid.uuid5(uuid.NAMESPACE_URL, key))
    if not any(x.id == fid for x in findings):
        findings.append(Finding(fid, title, severity, confidence, category, asset,
                                description, evidence[:1200], remediation, cve=cve))


class SameOriginCrawler(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, str]] = []
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"][:2048])
        if tag == "form":
            self.forms.append({"method": (a.get("method") or "GET").upper(),
                               "action": (a.get("action") or "").split("?", 1)[0][:512]})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_http_get(url: str, origin: tuple[str, str]) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme, parsed.netloc.lower()) != origin:
        raise ScopeError("Crawler blocked a cross-origin request.")
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json,*/*;q=0.2"})
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT) as response:
            body = response.read(MAX_HTTP_BODY + 1)
            return {"status": response.status, "headers": {k.lower(): v for k, v in response.headers.items()},
                    "body": body[:MAX_HTTP_BODY], "truncated": len(body) > MAX_HTTP_BODY, "url": url}
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location")
        return {"status": exc.code, "headers": {k.lower(): v for k, v in exc.headers.items()},
                "body": b"", "truncated": False, "url": url, "location": location}
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        return {"status": None, "headers": {}, "body": b"", "truncated": False,
                "url": url, "error": str(exc)[:300]}


def inspect_tls(host: str, port: int = 443) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname=host) as sock:
            cert = sock.getpeercert()
            expiry = cert.get("notAfter")
            days = None
            if expiry:
                days = (ssl.cert_time_to_seconds(expiry) - time.time()) / 86400
            return {"verified": True, "version": sock.version(), "cipher": sock.cipher(),
                    "subject": cert.get("subject"), "issuer": cert.get("issuer"),
                    "expires": expiry, "days_remaining": round(days, 1) if days is not None else None}


def web_assessment(target: str, findings: list[Finding]) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(target)
    host = parsed.hostname or ""
    origin = (parsed.scheme, parsed.netloc.lower())
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/", "", ""))
    first = safe_http_get(target, origin)
    if first["status"] is None:
        return {"target": target, "error": first.get("error"), "pages_checked": 0}
    headers = first["headers"]
    checks = {
        "content-security-policy": ("Missing Content-Security-Policy", "MEDIUM", "Define a restrictive CSP and validate it in report-only mode before enforcement."),
        "x-content-type-options": ("Missing X-Content-Type-Options", "LOW", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("Missing Referrer-Policy", "LOW", "Set a privacy-conscious Referrer-Policy."),
        "permissions-policy": ("Missing Permissions-Policy", "LOW", "Explicitly disable browser capabilities the application does not use."),
    }
    for header, (title, severity, fix) in checks.items():
        if not headers.get(header):
            add_finding(findings, title, severity, "HIGH", "web-configuration", host,
                        f"The response does not include {header}.", f"HTTP {first['status']}; header absent.", fix)
    if parsed.scheme == "https" and not headers.get("strict-transport-security"):
        add_finding(findings, "Missing HSTS", "MEDIUM", "HIGH", "tls-configuration", host,
                    "HTTPS response did not advertise HSTS.",
                    "Strict-Transport-Security header absent.", "After confirming HTTPS across subdomains, configure an appropriate HSTS policy.")
    if not headers.get("x-frame-options") and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
        add_finding(findings, "Missing clickjacking protection", "MEDIUM", "MEDIUM", "web-configuration", host,
                    "Neither X-Frame-Options nor CSP frame-ancestors was detected.",
                    "No frame embedding policy found.", "Set CSP frame-ancestors and/or X-Frame-Options.")
    if headers.get("server"):
        add_finding(findings, "Server banner disclosed", "INFO", "HIGH", "information-disclosure", host,
                    "The HTTP response exposes a server banner.",
                    f"Server: {headers['server'][:160]}", "Consider minimizing unnecessary version and platform disclosure.")
    cookies = []
    # urllib exposes Set-Cookie as separate header objects; values are never recorded.
    for cookie in first.get("headers", {}).get("set-cookie", "").split("\n"):
        if not cookie.strip():
            continue
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=", 1)[0][:80]
        flags = {p.split("=", 1)[0].lower() for p in parts[1:]}
        sessionish = bool(re.search(r"(session|auth|token|sid)", name, re.I))
        if parsed.scheme == "https" and "secure" not in flags:
            add_finding(findings, "Cookie missing Secure flag", "MEDIUM" if sessionish else "LOW", "HIGH",
                        "cookie-security", host, "A cookie lacks the Secure attribute.", f"Cookie name: {name}; value redacted.",
                        "Set Secure on cookies delivered over HTTPS.")
        if sessionish and "httponly" not in flags:
            add_finding(findings, "Session cookie missing HttpOnly", "MEDIUM", "HIGH", "cookie-security",
                        host, "A session-like cookie lacks HttpOnly.", f"Cookie name: {name}; value redacted.",
                        "Set HttpOnly on session and authentication cookies.")
        if "samesite" not in flags:
            add_finding(findings, "Cookie missing SameSite", "LOW", "MEDIUM", "cookie-security",
                        host, "A cookie does not specify SameSite.", f"Cookie name: {name}; value redacted.",
                        "Set an appropriate SameSite policy, usually Lax or Strict.")
        cookies.append({"name": name, "secure": "secure" in flags, "httponly": "httponly" in flags,
                        "samesite": next((p.split("=",1)[1] for p in parts[1:] if p.lower().startswith("samesite=")), None)})
    tls = None
    if parsed.scheme == "https":
        try:
            tls = inspect_tls(host, parsed.port or 443)
            if tls.get("days_remaining") is not None and tls["days_remaining"] < 21:
                add_finding(findings, "TLS certificate expiring soon", "MEDIUM", "HIGH", "tls-configuration",
                            host, "The certificate expires in fewer than 21 days.",
                            f"Days remaining: {tls['days_remaining']}", "Renew the certificate and verify automated renewal.")
            if tls.get("version") in {"TLSv1", "TLSv1.1"}:
                add_finding(findings, "Obsolete TLS protocol negotiated", "HIGH", "HIGH", "tls-configuration",
                            host, "The server negotiated an obsolete TLS protocol.", str(tls.get("version")),
                            "Disable TLS 1.0/1.1 and require TLS 1.2 or newer.")
        except (OSError, ssl.SSLError) as exc:
            tls = {"error": str(exc)[:300]}
    pages: list[dict[str, Any]] = []
    queue: list[tuple[str, int]] = [(target, 0)]
    visited: set[str] = set()
    discovered: set[str] = set()
    while queue and len(visited) < MAX_CRAWL_PAGES:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        result = first if url == target else safe_http_get(url, origin)
        pages.append({"url": url, "status": result.get("status"), "content_type": result.get("headers", {}).get("content-type")})
        if depth >= MAX_CRAWL_DEPTH or not result.get("body"):
            continue
        if "html" not in result.get("headers", {}).get("content-type", "").lower():
            continue
        parser = SameOriginCrawler()
        try:
            parser.feed(result["body"].decode("utf-8", errors="replace"))
        except Exception:
            continue
        for href in parser.links:
            absolute = urllib.parse.urljoin(url, href)
            p = urllib.parse.urlsplit(absolute)
            candidate = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))
            if (p.scheme, p.netloc.lower()) == origin and candidate not in visited and candidate not in discovered:
                if p.path and not re.search(r"/(logout|signout|delete|remove)(/|$)", p.path, re.I):
                    discovered.add(candidate)
                    if len(discovered) + len(visited) < MAX_CRAWL_PAGES:
                        queue.append((candidate, depth + 1))
        for form in parser.forms:
            pages[-1].setdefault("forms", []).append(form)
            if form["method"] not in {"GET", "POST"}:
                add_finding(findings, "Unusual form method", "LOW", "MEDIUM", "web-application",
                            host, "A form advertises an uncommon HTTP method.", form["method"],
                            "Review whether the method is required and enforce authorization server-side.")
    safe_resources = {}
    for path in SAFE_PATHS:
        url = urllib.parse.urljoin(base, path.lstrip("/"))
        resource = safe_http_get(url, origin)
        safe_resources[path] = {"status": resource.get("status"), "content_type": resource.get("headers", {}).get("content-type")}
    return {"target": target, "status": first["status"], "headers": headers, "cookies": cookies,
            "tls": tls, "pages_checked": len(pages), "pages": pages, "safe_resources": safe_resources,
            "technologies": {"server": headers.get("server"), "powered_by": headers.get("x-powered-by")},
            "http_methods_tested": ["GET"], "active_payloads_sent": False}


def run_nmap(target: str, addresses: list[str], profile: str, os_detect: bool, udp: bool) -> dict[str, Any]:
    binary = shutil.which("nmap")
    if not binary:
        return {"available": False, "status": "not_installed",
                "note": "Install Nmap on the worker to enable network discovery and service detection."}
    args = [binary, "-n", "-sT", "-sV", "--version-light", "--top-ports",
            "100" if profile == "passive" else "1000", "-T3", "--max-retries", "2",
            "--host-timeout", "5m", "-oX", "-"]
    if os_detect:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise ToolError("OS detection requires elevated worker privileges; rerun with --os-detect as root.")
        args.extend(["-O", "--osscan-limit"])
    if udp:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise ToolError("UDP scanning requires elevated worker privileges.")
        args.extend(["-sU", "--top-ports", "20"])
    # Resolve and validate before Nmap; use the exact hostname so virtual hosting and
    # service probes retain host context, while the allowlist is checked above.
    args.append(target)
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=NMAP_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ToolError("Nmap exceeded the configured six-minute scan timeout.") from exc
    if proc.returncode not in (0, 1):
        raise ToolError(f"Nmap failed: {proc.stderr[-1200:]}")
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(proc.stdout)
    except Exception as exc:
        raise ToolError("Nmap returned invalid XML output.") from exc
    hosts = []
    for node in root.findall("host"):
        addresses_found = [{"type": x.get("addrtype"), "address": x.get("addr")} for x in node.findall("address")]
        ports = []
        for port in node.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            ports.append({"protocol": port.get("protocol"), "port": int(port.get("portid")),
                          "state": state.get("state") if state is not None else "unknown",
                          "reason": state.get("reason") if state is not None else None,
                          "service": service.get("name") if service is not None else None,
                          "product": service.get("product") if service is not None else None,
                          "version": service.get("version") if service is not None else None,
                          "tunnel": service.get("tunnel") if service is not None else None})
        osmatch = node.find("./os/osmatch")
        hosts.append({"addresses": addresses_found, "status": (node.find("status").get("state") if node.find("status") is not None else "unknown"),
                      "hostname": (node.find("./hostnames/hostname").get("name") if node.find("./hostnames/hostname") is not None else None),
                      "os_guess": osmatch.get("name") if osmatch is not None else None, "ports": ports})
    return {"available": True, "status": "completed", "engine": "Nmap",
            "arguments_profile": profile, "addresses_resolved": addresses,
            "hosts": hosts, "host_count": len(hosts),
            "open_ports_count": sum(1 for h in hosts for p in h["ports"] if p["state"] == "open"),
            "nse_scripts": "not_run", "note": "No exploit or brute-force NSE scripts were executed."}


def run_zap_baseline(target: str, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"status": "not_requested"}
    docker = shutil.which("docker")
    if not docker:
        return {"status": "not_installed", "note": "Docker is required for the optional OWASP ZAP baseline integration."}
    # ZAP baseline is passive-first: spider plus passive rules; no active attack scan.
    command = [docker, "run", "--rm", "ghcr.io/zaproxy/zaproxy:stable",
               "zap-baseline.py", "-t", target, "-m", "2", "-T", "5", "-I", "-J", "/dev/stdout"]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    return {"status": "completed" if proc.returncode in (0, 1, 2) else "error",
            "exit_code": proc.returncode, "summary": (proc.stdout + proc.stderr)[-6000:],
            "mode": "baseline-passive", "active_attack_scan": False}


def assess_local_path(path: str | None, findings: list[Finding]) -> dict[str, Any]:
    if not path:
        return {"status": "not_requested"}
    root = Path(path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ToolError("--local-path must point to an existing directory.")
    checked = 0
    config_findings = []
    patterns = [
        (re.compile(r"(?i)^\s*privileged\s*:\s*true"), "Privileged container enabled", "HIGH",
         "Avoid privileged containers; grant only the capabilities required."),
        (re.compile(r"(?i)^\s*hostNetwork\s*:\s*true"), "Kubernetes host networking enabled", "MEDIUM",
         "Avoid host networking unless operationally required."),
        (re.compile(r"(?i)^\s*runAsUser\s*:\s*0"), "Kubernetes workload runs as root", "MEDIUM",
         "Use a dedicated non-root user and enforce runAsNonRoot."),
        (re.compile(r"(?i)^\s*allowPrivilegeEscalation\s*:\s*true"), "Privilege escalation allowed", "MEDIUM",
         "Set allowPrivilegeEscalation: false."),
        (re.compile(r"(?i)^\s*readOnlyRootFilesystem\s*:\s*false"), "Writable container root filesystem", "LOW",
         "Prefer readOnlyRootFilesystem: true where practical."),
    ]
    secret_patterns = [
        re.compile(r"""(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['"]?([A-Za-z0-9_./+=-]{12,})""")
    ]
    for file in root.rglob("*"):
        if not file.is_file() or file.is_symlink() or any(p in file.parts for p in (".git", "node_modules", ".venv", "venv")):
            continue
        if file.suffix.lower() not in {".yaml", ".yml", ".json", ".tf", ".env", ".toml", ".conf", ".dockerfile"} and file.name not in {"Dockerfile", ".env"}:
            continue
        try:
            if file.stat().st_size > 1_000_000:
                continue
            lines = file.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            checked += 1
            for pattern, title, severity, fix in patterns:
                if pattern.search(line):
                    add_finding(findings, title, severity, "MEDIUM", "local-configuration",
                                str(file.relative_to(root)), "A potentially unsafe infrastructure setting was found.",
                                f"Line {number}; value: {line.strip()[:100]}", fix)
            if any(p.search(line) for p in secret_patterns):
                add_finding(findings, "Potential hard-coded secret", "HIGH", "LOW", "secret-hygiene",
                            str(file.relative_to(root)), "A line resembles a hard-coded credential; value is redacted.",
                            f"Line {number}; secret value redacted.", "Move the secret to a managed secret store and rotate it.")
    trivy = shutil.which("trivy")
    trivy_result = {"status": "not_installed"}
    if trivy:
        proc = subprocess.run([trivy, "fs", "--scanners", "vuln,misconfig,secret", "--format", "json", str(root)],
                              capture_output=True, text=True, timeout=600, check=False)
        trivy_result = {"status": "completed" if proc.returncode == 0 else "completed_with_findings",
                        "exit_code": proc.returncode, "json": proc.stdout[:100000]}
    return {"status": "completed", "files_lines_checked": checked, "trivy": trivy_result}


def score_findings(findings: list[Finding]) -> dict[str, Any]:
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    counts = {key: sum(1 for f in findings if f.severity == key) for key in weights}
    penalty = min(100, sum(weights[f.severity] for f in findings))
    return {"risk_level": ("CRITICAL" if counts["CRITICAL"] else "HIGH" if counts["HIGH"] else
                           "MEDIUM" if counts["MEDIUM"] else "LOW" if counts["LOW"] else "INFO"),
            "score": max(0, 100 - penalty), "severity_counts": counts,
            "total_findings": len(findings),
            "scoring_note": "Heuristic prioritization score, not a formal CVSS score."}


def export_csv(report: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(Finding("", "", "", "", "", "", "", "", "")).keys()))
        writer.writeheader()
        for item in report.get("findings", []):
            writer.writerow(item)


def main() -> int:
    parser = argparse.ArgumentParser(description="Private, scope-enforced Scanner assessment worker")
    parser.add_argument("target", help="Authorized hostname, IP, or HTTP(S) URL")
    parser.add_argument("--profile", choices=("passive", "standard", "advanced"), default="standard")
    parser.add_argument("--authorized", action="store_true", help="Attest that you have written permission to assess this target")
    parser.add_argument("--os-detect", action="store_true", help="Optional Nmap OS fingerprinting (requires root)")
    parser.add_argument("--udp", action="store_true", help="Optional top-20 UDP scan (requires root)")
    parser.add_argument("--zap-baseline", action="store_true", help="Run optional passive OWASP ZAP baseline via Docker")
    parser.add_argument("--local-path", help="Assess a local source/configuration directory with safe checks and Trivy if installed")
    parser.add_argument("--output", default="scanner-report.json")
    args = parser.parse_args()
    if not args.authorized:
        parser.error("You must pass --authorized after obtaining permission from the system owner.")
    started = time.monotonic()
    try:
        allow_hosts, networks = load_allowlist()
        raw_target = args.target.strip()
        try:
            network = ipaddress.ip_network(raw_target, strict=False)
        except ValueError:
            network = None
        if network is not None:
            if network.num_addresses > MAX_TARGETS:
                raise ScopeError(f"Network exceeds the {MAX_TARGETS}-address cap.")
            if not any(network.subnet_of(n) for n in networks if n.version == network.version):
                raise ScopeError("CIDR must be contained in an explicitly authorized allowlist network.")
            target = str(network)
            host = str(network.network_address)
            addresses = [str(ip) for ip in network.hosts()]
            parsed = None
        else:
            target = normalize_target(raw_target)
            parsed = urllib.parse.urlsplit(target)
            host = parsed.hostname or ""
            addresses = resolve_target(host, allow_hosts, networks)
        findings: list[Finding] = []
        web = web_assessment(target, findings) if parsed and parsed.scheme in {"http", "https"} else {}
        nmap = run_nmap(target if network is not None else host, addresses, args.profile, args.os_detect, args.udp)
        zap = run_zap_baseline(target, args.zap_baseline)
        local = assess_local_path(args.local_path, findings)
        elapsed = round((time.monotonic() - started) * 1000)
        report = {
            "schema_version": "1.0", "scanner_version": VERSION, "scan_id": str(uuid.uuid4()),
            "generated_at": utc_now(), "target": target, "profile": args.profile,
            "authorization": {"attested": True, "scope_allowlist_enforced": True},
            "duration_ms": elapsed, "network": nmap, "web": web, "zap": zap, "local_assessment": local,
            "findings": [asdict(f) for f in findings], "summary": score_findings(findings),
            "capabilities": {
                "network_discovery": nmap.get("status") == "completed",
                "tcp_port_scan": nmap.get("status") == "completed",
                "service_version_detection": nmap.get("status") == "completed",
                "os_fingerprinting": bool(args.os_detect),
                "udp_scan": bool(args.udp),
                "web_crawling": bool(web.get("pages_checked")),
                "tls_assessment": bool(web.get("tls")),
                "http_security_headers": bool(web.get("headers")),
                "cookie_security": bool(web.get("cookies")),
                "api_documentation_discovery": bool(web.get("safe_resources")),
                "zap_passive_baseline": zap.get("status") in {"completed", "error"},
                "local_config_and_secret_checks": local.get("status") == "completed",
                "trivy": local.get("trivy", {}).get("status", "not_requested"),
                "active_exploitation": False, "credential_bruteforce": False,
                "destructive_tests": False, "unbounded_subdomain_bruteforce": False,
            },
            "limitations": [
                "No exploit execution, credential attacks, persistence, evasion, or denial-of-service tests.",
                "Nmap NSE scripts are not run; version fingerprints do not prove a CVE is exploitable.",
                "CVE correlation requires a separately maintained vulnerability intelligence feed or Trivy database.",
                "Cloud provider APIs, Kubernetes live-cluster access, authenticated IDOR tests, and full API schema fuzzing require dedicated authorized connectors and test credentials.",
                "The risk score is heuristic and must not be represented as CVSS.",
            ],
        }
        output = Path(args.output).expanduser()
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        csv_path = output.with_suffix(".csv")
        export_csv(report, csv_path)
        print(json.dumps({"status": "completed", "json_report": str(output.resolve()),
                          "csv_report": str(csv_path.resolve()), "summary": report["summary"],
                          "capabilities": report["capabilities"]}, indent=2))
        return 0
    except (ScopeError, ToolError, OSError, ValueError) as exc:
        print(f"Scanner error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
