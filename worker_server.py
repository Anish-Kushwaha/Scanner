#!/usr/bin/env python3
"""Private authenticated job API for the Scanner assessment worker.

Run behind a TLS reverse proxy or on a private network. This service is not
intended to be exposed directly to the public internet.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from scanner_engine import (
    Finding, ScopeError, ToolError, add_finding, load_allowlist, normalize_target,
    resolve_target, web_assessment, run_nmap, run_zap_baseline,
    score_findings, utc_now,
)

HOST = os.environ.get("SCANNER_WORKER_HOST", "127.0.0.1")
PORT = int(os.environ.get("SCANNER_WORKER_PORT", "8787"))
TOKEN = os.environ.get("SCANNER_WORKER_TOKEN", "")
SOURCE_SHA = os.environ.get("SCANNER_SOURCE_SHA", "")
JOB_DIR = Path(os.environ.get("SCANNER_JOB_DIR", "/var/lib/scanner/jobs"))
TOKEN_FILE = Path(os.environ.get("SCANNER_WORKER_TOKEN_FILE", str(JOB_DIR / ".worker-token")))
MAX_REQUEST = 8 * 1024 * 1024
MAX_JOBS = 100
executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scanner-job")
lock = threading.Lock()
active_jobs: set[str] = set()


def read_job(job_id: str):
    if not re.fullmatch(r"[a-f0-9-]{36}", job_id):
        return None
    path = JOB_DIR / f"{job_id}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def write_job(job: dict):
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    tmp = JOB_DIR / f".{job['job_id']}.{uuid.uuid4().hex}.tmp"
    tmp.write_text(json.dumps(job, indent=2), encoding="utf-8")
    os.replace(tmp, JOB_DIR / f"{job['job_id']}.json")


def recover_interrupted_jobs():
    """Mark jobs interrupted by a Sandbox stop as failed instead of leaving them running forever."""
    for path in JOB_DIR.glob("*.json"):
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(job, dict) or job.get("status") not in {"queued", "running"}:
            continue
        job_id = job.get("job_id", "")
        if not re.fullmatch(r"[a-f0-9-]{36}", job_id):
            continue
        job.update({
            "status": "failed",
            "completed_at": utc_now(),
            "error": "Sandbox session stopped before this assessment completed. Submit the assessment again.",
        })
        write_job(job)


def prune_job_history():
    """Remove the oldest completed/failed records when the bounded history is full."""
    files = list(JOB_DIR.glob("*.json"))
    if len(files) < MAX_JOBS:
        return
    terminal = []
    for path in files:
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(job, dict) and job.get("status") in {"completed", "failed"}:
            terminal.append((str(job.get("created_at", "")), path))
    terminal.sort(key=lambda item: item[0])
    while len(files) >= MAX_JOBS and terminal:
        _, path = terminal.pop(0)
        try:
            path.unlink()
            files.remove(path)
        except FileNotFoundError:
            if path in files:
                files.remove(path)


def execute_job(job_id: str, request: dict):
    job = read_job(job_id)
    if not job:
        return
    job["status"] = "running"
    job["started_at"] = utc_now()
    write_job(job)
    findings: list[Finding] = []
    modules = set(request.get("modules") or ["web", "network", "tls"])
    allowed_modules = {"web", "network", "tls", "zap"}
    if not modules or not modules.issubset(allowed_modules):
        raise ValueError("Unsupported assessment module requested.")
    target_raw = request.get("target", "")
    target = ""
    host = ""
    addresses = []
    if target_raw:
        try:
            network = ipaddress.ip_network(str(target_raw).strip(), strict=False)
        except ValueError:
            network = None
        allow_hosts, networks = load_allowlist()
        if network:
            if network.num_addresses > 256:
                raise ScopeError("Network scope is limited to 256 addresses.")
            if not any(network.subnet_of(n) for n in networks if n.version == network.version):
                raise ScopeError("CIDR must be contained in SCANNER_ALLOWED_TARGETS.")
            target = str(network)
            host = str(network.network_address)
            addresses = [str(ip) for ip in network.hosts()]
        else:
            target = normalize_target(str(target_raw))
            parsed = urlsplit(target)
            host = parsed.hostname or ""
            addresses = resolve_target(host, allow_hosts, networks)
    if ({"web", "network", "tls", "zap"} & modules) and not target:
        raise ValueError("A target is required for the selected network/web modules.")
    profile = request.get("profile", "standard")
    if profile not in {"passive", "standard", "advanced"}:
        raise ValueError("Invalid scan profile.")
    results = {"target": target, "profile": profile}
    if "network" in modules:
        # CIDR/IP scopes stay as network notation; URL targets must be reduced
        # to their validated hostname before passing them to Nmap.
        nmap_target = target if network is not None else host
        results["network"] = run_nmap(
            nmap_target, addresses, profile,
            bool(request.get("os_detect")), bool(request.get("udp")),
            request.get("scan_config") if isinstance(request.get("scan_config"), dict) else {},
        )
    if "web" in modules or "tls" in modules:
        if target.startswith(("http://", "https://")):
            results["web"] = web_assessment(target, findings)
        else:
            results["web"] = {"status": "not_applicable", "note": "Web checks require an HTTP(S) URL."}
    if "zap" in modules:
        results["zap"] = run_zap_baseline(target, True)
    results["findings"] = [f.__dict__ for f in findings]
    results["summary"] = score_findings(findings)
    results["scan_id"] = job_id
    results["schema_version"] = "1.1"
    results["authorization"] = {"attested": True, "allowlist_enforced": True}
    results["generated_at"] = utc_now()
    results["capabilities"] = {
        "web_crawling": bool(results.get("web", {}).get("pages_checked")),
        "network_discovery": results.get("network", {}).get("status") == "completed",
        "tcp_port_scan": results.get("network", {}).get("status") == "completed",
        "service_version_detection": results.get("network", {}).get("status") == "completed",
        "tls_assessment": bool(results.get("web", {}).get("tls")),
        "zap_passive_baseline": results.get("zap", {}).get("status") == "completed",
        "os_fingerprinting_requested": bool(request.get("os_detect")),
        "udp_scan_requested": bool(request.get("udp")),
        "active_exploitation": False,
        "credential_bruteforce": False,
        "destructive_tests": False,
    }
    results["limitations"] = [
        "No exploit execution, credential attacks, persistence, evasion, destructive tests, or denial-of-service checks.",
        "Service version fingerprints are not proof of CVE exploitability.",
        "The heuristic risk score is not CVSS.",
        "The worker is a single-host service; durable distributed queues, user accounts and team RBAC are not included.",
    ]
    job.update({"status": "completed", "completed_at": utc_now(), "report": results})
    write_job(job)


def run_job(job_id: str, request: dict):
    try:
        execute_job(job_id, request)
    except Exception as exc:
        job = read_job(job_id) or {"job_id": job_id}
        job.update({"status": "failed", "completed_at": utc_now(),
                    "error": str(exc)[:500]})
        write_job(job)
    finally:
        with lock:
            active_jobs.discard(job_id)


class Handler(BaseHTTPRequestHandler):
    server_version = "ScannerWorker/1.0"
    def log_message(self, fmt, *args):
        print("[worker] " + fmt % args, flush=True)

    def send_json(self, status, payload):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        try:
            token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            token = TOKEN
        return bool(token) and self.headers.get("Authorization", "") == "Bearer " + token

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {
                "status": "healthy",
                "service": "Scanner private worker",
                "nmap_privileges": bool(hasattr(os, "geteuid") and os.geteuid() == 0),
                "source_sha": SOURCE_SHA,
            })
            return
        if not self.authorized():
            self.send_json(401, {"error": "Worker authentication required."})
            return
        match = re.fullmatch(r"/v1/jobs/([a-f0-9-]{36})", self.path)
        if not match:
            self.send_json(404, {"error": "Endpoint not found."})
            return
        job = read_job(match.group(1))
        if not job:
            self.send_json(404, {"error": "Job not found."})
            return
        self.send_json(200, job)

    def do_POST(self):
        if self.path != "/v1/jobs":
            self.send_json(404, {"error": "Endpoint not found."})
            return
        if not self.authorized():
            self.send_json(401, {"error": "Worker authentication required."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Invalid content length."})
            return
        if length <= 0 or length > MAX_REQUEST:
            self.send_json(413, {"error": "Request body missing or too large."})
            return
        try:
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or data.get("authorization_confirmed") is not True:
                raise ValueError("Confirm written authorization for this assessment.")
            with lock:
                if len(active_jobs) >= 2:
                    self.send_json(429, {"error": "Worker capacity reached. Retry shortly."})
                    return
                if len(list(JOB_DIR.glob("*.json"))) >= MAX_JOBS:
                    prune_job_history()
                    if len(list(JOB_DIR.glob("*.json"))) >= MAX_JOBS:
                        self.send_json(429, {"error": "Job history is full because no completed or failed records can be pruned."})
                        return
                job_id = str(uuid.uuid4())
                job = {"job_id": job_id, "status": "queued", "created_at": utc_now()}
                write_job(job)
                active_jobs.add(job_id)
                executor.submit(run_job, job_id, data)
            self.send_json(202, {"job_id": job_id, "status": "queued"})
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json(400, {"error": str(exc)[:300]})

    def do_PUT(self):
        self.send_json(405, {"error": "Method not allowed."})
    def do_DELETE(self):
        self.send_json(405, {"error": "Method not allowed."})


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    if not TOKEN or len(TOKEN) < 32:
        raise SystemExit("Set SCANNER_WORKER_TOKEN to a random secret of at least 32 characters.")
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    recover_interrupted_jobs()
    print(f"Scanner worker listening on {HOST}:{PORT} (source {SOURCE_SHA or 'unknown'})", flush=True)
    ReusableThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
