#!/usr/bin/env python3
"""Private authenticated job API for the Scanner assessment worker.

Run behind a TLS reverse proxy or on a private network. This service is not
intended to be exposed directly to the public internet.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from scanner_engine import (
    Finding, ScopeError, ToolError, add_finding, load_allowlist, normalize_target,
    resolve_target, web_assessment, run_nmap, run_zap_baseline, assess_local_path,
    score_findings, utc_now,
)

HOST = os.environ.get("SCANNER_WORKER_HOST", "127.0.0.1")
PORT = int(os.environ.get("SCANNER_WORKER_PORT", "8787"))
TOKEN = os.environ.get("SCANNER_WORKER_TOKEN", "")
JOB_DIR = Path(os.environ.get("SCANNER_JOB_DIR", "/var/lib/scanner/jobs"))
MAX_REQUEST = 8 * 1024 * 1024
MAX_ARCHIVE = 6 * 1024 * 1024
MAX_EXTRACTED = 25 * 1024 * 1024
MAX_FILES = 1000
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


def safe_extract_archive(encoded: str, destination: Path):
    if not isinstance(encoded, str) or len(encoded) > (MAX_ARCHIVE * 4 // 3 + 16):
        raise ValueError("Source archive is too large.")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Source archive exceeds the upload limit.")
    total = 0
    count = 0
    with zipfile.ZipFile(__import__("io").BytesIO(raw)) as archive:
        for info in archive.infolist():
            count += 1
            if count > MAX_FILES:
                raise ValueError("Source archive contains too many files.")
            name = info.filename.replace("\\", "/")
            rel = PurePosixPath(name)
            mode = (info.external_attr >> 16) & 0o170000
            if rel.is_absolute() or ".." in rel.parts or mode == 0o120000:
                raise ValueError("Unsafe path or symbolic link found in source archive.")
            if info.is_dir():
                continue
            total += info.file_size
            if total > MAX_EXTRACTED:
                raise ValueError("Expanded source archive exceeds the 25 MB limit.")
            target = (destination / Path(*rel.parts)).resolve()
            if destination.resolve() not in target.parents:
                raise ValueError("Unsafe archive path.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=64 * 1024)


def execute_job(job_id: str, request: dict):
    job = read_job(job_id)
    if not job:
        return
    job["status"] = "running"
    job["started_at"] = utc_now()
    write_job(job)
    findings: list[Finding] = []
    modules = set(request.get("modules") or ["web", "network", "tls"])
    allowed_modules = {"web", "network", "tls", "zap", "local"}
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
    if "local" in modules and not request.get("source_archive"):
        raise ValueError("Upload a ZIP source/configuration archive to run local assessment.")
    profile = request.get("profile", "standard")
    if profile not in {"passive", "standard", "advanced"}:
        raise ValueError("Invalid scan profile.")
    results = {"target": target or "Local source archive", "profile": profile}
    if "network" in modules:
        results["network"] = run_nmap(
            target if "/" in target else host, addresses, profile,
            bool(request.get("os_detect")), bool(request.get("udp")),
        )
    if "web" in modules or "tls" in modules:
        if target.startswith(("http://", "https://")):
            results["web"] = web_assessment(target, findings)
        else:
            results["web"] = {"status": "not_applicable", "note": "Web checks require an HTTP(S) URL."}
    if "zap" in modules:
        results["zap"] = run_zap_baseline(target, True)
    if "local" in modules:
        with tempfile.TemporaryDirectory(prefix="scanner-source-") as temp:
            source = Path(temp) / "source"
            source.mkdir()
            safe_extract_archive(request["source_archive"], source)
            results["local_assessment"] = assess_local_path(str(source), findings)
    results["findings"] = [f.__dict__ for f in findings]
    results["summary"] = score_findings(findings)
    results["authorization"] = {"attested": True, "allowlist_enforced": True}
    results["generated_at"] = utc_now()
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
        return bool(TOKEN) and self.headers.get("Authorization", "") == "Bearer " + TOKEN

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"status": "healthy", "service": "Scanner private worker"})
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
                    self.send_json(429, {"error": "Job history capacity reached; archive old jobs."})
                    return
                job_id = str(uuid.uuid4())
                job = {"job_id": job_id, "status": "queued", "created_at": utc_now()}
                write_job(job)
                active_jobs.add(job_id)
                executor.submit(run_job, job_id, data)
            self.send_json(202, {"job_id": job_id, "status": "queued"})
        except (ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
            self.send_json(400, {"error": str(exc)[:300]})

    def do_PUT(self):
        self.send_json(405, {"error": "Method not allowed."})
    def do_DELETE(self):
        self.send_json(405, {"error": "Method not allowed."})


if __name__ == "__main__":
    if not TOKEN or len(TOKEN) < 32:
        raise SystemExit("Set SCANNER_WORKER_TOKEN to a random secret of at least 32 characters.")
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Scanner worker listening on {HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
