#!/usr/bin/env python3
"""Serialize and supervise the Scanner worker inside its persistent Vercel Sandbox."""
from __future__ import annotations

import fcntl
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
JOB_DIR = pathlib.Path(os.environ.get("SCANNER_JOB_DIR", str(ROOT / ".scanner-jobs")))
TOKEN = os.environ.get("SCANNER_WORKER_TOKEN", "")
SOURCE_SHA = os.environ.get("SCANNER_SOURCE_SHA", "")
HOST = "127.0.0.1"
PORT = int(os.environ.get("SCANNER_WORKER_PORT", "8080"))
PID_FILE = JOB_DIR / ".worker.pid"
TOKEN_FILE = JOB_DIR / ".worker-token"
LOG_FILE = ROOT / "worker.log"


def worker_healthy() -> bool:
    try:
        with urllib.request.urlopen(f"http://{HOST}:{PORT}/health", timeout=1.5) as response:
            data = json.loads(response.read().decode("utf-8"))
            if response.status != 200 or data.get("status") != "healthy":
                return False
            if data.get("nmap_privileges") is not True:
                return False
            if SOURCE_SHA and data.get("source_sha") != SOURCE_SHA:
                return False
        request = urllib.request.Request(
            f"http://{HOST}:{PORT}/v1/jobs/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": "Bearer " + TOKEN},
        )
        try:
            urllib.request.urlopen(request, timeout=1.5)
        except urllib.error.HTTPError as error:
            return error.code == 404
        return False
    except Exception:
        return False


def worker_processes() -> list[int]:
    found: list[int] = []
    proc_root = pathlib.Path("/proc")
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        try:
            args = (entry / "cmdline").read_bytes().split(b"\0")
            cwd = (entry / "cwd").resolve()
        except (OSError, PermissionError):
            continue
        if cwd == ROOT and any(arg == b"worker_server.py" or arg.endswith(b"/worker_server.py") for arg in args):
            found.append(pid)
    return found


def stop_stale_workers() -> None:
    pids = worker_processes()
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        remaining = [pid for pid in pids if pathlib.Path(f"/proc/{pid}").exists()]
        if not remaining:
            break
        time.sleep(0.1)
    for pid in pids:
        if pathlib.Path(f"/proc/{pid}").exists():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass


def install_nmap_if_missing() -> None:
    if shutil_which("nmap"):
        return
    for command in (["sudo", "-n", "apt-get", "update", "-qq"],
                    ["sudo", "-n", "apt-get", "install", "-y", "-qq", "nmap"]):
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=600)
        if completed.returncode:
            raise RuntimeError("Nmap installation failed: " + (completed.stderr or completed.stdout)[-600:])
    if not shutil_which("nmap"):
        raise RuntimeError("Nmap is still unavailable after installation.")


def shutil_which(name: str) -> str | None:
    from shutil import which
    return which(name)


def main() -> int:
    if len(TOKEN) < 32:
        raise SystemExit("SCANNER_WORKER_TOKEN is missing or too short.")
    if SOURCE_SHA and (len(SOURCE_SHA) != 40 or any(c not in "0123456789abcdef" for c in SOURCE_SHA)):
        raise SystemExit("SCANNER_SOURCE_SHA is invalid.")

    JOB_DIR.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(TOKEN, encoding="utf-8")
    TOKEN_FILE.chmod(0o600)

    lock_path = pathlib.Path("/tmp/scanner-worker-bootstrap.lock")
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)

        # Another cold-start invocation may have completed while this one waited.
        if worker_healthy():
            return 0

        # Give a just-launched process a short grace period before deciding it is stale.
        for _ in range(12):
            if worker_healthy():
                return 0
            time.sleep(0.25)

        stop_stale_workers()
        install_nmap_if_missing()

        # Fail clearly rather than repeatedly spawning workers against an unrelated listener.
        probe = socket.socket()
        try:
            probe.bind((HOST, PORT))
        except OSError as error:
            raise RuntimeError(f"Worker port {PORT} is already occupied by another process.") from error
        finally:
            probe.close()

        env = os.environ.copy()
        env.update({
            "SCANNER_WORKER_HOST": "0.0.0.0",
            "SCANNER_WORKER_PORT": str(PORT),
            "SCANNER_WORKER_TOKEN": TOKEN,
            "SCANNER_WORKER_TOKEN_FILE": str(TOKEN_FILE),
            "SCANNER_JOB_DIR": str(JOB_DIR),
            "SCANNER_SOURCE_SHA": SOURCE_SHA,
        })
        with LOG_FILE.open("ab", buffering=0) as log:
            process = subprocess.Popen(
                ["sudo", "-n", "-E", sys.executable, "worker_server.py"],
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
        PID_FILE.write_text(str(process.pid), encoding="ascii")

        for _ in range(48):
            if worker_healthy():
                print(json.dumps({"status": "healthy", "source_sha": SOURCE_SHA, "pid": process.pid}))
                return 0
            if process.poll() is not None:
                break
            time.sleep(0.25)

        stop_stale_workers()
        try:
            tail = LOG_FILE.read_text(encoding="utf-8", errors="replace")[-3000:]
        except OSError:
            tail = ""
        raise RuntimeError("Scanner worker failed its authenticated health check. " + tail[-1200:])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Scanner worker bootstrap error: {error}", file=sys.stderr)
        raise SystemExit(1)
