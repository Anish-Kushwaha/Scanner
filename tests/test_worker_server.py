import base64
import hashlib
import hmac
import ipaddress
import json
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import worker_server


class NmapTargetSelectionTests(unittest.TestCase):
    JOB_ID = "11111111-1111-4111-8111-111111111111"

    def execute_with_target(self, target, resolved):
        claims = {
            "sub": "22222222-2222-4222-8222-222222222222",
            "organization_id": "33333333-3333-4333-8333-333333333333",
            "project_id": "44444444-4444-4444-8444-444444444444",
            "engagement_id": "55555555-5555-4555-8555-555555555555",
            "target_id": "66666666-6666-4666-8666-666666666666",
            "job_id": self.JOB_ID,
            "target": target,
            "modules": ["network"],
            "profile": "passive",
            "max_hosts": 32,
        }
        request = {
            "target": target,
            "modules": ["network"],
            "profile": "passive",
            "os_detect": False,
            "udp": False,
            "signed_grant": "unit.test",
        }
        with tempfile.TemporaryDirectory() as temp:
            with (
                patch.object(worker_server, "JOB_DIR", Path(temp)),
                patch.object(worker_server, "verify_scope_grant", return_value=claims),
                patch.object(worker_server, "run_nmap", return_value={"status": "completed", "host_count": 1}) as nmap,
                patch.object(worker_server.socket, "getaddrinfo", return_value=[
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolved[0], 0))
                ]),
            ):
                worker_server.write_job({"job_id": self.JOB_ID, "status": "queued"})
                worker_server.execute_job(self.JOB_ID, request)
                saved = worker_server.read_job(self.JOB_ID)
                self.assertEqual(saved["status"], "completed")
                return nmap.call_args

    def test_web_url_passes_hostname_not_full_url_to_nmap(self):
        call = self.execute_with_target("https://scanme.nmap.org/", ["45.33.32.156"])
        self.assertEqual(call.args[0], "scanme.nmap.org")
        self.assertEqual(call.args[1], ["45.33.32.156"])

    def test_cidr_scope_keeps_network_notation_for_nmap(self):
        network = ipaddress.ip_network("8.8.8.0/30")
        claims = {
            "sub": "22222222-2222-4222-8222-222222222222",
            "organization_id": "33333333-3333-4333-8333-333333333333",
            "project_id": "44444444-4444-4444-8444-444444444444",
            "engagement_id": "55555555-5555-4555-8555-555555555555",
            "target_id": "66666666-6666-4666-8666-666666666666",
            "job_id": self.JOB_ID,
            "target": str(network),
            "modules": ["network"],
            "profile": "passive",
            "max_hosts": 8,
        }
        request = {"target": str(network), "modules": ["network"], "profile": "passive",
                   "os_detect": False, "udp": False, "signed_grant": "unit.test"}
        with tempfile.TemporaryDirectory() as temp:
            with (
                patch.object(worker_server, "JOB_DIR", Path(temp)),
                patch.object(worker_server, "verify_scope_grant", return_value=claims),
                patch.object(worker_server, "run_nmap", return_value={"status": "completed", "host_count": 1}) as nmap,
            ):
                worker_server.write_job({"job_id": self.JOB_ID, "status": "queued"})
                worker_server.execute_job(self.JOB_ID, request)
                self.assertEqual(nmap.call_args.args[0], str(network))
                self.assertEqual(nmap.call_args.args[1], [str(ip) for ip in network.hosts()])

    def test_private_dns_resolution_is_rejected(self):
        with self.assertRaises(worker_server.ScopeError):
            self.execute_with_target("https://example.com/", ["127.0.0.1"])


class ScopeGrantTests(unittest.TestCase):
    def make_grant(self, secret):
        now = int(time.time())
        claims = {
            "iss": "anish-enterprises-scanner", "aud": "scanner-worker",
            "sub": "22222222-2222-4222-8222-222222222222",
            "organization_id": "33333333-3333-4333-8333-333333333333",
            "project_id": "44444444-4444-4444-8444-444444444444",
            "engagement_id": "55555555-5555-4555-8555-555555555555",
            "target_id": "66666666-6666-4666-8666-666666666666",
            "job_id": "11111111-1111-4111-8111-111111111111",
            "target": "scanme.nmap.org", "modules": ["network"], "profile": "passive",
            "max_hosts": 8, "iat": now, "exp": now + 120, "jti": "grant-test"
        }
        encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        return claims, encoded + "." + supplied

    def test_valid_grant_is_accepted(self):
        claims, token = self.make_grant("a" * 64)
        request = {"target": claims["target"], "modules": claims["modules"],
                   "profile": claims["profile"], "signed_grant": token}
        with patch.object(worker_server, "SCOPE_SIGNING_SECRET", "a" * 64):
            self.assertEqual(worker_server.verify_scope_grant(request)["job_id"], claims["job_id"])

    def test_tampered_grant_is_rejected(self):
        claims, token = self.make_grant("a" * 64)
        request = {"target": claims["target"], "modules": claims["modules"],
                   "profile": claims["profile"], "signed_grant": token[:-1] + "x"}
        with patch.object(worker_server, "SCOPE_SIGNING_SECRET", "a" * 64):
            with self.assertRaises(worker_server.ScopeError):
                worker_server.verify_scope_grant(request)

    def test_expired_grant_is_rejected(self):
        claims, token = self.make_grant("a" * 64)
        claims["exp"] = int(time.time()) - 1
        encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        signature = hmac.new(("a" * 64).encode(), encoded.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        request = {"target": claims["target"], "modules": claims["modules"],
                   "profile": claims["profile"], "signed_grant": encoded + "." + supplied}
        with patch.object(worker_server, "SCOPE_SIGNING_SECRET", "a" * 64):
            with self.assertRaises(worker_server.ScopeError):
                worker_server.verify_scope_grant(request)


class JobLifecycleTests(unittest.TestCase):
    def make_job(self, job_id, status, created_at):
        return {"job_id": job_id, "status": status, "created_at": created_at}

    def test_recovery_marks_interrupted_jobs_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(worker_server, "JOB_DIR", root):
                worker_server.write_job(self.make_job(
                    "11111111-1111-4111-8111-111111111111", "queued", "2026-11-03T09:00:00Z"
                ))
                worker_server.write_job(self.make_job(
                    "22222222-2222-4222-8222-222222222222", "running", "2026-11-03T09:01:00Z"
                ))
                worker_server.write_job(self.make_job(
                    "33333333-3333-4333-8333-333333333333", "completed", "2026-11-03T09:02:00Z"
                ))
                worker_server.recover_interrupted_jobs()
                queued = worker_server.read_job("11111111-1111-4111-8111-111111111111")
                running = worker_server.read_job("22222222-2222-4222-8222-222222222222")
                completed = worker_server.read_job("33333333-3333-4333-8333-333333333333")
                self.assertEqual(queued["status"], "failed")
                self.assertEqual(running["status"], "failed")
                self.assertIn("Submit the assessment again", queued["error"])
                self.assertEqual(completed["status"], "completed")

    def test_prunes_oldest_terminal_job_when_history_is_full(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ids = [
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333",
            ]
            with patch.object(worker_server, "JOB_DIR", root), patch.object(worker_server, "MAX_JOBS", 3):
                worker_server.write_job(self.make_job(ids[0], "completed", "2026-11-03T09:00:00Z"))
                worker_server.write_job(self.make_job(ids[1], "failed", "2026-11-03T09:01:00Z"))
                worker_server.write_job(self.make_job(ids[2], "running", "2026-11-03T09:02:00Z"))
                worker_server.prune_job_history()
                self.assertIsNone(worker_server.read_job(ids[0]))
                self.assertIsNotNone(worker_server.read_job(ids[1]))
                self.assertIsNotNone(worker_server.read_job(ids[2]))


class WorkerAuthTests(unittest.TestCase):
    def test_authorization_reads_rotated_token_file(self):
        with tempfile.TemporaryDirectory() as temp:
            token_file = Path(temp) / ".worker-token"
            token_file.write_text("new-token-value", encoding="utf-8")
            handler = object.__new__(worker_server.Handler)
            handler.headers = {"Authorization": "Bearer new-token-value"}
            with patch.object(worker_server, "TOKEN", "old-token-value"), patch.object(worker_server, "TOKEN_FILE", token_file):
                self.assertTrue(handler.authorized())
                handler.headers = {"Authorization": "Bearer old-token-value"}
                self.assertFalse(handler.authorized())


if __name__ == "__main__":
    unittest.main()
