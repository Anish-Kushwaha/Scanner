import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import worker_server
class NmapTargetSelectionTests(unittest.TestCase):
    JOB_ID = "11111111-1111-4111-8111-111111111111"

    def execute_with_scope(self, target, hosts, networks, resolved):
        with tempfile.TemporaryDirectory() as temp:
            with (
                patch.object(worker_server, "JOB_DIR", Path(temp)),
                patch.object(worker_server, "load_allowlist", return_value=(hosts, networks)),
                patch.object(worker_server, "resolve_target", return_value=resolved),
                patch.object(worker_server, "run_nmap", return_value={"status": "completed", "host_count": 1}) as nmap,
            ):
                worker_server.write_job({"job_id": self.JOB_ID, "status": "queued"})
                worker_server.execute_job(
                    self.JOB_ID,
                    {"target": target, "modules": ["network"], "profile": "passive"},
                )
                saved = worker_server.read_job(self.JOB_ID)
                self.assertEqual(saved["status"], "completed")
                return nmap.call_args

    def test_web_url_passes_hostname_not_full_url_to_nmap(self):
        call = self.execute_with_scope(
            "https://scanme.nmap.org/",
            {"scanme.nmap.org"},
            [],
            ["45.33.32.156"],
        )
        self.assertEqual(call.args[0], "scanme.nmap.org")
        self.assertEqual(call.args[1], ["45.33.32.156"])

    def test_cidr_scope_keeps_network_notation_for_nmap(self):
        network = ipaddress.ip_network("192.0.2.0/24")
        call = self.execute_with_scope("192.0.2.0/24", set(), [network], [])
        self.assertEqual(call.args[0], "192.0.2.0/24")
        self.assertEqual(call.args[1], [str(ip) for ip in network.hosts()])


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
