import base64
import io
import ipaddress
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import worker_server
from worker_server import safe_extract_archive


class ArchiveSafetyTests(unittest.TestCase):
    def make_archive(self, name, body=b"sample"):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(name, body)
        return base64.b64encode(stream.getvalue()).decode()

    def test_extracts_regular_source_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            safe_extract_archive(self.make_archive("src/app.py", b"print('ok')"), root)
            self.assertEqual((root / "src/app.py").read_bytes(), b"print('ok')")

    def test_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                safe_extract_archive(self.make_archive("../outside.txt"), Path(temp))

    def test_rejects_absolute_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                safe_extract_archive(self.make_archive("/tmp/outside.txt"), Path(temp))


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


if __name__ == "__main__":
    unittest.main()
