import ipaddress
import subprocess
import unittest
from unittest.mock import patch

from scanner_engine import (
    Finding, ScopeError, SameOriginCrawler, is_in_scope, normalize_target,
    score_findings, run_nmap, ToolError,
)


class ScopeTests(unittest.TestCase):
    def test_normalizes_web_target_and_drops_query(self):
        self.assertEqual(normalize_target("https://example.test/a?q=secret"),
                         "https://example.test/a")

    def test_rejects_non_http_and_nonstandard_port(self):
        for target in ("ftp://example.test", "https://example.test:8443"):
            with self.subTest(target=target), self.assertRaises(ScopeError):
                normalize_target(target)

    def test_exact_hostname_allowlist(self):
        self.assertTrue(is_in_scope("app.example.test", {"app.example.test"}, []))
        self.assertFalse(is_in_scope("other.example.test", {"app.example.test"}, []))

    def test_cidr_allowlist(self):
        networks = [ipaddress.ip_network("192.0.2.0/24")]
        self.assertTrue(is_in_scope("192.0.2.12", set(), networks))
        self.assertFalse(is_in_scope("192.0.3.12", set(), networks))


class AnalysisTests(unittest.TestCase):
    def test_score_is_explicitly_heuristic_and_counts_severity(self):
        findings = [
            Finding("1", "a", "HIGH", "HIGH", "test", "host", "d", "e", "r"),
            Finding("2", "b", "LOW", "MEDIUM", "test", "host", "d", "e", "r"),
        ]
        result = score_findings(findings)
        self.assertEqual(result["severity_counts"]["HIGH"], 1)
        self.assertEqual(result["total_findings"], 2)
        self.assertIn("not a formal CVSS", result["scoring_note"])

    def test_crawler_collects_links_and_form_metadata_only(self):
        parser = SameOriginCrawler()
        parser.feed('<a href="/docs">Docs</a><form method="PUT" action="/update"></form>')
        self.assertEqual(parser.links, ["/docs"])
        self.assertEqual(parser.forms[0]["method"], "PUT")


class NmapPinningTests(unittest.TestCase):
    XML = '<nmaprun><host><status state="up"/><address addr="203.0.113.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port></ports></host></nmaprun>'

    @patch("scanner_engine.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner_engine.subprocess.run")
    def test_hostname_scan_uses_only_validated_ipv4_answers(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, self.XML, "")
        report = run_nmap("scanme.nmap.org", ["203.0.113.10"], "passive", False, False)
        command = run.call_args.args[0]
        self.assertIn("203.0.113.10", command)
        self.assertNotIn("scanme.nmap.org", command)
        self.assertEqual(report["host_count"], 1)
        self.assertEqual(report["open_ports_count"], 1)

    @patch("scanner_engine.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner_engine.subprocess.run")
    def test_mixed_ipv4_ipv6_answers_are_scanned_with_correct_family(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, "<nmaprun/>", "")
        run_nmap("scanme.nmap.org", ["203.0.113.10", "2001:db8::10"], "passive", False, False)
        self.assertEqual(run.call_count, 2)
        ipv4_command = run.call_args_list[0].args[0]
        ipv6_command = run.call_args_list[1].args[0]
        self.assertIn("203.0.113.10", ipv4_command)
        self.assertNotIn("-6", ipv4_command)
        self.assertIn("2001:db8::10", ipv6_command)
        self.assertIn("-6", ipv6_command)

    @patch("scanner_engine.shutil.which", return_value="/usr/bin/nmap")
    def test_hostname_without_validated_addresses_is_rejected(self, _which):
        with self.assertRaises(ToolError):
            run_nmap("scanme.nmap.org", [], "passive", False, False)



if __name__ == "__main__":
    unittest.main()
