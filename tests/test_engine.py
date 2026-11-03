import ipaddress
import unittest

from scanner_engine import (
    Finding, ScopeError, SameOriginCrawler, is_in_scope, normalize_target,
    score_findings,
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


if __name__ == "__main__":
    unittest.main()
