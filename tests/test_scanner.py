import socket
import unittest
from unittest.mock import patch

from api.index import (
    ScanExecutionError,
    TargetValidationError,
    analyze_security_posture,
    normalize_target,
    resolve_public_addresses,
    scan_target,
)


class TargetValidationTests(unittest.TestCase):
    def test_adds_https_to_bare_hostname_and_drops_query(self):
        self.assertEqual(
            normalize_target("example.com/path?q=private#fragment"),
            "https://example.com/path",
        )

    def test_accepts_http_and_standard_port_only(self):
        self.assertEqual(normalize_target("http://example.com:80"), "http://example.com/")
        with self.assertRaises(TargetValidationError):
            normalize_target("https://example.com:8443")

    def test_rejects_non_http_schemes_and_url_credentials(self):
        for target in ("ftp://example.com", "https://user:pass@example.com"):
            with self.subTest(target=target):
                with self.assertRaises(TargetValidationError):
                    normalize_target(target)

    def test_rejects_malformed_hosts(self):
        for target in ("https://", "https://bad host/", "https://a..b/"):
            with self.subTest(target=target):
                with self.assertRaises(TargetValidationError):
                    normalize_target(target)

    @patch("api.index.socket.getaddrinfo")
    def test_blocks_loopback_dns_answer(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        ]
        with self.assertRaises(TargetValidationError):
            resolve_public_addresses("localhost")

    @patch("api.index.socket.getaddrinfo")
    def test_blocks_mixed_public_and_private_dns_answers(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
        ]
        with self.assertRaises(TargetValidationError):
            resolve_public_addresses("mixed.example")


class SecurityAnalysisTests(unittest.TestCase):
    def test_missing_controls_and_session_cookie_flags_are_reported(self):
        result = analyze_security_posture(
            "https",
            {"server": "nginx"},
            ["sessionid=not-returned; Path=/"],
            "<html></html>",
            {"verified": True, "days_remaining": 5},
            200,
        )
        finding_types = {item["type"] for item in result["vulnerabilities"]}
        self.assertIn("Missing HSTS", finding_types)
        self.assertIn("Missing Content Security Policy", finding_types)
        self.assertIn("Cookie Missing Secure Flag", finding_types)
        self.assertIn("Cookie Missing HttpOnly Flag", finding_types)
        self.assertIn("TLS Certificate Expiring Soon", finding_types)
        # Cookie values must never be copied into findings or reports.
        self.assertNotIn("not-returned", str(result))

    def test_http_does_not_claim_hsts_is_missing(self):
        result = analyze_security_posture(
            "http", {}, [], "", {}, 200
        )
        self.assertEqual(
            result["security_headers"]["Strict-Transport-Security"],
            "NOT APPLICABLE (HTTP)",
        )
        self.assertNotIn(
            "Missing HSTS",
            {item["type"] for item in result["vulnerabilities"]},
        )


class ScanFlowTests(unittest.TestCase):
    @patch("api.index._request_once")
    @patch("api.index.resolve_public_addresses", return_value=["93.184.216.34"])
    def test_report_explicitly_marks_port_scan_as_not_performed(
        self, _resolve, request_once
    ):
        request_once.return_value = {
            "status_code": 200,
            "headers": {
                "server": "nginx",
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "strict-transport-security": "max-age=31536000",
                "referrer-policy": "strict-origin",
                "permissions-policy": "geolocation=()",
            },
            "set_cookies": [],
            "body": b"<html><body>safe page</body></html>",
            "truncated": False,
            "tls": {"verified": True, "version": "TLSv1.3", "days_remaining": 90},
        }

        result = scan_target("https://example.com")
        self.assertEqual(result["scan_status"], "completed")
        self.assertFalse(result["summary"]["port_scan_performed"])
        self.assertIsNone(result["network_info"]["open_ports_count"])
        self.assertEqual(result["network_info"]["port_scan_status"], "not_performed")
        self.assertEqual(result["summary"]["total_vulnerabilities"], 0)
        self.assertEqual(result["summary"]["risk_level"], "INFO")
        self.assertFalse(
            any("SQL Injection" in item["type"] or "XSS" in item["type"]
                for item in result["vulnerabilities"])
        )

    @patch("api.index._request_once")
    @patch(
        "api.index.resolve_public_addresses",
        side_effect=[
            ["93.184.216.34"],
            TargetValidationError("private destination blocked"),
        ],
    )
    def test_redirect_to_private_address_is_blocked(self, _resolve, request_once):
        request_once.return_value = {
            "status_code": 302,
            "headers": {"location": "http://127.0.0.1/admin"},
            "set_cookies": [],
            "body": b"",
            "truncated": False,
            "tls": {"verified": True},
        }
        with self.assertRaises(TargetValidationError):
            scan_target("https://example.com")


if __name__ == "__main__":
    unittest.main()
