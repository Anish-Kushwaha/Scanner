import io
import json
import socket
import unittest
from unittest.mock import patch

from api.index import (
    MAX_RATE_LIMIT_KEYS,
    RATE_LIMIT_REQUESTS,
    ScanExecutionError,
    TargetValidationError,
    _check_rate_limit,
    _rate_events,
    analyze_security_posture,
    handler,
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
            "headers": {"location": "https://127.0.0.1/admin"},
            "set_cookies": [],
            "body": b"",
            "truncated": False,
            "tls": {"verified": True},
        }
        with self.assertRaises(TargetValidationError):
            scan_target("https://example.com")




class RateLimitTests(unittest.TestCase):
    def setUp(self):
        _rate_events.clear()

    def tearDown(self):
        _rate_events.clear()

    @patch("api.index.time.monotonic")
    def test_rate_limit_is_ten_requests_per_sixty_seconds(self, monotonic):
        monotonic.return_value = 100.0
        results = [_check_rate_limit("client-A") for _ in range(RATE_LIMIT_REQUESTS + 1)]
        self.assertTrue(all(allowed for allowed, _ in results[:RATE_LIMIT_REQUESTS]))
        self.assertFalse(results[-1][0])
        self.assertGreaterEqual(results[-1][1], 1)

    @patch("api.index.time.monotonic")
    def test_rate_limit_entries_expire_and_allow_a_new_window(self, monotonic):
        monotonic.return_value = 100.0
        for _ in range(RATE_LIMIT_REQUESTS):
            self.assertTrue(_check_rate_limit("client-A")[0])
        self.assertFalse(_check_rate_limit("client-A")[0])
        monotonic.return_value = 161.0
        self.assertTrue(_check_rate_limit("client-A")[0])

    @patch("api.index.time.monotonic")
    def test_rate_limit_key_store_has_a_hard_memory_bound(self, monotonic):
        monotonic.return_value = 100.0
        for index in range(MAX_RATE_LIMIT_KEYS + 50):
            self.assertTrue(_check_rate_limit(f"client-{index}")[0])
        self.assertLessEqual(len(_rate_events), MAX_RATE_LIMIT_KEYS)


class ApiHandlerTests(unittest.TestCase):
    def make_handler(self, path, headers=None, body=b""):
        instance = object.__new__(handler)
        instance.path = path
        instance.headers = headers or {}
        instance.rfile = io.BytesIO(body)
        instance.wfile = io.BytesIO()
        instance.client_address = ("198.51.100.17", 12345)
        instance.responses = []
        instance.response_headers = {}
        instance.send_response = lambda status, message=None: instance.responses.append(status)
        instance.send_header = lambda key, value: instance.response_headers.__setitem__(key.lower(), value)
        instance.end_headers = lambda: None
        return instance

    def test_health_route_normalizes_trailing_slash_and_query(self):
        request = self.make_handler("/health/?check=1")
        request.do_GET()
        self.assertEqual(request.responses[0], 200)
        payload = json.loads(request.wfile.getvalue())
        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["version"], "4.0.0")

    def test_scan_endpoint_get_is_method_not_allowed(self):
        request = self.make_handler("/api/scan")
        request.do_GET()
        self.assertEqual(request.responses[0], 405)
        self.assertEqual(request.response_headers["allow"], "POST, OPTIONS")


    def test_post_accepts_configured_vercel_frontend_origin_for_preflight(self):
        request = self.make_handler(
            "/api/scan",
            {"Origin": "https://scanner-rose-rho.vercel.app"},
        )
        request.do_OPTIONS()
        self.assertEqual(request.responses[0], 204)
        self.assertEqual(
            request.response_headers["access-control-allow-origin"],
            "https://scanner-rose-rho.vercel.app",
        )

    def test_post_requires_approved_frontend_origin(self):
        payload = json.dumps({
            "target": "https://example.com",
            "authorization_confirmed": True,
        }).encode()
        request = self.make_handler(
            "/api/scan",
            {"Origin": "https://attacker.example", "Content-Length": str(len(payload))},
            payload,
        )
        request.do_POST()
        self.assertEqual(request.responses[0], 403)

    def test_post_requires_explicit_authorization_attestation(self):
        payload = json.dumps({"target": "https://example.com"}).encode()
        request = self.make_handler(
            "/api/scan",
            {"Origin": "https://anish-kushwaha.github.io", "Content-Length": str(len(payload))},
            payload,
        )
        request.do_POST()
        self.assertEqual(request.responses[0], 403)

    def test_post_rejects_private_destination_without_connecting(self):
        payload = json.dumps({
            "target": "http://127.0.0.1",
            "authorization_confirmed": True,
        }).encode()
        request = self.make_handler(
            "/api/scan",
            {"Origin": "https://anish-kushwaha.github.io", "Content-Length": str(len(payload))},
            payload,
        )
        request.do_POST()
        self.assertEqual(request.responses[0], 400)
        self.assertIn("blocked", json.loads(request.wfile.getvalue())["error"].lower())

    def test_post_rejects_oversized_request_body(self):
        request = self.make_handler(
            "/api/scan",
            {
                "Origin": "https://anish-kushwaha.github.io",
                "Content-Length": "9000",
            },
            b"",
        )
        request.do_POST()
        self.assertEqual(request.responses[0], 413)


if __name__ == "__main__":
    unittest.main()
