"""Safe, low-impact HTTP security posture scanner for Vercel.

This public endpoint deliberately does not perform exploitation, directory
brute forcing, or TCP port enumeration. It fetches only the requested page,
validates every DNS result, pins the connection to a validated public IP, and
revalidates every redirect before following it.
"""
from collections import OrderedDict, deque
from datetime import datetime, timezone
import http.client
import http.server
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import uuid
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit


VERSION = "4.0.0"
MAX_BODY_BYTES = 8192
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REDIRECTS = 2
REQUEST_TIMEOUT_SECONDS = 2.5
RATE_WINDOW_SECONDS = 60
RATE_LIMIT_REQUESTS = 10
MAX_RATE_LIMIT_KEYS = 4096

DEFAULT_ALLOWED_ORIGINS = {
    "https://anish-kushwaha.github.io",
    "https://scanner-rose-rho.vercel.app",
}
ALLOWED_ORIGINS = frozenset(
    origin.strip()
    for origin in os.environ.get(
        "SCANNER_ALLOWED_ORIGINS",
        ",".join(sorted(DEFAULT_ALLOWED_ORIGINS)),
    ).split(",")
    if origin.strip()
)

_rate_lock = threading.Lock()
_rate_events = OrderedDict()


class TargetValidationError(ValueError):
    """The requested target is malformed or outside the safe scan policy."""


class ScanExecutionError(RuntimeError):
    """The target could not be fetched safely."""


def normalize_target(raw_target):
    """Normalize an HTTP(S) URL while discarding query strings and fragments."""
    if not isinstance(raw_target, str):
        raise TargetValidationError("Target must be a URL string.")

    value = raw_target.strip()
    if not value:
        raise TargetValidationError("A target URL is required.")
    if len(value) > 2048:
        raise TargetValidationError("Target URL is too long.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise TargetValidationError("Target URL contains invalid control characters.")

    explicit_scheme = re.match(r"^([a-z][a-z0-9+.-]*)://", value, re.IGNORECASE)
    if explicit_scheme and explicit_scheme.group(1).lower() not in {"http", "https"}:
        raise TargetValidationError("Only HTTP and HTTPS targets are supported.")
    if not explicit_scheme:
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise TargetValidationError("Target URL is malformed.") from None

    if scheme not in {"http", "https"}:
        raise TargetValidationError("Only HTTP and HTTPS targets are supported.")
    if not host:
        raise TargetValidationError("Target URL must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("URLs containing credentials are not allowed.")

    try:
        ipaddress.ip_address(host)
        normalized_host = host.lower()
    except ValueError:
        try:
            normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise TargetValidationError("Target hostname is invalid.") from None

        if (
            not normalized_host
            or len(normalized_host) > 253
            or not re.fullmatch(r"[a-z0-9.-]+", normalized_host)
            or normalized_host.startswith(".")
            or normalized_host.endswith(".")
            or ".." in normalized_host
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                for label in normalized_host.split(".")
            )
        ):
            raise TargetValidationError("Target hostname is invalid.")

    expected_port = 443 if scheme == "https" else 80
    if port is not None and port != expected_port:
        raise TargetValidationError(
            "Only standard web ports are enabled (HTTP 80 and HTTPS 443)."
        )

    host_for_url = (
        "[" + normalized_host + "]" if ":" in normalized_host else normalized_host
    )
    path = quote(
        unquote(parsed.path or "/"),
        safe="/%:@!$&'()*+,;=-._~",
    )
    if len(path) > 1024:
        raise TargetValidationError("Target path is too long.")

    return urlunsplit((scheme, host_for_url, path, "", ""))


def is_public_address(value):
    """Return True only for globally routable unicast IP addresses."""
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False

    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def resolve_public_addresses(hostname):
    """Resolve a host and reject it if any DNS answer is not globally routable."""
    try:
        literal = ipaddress.ip_address(hostname)
        resolved = [str(literal)]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                hostname,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror:
            raise TargetValidationError("Target hostname could not be resolved.") from None

        resolved = []
        for record in records:
            address = record[4][0]
            if address not in resolved:
                resolved.append(address)

    if not resolved:
        raise TargetValidationError("Target hostname did not resolve to an IP address.")
    if any(not is_public_address(address) for address in resolved):
        raise TargetValidationError(
            "Private, local, reserved, or non-public IP destinations are blocked."
        )

    return resolved


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a validated IP while preserving TLS SNI."""

    def __init__(self, address, hostname, port, timeout):
        self._tls_hostname = hostname
        context = ssl.create_default_context()
        super().__init__(host=address, port=port, timeout=timeout, context=context)

    def connect(self):
        sock = socket.create_connection(
            (self.host, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(
            sock,
            server_hostname=self._tls_hostname,
        )


def _request_once(parsed, validated_ip):
    """Issue one bounded GET request to a validated, pinned destination IP."""
    scheme = parsed.scheme
    hostname = parsed.hostname
    port = 443 if scheme == "https" else 80
    if scheme == "https":
        connection = _PinnedHTTPSConnection(
            validated_ip,
            hostname,
            port,
            REQUEST_TIMEOUT_SECONDS,
        )
    else:
        connection = http.client.HTTPConnection(
            validated_ip,
            port=port,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

    host_header = ("[" + hostname + "]") if ":" in hostname else hostname
    try:
        connection.request(
            "GET",
            parsed.path or "/",
            headers={
                "Host": host_header,
                "User-Agent": "Scanner-SafeAudit/4.0 (+https://github.com/Anish-Kushwaha/Scanner)",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        truncated = len(body) > MAX_RESPONSE_BYTES
        if truncated:
            body = body[:MAX_RESPONSE_BYTES]

        headers = {}
        set_cookies = []
        for name, value in response.getheaders():
            key = name.lower()
            if key == "set-cookie":
                if len(set_cookies) < 10:
                    set_cookies.append(value[:512])
            else:
                headers[key] = value[:512]

        tls_info = {"verified": scheme == "https"}
        if scheme == "https" and connection.sock:
            tls_info["version"] = connection.sock.version()
            certificate = connection.sock.getpeercert()
            expires = certificate.get("notAfter")
            if expires:
                expiry_epoch = ssl.cert_time_to_seconds(expires)
                expires_at = datetime.fromtimestamp(expiry_epoch, timezone.utc)
                tls_info["expires_at"] = expires_at.isoformat()
                tls_info["days_remaining"] = (
                    expires_at - datetime.now(timezone.utc)
                ).days

        return {
            "status_code": response.status,
            "reason": response.reason,
            "headers": headers,
            "set_cookies": set_cookies,
            "body": body,
            "truncated": truncated,
            "tls": tls_info,
        }
    except (socket.timeout, TimeoutError, ssl.SSLError, OSError, http.client.HTTPException):
        raise
    finally:
        connection.close()


def _add_finding(findings, kind, risk, description, recommendation, evidence=None):
    item = {
        "type": kind,
        "risk": risk,
        "description": description,
        "recommendation": recommendation,
    }
    if evidence:
        item["evidence"] = evidence
    findings.append(item)


def analyze_security_posture(scheme, headers, set_cookies, body, tls_info, status_code):
    """Create conservative findings from response metadata; never infer exploitability."""
    findings = []
    header = lambda key: headers.get(key.lower(), "")
    server = header("server")
    powered_by = header("x-powered-by")
    csp = header("content-security-policy")
    frame_options = header("x-frame-options")

    security_headers = {
        "Content-Security-Policy": csp or "MISSING",
        "X-Frame-Options": frame_options or "MISSING",
        "X-Content-Type-Options": header("x-content-type-options") or "MISSING",
        "Strict-Transport-Security": (
            header("strict-transport-security") or "MISSING"
        ) if scheme == "https" else "NOT APPLICABLE (HTTP)",
        "Referrer-Policy": header("referrer-policy") or "MISSING",
        "Permissions-Policy": header("permissions-policy") or "MISSING",
    }

    if scheme == "https" and not header("strict-transport-security"):
        _add_finding(
            findings, "Missing HSTS", "MEDIUM",
            "The HTTPS response does not advertise Strict-Transport-Security.",
            "After confirming all subdomains support HTTPS, configure an appropriate HSTS policy.",
        )
    if not csp:
        _add_finding(
            findings, "Missing Content Security Policy", "MEDIUM",
            "The response does not include a Content-Security-Policy header.",
            "Define a restrictive Content Security Policy and test it in report-only mode before enforcement.",
        )
    if not frame_options and "frame-ancestors" not in csp.lower():
        _add_finding(
            findings, "Missing Clickjacking Protection", "MEDIUM",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was detected.",
            "Set X-Frame-Options or an appropriate Content-Security-Policy frame-ancestors directive.",
        )
    if header("x-content-type-options").lower() != "nosniff":
        _add_finding(
            findings, "Missing MIME Sniffing Protection", "LOW",
            "X-Content-Type-Options is absent or is not set to nosniff.",
            "Set X-Content-Type-Options: nosniff.",
        )
    if not header("referrer-policy"):
        _add_finding(
            findings, "Missing Referrer Policy", "LOW",
            "The response does not specify a Referrer-Policy.",
            "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin.",
        )
    if not header("permissions-policy"):
        _add_finding(
            findings, "Missing Permissions Policy", "LOW",
            "The response does not specify a Permissions-Policy.",
            "Explicitly disable browser features that the application does not need.",
        )

    session_name = re.compile(r"(session|sess|auth|token|sid)", re.IGNORECASE)
    for cookie in set_cookies:
        parts = [part.strip() for part in cookie.split(";")]
        cookie_name = parts[0].split("=", 1)[0][:80] if parts else "cookie"
        flags = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}
        is_session_cookie = bool(session_name.search(cookie_name))
        if scheme == "https" and "secure" not in flags:
            _add_finding(
                findings, "Cookie Missing Secure Flag",
                "MEDIUM" if is_session_cookie else "LOW",
                "A cookie was set without the Secure attribute.",
                "Add the Secure attribute to cookies served over HTTPS.",
                evidence={"cookie_name": cookie_name},
            )
        if "httponly" not in flags:
            _add_finding(
                findings, "Cookie Missing HttpOnly Flag",
                "MEDIUM" if is_session_cookie else "LOW",
                "A cookie was set without the HttpOnly attribute.",
                "Add HttpOnly to cookies that do not need JavaScript access.",
                evidence={"cookie_name": cookie_name},
            )
        if not any(part.lower().startswith("samesite=") for part in parts[1:]):
            _add_finding(
                findings, "Cookie Missing SameSite Attribute", "LOW",
                "A cookie was set without an explicit SameSite attribute.",
                "Set an appropriate SameSite policy for the application.",
                evidence={"cookie_name": cookie_name},
            )

    technologies = set()
    server_lower = server.lower()
    powered_lower = powered_by.lower()
    body_lower = body.lower()
    for marker, technology in (
        ("nginx", "nginx"),
        ("apache", "Apache HTTP Server"),
        ("microsoft-iis", "Microsoft IIS"),
        ("cloudflare", "Cloudflare"),
    ):
        if marker in server_lower:
            technologies.add(technology)
    if "php" in powered_lower:
        technologies.add("PHP")
    if "asp.net" in powered_lower:
        technologies.add("ASP.NET")
    if "express" in powered_lower:
        technologies.add("Express")
    if "wp-content" in body_lower or "wp-includes" in body_lower:
        technologies.add("WordPress")
    if "__next" in body_lower:
        technologies.add("Next.js")
    if "data-reactroot" in body_lower or "react-dom" in body_lower:
        technologies.add("React")

    tls = tls_info or {}
    days_remaining = tls.get("days_remaining")
    if isinstance(days_remaining, int) and days_remaining < 30:
        _add_finding(
            findings, "TLS Certificate Expiring Soon",
            "HIGH" if days_remaining < 7 else "MEDIUM",
            f"The verified TLS certificate expires in approximately {max(days_remaining, 0)} days.",
            "Renew the certificate before expiry and verify automated renewal.",
            evidence={"days_remaining": days_remaining},
        )

    if status_code >= 500:
        _add_finding(
            findings, "Server Error Response", "INFO",
            f"The target returned HTTP {status_code}; this is an availability signal, not proof of a security vulnerability.",
            "Review application and server logs for the corresponding request.",
        )

    return {
        "security_headers": security_headers,
        "vulnerabilities": findings,
        "technologies": sorted(technologies),
        "server_info": {
            "server": server or "Not disclosed",
            "powered_by": powered_by or "Not disclosed",
        },
    }


def calculate_risk_level(findings):
    priorities = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    if not findings:
        return "INFO"
    return max(
        (finding.get("risk", "INFO") for finding in findings),
        key=lambda level: priorities.get(level, 0),
    )


def scan_target(raw_target):
    """Fetch one web page and produce a bounded, non-invasive posture report."""
    started = time.monotonic()
    original_url = normalize_target(raw_target)
    current_url = original_url
    visited = set()
    redirects = 0

    for attempt in range(MAX_REDIRECTS + 1):
        parsed = urlsplit(current_url)
        visit_key = (parsed.scheme, parsed.netloc, parsed.path)
        if visit_key in visited:
            raise ScanExecutionError("The target returned a redirect loop.")
        visited.add(visit_key)

        addresses = resolve_public_addresses(parsed.hostname)
        try:
            response = _request_once(parsed, addresses[0])
        except ssl.SSLCertVerificationError:
            raise ScanExecutionError("TLS certificate verification failed.") from None
        except (socket.timeout, TimeoutError):
            raise ScanExecutionError("The target timed out.") from None
        except (ssl.SSLError, OSError, http.client.HTTPException):
            raise ScanExecutionError("The target could not be reached securely.") from None

        location = response["headers"].get("location")
        if response["status_code"] in {301, 302, 303, 307, 308} and location:
            if attempt >= MAX_REDIRECTS:
                raise ScanExecutionError("The target exceeded the redirect limit.")
            next_url = normalize_target(urljoin(current_url, location))
            if parsed.scheme == "https" and urlsplit(next_url).scheme == "http":
                raise TargetValidationError("HTTPS-to-HTTP downgrade redirects are blocked.")
            current_url = next_url
            redirects += 1
            continue
        break
    else:
        raise ScanExecutionError("The target could not be fetched.")

    final_parsed = urlsplit(current_url)
    final_ip = addresses[0]
    body = response["body"].decode("utf-8", errors="replace")
    analysis = analyze_security_posture(
        final_parsed.scheme,
        response["headers"],
        response["set_cookies"],
        body,
        response["tls"],
        response["status_code"],
    )

    safe_headers = {}
    for key in (
        "server", "x-powered-by", "content-type", "content-length",
        "cache-control", "strict-transport-security",
        "content-security-policy", "x-frame-options",
        "x-content-type-options", "referrer-policy", "permissions-policy",
    ):
        if key in response["headers"]:
            safe_headers[key] = response["headers"][key]

    findings = analysis["vulnerabilities"]
    if final_parsed.scheme == "http":
        _add_finding(
            findings, "Unencrypted HTTP", "MEDIUM",
            "The final page is served over unencrypted HTTP.",
            "Serve the application over HTTPS and redirect HTTP requests to HTTPS.",
        )

    duration_ms = round((time.monotonic() - started) * 1000)
    network_info = {
        "domain": final_parsed.hostname,
        "ip": final_ip,
        "port": 443 if final_parsed.scheme == "https" else 80,
        "protocol": final_parsed.scheme,
        "open_ports": [],
        "open_ports_count": None,
        "port_scan_status": "not_performed",
    }

    return {
        "scan_id": "scan_" + uuid.uuid4().hex[:12],
        "target": original_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_type": "Non-invasive HTTP security posture assessment",
        "scan_status": "completed",
        "vulnerabilities": [
            {"id": f"finding_{index:02d}", **finding}
            for index, finding in enumerate(findings, start=1)
        ],
        "network_info": network_info,
        "web_info": {
            "server": analysis["server_info"]["server"],
            "server_info": analysis["server_info"],
            "headers": safe_headers,
            "security_headers": analysis["security_headers"],
            "warnings": [],
            "response_info": {
                "status_code": response["status_code"],
                "url": current_url,
                "redirects": redirects,
                "content_length": len(response["body"]),
                "body_truncated": response["truncated"],
                "duration_ms": duration_ms,
            },
            "tls": response["tls"],
        },
        "geolocation": {"status": "not_collected"},
        "technologies": analysis["technologies"],
        "limitations": [
            "TCP port enumeration is disabled in the public hosted scanner.",
            "Exploit-based SQL injection and XSS tests are disabled.",
            "Directory brute forcing and sensitive-file probing are disabled.",
            "Only the requested page is fetched; query strings are not sent.",
            "A clean result is not proof that a system is secure.",
        ],
        "summary": {
            "total_vulnerabilities": len(findings),
            "risk_level": calculate_risk_level(findings),
            "open_ports": None,
            "port_scan_performed": False,
            "technologies_found": len(analysis["technologies"]),
            "scan_duration_ms": duration_ms,
            "status": "success",
        },
    }


def _rate_limit_key(request_handler):
    value = (
        request_handler.headers.get("x-vercel-forwarded-for")
        or request_handler.headers.get("x-real-ip")
        or request_handler.headers.get("x-forwarded-for")
        or ""
    ).split(",", 1)[0].strip()
    if not value:
        try:
            value = request_handler.client_address[0]
        except (AttributeError, IndexError, TypeError):
            value = "unknown"
    return value[:80]


def _check_rate_limit(key):
    """Best-effort per-runtime fallback; Vercel WAF is the shared edge limiter."""
    now = time.monotonic()
    with _rate_lock:
        events = _rate_events.pop(key, deque())
        while events and now - events[0] >= RATE_WINDOW_SECONDS:
            events.popleft()

        if len(events) >= RATE_LIMIT_REQUESTS:
            retry_after = max(1, int(RATE_WINDOW_SECONDS - (now - events[0])))
            _rate_events[key] = events
            return False, retry_after

        events.append(now)
        _rate_events[key] = events

        # Bound memory even if requests arrive from many one-off source IPs.
        while len(_rate_events) > MAX_RATE_LIMIT_KEYS:
            _rate_events.popitem(last=False)

        return True, 0


class handler(http.server.BaseHTTPRequestHandler):
    """Vercel Python function entry point."""

    def _send_json(self, status, payload, extra_headers=None):
        body = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, str(value))
        self.end_headers()
        self.wfile.write(body)

    def _path(self):
        return urlsplit(self.path).path.rstrip("/") or "/"

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if origin not in ALLOWED_ORIGINS:
            self._send_json(403, {"error": "Origin is not allowed."})
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self._path()
        if path == "/":
            self._send_json(200, {
                "name": "Scanner API",
                "version": VERSION,
                "status": "available",
                "endpoints": {"health": "GET /health", "scan": "POST /api/scan"},
                "scan_mode": "non-invasive HTTP security posture assessment",
                "warning": "Scan only systems you own or are explicitly authorized to assess.",
            })
        elif path == "/health":
            self._send_json(200, {
                "status": "healthy",
                "service": "Scanner API",
                "version": VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        elif path == "/api/scan":
            self._send_json(
                405,
                {"error": "Method not allowed.", "allowed_method": "POST"},
                {"Allow": "POST, OPTIONS"},
            )
        else:
            self._send_json(404, {
                "error": "Endpoint not found.",
                "available_endpoints": ["/", "/health", "/api/scan"],
            })

    def do_POST(self):
        if self._path() != "/api/scan":
            self._send_json(404, {"error": "Endpoint not found."})
            return

        origin = self.headers.get("Origin")
        if origin not in ALLOWED_ORIGINS:
            self._send_json(403, {
                "error": "Requests must come from the approved Scanner web application."
            })
            return

        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length or "0")
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length."})
            return
        if content_length <= 0:
            self._send_json(400, {"error": "A JSON request body is required."})
            return
        if content_length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "Request body is too large."})
            return

        try:
            data = json.loads(self.rfile.read(content_length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "Invalid JSON request body."})
            return
        if not isinstance(data, dict):
            self._send_json(400, {"error": "JSON body must be an object."})
            return
        if data.get("authorization_confirmed") is not True:
            self._send_json(403, {
                "error": "Confirm that you own the target or have explicit permission to assess it."
            })
            return

        allowed, retry_after = _check_rate_limit(_rate_limit_key(self))
        if not allowed:
            self._send_json(
                429,
                {"error": "Scan rate limit reached. Please try again later."},
                {"Retry-After": retry_after},
            )
            return

        try:
            result = scan_target(data.get("target"))
            self._send_json(200, result)
        except TargetValidationError as error:
            self._send_json(400, {"error": str(error)})
        except ScanExecutionError as error:
            self._send_json(502, {"error": str(error)})
        except Exception:
            print("[scanner] Unexpected scan failure", flush=True)
            self._send_json(500, {"error": "An internal scanner error occurred."})

    def _method_not_allowed(self):
        self._send_json(
            405,
            {"error": "Method not allowed.", "allowed_methods": ["GET", "POST", "OPTIONS"]},
            {"Allow": "GET, POST, OPTIONS"},
        )

    def do_PUT(self):
        self._method_not_allowed()

    def do_PATCH(self):
        self._method_not_allowed()

    def do_DELETE(self):
        self._method_not_allowed()


if __name__ == "__main__":
    print(f"Scanner API {VERSION}; deploy with Vercel's Python runtime.")
