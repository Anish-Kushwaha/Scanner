# Scanner

**Scanner is a professional, low-impact website security posture assessment tool.**

- Web application: https://scanner-rose-rho.vercel.app
- API health: https://scanner-rose-rho.vercel.app/health
- Repository: https://github.com/Anish-Kushwaha/Scanner

## Product scope

Scanner inspects one public HTTP(S) page and reports observable security configuration signals:

- HTTP response security headers: Content Security Policy, HSTS, clickjacking controls, MIME sniffing, Referrer Policy and Permissions Policy.
- Cookie attributes: Secure, HttpOnly and SameSite. Cookie values are never written to findings.
- TLS certificate verification, protocol version and expiry window.
- Response status, redirect count, bounded server metadata and selected technology hints.

The interface does not invent findings when the API fails. An unsuccessful request remains an error and no synthetic scan result is stored.

## Safety model

The public endpoint is intentionally non-invasive:

- Only HTTP and HTTPS on standard ports 80 and 443.
- Only globally routable public IP destinations; private, loopback, link-local, multicast, reserved and unspecified addresses are blocked.
- Every DNS answer is checked, connections are pinned to a validated address, and redirect destinations are validated again.
- HTTPS certificate validation is enabled. HTTPS-to-HTTP downgrade redirects are rejected.
- Maximum two redirects, bounded request body and response body, and short request timeouts.
- Query strings and fragments are discarded.
- No TCP port scanning, service enumeration, directory brute forcing, file probing, SQL injection payloads, XSS payloads, or exploitation.

This is not a full penetration test. Findings are configuration signals that need context and manual validation. No findings does not mean a system is secure.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | / | Web application |
| GET | /health | API health |
| POST | /api/scan | Run an assessment |
| OPTIONS | /api/scan | CORS preflight |

Example JSON request:

    {
      "target": "https://example.com",
      "authorization_confirmed": true
    }

The authorization flag is an explicit user attestation, not identity verification or strong authentication. Browser-origin checks are a CORS control, not an authentication boundary; non-browser clients can forge an Origin header. Vercel Firewall is enabled for this project with a shared fixed-window rule limiting POST requests to /api/scan to 10 requests per client IP per 60 seconds. The in-process rate limit is an additional best-effort safeguard, not a durable shared quota. The authorization flag and browser-origin checks are not strong authentication. Before offering unrestricted public or commercial access, add authenticated API credentials, usage monitoring and an abuse-response process.

### Status codes

- 200 completed assessment.
- 400 invalid target or blocked destination.
- 403 origin or authorization attestation rejected.
- 405 unsupported method.
- 413 request body too large.
- 429 in-process rate limit reached.
- 502 target could not be reached safely.
- 500 generic internal scanner error.

## Development

Requirements: Python 3.12+, Node.js 22+ for frontend syntax checks.

    python -m py_compile api/index.py tests/test_scanner.py
    python -m unittest discover -s tests -v
    python tests/check_frontend.py

GitHub Actions runs these checks on pushes and pull requests. Tests cover URL validation, private and mixed DNS rejection, redirect safety, TLS/header/cookie analysis, authorization, CORS, request limits, rate limiting, and truthful report semantics.

## Vercel

The root HTML pages are served statically and api/index.py is deployed as a Python function. The Vercel configuration applies security headers and routes /health and /api/scan to the function while leaving static page delivery to the filesystem.

After deployment, verify:

    curl -i https://scanner-rose-rho.vercel.app/
    curl -i https://scanner-rose-rho.vercel.app/health
    curl -i https://scanner-rose-rho.vercel.app/api/scan

The last request should return 405 Method Not Allowed because the scan endpoint accepts POST only.

Allowed browser origins are configured in api/index.py. The production origin and GitHub Pages origin are included; same-origin Vercel previews are allowed for their own preview host only.

## Android

The android/ project wraps the same-origin Scanner web application in a hardened Android WebView. It disables file/content access and mixed content, enables Safe Browsing where supported, restricts in-app navigation to the Scanner host, and opens other HTTPS links externally.

Build a debug APK with JDK 17 and Android SDK:

    cd android
    gradle --no-daemon assembleDebug

The APK is produced at android/app/build/outputs/apk/debug/app-debug.apk. GitHub Actions builds and uploads the unsigned debug APK as a workflow artifact. A signed release build requires a keystore stored outside Git and configured with protected CI secrets.

## Responsible use

Only assess systems you own or have explicit permission to assess. The confirmation checkbox records user attestation but cannot independently verify authorization. Respect the target owner's scope, rate limits and operating requirements.

## License

MIT. See LICENSE.md.
