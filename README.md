# Scanner v4.0

**A low-impact HTTP security posture checker with a GitHub Pages frontend and a Vercel Python API.**

Live interface and backend: https://scanner-rose-rho.vercel.app  
Backend health: https://scanner-rose-rho.vercel.app/health  
Source: https://github.com/Anish-Kushwaha/Scanner

## What it does

Scanner v4 performs a bounded, non-invasive review of a single public HTTP(S) page:

- Validates target URLs, DNS answers, and redirect destinations.
- Blocks private, loopback, link-local, reserved, and other non-global IP ranges.
- Pins requests to validated IP addresses to reduce DNS-rebinding and time-of-check/time-of-use risk.
- Verifies TLS certificates and reports certificate expiry information when available.
- Reviews HTTP security headers and cookie security attributes.
- Uses request timeouts, redirect limits, response-size limits, and bounded request bodies.
- Produces a JSON assessment report for download or sharing.

The report page reads the most recent versioned report stored in the same browser. It does not launch a second scan.

## Deliberate scope limits

The public hosted service is **not** a full penetration-testing platform. It does not:

- Enumerate TCP ports or perform banner sweeps.
- Send SQL injection, XSS, authentication-bypass, or other exploit payloads.
- Brute-force directories, files, or administrative endpoints.
- Probe private infrastructure or non-standard ports.
- Collect IP geolocation from third-party services.

A finding is a signal for manual review, not proof of exploitability. Likewise, a clean report is not proof that a target is secure. Missing headers can be context-dependent and must be evaluated against the application's requirements.

## API

Base URL: `https://scanner-rose-rho.vercel.app`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Service metadata and available routes |
| GET | `/health` | Health check |
| POST | `/api/scan` | Run a low-impact HTTP posture assessment |
| OPTIONS | `/api/scan` | Browser CORS preflight |

Example request:

```http
POST /api/scan HTTP/1.1
Content-Type: application/json
Origin: https://anish-kushwaha.github.io

{
  "target": "https://example.com",
  "authorization_confirmed": true
}
```

The `authorization_confirmed` flag is an explicit user attestation, **not** strong authentication. The API currently permits the configured browser origin and applies a best-effort per-runtime rate limit. In addition, the active Vercel WAF rule limits `POST /api/scan` to 10 requests per client IP per 60-second fixed window; it does not throttle the health endpoint. Browser CORS is not an authorization boundary: non-browser clients can forge an Origin header. The edge WAF limit is the primary shared rate control; the in-process limit is only a secondary per-runtime safeguard. For broad public or commercial use, add authenticated accounts/API tokens, usage monitoring, and a durable abuse-response process.

### Response behavior

- `200`: completed assessment.
- `400`: malformed target, unsupported scheme/port, or blocked DNS destination.
- `403`: origin or authorization confirmation rejected.
- `405`: unsupported HTTP method.
- `413`: request body too large.
- `429`: runtime rate limit reached; check `Retry-After`.
- `502`: destination could not be reached safely.
- `500`: generic internal scanner error. Sensitive exception details are not returned.

Only HTTP/HTTPS on standard ports 80/443 are supported. The service discards query strings and fragments from scan requests so it does not submit arbitrary application actions or query parameters.

## Configuration

The default allowed browser origin is:

```text
https://anish-kushwaha.github.io
```

Set the Vercel environment variable `SCANNER_ALLOWED_ORIGINS` to a comma-separated list of exact origins only when an additional frontend origin is intentionally deployed. Do not include paths or trailing slashes.

The backend uses Python's standard library only. `requirements.txt` is intentionally dependency-free.

## Development and tests

Requirements: Python 3.12 or newer.

```bash
python -m unittest discover -s tests -v
python -m py_compile api/index.py
```

The GitHub Actions workflow `.github/workflows/backend-tests.yml` runs the regression suite when backend files change. It covers URL validation, private-IP and mixed-DNS rejection, conservative header/cookie findings, redirect safety, and honest reporting of disabled port scanning.

## Vercel deployment

The repository is configured for Vercel's Python runtime. All routes are dispatched to `api/index.py`, which normalizes paths before routing so a trailing slash or query string does not accidentally turn a valid endpoint into a 404.

After deployment, verify:

```bash
curl -i https://scanner-rose-rho.vercel.app/
curl -i https://scanner-rose-rho.vercel.app/health
curl -i https://scanner-rose-rho.vercel.app/api/scan
```

The third request should return `405 Method Not Allowed` because the scan endpoint accepts POST only.

## Android app

The repository includes an Android WebView container under `android/`. It loads the hosted Scanner interface; the backend is still hosted separately on Vercel.

Build a debug APK with JDK 17 and Android SDK installed:

```bash
cd android
gradle --no-daemon assembleDebug
```

Output: `android/app/build/outputs/apk/debug/app-debug.apk`.

GitHub Actions builds the debug APK on relevant pushes and pull requests. The generated debug APK is unsigned and intended for testing. A signed release requires a keystore kept outside Git and configured through protected CI secrets.

## Responsible use

Only assess systems you own or have explicit permission to assess. The checkbox in the interface records that confirmation but cannot independently verify ownership. Respect the target owner's scope, rate limits, and operating requirements.

## License

MIT. See [LICENSE.md](LICENSE.md).
