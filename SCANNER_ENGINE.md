# Scanner Platform Engine (v5)

This is the dedicated Python worker for private, authorized assessments. The Vercel-hosted UI remains a control/reporting frontend; **do not run Nmap, ZAP, Trivy, or long-running scans inside a Vercel Function**. Deploy this worker on a private Linux VM/container and connect it to an authenticated job queue/API before exposing scan controls to the UI.

## Scope gate — required

Configure exact hostnames/IPs and/or CIDR blocks in the worker environment:

```bash
export SCANNER_ALLOWED_TARGETS="app.example.com,203.0.113.10,192.0.2.0/24"
```

CIDR scans are limited to 256 addresses and must be contained within an explicitly allowlisted network. A hostname must be explicitly allowlisted. The CLI also requires an explicit `--authorized` attestation. Do not put third-party or public targets in the allowlist unless you have written authorization and a defined scope.

## Install

Python 3.10+ is sufficient for the standard-library engine. Install optional tools on the Linux worker:

- Nmap: host discovery, bounded TCP port scan, service/version detection; optional OS detection and top-20 UDP scan require root.
- Docker: optional OWASP ZAP baseline integration. This runs the baseline/passive workflow, not the active attack scan.
- Trivy: optional local source/configuration, dependency, misconfiguration and secret scan.

Example on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y nmap
# Install Docker and Trivy from their official vendor instructions if required.
```

## Usage

Single host/web application:

```bash
python scanner_engine.py https://app.example.com --authorized --profile standard --zap-baseline
```

Bounded, explicitly authorized network:

```bash
python scanner_engine.py 192.0.2.0/28 --authorized --profile standard
```

Optional OS fingerprinting/UDP checks (requires root and explicit authorization):

```bash
sudo -E python scanner_engine.py 192.0.2.0/28 --authorized --os-detect --udp
```

Local repository/infrastructure assessment:

```bash
python scanner_engine.py https://app.example.com --authorized --local-path ./source
```

Outputs: JSON report and a companion CSV findings register. The report includes capability flags, timestamps, scan scope, evidence, confidence, remediation and limitations.

## Implemented in this worker

- Exact hostname/IP/CIDR allowlist enforcement and bounded CIDR expansion.
- DNS resolution and target validation.
- Nmap TCP top-port discovery, service/version fingerprints, optional OS fingerprinting and optional top-20 UDP scan.
- HTTP same-origin crawling with bounded depth/pages; GET-only requests; skips obvious logout/delete links.
- Security header, cookie-attribute, TLS certificate/protocol and basic server-banner checks.
- Safe well-known resource/API-documentation discovery (robots, sitemap, security.txt, OpenAPI/Swagger paths).
- Optional OWASP ZAP baseline/passive scan through Docker.
- Local Docker/Kubernetes configuration heuristics and redacted potential-secret detection.
- Optional Trivy filesystem scan for vulnerabilities, misconfiguration and secrets.
- Evidence-backed findings, confidence labels, heuristic prioritization score, JSON and CSV export.

## Not yet implemented / requires additional integrations

The worker intentionally does not claim feature parity with Nmap, ZAP, Nessus, or commercial ASM platforms. The following require separately designed connectors, data feeds, authentication, and/or infrastructure:

- Durable team identity, SSO/OAuth, RBAC, approvals, audit log storage and encrypted secrets.
- Job queue, distributed worker fleet, pause/resume/cancel, quotas, notifications and scheduled scans.
- Full IPv6/CIDR asset management, passive subdomain intelligence and certificate-transparency ingestion.
- Comprehensive UDP fingerprinting, traceroute/topology visualization and specialized protocol enumeration (SMB, SNMP, SMTP, RDP, database-specific checks).
- CVE enrichment against a maintained vulnerability database; Nmap service version alone is not a CVE confirmation.
- Authenticated web testing, IDOR/BOLA tests with multiple authorized test accounts, API schema fuzzing and WebSocket testing.
- Cloud-provider APIs, live Kubernetes cluster assessment, container registry/image workflows and CI/CD integrations.
- SARIF/XML/PDF exports, historical diffing, finding lifecycle workflow and dashboard analytics.

These are not represented as completed capabilities in the report. No scan result should be labelled "all vulnerabilities tested".

## Safety boundaries

The worker does not run exploit payloads, credential brute force, persistence, evasion, destructive tests, denial-of-service checks, or arbitrary Nmap NSE scripts. ZAP is invoked in baseline/passive mode only. Nmap version detection and OS fingerprinting can generate network traffic; use conservative rates and the owner's maintenance window. Local secret findings redact matched values.

The current script is a single-worker CLI, not a multi-user web service. Do not expose it directly to the internet. A production team deployment needs authenticated API/job orchestration, a private network, per-user authorization, durable logs, secret management, and an emergency stop.
