# Scanner online worker deployment

The Vercel app is the dashboard/API gateway. Long-running Nmap/ZAP/Trivy tasks must run on a separate private worker. This folder contains the worker HTTP service and Docker image.

## Required worker secrets and scope

Set these environment variables on the worker host:

- `SCANNER_WORKER_TOKEN`: random secret with at least 32 characters.
- `SCANNER_ALLOWED_TARGETS`: exact hostnames/IPs and explicitly authorized CIDRs, comma separated.
- `SCANNER_WORKER_HOST=0.0.0.0`
- `SCANNER_WORKER_PORT=8787`
- `SCANNER_JOB_DIR=/data/jobs` on a persistent volume.

Run behind HTTPS and firewall the worker so only the Vercel gateway can reach it. Never expose the token in browser JavaScript or an Android APK.

## Vercel gateway variables

Set the following on the Vercel project (Preview and Production):

- `SCANNER_WORKER_URL`: HTTPS base URL of the private worker.
- `SCANNER_WORKER_TOKEN`: the same secret as the worker.

Redeploy Vercel after adding variables. The dashboard calls only same-origin `/api/worker`; the gateway forwards requests and adds the secret server-side.

## Deploy with Docker

```bash
docker build -t scanner-worker .
docker run -d --restart unless-stopped --name scanner-worker \
  -p 127.0.0.1:8787:8787 \
  -v scanner-jobs:/data/jobs \
  -e SCANNER_WORKER_TOKEN="$SCANNER_WORKER_TOKEN" \
  -e SCANNER_ALLOWED_TARGETS="app.example.com,192.0.2.0/28" \
  -e SCANNER_WORKER_HOST=0.0.0.0 \
  scanner-worker
```

Place a TLS reverse proxy in front of the worker and restrict inbound traffic. The worker has two concurrent jobs and persists JSON job records on its volume. It is a single-host queue, not a distributed enterprise queue.

## Online modules

- Web posture and same-origin crawl
- Nmap TCP port/service detection (passive/standard/advanced port profiles)
- Optional OS detection and top-20 UDP scan (root privileges required)
- TLS and cookie/security-header checks
- Optional ZAP baseline mode via Docker (the image must be installed and the Docker socket securely available; otherwise it reports unavailable)
- ZIP source/configuration inspection and optional Trivy (install Trivy into the image to enable)
- JSON report with CSV export in the browser

The API requires a bearer token between Vercel and the worker. The browser never receives it. The authorization checkbox is an attestation, not identity proof. A public commercial service still requires real user accounts, per-user permissions, stronger quotas, audit retention and incident monitoring.


## Vercel Sandbox deployment

The Scanner worker runs in a named, persistent Vercel Sandbox. The Vercel serverless gateway uses the `@vercel/sandbox` SDK to retrieve or resume that sandbox on demand, verify the worker process, and then proxy authenticated job requests. The browser and Android app never receive the worker bearer token.

- Sandbox name: `scanner-worker`
- Region: `bom1` (Mumbai)
- Compute: 1 vCPU / 2 GB RAM
- Exposed worker port: `8080`
- Filesystem: persistent snapshots enabled; one latest snapshot retained
- Snapshot retention: 7 days
- Session timeout: 45 minutes (Hobby-compatible)
- Vercel project OIDC token generation is enabled for the server-side Sandbox SDK.
- The bearer token is stored as a sensitive Vercel Preview environment variable and is not committed here.

The current worker scope is deliberately restricted to the exact Scanner preview hostname and `scanme.nmap.org` for safe Nmap validation. Add only targets for which the operator has written authorization. The gateway passes the configured `SCANNER_ALLOWED_TARGETS` allowlist into the worker every time it starts.

**Lifecycle and cost:** a session is not an always-on server. It stops at its configured timeout; the next dashboard API request resumes the named sandbox from its latest snapshot and starts the worker again. This provides on-demand availability without a permanently running VM, but the first request after a stop can take longer and compute/snapshot/network usage may be billable. It is not an always-on production SLA or a distributed job queue.
