import { Sandbox } from "@vercel/sandbox";

export const config = { api: { bodyParser: false } };

const SANDBOX_NAME = process.env.SCANNER_SANDBOX_NAME || "scanner-worker";
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 10;
const rateBuckets = new Map();

let cachedWorkerBase = "";
let cachedAt = 0;
let sandboxRequest = null;

function sendJson(res, status, payload, headers = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  for (const [key, value] of Object.entries(headers)) res.setHeader(key, value);
  res.end(JSON.stringify(payload));
}

function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return false;

  const forwardedHost = req.headers["x-forwarded-host"] || req.headers.host || "";
  const requestHost = String(forwardedHost).split(",")[0].trim().split(":")[0].toLowerCase();
  try {
    const parsed = new URL(origin);
    if (parsed.protocol === "https:" && parsed.hostname.toLowerCase() === requestHost && parsed.host.toLowerCase() === requestHost) {
      return true;
    }
  } catch {}

  const allowed = (process.env.SCANNER_ALLOWED_ORIGINS || "https://anish-kushwaha.github.io,https://scanner-rose-rho.vercel.app")
    .split(",").map((item) => item.trim()).filter(Boolean);
  return allowed.includes(origin);
}

function clientKey(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return String(forwarded).split(",")[0].trim().slice(0, 80);
  return String(req.socket?.remoteAddress || "unknown").slice(0, 80);
}

function checkRateLimit(req) {
  const key = clientKey(req);
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.startedAt >= RATE_WINDOW_MS) {
    bucket = { startedAt: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (rateBuckets.size > 4096) {
    for (const [ip, value] of rateBuckets) {
      if (now - value.startedAt >= RATE_WINDOW_MS) rateBuckets.delete(ip);
    }
  }
  return bucket.count <= RATE_LIMIT;
}

async function readBody(req) {
  const declared = Number(req.headers["content-length"] || 0);
  if (declared > MAX_BODY_BYTES) return null;
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += part.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(part);
  }
  return Buffer.concat(chunks);
}

async function workerHealth(base, expectedSha) {
  try {
    const response = await fetch(base + "/health", {
      cache: "no-store",
      signal: AbortSignal.timeout(2500)
    });
    if (!response.ok) return false;
    const health = await response.json();
    return health?.status === "healthy"
      && health?.nmap_privileges === true
      && (!expectedSha || health?.source_sha === expectedSha);
  } catch {
    return false;
  }
}

async function getWorkerBase() {
  const token = process.env.SCANNER_WORKER_TOKEN || "";
  const allowedTargets = process.env.SCANNER_ALLOWED_TARGETS || "";
  if (token.length < 32 || !allowedTargets.trim()) {
    const error = new Error("The Vercel preview environment is missing the worker token or authorized target allowlist.");
    error.code = "worker_not_configured";
    throw error;
  }

  const expectedSha = process.env.VERCEL_GIT_COMMIT_SHA || "";
  if (cachedWorkerBase && Date.now() - cachedAt < 15_000) {
    if (await workerHealth(cachedWorkerBase, expectedSha)) return cachedWorkerBase;
    cachedWorkerBase = "";
    cachedAt = 0;
  }
  if (sandboxRequest) return sandboxRequest;

  sandboxRequest = (async () => {
    const sandbox = await Sandbox.getOrCreate({
      name: SANDBOX_NAME,
      runtime: "node22",
      resources: { vcpus: 1 },
      ports: [8080],
      region: "bom1",
      timeout: 45 * 60 * 1000,
      persistent: true,
      snapshotExpiration: 7 * 24 * 60 * 60 * 1000,
      keepLastSnapshots: { count: 1, deleteEvicted: true },
      networkPolicy: { mode: "allow-all" },
      tags: { app: "scanner", role: "worker" },
      onCreate: async (sbx) => {
        const setup = await sbx.runCommand({
          cmd: "bash",
          args: ["-lc", "git clone --depth 1 --branch scanner-platform-v2 https://github.com/Anish-Kushwaha/Scanner.git /vercel/Scanner && sudo apt-get update -qq && sudo apt-get install -y -qq nmap && mkdir -p /vercel/Scanner/.scanner-jobs"],
          timeout: 600000
        });
        if (setup.exitCode !== 0) throw new Error("Unable to prepare the Scanner worker sandbox.");
      }
    });

    const sourceSha = process.env.VERCEL_GIT_COMMIT_SHA || "";
    if (!/^[a-f0-9]{40}$/.test(sourceSha)) {
      throw new Error("The deployment Git commit SHA is unavailable; cannot pin the worker source safely.");
    }

    // Keep the persistent Sandbox's code in lockstep with this exact deployment.
    const sync = await sandbox.runCommand({
      cmd: "bash",
      args: ["-lc", "set -e; cd /vercel/Scanner; if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then git init -q; fi; git remote get-url origin >/dev/null 2>&1 || git remote add origin https://github.com/Anish-Kushwaha/Scanner.git; git fetch --depth=1 origin " + sourceSha + " && git reset --hard " + sourceSha],
      timeout: 180000
    });
    if (sync.exitCode !== 0) {
      throw new Error("Unable to update the persistent worker source to this deployment commit.");
    }

    const boot = await sandbox.runCommand({
      cmd: "python3",
      args: ["scripts/bootstrap_worker.py"],
      cwd: "/vercel/Scanner",
      env: {
        SCANNER_WORKER_HOST: "0.0.0.0",
        SCANNER_WORKER_PORT: "8080",
        SCANNER_WORKER_TOKEN: token,
        SCANNER_ALLOWED_TARGETS: allowedTargets,
        SCANNER_JOB_DIR: "/vercel/Scanner/.scanner-jobs",
        SCANNER_SOURCE_SHA: sourceSha
      },
      timeout: 600000
    });
    if (boot.exitCode !== 0) {
      throw new Error("The Scanner worker bootstrap failed its serialized startup and authenticated health checks.");
    }

    const base = sandbox.domain(8080);
    if (!(await workerHealth(base, sourceSha))) {
      throw new Error("The resumed Scanner worker failed health, root-privilege, or source-version verification.");
    }

    cachedWorkerBase = base;
    cachedAt = Date.now();
    return base;
  })().finally(() => {
    sandboxRequest = null;
  });

  return sandboxRequest;
}

async function proxyToWorker(req, res, method, path, payload) {
  try {
    const base = await getWorkerBase();
    const token = process.env.SCANNER_WORKER_TOKEN;
    const response = await fetch(base + path, {
      method,
      headers: {
        Authorization: "Bearer " + token,
        Accept: "application/json",
        ...(payload === undefined ? {} : { "Content-Type": "application/json" })
      },
      body: payload === undefined ? undefined : JSON.stringify(payload),
      cache: "no-store",
      signal: AbortSignal.timeout(12_000)
    });
    const raw = await response.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_RESPONSE_BYTES) {
      return sendJson(res, 502, { error: "Worker response exceeded the gateway limit." });
    }
    let result;
    try {
      result = JSON.parse(raw);
    } catch {
      return sendJson(res, 502, { error: "Worker returned an invalid response." });
    }
    return sendJson(res, response.status, result);
  } catch (error) {
    const code = error?.code === "worker_not_configured" ? "worker_not_configured" : "worker_unavailable";
    const status = code === "worker_not_configured" ? 503 : 502;
    return sendJson(res, status, {
      error: code === "worker_not_configured"
        ? "The advanced scanning worker is not configured for this deployment."
        : "The Vercel Sandbox worker could not be resumed or reached.",
      code,
      detail: String(error?.message || "Unknown worker startup error.").slice(0, 240)
    });
  }
}

export default async function handler(req, res) {
  const url = new URL(req.url || "/api/worker", "https://" + (req.headers.host || "localhost"));
  if (req.headers.origin && originAllowed(req)) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader("Vary", "Origin");
  }

  if (req.method === "OPTIONS") {
    if (!originAllowed(req)) return sendJson(res, 403, { error: "Origin is not allowed." });
    res.statusCode = 204;
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Max-Age", "600");
    return res.end();
  }

  if (req.method === "GET") {
    if (req.headers.origin && !originAllowed(req)) return sendJson(res, 403, { error: "Origin is not allowed." });
    const jobId = url.searchParams.get("job_id") || "";
    if (jobId && !/^[a-f0-9-]{36}$/.test(jobId)) return sendJson(res, 400, { error: "Invalid job identifier." });
    return proxyToWorker(req, res, "GET", jobId ? "/v1/jobs/" + jobId : "/health");
  }

  if (req.method === "POST") {
    if (!originAllowed(req)) return sendJson(res, 403, { error: "Requests must come from the Scanner web application." });
    const raw = await readBody(req);
    if (!raw) return sendJson(res, 413, { error: "Request body missing or larger than 4 MB." });
    let payload;
    try {
      payload = JSON.parse(raw.toString("utf8"));
    } catch {
      return sendJson(res, 400, { error: "Invalid JSON request." });
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload) || payload.authorization_confirmed !== true) {
      return sendJson(res, 403, { error: "Confirm that you own the target or have explicit authorization." });
    }
    if (!checkRateLimit(req)) return sendJson(res, 429, { error: "Rate limit reached." }, { "Retry-After": "60" });
    return proxyToWorker(req, res, "POST", "/v1/jobs", payload);
  }

  res.setHeader("Allow", "GET, POST, OPTIONS");
  return sendJson(res, 405, { error: "Method not allowed." });
}
