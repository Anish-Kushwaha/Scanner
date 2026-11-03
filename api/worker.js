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

async function getWorkerBase() {
  const token = process.env.SCANNER_WORKER_TOKEN || "";
  const allowedTargets = process.env.SCANNER_ALLOWED_TARGETS || "";
  if (token.length < 32 || !allowedTargets.trim()) {
    const error = new Error("The Vercel preview environment is missing the worker token or authorized target allowlist.");
    error.code = "worker_not_configured";
    throw error;
  }

  if (cachedWorkerBase && Date.now() - cachedAt < 15_000) {
    try {
      const cachedHealth = await fetch(cachedWorkerBase + "/health", {
        cache: "no-store",
        signal: AbortSignal.timeout(2000)
      });
      if (cachedHealth.ok) return cachedWorkerBase;
    } catch {}
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

    const bootstrap = [
      "import json, os, pathlib, subprocess, sys, time, urllib.error, urllib.request",
      "root = '/vercel/Scanner'",
      "if not os.path.isfile(root + '/worker_server.py'): raise SystemExit('Scanner worker source is missing')",
      "job_dir = os.environ.get('SCANNER_JOB_DIR', root + '/.scanner-jobs')",
      "pathlib.Path(job_dir).mkdir(parents=True, exist_ok=True)",
      "token = os.environ.get('SCANNER_WORKER_TOKEN', '')",
      "if len(token) < 32: raise SystemExit('Scanner worker token is missing or too short')",
      "token_file = pathlib.Path(job_dir) / '.worker-token'",
      "token_file.write_text(token, encoding='utf-8')",
      "os.chmod(token_file, 0o600)",
      "def healthy():",
      "    try:",
      "        with urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=1) as response:",
      "            health = json.loads(response.read().decode('utf-8'))",
      "            if response.status != 200 or not health.get('nmap_privileges'): return False",
      "        request = urllib.request.Request('http://127.0.0.1:8080/v1/jobs/00000000-0000-0000-0000-000000000000', headers={'Authorization': 'Bearer ' + token})",
      "        try:",
      "            urllib.request.urlopen(request, timeout=1)",
      "        except urllib.error.HTTPError as error:",
      "            return error.code == 404",
      "        return False",
      "    except Exception:",
      "        return False",
      "if not healthy():",
      "    subprocess.run(['sudo', '-n', 'pkill', '-f', '[w]orker_server.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)",
      "    time.sleep(0.25)",
      "    log = open(root + '/worker.log', 'ab', buffering=0)",
      "    subprocess.Popen(['sudo', '-n', '-E', sys.executable, 'worker_server.py'], cwd=root, env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)",
      "    log.close()",
      "for _ in range(40):",
      "    if healthy(): sys.exit(0)",
      "    time.sleep(0.25)",
      "print('Scanner worker did not become healthy', file=sys.stderr)",
      "sys.exit(1)"
    ].join("\n");

    const boot = await sandbox.runCommand({
      cmd: "python3",
      args: ["-c", bootstrap],
      env: {
        SCANNER_WORKER_HOST: "0.0.0.0",
        SCANNER_WORKER_PORT: "8080",
        SCANNER_WORKER_TOKEN: token,
        SCANNER_ALLOWED_TARGETS: allowedTargets,
        SCANNER_JOB_DIR: "/vercel/Scanner/.scanner-jobs"
      }
    });
    if (boot.exitCode !== 0) throw new Error("The Scanner worker could not be started in its Vercel Sandbox.");

    const base = sandbox.domain(8080);
    const health = await fetch(base + "/health", {
      cache: "no-store",
      signal: AbortSignal.timeout(8000)
    });
    if (!health.ok) throw new Error("The resumed Scanner worker did not pass its health check.");

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
        ? "The advanced scanning worker is not configured for this preview deployment."
        : "The Vercel Sandbox worker could not be resumed or reached.",
      code
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
