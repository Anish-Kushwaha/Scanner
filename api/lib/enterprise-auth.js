import { createHmac } from "node:crypto";

function bearer(req) {
  const header = String(req.headers.authorization || "");
  const match = header.match(/^Bearer\s+([A-Za-z0-9._~-]+)$/i);
  if (!match) throw Object.assign(new Error("Sign in with an approved ANISH ENTERPRISES account."), { status: 401, code: "authentication_required" });
  return match[1];
}

function config() {
  const url = process.env.SUPABASE_URL || "";
  const key = process.env.SUPABASE_PUBLISHABLE_KEY || "";
  const secret = process.env.SCANNER_SCOPE_SIGNING_SECRET || "";
  if (!url || !key || secret.length < 48) {
    throw Object.assign(new Error("Enterprise authorization is not configured on the gateway."), { status: 503, code: "enterprise_auth_unconfigured" });
  }
  return { url: url.replace(/\/$/, ""), key, secret };
}

async function edgeCall(req, payload) {
  const cfg = config();
  const accessToken = bearer(req);
  const response = await fetch(cfg.url + "/functions/v1/authorize-assessment", {
    method: "POST",
    headers: {
      apikey: cfg.key,
      Authorization: "Bearer " + accessToken,
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify(payload),
    cache: "no-store",
    signal: AbortSignal.timeout(12_000)
  });
  const raw = await response.text();
  let data;
  try { data = JSON.parse(raw); } catch { data = null; }
  if (!response.ok) {
    const error = new Error(data?.error || "ANISH ENTERPRISES authorization denied this request.");
    error.status = response.status;
    error.code = data?.code || "enterprise_authorization_denied";
    throw error;
  }
  return data;
}

function signGrant(claims, secret) {
  const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return encoded + "." + signature;
}

export async function authorizeAssessment(req, payload) {
  const cfg = config();
  const response = await edgeCall(req, { ...payload, action: "authorize_scan" });
  if (!response?.authorized || !response?.grant?.job_id) {
    throw Object.assign(new Error("The enterprise authorization service returned an invalid grant."), { status: 502, code: "invalid_engagement_grant" });
  }
  return { ...response.grant, signed_grant: signGrant(response.grant, cfg.secret) };
}

export async function authorizeHealth(req) {
  const response = await edgeCall(req, { action: "authorize_health" });
  if (!response?.authorized) throw Object.assign(new Error("Approved organization access is required."), { status: 403, code: "organization_access_denied" });
  return response;
}

export async function authorizeJobStatus(req, jobId) {
  const response = await edgeCall(req, { action: "authorize_job_status", job_id: jobId });
  if (!response?.authorized || !response?.worker_job_id) {
    throw Object.assign(new Error("You cannot access this assessment."), { status: 403, code: "job_access_denied" });
  }
  return response.worker_job_id;
}
