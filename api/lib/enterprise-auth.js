import crypto from "node:crypto";

const REQUIRED = ["SUPABASE_URL","SUPABASE_ANON_KEY","SUPABASE_SERVICE_ROLE_KEY","SCANNER_SCOPE_SIGNING_SECRET"];

function config() {
  const missing = REQUIRED.filter((key) => !process.env[key]);
  if (missing.length) throw Object.assign(new Error("Enterprise identity is not configured."), { status: 503, code: "enterprise_auth_unconfigured" });
  return {
    url: process.env.SUPABASE_URL.replace(/\/$/, ""),
    anon: process.env.SUPABASE_ANON_KEY,
    service: process.env.SUPABASE_SERVICE_ROLE_KEY,
    signing: process.env.SCANNER_SCOPE_SIGNING_SECRET
  };
}

async function jsonFetch(url, headers, options = {}) {
  const response = await fetch(url, { ...options, headers: { ...headers, ...(options.headers || {}) }, cache: "no-store", signal: AbortSignal.timeout(8000) });
  const raw = await response.text();
  let data = null;
  try { data = raw ? JSON.parse(raw) : null; } catch {}
  if (!response.ok) throw Object.assign(new Error("Enterprise authorization service rejected the request."), { status: response.status === 401 ? 401 : 403, code: "enterprise_authorization_denied" });
  return data;
}

export async function authorizeAssessment(req, payload) {
  const cfg = config();
  const header = String(req.headers.authorization || "");
  const match = header.match(/^Bearer\s+([A-Za-z0-9._~-]+)$/i);
  if (!match) throw Object.assign(new Error("Sign in with an approved ANISH ENTERPRISES account."), { status: 401, code: "authentication_required" });

  const user = await jsonFetch(cfg.url + "/auth/v1/user", { apikey: cfg.anon, Authorization: "Bearer " + match[1] });
  if (!user?.id) throw Object.assign(new Error("Your session is invalid or expired."), { status: 401, code: "invalid_session" });

  const adminHeaders = { apikey: cfg.service, Authorization: "Bearer " + cfg.service };
  const query = async (table, params) => jsonFetch(cfg.url + "/rest/v1/" + table + "?" + params, adminHeaders);
  const profiles = await query("user_profiles", "select=user_id,account_status&id=eq." + encodeURIComponent(user.id) + "&limit=1");
  if (!profiles?.[0] || profiles[0].account_status !== "approved") throw Object.assign(new Error("Your account has not been approved by ANISH ENTERPRISES."), { status: 403, code: "account_not_approved" });

  const { organization_id, project_id, engagement_id, target_id } = payload || {};
  if (![organization_id,project_id,engagement_id,target_id].every((v) => typeof v === "string" && /^[0-9a-f-]{36}$/i.test(v))) {
    throw Object.assign(new Error("Select a project, approved engagement and verified target before scanning."), { status: 400, code: "engagement_context_required" });
  }
  const [memberships, orgs, projects, engagements, targets] = await Promise.all([
    query("organization_memberships", "select=role,status&organization_id=eq."+organization_id+"&user_id=eq."+user.id+"&status=eq.active&limit=1"),
    query("organizations", "select=id,status&id=eq."+organization_id+"&status=eq.verified&limit=1"),
    query("projects", "select=id,organization_id&id=eq."+project_id+"&organization_id=eq."+organization_id+"&limit=1"),
    query("engagements", "select=id,organization_id,project_id,status,starts_at,expires_at,policy&id=eq."+engagement_id+"&organization_id=eq."+organization_id+"&project_id=eq."+project_id+"&status=in.(approved,active)&limit=1"),
    query("engagement_targets", "select=id,engagement_id,asset_id,allowed_modules,constraints&id=eq."+target_id+"&engagement_id=eq."+engagement_id+"&limit=1")
  ]);
  const membership = memberships?.[0], org = orgs?.[0], project = projects?.[0], engagement = engagements?.[0], target = targets?.[0];
  if (!membership || !org || !project || !engagement || !target) throw Object.assign(new Error("Your account is not authorized for this organization's selected engagement and target."), { status: 403, code: "engagement_access_denied" });
  if (!["owner","security_engineer"].includes(membership.role)) throw Object.assign(new Error("Your organization role cannot launch assessments."), { status: 403, code: "role_not_permitted" });
  const now = Date.now();
  if (engagement.starts_at && Date.parse(engagement.starts_at) > now) throw Object.assign(new Error("This engagement has not started yet."), { status: 403, code: "engagement_not_started" });
  if (engagement.expires_at && Date.parse(engagement.expires_at) <= now) throw Object.assign(new Error("This engagement has expired."), { status: 403, code: "engagement_expired" });

  const assets = await query("assets", "select=id,canonical_target,kind,verification_status,verified_at& id=eq.".replace(" ","") + target.asset_id + "&organization_id=eq."+organization_id+"&project_id=eq."+project_id+"&limit=1");
  const asset = assets?.[0];
  if (!asset || asset.verification_status !== "verified" || !asset.verified_at) throw Object.assign(new Error("The target must have current ownership or written-authorization verification."), { status: 403, code: "target_not_verified" });
  const evidence = await query("authorization_evidence", "select=id,verified_at,expires_at&engagement_id=eq."+engagement_id+"&verified_at=not.is.null&limit=1");
  if (!evidence?.some((item) => !item.expires_at || Date.parse(item.expires_at) > now)) throw Object.assign(new Error("The engagement has no current authorization evidence."), { status: 403, code: "authorization_evidence_missing" });

  const requested = Array.isArray(payload.modules) ? payload.modules : ["web","tls"];
  const allowed = new Set(target.allowed_modules || []);
  const policyModules = new Set(engagement.policy?.modules || []);
  if (!requested.length || requested.some((module) => !allowed.has(module) || !policyModules.has(module))) throw Object.assign(new Error("Requested scan modules exceed the approved engagement policy."), { status: 403, code: "module_out_of_scope" });
  const targetValue = asset.canonical_target;
  if (payload.target && String(payload.target).toLowerCase() !== String(targetValue).toLowerCase()) throw Object.assign(new Error("The submitted target does not match the verified engagement asset."), { status: 403, code: "target_mismatch" });

  const claims = {
    iss: "anish-enterprises-scanner",
    aud: "scanner-worker",
    sub: user.id,
    organization_id, project_id, engagement_id, target_id,
    target: targetValue,
    modules: requested,
    profile: payload.profile || "passive",
    max_hosts: Math.min(Number(engagement.policy?.max_hosts || 32), Number(target.constraints?.max_hosts || 32)),
    iat: Math.floor(now / 1000),
    exp: Math.floor(now / 1000) + 300,
    jti: crypto.randomUUID()
  };
  const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = crypto.createHmac("sha256", cfg.signing).update(encoded).digest("base64url");
  return { ...claims, signed_grant: encoded + "." + signature };
}
