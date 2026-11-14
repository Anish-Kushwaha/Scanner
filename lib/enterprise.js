import crypto from "node:crypto";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

const COOKIE_ACCESS = "scanner_access";
const COOKIE_REFRESH = "scanner_refresh";

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Server configuration missing ${name}.`);
  return value.replace(/\/$/, "");
}

export function platformConfig() {
  return {
    url: requiredEnv("SCANNER_SUPABASE_URL"),
    anonKey: requiredEnv("SCANNER_SUPABASE_ANON_KEY"),
    serviceKey: requiredEnv("SCANNER_SUPABASE_SERVICE_ROLE_KEY"),
  };
}

export function json(res, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
  res.end(JSON.stringify(body));
}

export function readCookies(req) {
  const raw = String(req.headers.cookie || "");
  const out = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try { out[key] = decodeURIComponent(value); } catch { out[key] = ""; }
  }
  return out;
}

function setCookie(res, name, value, maxAge) {
  const existing = res.getHeader("Set-Cookie");
  const list = Array.isArray(existing) ? existing : existing ? [String(existing)] : [];
  list.push(`${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`);
  res.setHeader("Set-Cookie", list);
}

export function clearSessionCookies(res) {
  const existing = res.getHeader("Set-Cookie");
  const list = Array.isArray(existing) ? existing : existing ? [String(existing)] : [];
  for (const name of [COOKIE_ACCESS, COOKIE_REFRESH]) {
    list.push(`${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
  }
  res.setHeader("Set-Cookie", list);
}

export async function signInWithPassword(email, password) {
  const cfg = platformConfig();
  const response = await fetch(`${cfg.url}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: cfg.anonKey, "Content-Type": "application/json" },
    body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
    signal: AbortSignal.timeout(12000),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token || !data.refresh_token) {
    throw Object.assign(new Error("Invalid email/password or sign-in unavailable."), { status: 401 });
  }
  return data;
}

export function storeSessionCookies(res, session) {
  const accessAge = Math.max(60, Math.min(Number(session.expires_in) || 3600, 86400));
  setCookie(res, COOKIE_ACCESS, session.access_token, accessAge);
  setCookie(res, COOKIE_REFRESH, session.refresh_token, 60 * 60 * 24 * 30);
}

async function refreshSession(refreshToken) {
  const cfg = platformConfig();
  const response = await fetch(`${cfg.url}/auth/v1/token?grant_type=refresh_token`, {
    method: "POST",
    headers: { apikey: cfg.anonKey, "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
    signal: AbortSignal.timeout(12000),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) return null;
  return data;
}

async function currentUser(accessToken) {
  const cfg = platformConfig();
  const response = await fetch(`${cfg.url}/auth/v1/user`, {
    headers: { apikey: cfg.anonKey, Authorization: `Bearer ${accessToken}` },
    cache: "no-store",
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) return null;
  const user = await response.json().catch(() => null);
  return user?.id ? user : null;
}

async function accessSnapshot(accessToken) {
  const cfg = platformConfig();
  const response = await fetch(`${cfg.url}/rest/v1/rpc/get_my_platform_access`, {
    method: "POST",
    headers: {
      apikey: cfg.anonKey,
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: "{}",
    cache: "no-store",
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error("Unable to load platform access profile.");
  return response.json();
}

export async function getAccessContext(req, res) {
  const cookies = readCookies(req);
  const authHeader = String(req.headers.authorization || "");
  let accessToken = cookies[COOKIE_ACCESS] || (authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "");
  let user = accessToken ? await currentUser(accessToken) : null;

  if (!user && cookies[COOKIE_REFRESH] && res) {
    const refreshed = await refreshSession(cookies[COOKIE_REFRESH]);
    if (refreshed) {
      storeSessionCookies(res, refreshed);
      accessToken = refreshed.access_token;
      user = await currentUser(accessToken);
    } else {
      clearSessionCookies(res);
    }
  }
  if (!user) return null;

  const access = await accessSnapshot(accessToken);
  const profileStatus = access?.profile_status || "pending";
  const admin = access?.platform_admin || { is_admin: false };
  const memberships = Array.isArray(access?.memberships) ? access.memberships : [];
  const activeMemberships = memberships.filter((m) =>
    m.membership_status === "active" && m.organization_status === "active"
  );
  const pendingInvites = memberships.filter((m) =>
    m.membership_status === "invited" && m.organization_status === "active"
  );
  const platformAdmin = Boolean(admin?.is_admin) && profileStatus === "active";
  const adminRole = admin?.role || null;
  if (profileStatus !== "active" || (!platformAdmin && activeMemberships.length === 0 && pendingInvites.length === 0)) {
    return { user, accessToken, access, profileStatus, platformAdmin, adminRole, memberships: activeMemberships, pendingInvites, denied: true };
  }
  return { user, accessToken, access, profileStatus, platformAdmin, adminRole, memberships: activeMemberships, pendingInvites, denied: false };
}

export function hasPlatformRole(ctx, roles = ["super_admin", "platform_admin", "security_analyst"]) {
  return Boolean(ctx?.platformAdmin && roles.includes(ctx.adminRole));
}

export function hasOrgRole(ctx, organizationId, roles = null) {
  // Platform auditors and analysts do not implicitly become tenant owners.
  if (ctx?.platformAdmin && ["super_admin", "platform_admin"].includes(ctx.adminRole)) return true;
  return (ctx?.memberships || []).some((membership) =>
    membership.organization_id === organizationId &&
    (!roles || roles.includes(membership.membership_role))
  );
}

export function requirePlatformAdmin(ctx) {
  if (!ctx || ctx.denied || !hasPlatformRole(ctx)) {
    throw Object.assign(new Error("ANISH ENTERPRISES platform administrator permission required."), { status: 403 });
  }
}

export function requireOrganizationRole(ctx, organizationId, roles = null) {
  if (!ctx || ctx.denied || !hasOrgRole(ctx, organizationId, roles)) {
    throw Object.assign(new Error("You do not have the required permission in this organization."), { status: 403 });
  }
}

export async function dbRequest(path, options = {}) {
  const cfg = platformConfig();
  const response = await fetch(`${cfg.url}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: cfg.serviceKey,
      Authorization: `Bearer ${cfg.serviceKey}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    cache: "no-store",
    signal: options.signal || AbortSignal.timeout(12000),
  });
  const raw = await response.text();
  let data = null;
  try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
  if (!response.ok) {
    const error = new Error(data?.message || data?.hint || "Database operation failed.");
    error.status = response.status >= 500 ? 500 : 400;
    error.databaseCode = data?.code;
    throw error;
  }
  return data;
}

export async function auditEvent(ctx, organizationId, action, resourceType, resourceId, outcome = "success", metadata = {}) {
  const event = {
    organization_id: organizationId || null,
    actor_user_id: ctx?.user?.id || null,
    actor_kind: ctx?.user?.id ? "user" : "system",
    action,
    resource_type: resourceType,
    resource_id: resourceId ? String(resourceId) : null,
    outcome,
    metadata,
  };
  await dbRequest("audit_events", {
    method: "POST",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify(event),
  });
}

export function normalizeAsset(assetType, rawValue) {
  if (typeof rawValue !== "string" || rawValue.length > 2048) {
    throw Object.assign(new Error("Target value is missing or too long."), { status: 400 });
  }
  const value = rawValue.trim();
  if (!value || /[\s\u0000-\u001f]/.test(value)) {
    throw Object.assign(new Error("Target must be a hostname, IP address or CIDR without whitespace."), { status: 400 });
  }

  if (assetType === "domain") {
    const candidate = value.replace(/^https?:\/\//i, "").replace(/\/$/, "").replace(/\.$/, "");
    if (candidate.includes("/") || candidate.includes("@") || candidate.includes(":")) {
      throw Object.assign(new Error("Enter a bare domain name without URL paths, credentials or ports."), { status: 400 });
    }
    const ascii = domainToASCII(candidate.toLowerCase());
    if (!ascii || ascii.length > 253 || !ascii.includes(".") ||
        !ascii.split(".").every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) ||
        isIP(ascii)) {
      throw Object.assign(new Error("Invalid public domain name."), { status: 400 });
    }
    return ascii;
  }

  if (assetType === "url") {
    let parsed;
    try { parsed = new URL(value); }
    catch { throw Object.assign(new Error("Enter a valid HTTP(S) URL."), { status: 400 }); }
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password ||
        !parsed.hostname || parsed.port && !["80", "443"].includes(parsed.port) || isIP(parsed.hostname)) {
      throw Object.assign(new Error("URL assets must use a public DNS hostname, HTTP(S), standard ports and no embedded credentials."), { status: 400 });
    }
    const host = domainToASCII(parsed.hostname.toLowerCase());
    if (!host || host.length > 253) throw Object.assign(new Error("Invalid URL hostname."), { status: 400 });
    parsed.hostname = host;
    parsed.search = "";
    parsed.hash = "";
    parsed.pathname = parsed.pathname || "/";
    return parsed.toString();
  }

  if (assetType === "ip") {
    if (!isIP(value)) throw Object.assign(new Error("Enter a valid IPv4 or IPv6 address."), { status: 400 });
    return value.toLowerCase();
  }

  if (assetType === "cidr") {
    const slash = value.lastIndexOf("/");
    if (slash < 1) throw Object.assign(new Error("Enter a CIDR range, for example 203.0.113.0/28."), { status: 400 });
    const address = value.slice(0, slash);
    const prefix = Number(value.slice(slash + 1));
    const version = isIP(address);
    const maxPrefix = version === 4 ? 32 : version === 6 ? 128 : -1;
    if (maxPrefix < 0 || !Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
      throw Object.assign(new Error("Invalid CIDR range."), { status: 400 });
    }
    return `${address.toLowerCase()}/${prefix}`;
  }

  throw Object.assign(new Error("Unsupported asset type."), { status: 400 });
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function generateChallenge() {
  return crypto.randomBytes(24).toString("base64url");
}

export function signScopeGrant(grant, secret) {
  const canonical = JSON.stringify(grant, Object.keys(grant).sort());
  return crypto.createHmac("sha256", secret).update(canonical).digest("hex");
}
