import { resolveTxt } from "node:dns/promises";
import {
  platformConfig, json, clearSessionCookies, signInWithPassword, storeSessionCookies,
  getAccessContext, hasPlatformRole, dbRequest, auditEvent, requireOrganizationRole,
  normalizeAsset, generateChallenge, sha256,
} from "../lib/enterprise.js";

export const config = { runtime: "nodejs" };
const buckets = new Map();
const modules = new Set(["web", "network", "tls", "zap"]);
const urlFor = (req) => new URL(req.url || "/api/enterprise", "https://" + (req.headers.host || "localhost"));

function sameOrigin(req) {
  const origin = req.headers.origin;
  const host = String(req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim().toLowerCase();
  try { const u = new URL(origin); return u.protocol === "https:" && u.host.toLowerCase() === host; }
  catch { return false; }
}
function rateLimit(req, key, max, interval) {
  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const k = key + ":" + ip;
  const now = Date.now();
  let b = buckets.get(k);
  if (!b || now - b.start > interval) { b = { start: now, count: 0 }; buckets.set(k, b); }
  b.count++;
  for (const [name, item] of buckets) if (now - item.start > interval) buckets.delete(name);
  return b.count <= max;
}
async function readBody(req, max = 32768) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > max) throw Object.assign(new Error("Request body too large."), { status: 413 }); chunks.push(chunk); }
  try { const x = JSON.parse(Buffer.concat(chunks).toString("utf8")); if (!x || typeof x !== "object" || Array.isArray(x)) throw 0; return x; }
  catch { throw Object.assign(new Error("Invalid JSON request."), { status: 400 }); }
}
const qs = (filters) => new URLSearchParams(filters).toString();
async function getOne(table, filters, select = "*") {
  const rows = await dbRequest(table + "?" + qs({ select, ...filters, limit: "1" }));
  return Array.isArray(rows) ? rows[0] || null : null;
}
async function getRows(table, filters, select = "*", order = "created_at.desc") {
  return dbRequest(table + "?" + qs({ select, ...filters, order }));
}
async function insertOne(table, body) {
  const rows = await dbRequest(table, { method: "POST", headers: { Prefer: "return=representation" }, body: JSON.stringify(body) });
  return Array.isArray(rows) ? rows[0] || null : null;
}
async function patchOne(table, filters, body) {
  const rows = await dbRequest(table + "?" + qs(filters), { method: "PATCH", headers: { Prefer: "return=representation" }, body: JSON.stringify(body) });
  return Array.isArray(rows) ? rows[0] || null : null;
}
function fail(message, status = 400) { throw Object.assign(new Error(message), { status }); }
function admin(ctx, roles = ["super_admin", "platform_admin", "security_analyst"]) {
  if (!ctx || ctx.denied || !ctx.platformAdmin || !roles.includes(ctx.adminRole)) fail("ANISH ENTERPRISES administrator permission required.", 403);
}
function orgRole(ctx, orgId, roles) { requireOrganizationRole(ctx, orgId, roles); }
function emailValid(value) {
  if (typeof value !== "string") return "";
  const v = value.trim().toLowerCase();
  return v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? v : "";
}
function uuid(value) { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); }
function slug(value) { return String(value || "").toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48); }
async function sessionContext(req, res) {
  const ctx = await getAccessContext(req, res);
  if (!ctx) fail("Sign in with an ANISH ENTERPRISES invitation.", 401);
  if (ctx.denied) fail("Your account is awaiting ANISH ENTERPRISES approval or has been suspended.", 403);
  return ctx;
}
async function registerAsset(ctx, data) {
  const org = data.organization_id, projectId = data.project_id;
  if (!uuid(org) || !uuid(projectId)) fail("Valid organization and project IDs are required.");
  orgRole(ctx, org, ["owner", "org_admin", "security_engineer"]);
  const project = await getOne("projects", { id: "eq." + projectId, organization_id: "eq." + org, status: "eq.active" });
  if (!project) fail("Active project not found in this organization.", 404);
  const type = String(data.asset_type || "");
  const value = normalizeAsset(type, data.target);
  if (await getOne("assets", { project_id: "eq." + projectId, canonical_value: "eq." + value })) fail("Asset already registered.", 409);
  const domain = type === "domain";
  const token = domain ? generateChallenge() : null;
  const asset = await insertOne("assets", {
    organization_id: org, project_id: projectId, asset_type: type, canonical_value: value,
    verification_status: domain ? "pending_dns" : "pending_review",
    verification_method: domain ? "dns_txt" : "manual_review",
    challenge_hash: token ? sha256(token) : null,
    challenge_expires_at: token ? new Date(Date.now() + 86400000).toISOString() : null,
    authorization_evidence: String(data.authorization_evidence || "").trim().slice(0, 2000) || null,
    created_by: ctx.user.id,
  });
  await auditEvent(ctx, org, "asset.registered", "asset", asset.id, "success", { asset_type: type });
  return {
    asset,
    verification: domain ? {
      method: "dns_txt", record_type: "TXT",
      record_name: "_anish-enterprises-verification." + value,
      record_value: "anish-enterprises-verification=" + token,
      expires_at: asset.challenge_expires_at,
    } : { method: "manual_review", message: "ANISH ENTERPRISES must review authorization evidence for IP/CIDR assets." },
  };
}
async function verifyAsset(ctx, data) {
  if (!uuid(data.asset_id) || !uuid(data.organization_id)) fail("Invalid asset identifier.");
  orgRole(ctx, data.organization_id, ["owner", "org_admin", "security_engineer"]);
  const asset = await getOne("assets", { id: "eq." + data.asset_id, organization_id: "eq." + data.organization_id });
  if (!asset || asset.asset_type !== "domain") fail("Domain asset not found.", 404);
  if (asset.verification_status === "verified") return asset;
  if (asset.verification_status !== "pending_dns" || !asset.challenge_hash ||
      !asset.challenge_expires_at || new Date(asset.challenge_expires_at).getTime() < Date.now()) fail("DNS challenge expired or invalid.", 409);
  let records = [];
  try { records = (await resolveTxt("_anish-enterprises-verification." + asset.canonical_value)).map(parts => parts.join("")); } catch {}
  const record = records.find(x => x.startsWith("anish-enterprises-verification="));
  if (!record || sha256(record.slice("anish-enterprises-verification=".length)) !== asset.challenge_hash) {
    fail("DNS TXT proof was not found. Publish the provided TXT record and retry.", 409);
  }
  const result = await patchOne("assets", { id: "eq." + asset.id }, {
    verification_status: "verified", verified_at: new Date().toISOString(), challenge_hash: null, challenge_expires_at: null,
  });
  await auditEvent(ctx, asset.organization_id, "asset.verified", "asset", asset.id, "success", { method: "dns_txt" });
  return result;
}
async function sendInvitation(email, redirectTo, metadata) {
  const cfg = platformConfig();
  const response = await fetch(cfg.url + "/auth/v1/invite", {
    method: "POST",
    headers: { apikey: cfg.serviceKey, Authorization: "Bearer " + cfg.serviceKey, "Content-Type": "application/json" },
    body: JSON.stringify({ email, data: metadata, redirect_to: redirectTo }),
    signal: AbortSignal.timeout(15000),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body.id) fail(body.msg || body.message || "Supabase could not create the invitation.", 400);
  return body;
}
async function createEngagement(ctx, data) {
  const org = data.organization_id, projectId = data.project_id;
  if (!uuid(org) || !uuid(projectId)) fail("Valid organization and project IDs are required.");
  orgRole(ctx, org, ["owner", "org_admin", "security_engineer"]);
  if (!await getOne("projects", { id: "eq." + projectId, organization_id: "eq." + org, status: "eq.active" })) fail("Project not found.", 404);
  const ids = Array.isArray(data.asset_ids) ? [...new Set(data.asset_ids)] : [];
  if (!ids.length || ids.length > 100 || !ids.every(uuid)) fail("Select 1–100 valid project assets.");
  const selectedModules = Array.isArray(data.allowed_modules) ? [...new Set(data.allowed_modules)] : ["web", "network", "tls"];
  if (!selectedModules.length || selectedModules.some(x => !modules.has(x))) fail("Unsupported assessment module.");
  const assets = await getRows("assets", {
    organization_id: "eq." + org, project_id: "eq." + projectId, id: "in.(" + ids.join(",") + ")",
  }, "id,asset_type,canonical_value,verification_status");
  if (assets.length !== ids.length || assets.some(x => x.verification_status !== "verified")) fail("Every engagement target must be verified or manually approved.", 409);
  const name = String(data.name || "").trim().slice(0, 120);
  if (!name) fail("Engagement name is required.");
  const engagement = await insertOne("engagements", {
    organization_id: org, project_id: projectId, name,
    purpose: String(data.purpose || "").trim().slice(0, 2000),
    status: "pending_review", allowed_modules: selectedModules,
    starts_at: data.starts_at || new Date().toISOString(),
    expires_at: data.expires_at || new Date(Date.now() + 30 * 86400000).toISOString(),
    max_hosts: Math.max(1, Math.min(Number(data.max_hosts) || 1, 256)),
    created_by: ctx.user.id,
  });
  await dbRequest("engagement_assets", {
    method: "POST", headers: { Prefer: "return=minimal" },
    body: JSON.stringify(ids.map(asset_id => ({ engagement_id: engagement.id, organization_id: org, asset_id }))),
  });
  await auditEvent(ctx, org, "engagement.submitted", "engagement", engagement.id, "success", { asset_count: ids.length, modules: selectedModules });
  return engagement;
}
async function review(ctx, table, id, action, note) {
  admin(ctx);
  if (!uuid(id) || !["approve", "reject"].includes(action)) fail("Invalid review request.");
  const item = await getOne(table, { id: "eq." + id });
  if (!item) fail("Review item not found.", 404);
  if (table === "engagements" && item.status !== "pending_review") fail("Engagement is not pending review.", 409);
  if (table === "assets" && item.verification_status !== "pending_review") fail("Asset is not pending manual review.", 409);
  const now = new Date().toISOString();
  const patch = table === "engagements" ?
    (action === "approve" ? { status: "approved", approved_by: ctx.user.id, approved_at: now, approval_note: String(note || "Approved by ANISH ENTERPRISES.").slice(0, 1000) } : { status: "rejected", approval_note: String(note || "Rejected.").slice(0, 1000) }) :
    (action === "approve" ? { verification_status: "verified", reviewed_by: ctx.user.id, reviewed_at: now, verified_at: now } : { verification_status: "rejected", reviewed_by: ctx.user.id, reviewed_at: now });
  const updated = await patchOne(table, { id: "eq." + id }, patch);
  await auditEvent(ctx, item.organization_id || null, table.slice(0, -1) + "." + action, table.slice(0, -1), id, "success", { note: String(note || "").slice(0, 1000) });
  return updated;
}

export default async function handler(req, res) {
  const url = urlFor(req);
  const path = url.pathname.replace(/^\/api\/enterprise\/?/, "").replace(/\/$/, "");
  try {
    if (req.method === "OPTIONS") {
      if (!sameOrigin(req)) return json(res, 403, { error: "Origin rejected." });
      res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      res.statusCode = 204; return res.end();
    }
    if (req.method === "POST" && path !== "access-requests" && !sameOrigin(req)) return json(res, 403, { error: "Cross-origin request rejected." });

    if (req.method === "POST" && path === "login") {
      if (!rateLimit(req, "login", 10, 900000)) return json(res, 429, { error: "Too many sign-in attempts." });
      const data = await readBody(req, 16384);
      const email = emailValid(data.email);
      if (!email || typeof data.password !== "string" || !data.password) fail("Valid email and password required.");
      const session = await signInWithPassword(email, data.password);
      storeSessionCookies(res, session);
      const ctx = await getAccessContext({ headers: { cookie: "scanner_access=" + encodeURIComponent(session.access_token) + "; scanner_refresh=" + encodeURIComponent(session.refresh_token) } }, res);
      if (!ctx || ctx.denied) { clearSessionCookies(res); fail("Your account is awaiting ANISH ENTERPRISES approval or has been suspended.", 403); }
      return json(res, 200, { ok: true, user: { id: ctx.user.id, email: ctx.user.email }, access: ctx.access });
    }
    if (req.method === "POST" && path === "logout") { clearSessionCookies(res); return json(res, 200, { ok: true }); }

    if (req.method === "POST" && path === "access-requests") {
      if (!rateLimit(req, "request", 4, 3600000)) return json(res, 429, { error: "Too many access requests." });
      const data = await readBody(req, 16384);
      const email = emailValid(data.email);
      const fullName = String(data.full_name || "").trim().slice(0, 120);
      const orgName = String(data.organization_name || "").trim().slice(0, 160);
      const reason = String(data.business_reason || "").trim().slice(0, 2000);
      if (!email || !fullName || !orgName || reason.length < 20) fail("Complete all fields and provide a business reason (20+ characters).");
      await insertOne("access_requests", {
        email, full_name: fullName, organization_name: orgName,
        organization_website: String(data.organization_website || "").trim().slice(0, 255) || null,
        business_reason: reason, status: "pending",
      });
      return json(res, 202, { ok: true, message: "Request submitted for ANISH ENTERPRISES review." });
    }

    const ctx = await sessionContext(req, res);
    if (req.method === "GET" && path === "me") return json(res, 200, { user: { id: ctx.user.id, email: ctx.user.email }, access: ctx.access });

    if (req.method === "GET" && path === "admin/requests") {
      admin(ctx);
      return json(res, 200, { requests: await getRows("access_requests", { status: "eq.pending" }, "*") });
    }

    const requestReview = path.match(/^admin\/requests\/([0-9a-f-]{36})\/(approve|reject)$/);
    if (req.method === "POST" && requestReview) {
      const data = await readBody(req);
      admin(ctx, requestReview[2] === "approve" ? ["super_admin", "platform_admin", "security_analyst"] : ["super_admin", "platform_admin"]);
      const item = await getOne("access_requests", { id: "eq." + requestReview[1], status: "eq.pending" });
      if (!item) fail("Pending access request not found.", 404);
      if (requestReview[2] === "reject") {
        const updated = await patchOne("access_requests", { id: "eq." + item.id }, { status: "rejected", reviewed_by: ctx.user.id, reviewed_at: new Date().toISOString(), review_note: String(data.review_note || "").slice(0, 1000) });
        return json(res, 200, { request: updated });
      }
      const orgSlug = slug(data.slug || item.organization_name);
      if (!orgSlug) fail("Organization slug required.");
      const org = await insertOne("organizations", { name: item.organization_name, slug: orgSlug, website: item.organization_website, status: "active", verified_at: new Date().toISOString() });
      await patchOne("access_requests", { id: "eq." + item.id }, { status: "approved", reviewed_by: ctx.user.id, reviewed_at: new Date().toISOString(), review_note: String(data.review_note || "Approved.").slice(0, 1000) });
      await auditEvent(ctx, org.id, "access_request.approved", "access_request", item.id, "success", {});
      return json(res, 201, { organization: org, next_step: "Invite the approved organization owner." });
    }

    const invite = path.match(/^admin\\/organizations\\/([0-9a-f-]{36})\\/invite$/);
    if (req.method === "POST" && invite) {
      admin(ctx, ["super_admin", "platform_admin"]);
      const data = await readBody(req);
      const email = emailValid(data.email);
      const role = String(data.role || "owner");
      if (!email || !["owner", "org_admin", "security_engineer", "developer", "auditor"].includes(role)) fail("Valid email and organization role are required.");
      const organization = await getOne("organizations", { id: "eq." + invite[1], status: "eq.active" });
      if (!organization) fail("Active organization not found.", 404);
      const invited = await sendInvitation(email, url.origin + "/enterprise.html?invited=1", { organization_id: organization.id, invited_role: role });
      await dbRequest("platform_profiles?on_conflict=user_id", {
        method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({ user_id: invited.id, email, display_name: String(data.display_name || "").slice(0, 120), status: "active" }),
      });
      await dbRequest("org_memberships?on_conflict=organization_id,user_id", {
        method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({ organization_id: organization.id, user_id: invited.id, role, status: "active", invited_by: ctx.user.id }),
      });
      await auditEvent(ctx, organization.id, "user.invited", "user", invited.id, "success", { role });
      return json(res, 201, { invited: true, email, role });
    }

    const projects = path.match(/^organizations\/([0-9a-f-]{36})\/projects$/);
    if (projects && req.method === "GET") {
      orgRole(ctx, projects[1], null);
      return json(res, 200, { projects: await getRows("projects", { organization_id: "eq." + projects[1] }, "*") });
    }
    if (projects && req.method === "POST") {
      orgRole(ctx, projects[1], ["owner", "org_admin", "security_engineer"]);
      const data = await readBody(req);
      const name = String(data.name || "").trim().slice(0, 120);
      const projectSlug = slug(data.slug || name);
      if (!name || !projectSlug) fail("Project name required.");
      const project = await insertOne("projects", { organization_id: projects[1], name, slug: projectSlug, description: String(data.description || "").slice(0, 2000), created_by: ctx.user.id });
      await auditEvent(ctx, projects[1], "project.created", "project", project.id, "success", {});
      return json(res, 201, { project });
    }

    if (req.method === "POST" && path === "assets") return json(res, 201, await registerAsset(ctx, await readBody(req)));
    if (req.method === "POST" && path === "assets/verify") return json(res, 200, { asset: await verifyAsset(ctx, await readBody(req)) });
    const assets = path.match(/^organizations\/([0-9a-f-]{36})\/assets$/);
    if (req.method === "GET" && assets) {
      orgRole(ctx, assets[1], null);
      return json(res, 200, { assets: await getRows("assets", { organization_id: "eq." + assets[1] }, "*") });
    }

    if (req.method === "POST" && path === "engagements") return json(res, 201, { engagement: await createEngagement(ctx, await readBody(req)) });
    const engagements = path.match(/^organizations\/([0-9a-f-]{36})\/engagements$/);
    if (req.method === "GET" && engagements) {
      orgRole(ctx, engagements[1], null);
      return json(res, 200, { engagements: await getRows("engagements", { organization_id: "eq." + engagements[1] }, "*") });
    }
    const engagementReview = path.match(/^admin\/engagements\/([0-9a-f-]{36})\/(approve|reject)$/);
    if (req.method === "POST" && engagementReview) return json(res, 200, { engagement: await review(ctx, "engagements", engagementReview[1], engagementReview[2], (await readBody(req)).review_note) });
    const assetReview = path.match(/^admin\/assets\/([0-9a-f-]{36})\/(approve|reject)$/);
    if (req.method === "POST" && assetReview) return json(res, 200, { asset: await review(ctx, "assets", assetReview[1], assetReview[2], (await readBody(req)).review_note) });

    return json(res, 404, { error: "Enterprise endpoint not found." });
  } catch (error) {
    const status = Number(error?.status) || 500;
    return json(res, status, { error: status >= 500 ? "Enterprise platform request failed. Check server configuration." : String(error.message || "Request rejected.") });
  }
}
