import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "https://scanner-rose-rho.vercel.app",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin"
};

function reply(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}

function jwtClaims(token: string) {
  const part = token.split(".")[1];
  if (!part) throw new Error("Invalid access token.");
  const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")));
}

function fail(message: string, status = 403, code = "enterprise_authorization_denied") {
  return Object.assign(new Error(message), { status, code });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (req.method !== "POST") return reply(405, { error: "Method not allowed." });

  try {
    const authHeader = req.headers.get("Authorization") || "";
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!match) throw fail("Sign in with an approved ANISH ENTERPRISES account.", 401, "authentication_required");
    const accessToken = match[1];

    const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
    const publishableKeys = JSON.parse(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS") || "{}");
    const secretKeys = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") || "{}");
    const publishableKey = publishableKeys.default || Deno.env.get("SUPABASE_ANON_KEY") || "";
    const secretKey = secretKeys.default || Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
    if (!supabaseUrl || !publishableKey || !secretKey) throw fail("Enterprise authorization service is not configured.", 503, "auth_service_unconfigured");

    const authClient = createClient(supabaseUrl, publishableKey, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: { headers: { Authorization: "Bearer " + accessToken } }
    });
    const { data: userData, error: userError } = await authClient.auth.getUser(accessToken);
    if (userError || !userData.user) throw fail("Your session is invalid or expired.", 401, "invalid_session");
    const user = userData.user;
    const claims = jwtClaims(accessToken);
    const admin = createClient(supabaseUrl, secretKey, { auth: { persistSession: false, autoRefreshToken: false } });

    const { data: profile, error: profileError } = await admin
      .from("user_profiles").select("account_status").eq("user_id", user.id).maybeSingle();
    if (profileError) throw fail("Unable to verify account approval.", 503, "profile_lookup_failed");
    if (!profile || profile.account_status !== "approved") throw fail("Your account has not been approved by ANISH ENTERPRISES.", 403, "account_not_approved");

    const body = await req.json().catch(() => ({}));
    const action = body.action || "authorize_scan";

    if (action === "authorize_health") {
      const { data: memberships, error } = await admin.from("organization_memberships")
        .select("organization_id,role,status,organizations!inner(status)")
        .eq("user_id", user.id).eq("status", "active").eq("organizations.status", "verified").limit(1);
      if (error) throw fail("Unable to verify organization access.", 503, "membership_lookup_failed");
      if (!memberships?.length) throw fail("Your account has no active verified organization membership.", 403, "organization_access_denied");
      return reply(200, { authorized: true, user_id: user.id });
    }

    if (action === "authorize_job_status") {
      const jobId = String(body.job_id || "");
      if (!/^[0-9a-f-]{36}$/i.test(jobId)) throw fail("Invalid assessment identifier.", 400, "invalid_job_id");
      const { data: job, error } = await admin.from("assessment_jobs")
        .select("id,organization_id,worker_job_id")
        .eq("id", jobId).maybeSingle();
      if (error) throw fail("Unable to verify assessment access.", 503, "job_lookup_failed");
      if (!job) throw fail("Assessment not found.", 404, "job_not_found");
      const { data: membership } = await admin.from("organization_memberships")
        .select("id").eq("organization_id", job.organization_id).eq("user_id", user.id).eq("status", "active").maybeSingle();
      const { data: organization } = await admin.from("organizations")
        .select("id").eq("id", job.organization_id).eq("status", "verified").maybeSingle();
      if (!membership || !organization) throw fail("You cannot access this assessment.", 403, "job_access_denied");
      return reply(200, { authorized: true, worker_job_id: job.worker_job_id || job.id });
    }

    if (action !== "authorize_scan") throw fail("Unsupported authorization action.", 400, "invalid_action");

    // Elevated scan execution requires MFA. The identity and access checks below are
    // still enforced independently; AAL is an additional control, not a substitute.
    if (claims.aal !== "aal2") throw fail("Multi-factor authentication is required before launching assessments.", 403, "mfa_required");

    const organizationId = String(body.organization_id || "");
    const projectId = String(body.project_id || "");
    const engagementId = String(body.engagement_id || "");
    const targetId = String(body.target_id || "");
    if (![organizationId, projectId, engagementId, targetId].every(v => /^[0-9a-f-]{36}$/i.test(v))) {
      throw fail("Select an organization, project, approved engagement and verified target.", 400, "engagement_context_required");
    }

    const [{ data: membership, error: membershipError },
      { data: organization, error: organizationError },
      { data: project, error: projectError },
      { data: engagement, error: engagementError },
      { data: target, error: targetError }] = await Promise.all([
      admin.from("organization_memberships").select("role,status").eq("organization_id", organizationId).eq("user_id", user.id).eq("status", "active").maybeSingle(),
      admin.from("organizations").select("id,status").eq("id", organizationId).eq("status", "verified").maybeSingle(),
      admin.from("projects").select("id,organization_id").eq("id", projectId).eq("organization_id", organizationId).maybeSingle(),
      admin.from("engagements").select("id,organization_id,project_id,status,starts_at,expires_at,policy,approved_at,approved_by").eq("id", engagementId).eq("organization_id", organizationId).eq("project_id", projectId).in("status", ["approved","active"]).maybeSingle(),
      admin.from("engagement_targets").select("id,engagement_id,asset_id,allowed_modules,constraints").eq("id", targetId).eq("engagement_id", engagementId).maybeSingle()
    ]);
    if (membershipError || organizationError || projectError || engagementError || targetError) throw fail("Unable to validate engagement authorization.", 503, "engagement_lookup_failed");
    if (!membership || !organization || !project || !engagement || !target) throw fail("Your account is not authorized for this organization's selected engagement and target.", 403, "engagement_access_denied");
    if (!["owner","security_engineer"].includes(membership.role)) throw fail("Your organization role cannot launch assessments.", 403, "role_not_permitted");

    const now = Date.now();
    if (!engagement.approved_by || !engagement.approved_at) throw fail("The engagement has not been approved by ANISH ENTERPRISES.", 403, "engagement_not_approved");
    if (engagement.starts_at && Date.parse(engagement.starts_at) > now) throw fail("This engagement has not started.", 403, "engagement_not_started");
    if (engagement.expires_at && Date.parse(engagement.expires_at) <= now) throw fail("This engagement has expired.", 403, "engagement_expired");

    const { data: asset, error: assetError } = await admin.from("assets")
      .select("id,organization_id,project_id,kind,canonical_target,verification_status,verified_at")
      .eq("id", target.asset_id).eq("organization_id", organizationId).eq("project_id", projectId).maybeSingle();
    if (assetError) throw fail("Unable to verify target ownership.", 503, "asset_lookup_failed");
    if (!asset || asset.verification_status !== "verified" || !asset.verified_at) throw fail("Target ownership or written authorization has not been verified.", 403, "target_not_verified");

    const { data: evidenceRows, error: evidenceError } = await admin.from("authorization_evidence")
      .select("id,verified_at,expires_at").eq("engagement_id", engagementId).not("verified_at", "is", null);
    if (evidenceError) throw fail("Unable to verify authorization evidence.", 503, "evidence_lookup_failed");
    const validEvidence = (evidenceRows || []).some(ev => !ev.expires_at || Date.parse(ev.expires_at) > now);
    if (!validEvidence) throw fail("The engagement has no current written or independently verified authorization evidence.", 403, "authorization_evidence_missing");

    const modules = Array.isArray(body.modules) ? [...new Set(body.modules.map(String))] : ["web","tls"];
    const allowed = new Set(target.allowed_modules || []);
    const policyModules = new Set(engagement.policy?.modules || []);
    if (!modules.length || modules.some(m => !allowed.has(m) || !policyModules.has(m))) throw fail("Requested modules exceed the approved engagement scope.", 403, "module_out_of_scope");
    const profile = String(body.profile || "passive");
    if (profile !== String(engagement.policy?.profile || "passive")) throw fail("Requested profile exceeds the approved engagement policy.", 403, "profile_out_of_scope");
    const canonicalTarget = String(asset.canonical_target);
    if (String(body.target || "").trim().toLowerCase() !== canonicalTarget.trim().toLowerCase()) throw fail("The submitted target does not match the verified asset.", 403, "target_mismatch");

    const maxHosts = Math.min(Number(engagement.policy?.max_hosts || 32), Number(target.constraints?.max_hosts || 32), 256);
    const jobId = crypto.randomUUID();
    const { data: job, error: jobError } = await admin.from("assessment_jobs").insert({
      id: jobId,
      worker_job_id: jobId,
      organization_id: organizationId,
      project_id: projectId,
      engagement_id: engagementId,
      target_id: targetId,
      requested_by: user.id,
      status: "queued",
      modules,
      profile
    }).select("id").single();
    if (jobError || !job) throw fail("Unable to create the assessment record.", 503, "job_create_failed");

    const grant = {
      iss: "anish-enterprises-scanner",
      aud: "scanner-worker",
      sub: user.id,
      organization_id: organizationId,
      project_id: projectId,
      engagement_id: engagementId,
      target_id: targetId,
      job_id: job.id,
      target: canonicalTarget,
      modules,
      profile,
      max_hosts: maxHosts,
      os_detect: Boolean(engagement.policy?.os_detect),
      udp: Boolean(engagement.policy?.udp),
      iat: Math.floor(now / 1000),
      exp: Math.floor(now / 1000) + 300,
      jti: crypto.randomUUID()
    };
    return reply(200, { authorized: true, grant });
  } catch (error) {
    const status = Number((error as {status?:number}).status || 403);
    const code = String((error as {code?:string}).code || "enterprise_authorization_denied");
    return reply(status, { error: error instanceof Error ? error.message : "Authorization failed.", code });
  }
});
