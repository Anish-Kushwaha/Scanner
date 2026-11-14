import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "https://scanner-rose-rho.vercel.app",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin"
};
const reply = (status: number, body: Record<string, unknown>) => new Response(JSON.stringify(body), {
  status, headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store" }
});
const fail = (message: string, status = 403, code = "asset_authorization_denied") =>
  Object.assign(new Error(message), { status, code });

async function sha256(value: string) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function normalizeDomain(input: string) {
  const raw = input.trim().toLowerCase();
  const url = new URL(raw.includes("://") ? raw : "https://" + raw);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw fail("Only HTTP or HTTPS domains are accepted.", 400, "invalid_target");
  if (url.username || url.password || url.port || url.pathname !== "/" || url.search || url.hash) {
    throw fail("Enter a domain hostname only; ports, paths, credentials and query strings are not accepted.", 400, "invalid_target");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host.includes(".") || host.length > 253 || host === "localhost" || host.endsWith(".local")) throw fail("Enter a fully qualified public domain name.", 400, "invalid_domain");
  return host;
}
async function dnsJson(name: string, type: "TXT" | "A" | "AAAA") {
  const response = await fetch("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type, {
    headers: { Accept: "application/dns-json" },
    signal: AbortSignal.timeout(7000),
    cache: "no-store"
  });
  if (!response.ok) throw fail("DNS verification provider is temporarily unavailable.", 502, "dns_provider_error");
  return await response.json();
}
function isPublicIPv4(value: string) {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a,b] = parts;
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)));
}
function publicDnsAddresses(answer: any[]) {
  const values = (answer || []).filter(a => a.type === 1 || a.type === 28).map(a => String(a.data || "").replace(/^"|"$/g,""));
  const v4 = values.filter(v => v.includes("."));
  const v6 = values.filter(v => v.includes(":"));
  if (v4.some(v => !isPublicIPv4(v))) return false;
  // Reject IPv6 ULA, loopback, link-local, multicast and unspecified ranges.
  if (v6.some(v => {
    const x = v.toLowerCase();
    return x === "::" || x === "::1" || x.startsWith("fc") || x.startsWith("fd") || x.startsWith("fe8") || x.startsWith("fe9") || x.startsWith("fea") || x.startsWith("feb") || x.startsWith("ff");
  })) return false;
  return values.length > 0;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, {status:204,headers:cors});
  if (req.method !== "POST") return reply(405,{error:"Method not allowed."});
  try {
    const authHeader=req.headers.get("Authorization")||"";
    const tokenMatch=authHeader.match(/^Bearer\s+(.+)$/i);
    if (!tokenMatch) throw fail("Sign in with an approved ANISH ENTERPRISES account.",401,"authentication_required");
    const url=Deno.env.get("SUPABASE_URL")||"";
    const pkeys=JSON.parse(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS")||"{}");
    const skeys=JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")||"{}");
    const publishable=pkeys.default||Deno.env.get("SUPABASE_ANON_KEY")||"";
    const secret=skeys.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||"";
    if(!url||!publishable||!secret) throw fail("Enterprise identity service is not configured.",503,"auth_unconfigured");
    const auth=createClient(url,publishable,{auth:{persistSession:false,autoRefreshToken:false}});
    const {data:userData,error:userErr}=await auth.auth.getUser(tokenMatch[1]);
    if(userErr||!userData.user) throw fail("Your session is invalid or expired.",401,"invalid_session");
    const user=userData.user;
    const admin=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
    const {data:profile}=await admin.from("user_profiles").select("account_status").eq("user_id",user.id).maybeSingle();
    if(profile?.account_status!=="approved") throw fail("Your account is not approved by ANISH ENTERPRISES.",403,"account_not_approved");

    const body=await req.json().catch(()=>({}));
    const action=String(body.action||"create_domain_challenge");
    const organizationId=String(body.organization_id||"");
    const projectId=String(body.project_id||"");
    const {data:membership}=await admin.from("organization_memberships").select("role")
      .eq("organization_id",organizationId).eq("user_id",user.id).eq("status","active").maybeSingle();
    const {data:organization}=await admin.from("organizations").select("id")
      .eq("id",organizationId).eq("status","verified").maybeSingle();
    const {data:project}=await admin.from("projects").select("id")
      .eq("id",projectId).eq("organization_id",organizationId).maybeSingle();
    if(!membership||!organization||!project) throw fail("You do not have access to this verified organization and project.",403,"organization_access_denied");
    if(!["owner","security_engineer"].includes(membership.role)) throw fail("Your organization role cannot manage verified assets.",403,"role_not_permitted");

    if(action==="create_domain_challenge") {
      const domain=normalizeDomain(String(body.domain||""));
      const token=randomToken();
      const hash=await sha256(token);
      const {data:existing}=await admin.from("assets").select("id,verification_status")
        .eq("project_id",projectId).eq("canonical_target",domain).maybeSingle();
      if(existing?.verification_status==="verified") return reply(200,{asset_id:existing.id,status:"verified",domain});
      if(existing) {
        const {error:updErr}=await admin.from("assets").update({
          verification_status:"pending",verification_method:"dns_txt",
          verification_token_hash:hash,verified_at:null,verified_by:null
        }).eq("id",existing.id);
        if(updErr) throw fail("Could not refresh the domain verification challenge.",500,"asset_update_failed");
        return reply(200,{asset_id:existing.id,status:"pending",domain,record_name:"_anish-enterprises-scanner-verify."+domain,record_type:"TXT",record_value:"anish-enterprises-verification="+token,instructions:"Add this TXT record to the domain DNS. Then choose Verify domain."});
      }
      const {data:asset,error:insertErr}=await admin.from("assets").insert({
        organization_id:organizationId,project_id:projectId,kind:"domain",canonical_target:domain,
        verification_status:"pending",verification_method:"dns_txt",verification_token_hash:hash,created_by:user.id
      }).select("id").single();
      if(insertErr||!asset) throw fail("Could not register the domain asset.",500,"asset_create_failed");
      return reply(200,{asset_id:asset.id,status:"pending",domain,record_name:"_anish-enterprises-scanner-verify."+domain,record_type:"TXT",record_value:"anish-enterprises-verification="+token,instructions:"Add this TXT record to the domain DNS. Then choose Verify domain."});
    }

    if(action==="verify_domain") {
      const assetId=String(body.asset_id||"");
      const {data:asset,error:assetErr}=await admin.from("assets").select("id,kind,canonical_target,verification_status,verification_token_hash")
        .eq("id",assetId).eq("organization_id",organizationId).eq("project_id",projectId).maybeSingle();
      if(assetErr||!asset||asset.kind!=="domain"||asset.verification_status!=="pending"||!asset.verification_token_hash) throw fail("No pending domain verification challenge was found.",404,"challenge_not_found");
      const recordName="_anish-enterprises-scanner-verify."+asset.canonical_target;
      const txt=await dnsJson(recordName,"TXT");
      const expected="anish-enterprises-verification=";
      const values=(txt.Answer||[]).filter((a:any)=>a.type===16).map((a:any)=>String(a.data||"").replace(/^"|"$/g,""));
      const matching=values.find((v:string)=>v.startsWith(expected));
      if(!matching||await sha256(matching.slice(expected.length))!==asset.verification_token_hash) throw fail("The required DNS TXT challenge was not found or did not match.",409,"dns_challenge_not_found");

      const [a,aaaa]=await Promise.all([dnsJson(asset.canonical_target,"A"),dnsJson(asset.canonical_target,"AAAA")]);
      const answers=[...(a.Answer||[]),...(aaaa.Answer||[])];
      if(!publicDnsAddresses(answers)) throw fail("The domain must resolve only to public, routable addresses before it can be scanned by the hosted worker.",403,"non_public_dns_target");

      const {error:updateErr}=await admin.from("assets").update({
        verification_status:"verified",verification_method:"dns_txt",verification_token_hash:null,
        verified_at:new Date().toISOString(),verified_by:user.id
      }).eq("id",asset.id);
      if(updateErr) throw fail("DNS proof succeeded but asset verification could not be saved.",500,"asset_verify_failed");
      await admin.from("audit_events").insert({
        organization_id:organizationId,actor_user_id:user.id,action:"asset.domain_verified",
        resource_type:"asset",resource_id:asset.id,severity:"info",
        metadata:{verification_method:"dns_txt",domain:asset.canonical_target}
      });
      return reply(200,{verified:true,asset_id:asset.id,domain:asset.canonical_target,method:"dns_txt"});
    }
    throw fail("Unsupported asset verification action.",400,"invalid_action");
  } catch(error) {
    return reply(Number((error as any).status||403),{
      error:error instanceof Error?error.message:"Asset verification failed.",
      code:String((error as any).code||"asset_authorization_denied")
    });
  }
});
