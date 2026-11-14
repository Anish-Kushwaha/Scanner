import { createClient } from "npm:@supabase/supabase-js@2";
const cors={"Access-Control-Allow-Origin":"https://scanner-rose-rho.vercel.app","Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Vary":"Origin"};
const reply=(status:number,body:Record<string,unknown>)=>new Response(JSON.stringify(body),{status,headers:{...cors,"Content-Type":"application/json","Cache-Control":"no-store"}});
const fail=(message:string,status=403,code="engagement_request_denied")=>Object.assign(new Error(message),{status,code});
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return reply(405,{error:"Method not allowed."});
 try{
  const match=(req.headers.get("Authorization")||"").match(/^Bearer\s+(.+)$/i);
  if(!match)throw fail("Authentication required.",401,"authentication_required");
  const url=Deno.env.get("SUPABASE_URL")||"",p=JSON.parse(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS")||"{}"),s=JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")||"{}");
  const auth=createClient(url,p.default||Deno.env.get("SUPABASE_ANON_KEY")||"",{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:userData,error:userError}=await auth.auth.getUser(match[1]);
  if(userError||!userData.user)throw fail("Invalid session.",401,"invalid_session");
  const claims=JSON.parse(atob(match[1].split(".")[1].replace(/-/g,"+").replace(/_/g,"/")));
  if(claims.aal!=="aal2")throw fail("MFA is required to request an assessment engagement.",403,"mfa_required");
  const admin=createClient(url,s.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||"",{auth:{persistSession:false,autoRefreshToken:false}});
  const user=userData.user,body=await req.json();
  const orgId=String(body.organization_id||""),projectId=String(body.project_id||"");
  const {data:profile}=await admin.from("user_profiles").select("account_status").eq("user_id",user.id).maybeSingle();
  if(profile?.account_status!=="approved")throw fail("Your account is not approved.",403,"account_not_approved");
  const {data:membership}=await admin.from("organization_memberships").select("role")
   .eq("organization_id",orgId).eq("user_id",user.id).eq("status","active").maybeSingle();
  const {data:org}=await admin.from("organizations").select("id").eq("id",orgId).eq("status","verified").maybeSingle();
  const {data:project}=await admin.from("projects").select("id").eq("id",projectId).eq("organization_id",orgId).maybeSingle();
  if(!membership||!org||!project)throw fail("Verified organization membership and project access are required.");
  if(!["owner","security_engineer"].includes(membership.role))throw fail("Your role cannot request security engagements.");
  const title=String(body.title||"").trim().slice(0,120);
  const purpose=String(body.purpose||"").trim().slice(0,1000);
  const assetIds=Array.isArray(body.asset_ids)?[...new Set(body.asset_ids.map(String))]:[];
  const modules=Array.isArray(body.modules)?[...new Set(body.modules.map(String))]:[];
  const validModules=new Set(["web","network","tls","zap"]);
  if(!title||!assetIds.length||!modules.length||modules.some(m=>!validModules.has(m)))throw fail("Provide a title, verified targets and supported assessment modules.",400,"invalid_engagement");
  if(!["passive","standard","advanced"].includes(body.profile))throw fail("Invalid scan profile.",400,"invalid_profile");
  const {data:assets,error:assetsError}=await admin.from("assets").select("id,kind,canonical_target,verification_status,verification_method,verified_at,verified_by")
   .eq("organization_id",orgId).eq("project_id",projectId).in("id",assetIds).eq("verification_status","verified");
  if(assetsError||!assets||assets.length!==assetIds.length)throw fail("Every target must be a verified asset in the selected project.",403,"asset_not_verified");
  const maxHosts=Math.min(Math.max(Number(body.max_hosts||32),1),256);
  const policy={profile:body.profile,modules,max_hosts:maxHosts,max_concurrency:1,os_detect:Boolean(body.os_detect),udp:Boolean(body.udp)};
  const {data:engagement,error:engagementError}=await admin.from("engagements").insert({
   organization_id:orgId,project_id:projectId,title,purpose,status:"pending_approval",
   requested_by:user.id,policy
  }).select("id").single();
  if(engagementError||!engagement)throw fail("Could not create the engagement request.",500,"engagement_create_failed");
  const targetRows=assets.map((asset:any)=>({engagement_id:engagement.id,asset_id:asset.id,allowed_modules:modules,constraints:{max_hosts:maxHosts}}));
  const {error:targetError}=await admin.from("engagement_targets").insert(targetRows);
  if(targetError)throw fail("Could not add targets to the engagement request.",500,"engagement_targets_failed");
  const evidenceRows=assets.map((asset:any)=>({
   engagement_id:engagement.id,
   evidence_type:asset.verification_method==="dns_txt"?"domain_dns":"written_permission",
   verified_by:asset.verification_method==="dns_txt"?asset.verified_by:null,
   verified_at:asset.verification_method==="dns_txt"?asset.verified_at:null,
   notes:asset.verification_method==="dns_txt"?"Domain ownership was proven by DNS TXT challenge.":"Requires ANISH ENTERPRISES manual authorization review."
  }));
  const {error:evidenceError}=await admin.from("authorization_evidence").insert(evidenceRows);
  if(evidenceError)throw fail("Could not attach authorization evidence to the engagement.",500,"evidence_create_failed");
  await admin.from("audit_events").insert({organization_id:orgId,actor_user_id:user.id,action:"engagement.requested",resource_type:"engagement",resource_id:engagement.id,severity:"info",metadata:{asset_count:assetIds.length,modules,profile:body.profile}});
  return reply(200,{created:true,engagement_id:engagement.id,status:"pending_approval",message:"Engagement submitted for ANISH ENTERPRISES review."});
 }catch(error){return reply(Number((error as any).status||500),{error:error instanceof Error?error.message:"Engagement request failed.",code:String((error as any).code||"engagement_request_denied")});}
});
