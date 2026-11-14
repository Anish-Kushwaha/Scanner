import { createClient } from "npm:@supabase/supabase-js@2";

const cors={"Access-Control-Allow-Origin":"https://scanner-rose-rho.vercel.app","Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Vary":"Origin"};
const reply=(status:number,body:Record<string,unknown>)=>new Response(JSON.stringify(body),{status,headers:{...cors,"Content-Type":"application/json","Cache-Control":"no-store"}});
const fail=(message:string,status=403,code="admin_action_denied")=>Object.assign(new Error(message),{status,code});

Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="POST")return reply(405,{error:"Method not allowed."});
 try{
  const match=(req.headers.get("Authorization")||"").match(/^Bearer\s+(.+)$/i);
  if(!match)throw fail("Authentication required.",401,"authentication_required");
  const url=Deno.env.get("SUPABASE_URL")||"",p=JSON.parse(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS")||"{}"),s=JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")||"{}");
  const pub=p.default||Deno.env.get("SUPABASE_ANON_KEY")||"",secret=s.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||"";
  if(!url||!pub||!secret)throw fail("Admin service is not configured.",503,"admin_service_unconfigured");
  const auth=createClient(url,pub,{auth:{persistSession:false,autoRefreshToken:false},global:{headers:{Authorization:"Bearer "+match[1]}}});
  const {data:userData,error:userError}=await auth.auth.getUser(match[1]);
  if(userError||!userData.user)throw fail("Invalid session.",401,"invalid_session");
  const user=userData.user;
  const jwtPart=match[1].split(".")[1];
  const jwtClaims=JSON.parse(atob(jwtPart.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(jwtPart.length/4)*4,"=")));
  if(jwtClaims.aal!=="aal2")throw fail("Multi-factor authentication is required for platform administration.",403,"mfa_required");
  const admin=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
  const body=await req.json();
  const action=String(body.action||"");

  if(action==="bootstrap_first_admin"){
   if(String(user.email||"").toLowerCase()!=="anishkushwahag28@gmail.com")
    throw fail("Only the verified ANISH ENTERPRISES owner email can bootstrap the first administrator.",403,"bootstrap_email_mismatch");
   const {data:bootstrapped,error:bootstrapError}=await admin.rpc("bootstrap_first_platform_admin",{check_user_id:user.id});
   if(bootstrapError||bootstrapped!==true)
    throw fail(bootstrapError?.message||"First administrator bootstrap was not completed.",409,"bootstrap_failed");
   return reply(200,{bootstrapped:true,role:"supreme_admin",email:"anishkushwahag28@gmail.com"});
  }

  const {data:isAdmin,error:adminCheckError}=await admin.rpc("is_platform_admin_user",{check_user_id:user.id});
  if(adminCheckError||isAdmin!==true)throw fail("Only an ANISH ENTERPRISES platform administrator can perform this action.",403,"platform_admin_required");
  if(action==="dashboard"){
   const [{data:profiles},{data:organizations},{data:memberships},{data:engagements},{data:assets},{data:evidence},{data:userList}]=await Promise.all([
    admin.from("user_profiles").select("user_id,display_name,account_status,created_at").in("account_status",["pending","approved","suspended"]).order("created_at",{ascending:false}).limit(200),
    admin.from("organizations").select("id,legal_name,slug,status,created_at,created_by").in("status",["pending","verified","suspended"]).order("created_at",{ascending:false}).limit(200),
    admin.from("organization_memberships").select("id,organization_id,user_id,role,status,created_at").in("status",["invited","active","suspended"]).order("created_at",{ascending:false}).limit(300),
    admin.from("engagements").select("id,organization_id,project_id,title,purpose,status,requested_by,created_at,policy").in("status",["pending_approval","approved","active","rejected"]).order("created_at",{ascending:false}).limit(200),
    admin.from("assets").select("id,organization_id,project_id,kind,canonical_target,verification_status,verification_method,created_at").in("verification_status",["pending","verified"]).order("created_at",{ascending:false}).limit(200),
    admin.from("authorization_evidence").select("id,engagement_id,evidence_type,evidence_uri,evidence_sha256,verified_at,expires_at,notes,created_at").order("created_at",{ascending:false}).limit(300),
    admin.auth.admin.listUsers({page:1,perPage:500})
   ]);
   const users=userList?.users||[];
   const emailById=new Map(users.map((u:any)=>[u.id,u.email]));
   return reply(200,{
    users:(profiles||[]).map((x:any)=>({...x,email:emailById.get(x.user_id)||null})),
    organizations:organizations||[],
    memberships:(memberships||[]).map((x:any)=>({...x,email:emailById.get(x.user_id)||null})),
    engagements:engagements||[],
    assets:assets||[],
    evidence:evidence||[]
   });
  }

  if(action==="approve_user"||action==="suspend_user"||action==="reject_user"){
   const id=String(body.user_id||"");
   if(!/^[0-9a-f-]{36}$/i.test(id))throw fail("Invalid user identifier.",400,"invalid_user_id");
   const status=action==="approve_user"?"approved":action==="suspend_user"?"suspended":"rejected";
   const {error}=await admin.from("user_profiles").update({
    account_status:status,approved_at:status==="approved"?new Date().toISOString():null,
    approved_by:status==="approved"?user.id:null,updated_at:new Date().toISOString()
   }).eq("user_id",id);
   if(error)throw fail("Could not update account approval.",500,"user_update_failed");
   await admin.from("audit_events").insert({actor_user_id:user.id,action:"user."+status,resource_type:"user",resource_id:id,severity:status==="suspended"?"warning":"info"});
   return reply(200,{updated:true,user_id:id,account_status:status});
  }

  if(action==="verify_organization"||action==="suspend_organization"||action==="reject_organization"){
   const id=String(body.organization_id||"");
   if(!/^[0-9a-f-]{36}$/i.test(id))throw fail("Invalid organization identifier.",400,"invalid_organization_id");
   const status=action==="verify_organization"?"verified":action==="suspend_organization"?"suspended":"rejected";
   const {error}=await admin.from("organizations").update({
    status,verified_at:status==="verified"?new Date().toISOString():null,
    verified_by:status==="verified"?user.id:null,verification_method:status==="verified"?"manual_admin_review":null,
    updated_at:new Date().toISOString()
   }).eq("id",id);
   if(error)throw fail("Could not update organization verification.",500,"organization_update_failed");
   await admin.from("audit_events").insert({organization_id:id,actor_user_id:user.id,action:"organization."+status,resource_type:"organization",resource_id:id,severity:status==="suspended"?"warning":"info"});
   return reply(200,{updated:true,organization_id:id,status});
  }

  if(action==="approve_membership"||action==="revoke_membership"){
   const id=String(body.membership_id||"");
   const {data:membership}=await admin.from("organization_memberships").select("id,organization_id,user_id").eq("id",id).maybeSingle();
   if(!membership)throw fail("Membership not found.",404,"membership_not_found");
   const status=action==="approve_membership"?"active":"revoked";
   const {error}=await admin.from("organization_memberships").update({status,approved_by:status==="active"?user.id:null,updated_at:new Date().toISOString()}).eq("id",id);
   if(error)throw fail("Could not update membership.",500,"membership_update_failed");
   await admin.from("audit_events").insert({organization_id:membership.organization_id,actor_user_id:user.id,action:"membership."+status,resource_type:"membership",resource_id:id,severity:"info"});
   return reply(200,{updated:true,membership_id:id,status});
  }

  if(action==="invite_member"){
   const organizationId=String(body.organization_id||""),email=String(body.email||"").trim().toLowerCase(),role=String(body.role||"developer");
   if(!/^[0-9a-f-]{36}$/i.test(organizationId)||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))throw fail("A valid organization and email are required.",400,"invalid_invitation");
   if(!["owner","security_engineer","developer","auditor"].includes(role))throw fail("Invalid organization role.",400,"invalid_role");
   const {data:org}=await admin.from("organizations").select("id,status").eq("id",organizationId).eq("status","verified").maybeSingle();
   if(!org)throw fail("Only verified organizations can invite members.",403,"organization_not_verified");
   const {data:invited,error:inviteError}=await admin.auth.admin.inviteUserByEmail(email,{redirectTo:"https://scanner-rose-rho.vercel.app/login.html"});
   if(inviteError||!invited.user)throw fail(inviteError?.message||"Invitation could not be sent.",400,"invite_failed");
   const memberId=invited.user.id;
   const {error:profileError}=await admin.from("user_profiles").upsert({
    user_id:memberId,display_name:String(body.display_name||"").slice(0,120),
    account_status:"approved",approved_at:new Date().toISOString(),approved_by:user.id,updated_at:new Date().toISOString()
   },{onConflict:"user_id"});
   if(profileError)throw fail("Invitation sent but account approval could not be recorded.",500,"invite_approval_failed");
   const {error:memberError}=await admin.from("organization_memberships").upsert({
    organization_id:organizationId,user_id:memberId,role,status:"invited",invited_by:user.id
   },{onConflict:"organization_id,user_id"});
   if(memberError)throw fail("Invitation sent but organization membership could not be created.",500,"membership_invite_failed");
   await admin.from("audit_events").insert({organization_id:organizationId,actor_user_id:user.id,action:"membership.invited",resource_type:"membership",resource_id:memberId,severity:"info",metadata:{email,role}});
   return reply(200,{invited:true,user_id:memberId,email,role});
  }

  if(action==="verify_evidence"){
   const evidenceId=String(body.evidence_id||""),notes=String(body.review_notes||"").trim();
   if(!/^[0-9a-f-]{36}$/i.test(evidenceId)||notes.length<20)throw fail("Evidence ID and detailed review notes are required.",400,"invalid_evidence_review");
   const {data:evidence}=await admin.from("authorization_evidence").select("id,engagement_id").eq("id",evidenceId).maybeSingle();
   if(!evidence)throw fail("Authorization evidence not found.",404,"evidence_not_found");
   const {data:engagement}=await admin.from("engagements").select("organization_id").eq("id",evidence.engagement_id).maybeSingle();
   const {error}=await admin.from("authorization_evidence").update({verified_by:user.id,verified_at:new Date().toISOString(),notes}).eq("id",evidenceId);
   if(error)throw fail("Could not approve authorization evidence.",500,"evidence_update_failed");
   await admin.from("audit_events").insert({organization_id:engagement?.organization_id,actor_user_id:user.id,action:"authorization_evidence.verified",resource_type:"authorization_evidence",resource_id:evidenceId,severity:"warning",metadata:{review_notes:notes}});
   return reply(200,{verified:true,evidence_id:evidenceId});
  }

  if(action==="approve_engagement"||action==="reject_engagement"){
   const id=String(body.engagement_id||"");
   const {data:engagement}=await admin.from("engagements").select("id,organization_id,project_id,status,policy").eq("id",id).maybeSingle();
   if(!engagement)throw fail("Engagement not found.",404,"engagement_not_found");
   if(action==="reject_engagement"){
    const {error}=await admin.from("engagements").update({status:"rejected"}).eq("id",id);
    if(error)throw fail("Could not reject engagement.",500,"engagement_update_failed");
    await admin.from("audit_events").insert({organization_id:engagement.organization_id,actor_user_id:user.id,action:"engagement.rejected",resource_type:"engagement",resource_id:id,severity:"warning"});
    return reply(200,{updated:true,status:"rejected"});
   }
   const {data:targets}=await admin.from("engagement_targets").select("id,asset_id,allowed_modules").eq("engagement_id",id);
   if(!targets?.length)throw fail("Engagement has no targets.",409,"engagement_has_no_targets");
   const assetIds=targets.map((t:any)=>t.asset_id);
   const {data:assets}=await admin.from("assets").select("id,verification_status").in("id",assetIds).eq("verification_status","verified");
   if(!assets||assets.length!==assetIds.length)throw fail("Every engagement target must have verified ownership or written authorization.",403,"unverified_engagement_target");
   const {data:evidence}=await admin.from("authorization_evidence").select("id,verified_at,expires_at").eq("engagement_id",id).not("verified_at","is",null);
   const now=Date.now();
   if(!evidence?.some((ev:any)=>!ev.expires_at||Date.parse(ev.expires_at)>now))throw fail("Current authorization evidence is required before approval.",403,"authorization_evidence_missing");
   const {error}=await admin.from("engagements").update({status:"approved",approved_by:user.id,approved_at:new Date().toISOString()}).eq("id",id);
   if(error)throw fail("Could not approve engagement.",500,"engagement_update_failed");
   await admin.from("audit_events").insert({organization_id:engagement.organization_id,actor_user_id:user.id,action:"engagement.approved",resource_type:"engagement",resource_id:id,severity:"info"});
   return reply(200,{updated:true,status:"approved"});
  }

  throw fail("Unsupported admin action.",400,"invalid_admin_action");
 }catch(error){
  return reply(Number((error as any).status||500),{error:error instanceof Error?error.message:"Admin operation failed.",code:String((error as any).code||"admin_action_denied")});
 }
});
