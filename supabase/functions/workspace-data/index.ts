import { createClient } from "npm:@supabase/supabase-js@2";
const cors={"Access-Control-Allow-Origin":"https://scanner-rose-rho.vercel.app","Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"GET, POST, OPTIONS","Vary":"Origin"};
const reply=(status:number,body:Record<string,unknown>)=>new Response(JSON.stringify(body),{status,headers:{...cors,"Content-Type":"application/json","Cache-Control":"no-store"}});
Deno.serve(async(req:Request)=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:cors});
 if(req.method!=="GET"&&req.method!=="POST")return reply(405,{error:"Method not allowed."});
 try{
  const match=(req.headers.get("Authorization")||"").match(/^Bearer\s+(.+)$/i);
  if(!match)return reply(401,{error:"Authentication required."});
  const url=Deno.env.get("SUPABASE_URL")||"";
  const p=JSON.parse(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS")||"{}");
  const s=JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")||"{}");
  const pub=p.default||Deno.env.get("SUPABASE_ANON_KEY")||"";
  const sec=s.default||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||"";
  const auth=createClient(url,pub,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:userData,error:userError}=await auth.auth.getUser(match[1]);
  if(userError||!userData.user)return reply(401,{error:"Invalid session."});
  const admin=createClient(url,sec,{auth:{persistSession:false,autoRefreshToken:false}});
  const user=userData.user;
  const {data:profile}=await admin.from("user_profiles").select("display_name,account_status").eq("user_id",user.id).maybeSingle();
  if(profile?.account_status!=="approved")return reply(403,{error:"Your ANISH ENTERPRISES account is pending approval.",code:"account_not_approved"});
  const {data:members,error:memberError}=await admin.from("organization_memberships")
    .select("organization_id,role,status").eq("user_id",user.id).eq("status","active");
  if(memberError)return reply(503,{error:"Unable to load organization memberships."});
  const orgIds=(members||[]).map(m=>m.organization_id);
  if(!orgIds.length)return reply(200,{user:{id:user.id,email:user.email,display_name:profile.display_name},organizations:[]});
  const {data:orgs,error:orgError}=await admin.from("organizations").select("id,legal_name,slug,status")
    .in("id",orgIds).eq("status","verified");
  if(orgError)return reply(503,{error:"Unable to load verified organizations."});
  const organizations=[];
  for(const org of orgs||[]){
   const membership=(members||[]).find(m=>m.organization_id===org.id);
   const {data:projects}=await admin.from("projects").select("id,name,description")
    .eq("organization_id",org.id).order("created_at",{ascending:false});
   const projectRows=[];
   for(const project of projects||[]){
    const [{data:assets},{data:engagements}]=await Promise.all([
     admin.from("assets").select("id,kind,canonical_target,display_name,verification_status,verified_at")
      .eq("organization_id",org.id).eq("project_id",project.id).eq("verification_status","verified"),
     admin.from("engagements").select("id,title,status,starts_at,expires_at,policy")
      .eq("organization_id",org.id).eq("project_id",project.id).in("status",["approved","active"])
      .order("created_at",{ascending:false})
    ]);
    const engagementRows=[];
    for(const engagement of engagements||[]){
     const {data:targets}=await admin.from("engagement_targets").select("id,asset_id,allowed_modules,assets!inner(canonical_target,kind)")
      .eq("engagement_id",engagement.id);
     engagementRows.push({...engagement,targets:targets||[]});
    }
    projectRows.push({...project,assets:assets||[],engagements:engagementRows});
   }
   organizations.push({...org,role:membership?.role,projects:projectRows});
  }
  return reply(200,{user:{id:user.id,email:user.email,display_name:profile.display_name},organizations});
 }catch(_){return reply(500,{error:"Workspace information could not be loaded."});}
});
