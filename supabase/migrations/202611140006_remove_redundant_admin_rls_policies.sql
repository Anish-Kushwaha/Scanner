begin;
drop policy if exists profile_admin_manage on public.user_profiles;
drop policy if exists org_admin_manage on public.organizations;
drop policy if exists membership_admin_manage on public.organization_memberships;
drop policy if exists assets_admin_manage on public.assets;
drop policy if exists engagements_admin_manage on public.engagements;
drop policy if exists engagement_targets_admin_manage on public.engagement_targets;
drop policy if exists evidence_admin_manage on public.authorization_evidence;
drop policy if exists jobs_admin_manage on public.assessment_jobs;

drop policy if exists platform_admins_deny_client_access on private.platform_admins;
create policy platform_admins_deny_client_access
 on private.platform_admins
 as restrictive
 for all
 to anon, authenticated
 using (false)
 with check (false);
commit;