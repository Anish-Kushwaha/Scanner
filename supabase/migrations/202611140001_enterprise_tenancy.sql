begin;
create extension if not exists pgcrypto with schema extensions;
create type public.account_status as enum ('pending','approved','rejected','suspended');
create type public.organization_status as enum ('pending','verified','suspended','rejected');
create type public.membership_role as enum ('owner','security_engineer','developer','auditor');
create type public.membership_status as enum ('invited','active','suspended','revoked');
create type public.engagement_status as enum ('draft','pending_approval','approved','active','paused','completed','rejected','expired');
create type public.target_kind as enum ('domain','url','ip','cidr');
create type public.target_verification_status as enum ('pending','verified','rejected','expired');
create type public.audit_severity as enum ('info','warning','critical');

create table public.user_profiles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 display_name text, account_status public.account_status not null default 'pending',
 approved_at timestamptz, approved_by uuid references auth.users(id),
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 check (account_status <> 'approved' or (approved_at is not null and approved_by is not null))
);
create table public.organizations (
 id uuid primary key default gen_random_uuid(), legal_name text not null, slug text not null unique,
 status public.organization_status not null default 'pending', verification_method text,
 verified_at timestamptz, verified_by uuid references auth.users(id),
 created_by uuid not null references auth.users(id), created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 check (status <> 'verified' or (verified_at is not null and verified_by is not null))
);
create table public.organization_memberships (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 role public.membership_role not null default 'developer', status public.membership_status not null default 'invited',
 invited_by uuid references auth.users(id), approved_by uuid references auth.users(id),
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 unique (organization_id,user_id)
);
create table public.projects (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 name text not null, description text, created_by uuid not null references auth.users(id),
 created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table public.assets (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 project_id uuid not null references public.projects(id) on delete cascade, kind public.target_kind not null,
 canonical_target text not null, display_name text,
 verification_status public.target_verification_status not null default 'pending',
 verification_method text, verification_token_hash text, verified_at timestamptz,
 verified_by uuid references auth.users(id), created_by uuid not null references auth.users(id),
 created_at timestamptz not null default now(), unique(project_id,canonical_target),
 check (verification_status <> 'verified' or (verified_at is not null and verification_method is not null))
);
create table public.engagements (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 project_id uuid not null references public.projects(id) on delete cascade, title text not null, purpose text,
 status public.engagement_status not null default 'draft',
 requested_by uuid not null references auth.users(id), approved_by uuid references auth.users(id),
 approved_at timestamptz, starts_at timestamptz, expires_at timestamptz,
 policy jsonb not null default '{"profile":"passive","max_hosts":32,"max_concurrency":1,"modules":["web","tls"]}'::jsonb,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 check (status not in ('approved','active') or (approved_by is not null and approved_at is not null)),
 check (expires_at is null or starts_at is null or expires_at > starts_at)
);
create table public.engagement_targets (
 id uuid primary key default gen_random_uuid(), engagement_id uuid not null references public.engagements(id) on delete cascade,
 asset_id uuid not null references public.assets(id) on delete cascade,
 allowed_modules text[] not null default array['web','tls']::text[], constraints jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now(), unique(engagement_id,asset_id)
);
create table public.authorization_evidence (
 id uuid primary key default gen_random_uuid(), engagement_id uuid not null references public.engagements(id) on delete cascade,
 evidence_type text not null check (evidence_type in ('domain_dns','domain_http','ip_ownership','written_permission','contract','manual_review')),
 evidence_uri text, evidence_sha256 text, verified_by uuid references auth.users(id), verified_at timestamptz,
 expires_at timestamptz, notes text, created_at timestamptz not null default now(),
 check (evidence_sha256 is null or evidence_sha256 ~ '^[a-f0-9]{64}$')
);
create table public.assessment_jobs (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null references public.organizations(id) on delete cascade,
 project_id uuid not null references public.projects(id) on delete cascade,
 engagement_id uuid not null references public.engagements(id) on delete restrict,
 target_id uuid not null references public.engagement_targets(id) on delete restrict,
 requested_by uuid not null references auth.users(id),
 status text not null default 'queued' check (status in ('queued','running','completed','failed','cancelled')),
 modules text[] not null, profile text not null check (profile in ('passive','standard','advanced')),
 worker_job_id text unique, result_ref text, error_code text,
 created_at timestamptz not null default now(), started_at timestamptz, completed_at timestamptz
);
create table public.audit_events (
 id bigint generated always as identity primary key,
 organization_id uuid references public.organizations(id) on delete set null,
 actor_user_id uuid references auth.users(id) on delete set null,
 action text not null, resource_type text not null, resource_id text,
 severity public.audit_severity not null default 'info', metadata jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);
create index memberships_user_status_idx on public.organization_memberships(user_id,status);
create index projects_org_idx on public.projects(organization_id);
create index assets_org_project_idx on public.assets(organization_id,project_id);
create index engagements_org_status_idx on public.engagements(organization_id,status);
create index engagement_targets_engagement_idx on public.engagement_targets(engagement_id);
create index jobs_org_created_idx on public.assessment_jobs(organization_id,created_at desc);
create index audit_org_created_idx on public.audit_events(organization_id,created_at desc);

create or replace function public.is_platform_admin() returns boolean language sql stable security definer set search_path = '' as $$
 select coalesce((auth.jwt() -> 'app_metadata' ->> 'platform_role') = 'super_admin',false)
$$;
create or replace function public.is_approved_user() returns boolean language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.user_profiles p where p.user_id=(select auth.uid()) and p.account_status='approved')
$$;
create or replace function public.is_org_member(org_id uuid) returns boolean language sql stable security definer set search_path = '' as $$
 select public.is_platform_admin() or (public.is_approved_user() and exists(
  select 1 from public.organization_memberships m join public.organizations o on o.id=m.organization_id
  where m.organization_id=org_id and m.user_id=(select auth.uid()) and m.status='active' and o.status='verified'
 ))
$$;
create or replace function public.has_org_role(org_id uuid, allowed_roles public.membership_role[]) returns boolean language sql stable security definer set search_path = '' as $$
 select public.is_platform_admin() or (public.is_approved_user() and exists(
  select 1 from public.organization_memberships m where m.organization_id=org_id
  and m.user_id=(select auth.uid()) and m.status='active' and m.role=any(allowed_roles)
 ))
$$;

alter table public.user_profiles enable row level security;
alter table public.organizations enable row level security;
alter table public.organization_memberships enable row level security;
alter table public.projects enable row level security;
alter table public.assets enable row level security;
alter table public.engagements enable row level security;
alter table public.engagement_targets enable row level security;
alter table public.authorization_evidence enable row level security;
alter table public.assessment_jobs enable row level security;
alter table public.audit_events enable row level security;

create policy profile_self_read on public.user_profiles for select to authenticated using(user_id=(select auth.uid()) or public.is_platform_admin());
create policy profile_admin_manage on public.user_profiles for all to authenticated using(public.is_platform_admin()) with check(public.is_platform_admin());
create policy org_member_read on public.organizations for select to authenticated using(public.is_org_member(id));
create policy org_admin_manage on public.organizations for all to authenticated using(public.is_platform_admin()) with check(public.is_platform_admin());
create policy membership_org_read on public.organization_memberships for select to authenticated using(public.is_org_member(organization_id));
create policy membership_admin_manage on public.organization_memberships for all to authenticated using(public.is_platform_admin()) with check(public.is_platform_admin());
create policy projects_member_read on public.projects for select to authenticated using(public.is_org_member(organization_id));
create policy projects_owner_write on public.projects for insert to authenticated with check(public.has_org_role(organization_id,array['owner']::public.membership_role[]) and created_by=(select auth.uid()));
create policy projects_owner_update on public.projects for update to authenticated using(public.has_org_role(organization_id,array['owner']::public.membership_role[])) with check(public.has_org_role(organization_id,array['owner']::public.membership_role[]));
create policy projects_admin_delete on public.projects for delete to authenticated using(public.is_platform_admin());
create policy assets_member_read on public.assets for select to authenticated using(public.is_org_member(organization_id));
create policy assets_owner_insert on public.assets for insert to authenticated with check(public.has_org_role(organization_id,array['owner']::public.membership_role[]) and created_by=(select auth.uid()));
create policy assets_admin_manage on public.assets for all to authenticated using(public.is_platform_admin()) with check(public.is_platform_admin());
create policy engagements_member_read on public.engagements for select to authenticated using(public.is_org_member(organization_id));
create policy engagements_owner_insert on public.engagements for insert to authenticated with check(public.has_org_role(organization_id,array['owner','security_engineer']::public.membership_role[]) and requested_by=(select auth.uid()));
create policy engagements_admin_manage on public.engagements for all to authenticated using(public.is_platform_admin()) with check(public.is_platform_admin());
create policy engagement_targets_member_read on public.engagement_targets for select to authenticated using(exists(select 1 from public.engagements e where e.id=engagement_id and public.is_org_member(e.organization_id)));
create policy engagement_targets_admin_manage on public.engagement_targets for all to authenticated using(public.is_platform_admin()) with check(public.is_platform_admin());
create policy evidence_member_read on public.authorization_evidence for select to authenticated using(exists(select 1 from public.engagements e where e.id=engagement_id and public.is_org_member(e.organization_id)));
create policy evidence_admin_manage on public.authorization_evidence for all to authenticated using(public.is_platform_admin()) with check(public.is_platform_admin());
create policy jobs_member_read on public.assessment_jobs for select to authenticated using(public.is_org_member(organization_id));
create policy jobs_member_insert on public.assessment_jobs for insert to authenticated with check(public.has_org_role(organization_id,array['owner','security_engineer']::public.membership_role[]) and requested_by=(select auth.uid()));
create policy jobs_admin_manage on public.assessment_jobs for all to authenticated using(public.is_platform_admin()) with check(public.is_platform_admin());
create policy audit_member_read on public.audit_events for select to authenticated using(public.is_platform_admin() or (organization_id is not null and public.is_org_member(organization_id)));
create policy audit_admin_insert on public.audit_events for insert to authenticated with check(public.is_platform_admin() or actor_user_id=(select auth.uid()));

revoke all on public.user_profiles,public.organizations,public.organization_memberships,public.projects,public.assets,public.engagements,public.engagement_targets,public.authorization_evidence,public.assessment_jobs,public.audit_events from anon;
grant select,insert,update,delete on public.user_profiles,public.organizations,public.organization_memberships,public.projects,public.assets,public.engagements,public.engagement_targets,public.authorization_evidence,public.assessment_jobs,public.audit_events to authenticated;
commit;