-- ANISH ENTERPRISES / SCANNER
-- Enterprise control plane: identities, tenants, verified assets, engagements and audit.
-- Apply with the Supabase migration runner. Never expose service-role credentials to clients.

create extension if not exists pgcrypto;

create table if not exists public.platform_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text not null default '',
  status text not null default 'pending' check (status in ('pending','active','suspended','rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.platform_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('super_admin','platform_admin','security_analyst','auditor')),
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id)
);

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  website text,
  status text not null default 'pending' check (status in ('pending','active','suspended','rejected')),
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.org_memberships (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','org_admin','security_engineer','developer','auditor')),
  status text not null default 'invited' check (status in ('invited','active','suspended','revoked')),
  invited_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  unique (organization_id, user_id)
);

create table if not exists public.access_requests (
  id uuid primary key default gen_random_uuid(),
  requester_user_id uuid references auth.users(id) on delete set null,
  email text not null,
  full_name text not null,
  organization_name text not null,
  organization_website text,
  business_reason text not null,
  status text not null default 'pending' check (status in ('pending','approved','rejected','withdrawn')),
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  review_note text,
  created_at timestamptz not null default now()
);

create index if not exists access_requests_status_created_idx
  on public.access_requests(status, created_at desc);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  slug text not null,
  description text not null default '',
  status text not null default 'active' check (status in ('active','archived','suspended')),
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, slug),
  unique (id, organization_id)
);

create table if not exists public.assets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid not null,
  asset_type text not null check (asset_type in ('domain','ip','cidr','url')),
  canonical_value text not null,
  verification_status text not null default 'pending'
    check (verification_status in ('pending','pending_dns','pending_review','verified','rejected','expired')),
  verification_method text,
  challenge_hash text,
  challenge_expires_at timestamptz,
  verified_at timestamptz,
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  authorization_evidence text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (project_id, canonical_value),
  foreign key (project_id, organization_id) references public.projects(id, organization_id) on delete cascade
);

create index if not exists assets_org_status_idx
  on public.assets(organization_id, verification_status);

create table if not exists public.engagements (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid not null,
  name text not null,
  purpose text not null default '',
  status text not null default 'draft'
    check (status in ('draft','pending_review','approved','active','expired','revoked','rejected')),
  allowed_modules text[] not null default array['web','network','tls']::text[],
  starts_at timestamptz,
  expires_at timestamptz,
  max_hosts integer not null default 1 check (max_hosts between 1 and 256),
  max_jobs_per_day integer not null default 20 check (max_jobs_per_day between 1 and 500),
  approved_by uuid references auth.users(id),
  approved_at timestamptz,
  approval_note text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  foreign key (project_id, organization_id) references public.projects(id, organization_id) on delete cascade,
  check (cardinality(allowed_modules) > 0),
  check (allowed_modules <@ array['web','network','tls','zap']::text[]),
  check (expires_at is null or starts_at is null or expires_at > starts_at)
);

create index if not exists engagements_org_status_idx
  on public.engagements(organization_id, status, expires_at);

create table if not exists public.engagement_assets (
  engagement_id uuid not null,
  organization_id uuid not null,
  asset_id uuid not null,
  primary key (engagement_id, asset_id),
  foreign key (engagement_id, organization_id)
    references public.engagements(id, organization_id) on delete cascade,
  foreign key (asset_id, organization_id)
    references public.assets(id, organization_id) on delete cascade
);

create table if not exists public.assessments (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid not null,
  engagement_id uuid not null,
  asset_id uuid not null,
  submitted_by uuid references auth.users(id),
  status text not null default 'queued'
    check (status in ('queued','running','completed','failed','cancelled')),
  worker_job_id text unique,
  target_snapshot text not null,
  modules text[] not null,
  profile text not null default 'standard' check (profile in ('passive','standard','advanced')),
  summary jsonb not null default '{}'::jsonb,
  report_storage_key text,
  error_code text,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  foreign key (project_id, organization_id) references public.projects(id, organization_id) on delete cascade,
  foreign key (engagement_id, organization_id) references public.engagements(id, organization_id) on delete cascade,
  foreign key (asset_id, organization_id) references public.assets(id, organization_id) on delete cascade
);

create index if not exists assessments_tenant_created_idx
  on public.assessments(organization_id, created_at desc);

create table if not exists public.audit_events (
  id bigint generated always as identity primary key,
  organization_id uuid references public.organizations(id) on delete set null,
  actor_user_id uuid references auth.users(id) on delete set null,
  actor_kind text not null default 'user' check (actor_kind in ('user','system')),
  action text not null,
  resource_type text not null,
  resource_id text,
  outcome text not null default 'success' check (outcome in ('success','denied','failure')),
  ip_address inet,
  user_agent text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists audit_events_org_created_idx
  on public.audit_events(organization_id, created_at desc);

create or replace function public.is_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.platform_admins pa
    join public.platform_profiles pp on pp.user_id = pa.user_id
    where pa.user_id = auth.uid()
      and pa.role in ('super_admin','platform_admin','security_analyst','auditor')
      and pp.status = 'active'
  );
$$;

create or replace function public.has_org_role(p_org_id uuid, p_roles text[] default null)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.is_platform_admin() or exists (
    select 1 from public.org_memberships m
    join public.organizations o on o.id = m.organization_id
    join public.platform_profiles pp on pp.user_id = m.user_id
    where m.organization_id = p_org_id
      and m.user_id = auth.uid()
      and m.status = 'active'
      and pp.status = 'active'
      and o.status = 'active'
      and (p_roles is null or m.role = any(p_roles))
  );
$$;

create or replace function public.get_my_platform_access()
returns jsonb
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_profile jsonb;
  v_admin jsonb;
  v_memberships jsonb;
begin
  if auth.uid() is null then
    return jsonb_build_object('authenticated', false, 'platform_admin', false, 'profile_status', 'anonymous', 'memberships', '[]'::jsonb);
  end if;

  select to_jsonb(pp) into v_profile
  from public.platform_profiles pp
  where pp.user_id = auth.uid();

  select jsonb_build_object('is_admin', true, 'role', pa.role) into v_admin
  from public.platform_admins pa
  where pa.user_id = auth.uid();

  select coalesce(jsonb_agg(jsonb_build_object(
    'organization_id', o.id,
    'organization_name', o.name,
    'organization_slug', o.slug,
    'organization_status', o.status,
    'membership_role', m.role,
    'membership_status', m.status
  )), '[]'::jsonb)
  into v_memberships
  from public.org_memberships m
  join public.organizations o on o.id = m.organization_id
  where m.user_id = auth.uid();

  return jsonb_build_object(
    'authenticated', true,
    'platform_admin', coalesce(v_admin, jsonb_build_object('is_admin', false)),
    'profile_status', coalesce(v_profile->>'status', 'pending'),
    'profile', v_profile,
    'memberships', coalesce(v_memberships, '[]'::jsonb)
  );
end;
$$;

create or replace function public.record_audit_event(
  p_organization_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id text default null,
  p_outcome text default 'success',
  p_metadata jsonb default '{}'::jsonb
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare v_id bigint;
begin
  if auth.uid() is null and current_user <> 'service_role' then
    raise exception 'Authentication required';
  end if;
  if p_organization_id is not null
     and not public.has_org_role(p_organization_id, null) then
    raise exception 'Organization access denied';
  end if;
  insert into public.audit_events(
    organization_id, actor_user_id, action, resource_type, resource_id, outcome, metadata
  ) values (
    p_organization_id, auth.uid(), p_action, p_resource_type, p_resource_id,
    p_outcome, coalesce(p_metadata, '{}'::jsonb)
  ) returning id into v_id;
  return v_id;
end;
$$;

alter table public.platform_profiles enable row level security;
alter table public.platform_admins enable row level security;
alter table public.organizations enable row level security;
alter table public.org_memberships enable row level security;
alter table public.access_requests enable row level security;
alter table public.projects enable row level security;
alter table public.assets enable row level security;
alter table public.engagements enable row level security;
alter table public.engagement_assets enable row level security;
alter table public.assessments enable row level security;
alter table public.audit_events enable row level security;

drop policy if exists profile_self_read on public.platform_profiles;
create policy profile_self_read on public.platform_profiles for select
  using (user_id = auth.uid() or public.is_platform_admin());
drop policy if exists platform_admins_self_read on public.platform_admins;
create policy platform_admins_self_read on public.platform_admins for select
  using (user_id = auth.uid() or public.is_platform_admin());
drop policy if exists organizations_member_read on public.organizations;
create policy organizations_member_read on public.organizations for select
  using (public.has_org_role(id, null));
drop policy if exists memberships_org_read on public.org_memberships;
create policy memberships_org_read on public.org_memberships for select
  using (user_id = auth.uid() or public.has_org_role(organization_id, array['owner','org_admin']));
drop policy if exists access_requests_admin_read on public.access_requests;
create policy access_requests_admin_read on public.access_requests for select
  using (public.is_platform_admin());
drop policy if exists access_requests_user_read on public.access_requests;
create policy access_requests_user_read on public.access_requests for select
  using (requester_user_id = auth.uid());
drop policy if exists projects_member_read on public.projects;
create policy projects_member_read on public.projects for select
  using (public.has_org_role(organization_id, null));
drop policy if exists assets_member_read on public.assets;
create policy assets_member_read on public.assets for select
  using (public.has_org_role(organization_id, null));
drop policy if exists engagements_member_read on public.engagements;
create policy engagements_member_read on public.engagements for select
  using (public.has_org_role(organization_id, null));
drop policy if exists engagement_assets_member_read on public.engagement_assets;
create policy engagement_assets_member_read on public.engagement_assets for select
  using (public.has_org_role(organization_id, null));
drop policy if exists assessments_member_read on public.assessments;
create policy assessments_member_read on public.assessments for select
  using (public.has_org_role(organization_id, null));
drop policy if exists audit_member_read on public.audit_events;
create policy audit_member_read on public.audit_events for select
  using (public.is_platform_admin() or (organization_id is not null and public.has_org_role(organization_id, array['owner','org_admin','auditor'])));

-- Controlled writes go through server-side service-role APIs that independently
-- verify the caller, tenant membership, role and state. Direct client writes are
-- intentionally denied by the absence of INSERT/UPDATE/DELETE policies.

revoke all on function public.is_platform_admin() from public;
revoke all on function public.has_org_role(uuid, text[]) from public;
revoke all on function public.get_my_platform_access() from public;
revoke all on function public.record_audit_event(uuid,text,text,text,text,jsonb) from public;
grant execute on function public.is_platform_admin() to authenticated;
grant execute on function public.has_org_role(uuid, text[]) to authenticated;
grant execute on function public.get_my_platform_access() to authenticated;
grant execute on function public.record_audit_event(uuid,text,text,text,text,jsonb) to authenticated, service_role;

-- Bootstrap instruction: after the nominated ANISH ENTERPRISES owner signs in once,
-- insert that exact auth.users UUID into platform_profiles (status='active') and
-- platform_admins (role='super_admin') using the Supabase SQL editor. Never seed
-- an administrator from a user-controlled signup field or public email form.
