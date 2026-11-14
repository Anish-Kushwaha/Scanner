-- ANISH ENTERPRISES / SCANNER
-- Enterprise control plane: identities, tenants, verified assets, engagements and audit.
-- Direct browser writes are deliberately narrow; assessment creation and approvals use the
-- authenticated server-side control plane. Never expose a Supabase service-role key to clients.

create extension if not exists pgcrypto;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated, service_role;

-- An auth signup creates a pending profile only. It never creates a platform admin or tenant.
create table public.platform_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text not null default '',
  status text not null default 'pending'
    check (status in ('pending','active','suspended','rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.platform_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('super_admin','platform_admin','security_analyst','auditor')),
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id)
);

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  website text,
  status text not null default 'pending'
    check (status in ('pending','active','suspended','rejected')),
  verified_at timestamptz,
  verified_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.org_memberships (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','org_admin','security_engineer','developer','auditor')),
  status text not null default 'invited'
    check (status in ('invited','active','suspended','revoked')),
  invited_by uuid references auth.users(id),
  invited_at timestamptz not null default now(),
  accepted_at timestamptz,
  unique (organization_id, user_id),
  unique (id, organization_id)
);

create table public.access_requests (
  id uuid primary key default gen_random_uuid(),
  requester_user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  full_name text not null,
  organization_name text not null,
  organization_website text,
  business_reason text not null,
  status text not null default 'pending'
    check (status in ('pending','approved','rejected','withdrawn')),
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  review_note text,
  created_at timestamptz not null default now()
);
create index access_requests_status_created_idx
  on public.access_requests(status, created_at desc);

create table public.projects (
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

-- This is a tenant-owned asset inventory, not a global/static scan allowlist.
-- Assets start unverified. A private server-side verifier changes status only after proof.
create table public.assets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  project_id uuid not null,
  asset_type text not null check (asset_type in ('domain','ip','cidr','url')),
  canonical_value text not null,
  verification_status text not null default 'pending'
    check (verification_status in ('pending','pending_dns','pending_review','verified','rejected','expired')),
  verification_method text
    check (verification_method in ('dns_txt','http_file','authorization_document','manual')),
  challenge_hash text,
  challenge_expires_at timestamptz,
  verified_at timestamptz,
  verified_by uuid references auth.users(id),
  authorization_expires_at timestamptz,
  review_note text,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (project_id, canonical_value),
  unique (id, organization_id),
  foreign key (project_id, organization_id)
    references public.projects(id, organization_id) on delete cascade,
  check (verification_status <> 'verified' or verified_at is not null)
);
create index assets_org_status_idx
  on public.assets(organization_id, verification_status);
create index assets_project_type_idx
  on public.assets(project_id, asset_type);

create table public.asset_authorization_evidence (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null,
  asset_id uuid not null,
  storage_key text not null,
  evidence_type text not null
    check (evidence_type in ('ownership_document','written_authorization','dns_proof','http_proof','other')),
  sha256 text,
  review_status text not null default 'pending'
    check (review_status in ('pending','approved','rejected')),
  review_note text,
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  uploaded_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  foreign key (asset_id, organization_id)
    references public.assets(id, organization_id) on delete cascade
);
create index asset_evidence_org_asset_idx
  on public.asset_authorization_evidence(organization_id, asset_id, created_at desc);

create table public.engagements (
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
  foreign key (project_id, organization_id)
    references public.projects(id, organization_id) on delete cascade,
  check (cardinality(allowed_modules) > 0),
  check (allowed_modules <@ array['web','network','tls','zap']::text[]),
  check (expires_at is null or starts_at is null or expires_at > starts_at)
);
create index engagements_org_status_idx
  on public.engagements(organization_id, status, expires_at);

create table public.engagement_assets (
  engagement_id uuid not null,
  organization_id uuid not null,
  asset_id uuid not null,
  added_by uuid references auth.users(id),
  created_at timestamptz not null default now(),
  primary key (engagement_id, asset_id),
  foreign key (engagement_id, organization_id)
    references public.engagements(id, organization_id) on delete cascade,
  foreign key (asset_id, organization_id)
    references public.assets(id, organization_id) on delete cascade
);

create table public.assessments (
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
  unique (id, organization_id),
  unique (id, organization_id, asset_id),
  foreign key (project_id, organization_id)
    references public.projects(id, organization_id) on delete cascade,
  foreign key (engagement_id, organization_id)
    references public.engagements(id, organization_id) on delete cascade,
  foreign key (asset_id, organization_id)
    references public.assets(id, organization_id) on delete cascade,
  check (cardinality(modules) > 0),
  check (modules <@ array['web','network','tls','zap']::text[])
);
create index assessments_tenant_created_idx
  on public.assessments(organization_id, created_at desc);
create index assessments_queue_idx
  on public.assessments(status, created_at)
  where status in ('queued','running');

create table public.assessment_findings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  assessment_id uuid not null references public.assessments(id) on delete cascade,
  asset_id uuid not null references public.assets(id) on delete cascade,
  fingerprint text not null,
  title text not null,
  severity text not null check (severity in ('critical','high','medium','low','info')),
  confidence text not null default 'medium' check (confidence in ('high','medium','low')),
  category text not null,
  description text not null default '',
  evidence jsonb not null default '{}'::jsonb,
  remediation text not null default '',
  cve text,
  status text not null default 'open'
    check (status in ('open','accepted_risk','in_progress','resolved','false_positive')),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (assessment_id, fingerprint),
  foreign key (assessment_id, organization_id)
    references public.assessments(id, organization_id) on delete cascade,
  foreign key (asset_id, organization_id)
    references public.assets(id, organization_id) on delete cascade
);
create index findings_org_severity_idx
  on public.assessment_findings(organization_id, severity, status);

create table public.audit_events (
  id bigint generated always as identity primary key,
  organization_id uuid references public.organizations(id) on delete set null,
  actor_user_id uuid references auth.users(id) on delete set null,
  actor_kind text not null default 'user' check (actor_kind in ('user','system')),
  action text not null,
  resource_type text not null,
  resource_id text,
  outcome text not null default 'success'
    check (outcome in ('success','denied','failure')),
  ip_address inet,
  user_agent text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index audit_events_org_created_idx
  on public.audit_events(organization_id, created_at desc);
create index audit_events_actor_created_idx
  on public.audit_events(actor_user_id, created_at desc);

-- Authorization helpers live in a non-exposed schema. They read only the caller's
-- JWT identity and server-controlled membership/admin tables. User-editable
-- auth.user_metadata is never consulted for role decisions.
create or replace function private.is_platform_staff()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.platform_admins pa
    join public.platform_profiles pp on pp.user_id = pa.user_id
    where pa.user_id = (select auth.uid())
      and pa.role in ('super_admin','platform_admin','security_analyst')
      and pp.status = 'active'
  );
$$;

create or replace function private.is_platform_admin()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.platform_admins pa
    join public.platform_profiles pp on pp.user_id = pa.user_id
    where pa.user_id = (select auth.uid())
      and pa.role in ('super_admin','platform_admin')
      and pp.status = 'active'
  );
$$;

create or replace function private.is_platform_auditor()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.platform_admins pa
    join public.platform_profiles pp on pp.user_id = pa.user_id
    where pa.user_id = (select auth.uid())
      and pa.role in ('super_admin','platform_admin','security_analyst','auditor')
      and pp.status = 'active'
  );
$$;

create or replace function private.has_org_role(p_org_id uuid, p_roles text[] default null)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.org_memberships m
    join public.organizations o on o.id = m.organization_id
    join public.platform_profiles pp on pp.user_id = m.user_id
    where m.organization_id = p_org_id
      and m.user_id = (select auth.uid())
      and m.status = 'active'
      and pp.status = 'active'
      and o.status = 'active'
      and (p_roles is null or m.role = any(p_roles))
  );
$$;

create or replace function private.get_my_platform_access()
returns jsonb
language plpgsql stable security definer
set search_path = ''
as $$
declare
  v_profile jsonb;
  v_admin jsonb;
  v_memberships jsonb;
begin
  if (select auth.uid()) is null then
    return jsonb_build_object(
      'authenticated', false,
      'platform_role', null,
      'profile_status', 'anonymous',
      'memberships', '[]'::jsonb
    );
  end if;

  select to_jsonb(pp) into v_profile
  from public.platform_profiles pp
  where pp.user_id = (select auth.uid());

  select jsonb_build_object('role', pa.role) into v_admin
  from public.platform_admins pa
  where pa.user_id = (select auth.uid());

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
  where m.user_id = (select auth.uid());

  return jsonb_build_object(
    'authenticated', true,
    'platform_role', v_admin,
    'profile_status', coalesce(v_profile->>'status', 'pending'),
    'profile', v_profile,
    'memberships', coalesce(v_memberships, '[]'::jsonb)
  );
end;
$$;

-- Auth sign-up provisions a pending profile only. Privileges are assigned separately.
create or replace function private.handle_new_auth_user()
returns trigger
language plpgsql security definer
set search_path = ''
as $$
begin
  insert into public.platform_profiles(user_id, email, display_name, status)
  values (
    new.id,
    coalesce(new.email, ''),
    '',
    'pending'
  )
  on conflict (user_id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_scanner on auth.users;
create trigger on_auth_user_created_scanner
  after insert on auth.users
  for each row execute function private.handle_new_auth_user();

-- Enforce the engagement, asset, module, and time scope even for trusted server writes.
-- No scan can be created against an arbitrary target string supplied by the browser.
create or replace function private.enforce_assessment_scope()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_allowed_modules text[];
  v_engagement_status text;
  v_starts_at timestamptz;
  v_expires_at timestamptz;
  v_daily_limit integer;
  v_asset_value text;
  v_asset_expires_at timestamptz;
  v_count bigint;
begin
  select e.allowed_modules, e.status, e.starts_at, e.expires_at, e.max_jobs_per_day,
         a.canonical_value, a.authorization_expires_at
    into v_allowed_modules, v_engagement_status, v_starts_at, v_expires_at,
         v_daily_limit, v_asset_value, v_asset_expires_at
  from public.engagements e
  join public.engagement_assets ea
    on ea.engagement_id = e.id and ea.organization_id = e.organization_id
  join public.assets a
    on a.id = ea.asset_id and a.organization_id = ea.organization_id
  where e.id = new.engagement_id
    and e.organization_id = new.organization_id
    and e.project_id = new.project_id
    and a.id = new.asset_id
    and a.project_id = new.project_id
    and a.organization_id = new.organization_id
    and a.verification_status = 'verified'
    and (a.authorization_expires_at is null or a.authorization_expires_at > now());

  if v_asset_value is null then
    raise exception 'Assessment target is not verified or is not included in this engagement.'
      using errcode = '42501';
  end if;

  if v_engagement_status not in ('approved','active') then
    raise exception 'Engagement is not approved for scanning.' using errcode = '42501';
  end if;
  if v_starts_at is not null and now() < v_starts_at then
    raise exception 'Engagement has not started.' using errcode = '42501';
  end if;
  if v_expires_at is not null and now() >= v_expires_at then
    raise exception 'Engagement authorization has expired.' using errcode = '42501';
  end if;
  if new.target_snapshot <> v_asset_value then
    raise exception 'Requested target does not match the verified engagement asset.'
      using errcode = '42501';
  end if;
  if cardinality(new.modules) = 0 or not (new.modules <@ v_allowed_modules) then
    raise exception 'Requested modules exceed the approved engagement scope.'
      using errcode = '42501';
  end if;

  select count(*) into v_count
  from public.assessments existing
  where existing.organization_id = new.organization_id
    and existing.engagement_id = new.engagement_id
    and existing.created_at >= now() - interval '24 hours'
    and (tg_op = 'INSERT' or existing.id <> new.id);

  if v_count >= v_daily_limit then
    raise exception 'Engagement daily assessment limit reached.' using errcode = '42501';
  end if;

  return new;
end;
$$;

create trigger assessments_scope_guard
  before insert or update of organization_id, project_id, engagement_id, asset_id,
                            target_snapshot, modules, profile
  on public.assessments
  for each row execute function private.enforce_assessment_scope();

-- RLS: every customer-owned relation is partitioned by organization_id.
alter table public.platform_profiles enable row level security;
alter table public.platform_admins enable row level security;
alter table public.organizations enable row level security;
alter table public.org_memberships enable row level security;
alter table public.access_requests enable row level security;
alter table public.projects enable row level security;
alter table public.assets enable row level security;
alter table public.asset_authorization_evidence enable row level security;
alter table public.engagements enable row level security;
alter table public.engagement_assets enable row level security;
alter table public.assessments enable row level security;
alter table public.assessment_findings enable row level security;
alter table public.audit_events enable row level security;

create policy profiles_self_or_staff_read on public.platform_profiles for select to authenticated
  using (user_id = (select auth.uid()) or (select private.is_platform_staff()));

create policy platform_admins_self_or_admin_read on public.platform_admins for select to authenticated
  using (user_id = (select auth.uid()) or (select private.is_platform_admin()));

create policy organizations_member_or_staff_read on public.organizations for select to authenticated
  using ((select private.has_org_role(id, null)) or (select private.is_platform_staff()));

create policy memberships_self_or_admin_read on public.org_memberships for select to authenticated
  using (
    user_id = (select auth.uid())
    or (select private.has_org_role(organization_id, array['owner','org_admin']))
    or (select private.is_platform_staff())
  );

create policy access_requests_requester_or_staff_read on public.access_requests for select to authenticated
  using (
    requester_user_id = (select auth.uid())
    or (select private.is_platform_staff())
  );

create policy projects_member_or_staff_read on public.projects for select to authenticated
  using (
    (select private.has_org_role(organization_id, null))
    or (select private.is_platform_staff())
  );
create policy projects_manager_insert on public.projects for insert to authenticated
  with check (
    (select private.has_org_role(organization_id, array['owner','org_admin']))
    and status = 'active'
  );
create policy projects_manager_update on public.projects for update to authenticated
  using ((select private.has_org_role(organization_id, array['owner','org_admin'])))
  with check ((select private.has_org_role(organization_id, array['owner','org_admin'])));

create policy assets_member_or_staff_read on public.assets for select to authenticated
  using (
    (select private.has_org_role(organization_id, null))
    or (select private.is_platform_staff())
  );
create policy assets_manager_insert_pending on public.assets for insert to authenticated
  with check (
    (select private.has_org_role(organization_id, array['owner','org_admin','security_engineer']))
    and verification_status in ('pending','pending_dns','pending_review')
    and verified_at is null
    and verified_by is null
    and challenge_hash is null
  );
create policy assets_manager_update_unverified on public.assets for update to authenticated
  using (
    (select private.has_org_role(organization_id, array['owner','org_admin','security_engineer']))
    and verification_status <> 'verified'
  )
  with check (
    (select private.has_org_role(organization_id, array['owner','org_admin','security_engineer']))
    and verification_status in ('pending','pending_dns','pending_review','rejected','expired')
    and verified_at is null
    and verified_by is null
    and challenge_hash is null
  );

create policy asset_evidence_member_read on public.asset_authorization_evidence for select to authenticated
  using (
    (select private.has_org_role(organization_id, null))
    or (select private.is_platform_staff())
  );
create policy asset_evidence_member_insert on public.asset_authorization_evidence for insert to authenticated
  with check (
    (select private.has_org_role(organization_id, array['owner','org_admin','security_engineer']))
    and uploaded_by = (select auth.uid())
    and review_status = 'pending'
    and reviewed_by is null
    and reviewed_at is null
  );

create policy engagements_member_or_staff_read on public.engagements for select to authenticated
  using (
    (select private.has_org_role(organization_id, null))
    or (select private.is_platform_staff())
  );
create policy engagements_manager_create_draft on public.engagements for insert to authenticated
  with check (
    (select private.has_org_role(organization_id, array['owner','org_admin','security_engineer']))
    and status = 'draft'
    and approved_by is null
    and approved_at is null
  );
create policy engagements_manager_update_draft on public.engagements for update to authenticated
  using (
    (select private.has_org_role(organization_id, array['owner','org_admin','security_engineer']))
    and status = 'draft'
  )
  with check (
    (select private.has_org_role(organization_id, array['owner','org_admin','security_engineer']))
    and status in ('draft','pending_review')
    and approved_by is null
    and approved_at is null
  );

create policy engagement_assets_member_read on public.engagement_assets for select to authenticated
  using (
    (select private.has_org_role(organization_id, null))
    or (select private.is_platform_staff())
  );
create policy engagement_assets_manager_insert on public.engagement_assets for insert to authenticated
  with check (
    (select private.has_org_role(organization_id, array['owner','org_admin','security_engineer']))
    and exists (
      select 1 from public.engagements e
      where e.id = engagement_assets.engagement_id
        and e.organization_id = engagement_assets.organization_id
        and e.status = 'draft'
    )
    and exists (
      select 1 from public.assets a
      where a.id = engagement_assets.asset_id
        and a.organization_id = engagement_assets.organization_id
        and a.verification_status = 'verified'
        and (a.authorization_expires_at is null or a.authorization_expires_at > now())
    )
  );

create policy assessments_member_or_staff_read on public.assessments for select to authenticated
  using (
    (select private.has_org_role(organization_id, null))
    or (select private.is_platform_staff())
  );

create policy findings_member_or_staff_read on public.assessment_findings for select to authenticated
  using (
    (select private.has_org_role(organization_id, null))
    or (select private.is_platform_staff())
  );

create policy audit_events_read on public.audit_events for select to authenticated
  using (
    (select private.is_platform_auditor())
    or (
      organization_id is not null
      and (select private.has_org_role(organization_id, array['owner','org_admin','auditor']))
    )
  );

-- Explicit API grants. The 2026 Data API exposure change means schema exposure
-- must also be enabled deliberately in Supabase project settings; RLS remains mandatory.
grant usage on schema public to authenticated, service_role;
grant select on
  public.platform_profiles,
  public.platform_admins,
  public.organizations,
  public.org_memberships,
  public.access_requests,
  public.projects,
  public.assets,
  public.asset_authorization_evidence,
  public.engagements,
  public.engagement_assets,
  public.assessments,
  public.assessment_findings,
  public.audit_events
to authenticated;

grant all privileges on all tables in schema public to service_role;
grant usage, select on all sequences in schema public to service_role;

-- Read-only self-context is exposed as an authenticated RPC, not user metadata.
revoke all on function private.is_platform_staff() from public, anon;
revoke all on function private.is_platform_admin() from public, anon;
revoke all on function private.is_platform_auditor() from public, anon;
revoke all on function private.has_org_role(uuid,text[]) from public, anon;
revoke all on function private.get_my_platform_access() from public, anon;
revoke all on function private.handle_new_auth_user() from public, anon, authenticated;
revoke all on function private.enforce_assessment_scope() from public, anon, authenticated;
grant execute on function private.is_platform_staff() to authenticated;
grant execute on function private.is_platform_admin() to authenticated;
grant execute on function private.is_platform_auditor() to authenticated;
grant execute on function private.has_org_role(uuid,text[]) to authenticated;
grant execute on function private.get_my_platform_access() to authenticated;

-- Bootstrap: after the nominated ANISH ENTERPRISES owner signs in once, insert
-- that exact auth.users UUID into platform_admins as super_admin via the SQL editor.
-- The signup trigger creates a pending profile. No user_metadata or public form can
-- create or elevate an administrator. Never seed an administrator by email alone.
