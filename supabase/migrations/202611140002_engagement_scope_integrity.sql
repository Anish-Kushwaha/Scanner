-- Required composite uniqueness for tenant-preserving foreign keys.
do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'assets_id_organization_unique'
      and conrelid = 'public.assets'::regclass
  ) then
    alter table public.assets
      add constraint assets_id_organization_unique unique (id, organization_id);
  end if;
end $$;

-- Only active organizations can carry active engagements into an assessment.
create or replace function public.engagement_is_active(p_engagement_id uuid, p_asset_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.engagements e
    join public.organizations o on o.id = e.organization_id
    join public.org_memberships m on m.organization_id = e.organization_id
    join public.platform_profiles pp on pp.user_id = m.user_id
    join public.engagement_assets ea on ea.engagement_id = e.id and ea.organization_id = e.organization_id
    join public.assets a on a.id = ea.asset_id and a.organization_id = e.organization_id
    where e.id = p_engagement_id
      and ea.asset_id = p_asset_id
      and p_user_id = auth.uid()
      and m.user_id = auth.uid()
      and m.status = 'active'
      and pp.status = 'active'
      and o.status = 'active'
      and e.status in ('approved','active')
      and (e.starts_at is null or e.starts_at <= now())
      and (e.expires_at is null or e.expires_at > now())
      and a.verification_status = 'verified'
  );
$$;

revoke all on function public.engagement_is_active(uuid,uuid,uuid) from public;
grant execute on function public.engagement_is_active(uuid,uuid,uuid) to authenticated;
