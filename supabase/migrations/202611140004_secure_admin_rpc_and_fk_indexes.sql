begin;
create or replace function public.is_platform_admin_user(check_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select check_user_id is not null and exists (
    select 1 from private.platform_admins a where a.user_id = check_user_id
  );
$$;
revoke all on function public.is_platform_admin_user(uuid) from public, anon, authenticated;
grant execute on function public.is_platform_admin_user(uuid) to service_role;

create index if not exists authorization_evidence_engagement_idx
  on public.authorization_evidence(engagement_id);
create index if not exists engagement_targets_asset_idx
  on public.engagement_targets(asset_id);
commit;