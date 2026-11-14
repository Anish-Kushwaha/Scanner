begin;
create or replace function public.is_my_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $admin_check$
  select auth.uid() is not null and exists (
    select 1 from private.platform_admins a where a.user_id = auth.uid()
  );
$admin_check$;
revoke all on function public.is_my_platform_admin() from public, anon;
grant execute on function public.is_my_platform_admin() to authenticated;
commit;