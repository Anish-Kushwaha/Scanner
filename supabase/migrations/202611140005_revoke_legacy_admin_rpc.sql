begin;
revoke all on function public.is_my_platform_admin() from public, anon, authenticated;
grant execute on function public.is_my_platform_admin() to service_role;
commit;