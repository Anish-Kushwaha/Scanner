begin;
create or replace function public.bootstrap_first_platform_admin(check_user_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  account_email text;
begin
  select lower(u.email) into account_email
  from auth.users u
  where u.id = check_user_id and u.email_confirmed_at is not null;
  if account_email is distinct from 'anishkushwahag28@gmail.com' then
    raise exception 'Only the verified ANISH ENTERPRISES owner email can perform first-admin bootstrap.';
  end if;
  if exists (select 1 from private.platform_admins) then
    raise exception 'First platform administrator is already configured.';
  end if;
  insert into private.platform_admins(user_id,granted_by)
  values(check_user_id,'verified-owner-first-admin-bootstrap');
  update public.user_profiles
  set account_status='approved', approved_at=now(), approved_by=check_user_id, updated_at=now()
  where user_id=check_user_id;
  if not found then
    raise exception 'The owner profile is not ready. Sign out and sign in again after account setup.';
  end if;
  insert into public.audit_events(actor_user_id,action,resource_type,resource_id,severity,metadata)
  values(check_user_id,'platform_admin.first_bootstrap','platform_admin',check_user_id::text,'critical',
    jsonb_build_object('email',account_email,'method','verified_email_plus_aal2')) ;
  return true;
end;
$$;
revoke all on function public.bootstrap_first_platform_admin(uuid) from public, anon, authenticated;
grant execute on function public.bootstrap_first_platform_admin(uuid) to service_role;
commit;