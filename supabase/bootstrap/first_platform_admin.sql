-- FIRST PLATFORM ADMIN BOOTSTRAP — run once, manually, in Supabase SQL Editor.
-- Replace the UUID below with the auth.users.id for the verified owner account.
-- Do not commit a real owner UUID or email to source control.
do $bootstrap$
declare
  owner_id uuid := '00000000-0000-0000-0000-000000000000';
begin
  if owner_id = '00000000-0000-0000-0000-000000000000'::uuid then
    raise exception 'Replace owner_id with the verified owner auth.users UUID.';
  end if;
  if exists (select 1 from private.platform_admins) then
    raise exception 'A platform administrator already exists; bootstrap is locked.';
  end if;
  if not exists (select 1 from auth.users where id = owner_id and email_confirmed_at is not null) then
    raise exception 'Owner account must exist and have a verified email.';
  end if;
  insert into private.platform_admins(user_id,granted_by) values(owner_id,'one-time-owner-bootstrap');
  update public.user_profiles set account_status='approved',approved_at=now(),approved_by=owner_id,updated_at=now() where user_id=owner_id;
  if not found then raise exception 'User profile was not created; retry after the auth profile trigger completes.'; end if;
end
$bootstrap$;