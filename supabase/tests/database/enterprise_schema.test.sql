begin;
select plan(3);
select has_function('public','is_my_platform_admin',array[]::text[],'platform admin self-check helper exists');
select ok(not has_function_privilege('anon','public.is_my_platform_admin()','EXECUTE'),'anonymous cannot call platform admin self-check');
select ok(has_function_privilege('authenticated','public.is_my_platform_admin()','EXECUTE'),'authenticated can call safe own-admin self-check');
select * from finish();
rollback;