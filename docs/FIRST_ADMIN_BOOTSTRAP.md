# First platform administrator bootstrap

1. Open the production Scanner login page and register the owner's account using an email address controlled by ANISH ENTERPRISES.
2. Complete email verification and enroll a TOTP authenticator.
3. In Supabase Dashboard → Authentication → Users, copy that account's UUID.
4. Open Supabase SQL Editor. Copy `supabase/bootstrap/first_platform_admin.sql` and replace the all-zero UUID with the verified owner's UUID.
5. Run the SQL exactly once. It refuses to run if a platform administrator already exists.
6. Sign in again, complete MFA, then open `/admin.html`.
7. From the admin console, approve users, verify customer organizations, activate memberships, verify written authorization evidence, and approve engagements.

The bootstrap is deliberately manual. The first administrator must not be chosen by whichever visitor registers first. Never share the Supabase service-role key or make the private platform-admin registry writable from a browser.