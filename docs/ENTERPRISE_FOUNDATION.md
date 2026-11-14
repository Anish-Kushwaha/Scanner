# Enterprise foundation — ANISH ENTERPRISES Scanner

## Product boundary
Scanner is a permissioned, multi-tenant security-assessment service operated by ANISH ENTERPRISES. Platform access is approval-only. A verified account is not blanket authorization to scan arbitrary systems.

## Identity and approval
- Supabase Auth is the proposed identity provider.
- user_profiles.account_status defaults to pending; platform approval is required.
- Platform administrators are identified by the trusted app_metadata.platform_role=super_admin claim. Never use editable user metadata for privileges.
- Organizations default to pending; ANISH ENTERPRISES verifies them.
- Membership defaults to invited; users need approval and active membership in a verified organization.
- Require MFA (AAL2) for privileged actions, enforced server-side.

## Tenant isolation
Every tenant-owned record is linked to an organization. PostgreSQL Row Level Security is enabled on application tables. The service-role secret remains server-only and must never reach browser or Android clients.

## Dynamic target authorization
The global SCANNER_ALLOWED_TARGETS variable is not the customer asset registry and must not be used as a per-customer allowlist.

A scan is permitted only when the backend verifies:
1. Valid Supabase access token.
2. Approved, active user account.
3. Active role in a verified organization.
4. Project and engagement belong to that organization.
5. Engagement is approved, active, and not expired.
6. Target is attached to the engagement and ownership/authorization verification is current.
7. Requested modules/profile are within engagement policy.
8. Resolved IP addresses are revalidated immediately before execution. Block loopback, link-local, metadata, multicast and private ranges unless a separately approved private-agent engagement explicitly authorizes them.

Target onboarding uses DNS TXT or HTTP challenge for domains, suitable ownership evidence for IP ranges, or written permission plus ANISH ENTERPRISES manual approval. Domain subdomains are included only through explicit asset/engagement scope.

## Worker trust boundary
The browser never sends a trusted authorization_confirmed boolean. The authenticated control plane issues a short-lived, signed, single-engagement execution grant after database checks. The worker validates signature, expiry, engagement, organization, target, modules, policy limits, nonce and audience before resolving/scanning. Worker credentials and signing secrets stay server-side.

## Rollout order
1. Apply supabase/migrations/202611140001_enterprise_tenancy.sql to the selected active Supabase project.
2. Configure Supabase URL, publishable/anon key and server-only secret key in Vercel.
3. Bootstrap the first super-admin out-of-band using trusted app_metadata.
4. Add server-side authentication and admin/customer APIs.
5. Add asset verification and engagement approval workflows.
6. Replace static worker allowlist enforcement with signed engagement grants; do not remove scope validation before this replacement is live.
7. Add tenant-isolation, approval, expired-engagement, replay, DNS-rebinding and cross-tenant denial tests.
8. Only then promote customer login and scanning to production.

## Infrastructure status
The connected Supabase project named Anish-Kushwaha's Project was reported inactive when this foundation was prepared. No project was restored, created, billed or modified. Apply the migration only after confirming the intended project is active.
