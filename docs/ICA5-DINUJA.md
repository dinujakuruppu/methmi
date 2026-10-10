# ICA 5 - Admin authentication, authorization and security

This feature branch uses the existing Supabase Auth and `public.admins` allow-list. It does not introduce or claim ownership of the shared database schema, tours/vehicles/enquiries CRUD, or client demonstration video.

## Individual protected endpoint

`GET /api/admin/me` returns the signed-in administrator's private profile, including `id`, `email`, `role`, and the `admins.created_at` timestamp. It retrieves identity from a validated HttpOnly cookie and rechecks both Supabase Auth and the server-side `admins` table on each request.

- Missing, invalid or expired cookie: **401**.
- Valid Supabase user removed from the admins allow-list: **403**.
- Current permitted administrator: **200**, with their own DB-backed profile.
- Database error: generic **500**, no raw database diagnostics in the response.
- Browser-supplied user IDs/roles are ignored; profile responses disable caching.

The shared `requireAdmin` middleware now distinguishes unauthorized (401) from forbidden (403) requests without relying on frontend-only protection.

## Automated tests

`backend/tests/unit/admin-profile.test.ts` verifies anonymous, forged, expired, revoked, wrong-role, authorized, and database-error behavior. It also checks login input validation and secure cookie issuance. Tests use isolated mocks of Supabase: **no live customer data is used**.

From the repository root:

```sh
npm ci
npm run typecheck -w backend
npm run test -w backend
```

CI is configured for pushes to `dinuja-dev` and PRs targeting `Develop`. Confirm the checks actually pass before submitting.

## ICA 5 submission notes

This code is a proposed individual feature contribution for review. The student must inspect and understand it, verify it against their running Supabase test environment, and truthfully identify their own work. Shared project files are present in the branch as a working baseline; their presence is **not** evidence that they were authored by this member.

A separate peer-reviewed PR must be merged into the team's **Develop** branch. The client demo is group evidence and is not included here.
