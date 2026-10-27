# askm6

[![Checks](https://github.com/ArsPoghosyan/Mazda-AI-Assistant/actions/workflows/ci.yml/badge.svg)](https://github.com/ArsPoghosyan/Mazda-AI-Assistant/actions/workflows/ci.yml)

An independent, unofficial vehicle information assistant, unaffiliated with Mazda.
The first version targets Mazda 6, starting with verified 2020 information;
support for other Mazda models is a future possibility.

**Early development:** [askm6.com](https://askm6.com) hosts the landing page and API
health check. The full assistant is not available. Authentication works in local
development; public guest/account access remains gated.

[Local setup](#local-setup) · [API](#api-overview) · [Checks](#checks) ·
[Full technical reference](reference/IMPLEMENTATION.md)

## Current capabilities

| Area | Implemented |
| --- | --- |
| Web/API | React landing page, live connectivity feedback, FastAPI health and database readiness endpoints |
| Persistence | PostgreSQL/pgvector in Docker, SQLAlchemy pooling/TLS, Alembic, separate runtime/migration roles |
| Guests | Opaque HttpOnly sessions, hashed tokens, expiry-safe refresh, Turnstile, IP limits and manual retry guidance for new-session attempts |
| Accounts | Supabase email/password registration, email-code confirmation, sign-in, session restoration and current-session sign-out |
| Google | Browser-bound PKCE flow for new and returning accounts, IP limits with manual retry guidance, verified callback, encrypted session storage |
| Password recovery | CAPTCHA-protected email request, recovery-code/password reset, temporary provider-session cleanup and application-session invalidation |
| Session security | ES256 JWT verification, bounded signing-key cache, live provider-session checks for sign-in/cookie authentication, encrypted token refresh, transaction/expiry guards |
| Abuse controls | Recovery/sign-in/sign-up/confirmation/reset/guest-creation/Google-start throttling; optional scheduled expired-auth-record cleanup; public deployment pending |
| Validation | Offline API/component tests, guarded PostgreSQL integration tests, lint/types/build and GitHub Actions |

**Not implemented:** chat, conversation persistence, vehicle selection, retrieval,
AI calls, message quotas, automated guest-history cleanup and public
authentication deployment. Expired guest sessions are rejected before refresh.
Planned embeddings use OpenAI `text-embedding-3-small` (1536 dimensions); answer
generation is planned with Groq.

Sign-in failures now have secret-free stage diagnostics and tested
[commit-uncertainty/identity boundaries](reference/IMPLEMENTATION.md#provider-success-and-local-failure).
Local rollback does not revoke a provider session; automatic provider logout
remains unimplemented, and broader hosted linking/method behavior needs release validation.
Both Google and password sign-in require explicit sign-out when an account cookie
is present; a blocked attempt preserves the current session.

On page load, access controls wait for a bounded health check before account
session restoration starts, allowing an idle backend time to wake. Startup shows
a waiting message and offers manual retry on failure; it does not send periodic
keepalive requests. Public account browser controls remain disabled by default.

A Privacy Notice page is available at `/privacy`, with links from the footer and
account-creation form. It describes development-stage data flows and approved retention
choices. Further privacy and operational checks remain before public
authentication is enabled.

Development-stage Terms of Service are prepared at `/terms`, cross-linked with
the Privacy Notice and account-creation form. They describe current availability and
responsible use; these pages do not enable public sign-in.
The default-disabled Terms acceptance backend records a verified account's Terms
revision and server timestamp, exposes authenticated setup status, and provides
a tested access dependency for account resources. In development, verified
sign-in/restoration now checks setup status: missing agreement opens a modal
with an unchecked Terms checkbox and separate Privacy Notice link. Returning
accounts with recorded acceptance skip it. Email signup requires an unchecked
Terms checkbox before provider registration. An encrypted, one-hour HttpOnly
receipt carries the agreement through email confirmation and matching verified
sign-in; a Google callback can also save the confirmed receipt when its verified
account ID matches. Missing or expired receipts use the setup dialog. First-time
Google accounts without confirmed signup agreement keep the one-time setup flow.
Escape dismisses without accepting;
setup can be reopened and sign-out remains available. Hosted Terms forwarding
is independently default-off through `ACCOUNT_TERMS_PROXY_ENABLED`.

Guarded local database tests rehearse scoped manual account deletion and partial
failures with a mocked provider. They do not add an account-deletion endpoint or
establish live provider deletion behavior.

The public product name is **askm6**. The tab icon is an original `a6` monogram
in the website palette. Mazda 6 describes initial vehicle coverage; existing
repository, package, service and database identifiers retain their current names.

## Stack and layout

| Layer | Technology / location |
| --- | --- |
| Frontend | React, strict TypeScript, Vite, Tailwind CSS — `frontend/` |
| Backend | Python 3.12, FastAPI, Pydantic, SQLAlchemy, Alembic — `backend/` |
| Database | PostgreSQL with pgvector — Docker Compose locally |
| Identity | Supabase Auth; Cloudflare Turnstile |
| Deployment | Cloudflare Pages with health and default-off session proxy; FastAPI on Render |
| Dependencies | Locked in `backend/uv.lock` and `frontend/package-lock.json` |

This is a personal project developed in small, testable changes; external
contributions are not being accepted. CI results and history are available in
[GitHub Actions](https://github.com/ArsPoghosyan/Mazda-AI-Assistant/actions).

## Local setup

Commands below use PowerShell, starting from the repository root. Install Python
3.12, uv, Node.js 24 LTS/npm, and Docker Desktop for database-backed flows. Verify
`py -3.12 --version`, `uv --version`, `node --version` and `npm --version` in a fresh
terminal. In PyCharm, select a working interpreter rather than modifying a broken
existing environment.

<details>
<summary>Optional portable tools on the original Windows development machine</summary>

If the ignored local tool directories exist, prepend them in each terminal:

```powershell
$taskRoot = (Get-Location).Path
$env:Path = (Join-Path $taskRoot '.tools/node-v24.22.0-win-x64') + ';' + (Join-Path $taskRoot '.tools/bootstrap/Scripts') + ';' + $env:Path
```

The local versions are Node 24.22.0 and uv 0.13.1. They are not committed; fresh
clones need their own installations. The Node archive's official SHA-256 was
verified. The pre-existing root virtual environment is preserved and unused.

</details>

### Start the backend and frontend

First terminal:

```powershell
Set-Location backend
uv sync --locked
uv run uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Second terminal, starting from the repository root:

```powershell
Set-Location frontend
npm ci
npm run dev
```

Open [the local site](http://127.0.0.1:5173) and
[FastAPI docs](http://127.0.0.1:8000/docs). The page should show **API connected**;
stop FastAPI, reload, and use **Try again** to check the unavailable state.
For PyCharm, use `backend/.venv/Scripts/python.exe`, working directory `backend`.

Both servers bind to loopback. Vite proxies `/api` to `127.0.0.1:8000`, avoiding a
broad CORS policy. `--no-proxy-headers` prevents forwarded headers from replacing
the local peer/scheme; Vite requests can share a loopback address. Production
visitor identification requires separate proxy-chain verification.

### Database and environment files

Create an ignored root `.env` from [.env.example](.env.example), with a strong
local `POSTGRES_PASSWORD`, then start PostgreSQL from the repository root:

```powershell
docker compose up -d --wait db
```

It binds to `127.0.0.1:15432` and persists data in Docker's `postgres_data` volume.
Configure the backend using [backend/.env.example](backend/.env.example).
Settings load `backend/.env`; environment variables take precedence. Without
`DATABASE_URL`, health returns 200 and readiness returns 503. Readiness checks
connectivity with `SELECT 1`, not migrations or application-table permissions.

| Configuration | Purpose |
| --- | --- |
| `backend/.env` | Runtime `DATABASE_URL`, provider settings, feature flags and secrets |
| `backend/.env.migrations.local` | Separate `MIGRATION_DATABASE_URL` for local Alembic operations |
| `backend/.env.integration.local` | Guarded local `TEST_DATABASE_URL`; never use on the web service |
| `frontend/.env.development.local` | Public site key and optional public Google settings only |

Database URLs use `postgresql+psycopg://`; use `URL.create()` or encode reserved
password characters. Use the restricted application role at runtime, separate
migration credentials for Alembic, and separate test administrator credentials.
The default pool has two connections per process and no overflow.

Migrate the website's local `mazda6` and integration `askm6_test` databases
independently after verifying each target. Updating one does not update the other.
Sign-in requires account-session storage and provider-session uniqueness through
`08cad124d60b`; Google requires `b731b533d299`. Recovery migration
`0826d9fbcef3` is verified on both local website and test databases. The new
`0f42bd53f47a` migration permits separate sign-in limiter records and is now
verified on both local website and test databases. Migrate each target explicitly;
integration tests and enabled sign-in throttling require the current head.
Sign-up throttling requires `bcae4df0f56a`, now verified on both local databases
with unchanged application grants and no schema drift.
Email-confirmation throttling requires `6ef221a79f00`, also verified on both
local databases. Password-reset throttling requires `0ffc842c5360`, verified on
both local databases. Guest-creation throttling requires `aefd9866f033`, verified
on both local databases with unchanged grants. Google initiation throttling requires
`46250b6b2d17`, verified on both local databases. Terms acceptance adds
`b4d7e2806a12`, verified on both local website and test databases; integration tests
require this head. The local website now has Terms setup enabled for controlled
manual flow checks. The hosted database has not received this Terms migration;
hosted authentication remains disabled.

Remote URLs require `sslmode=verify-full` and `sslrootcert` pointing to the CA
certificate. Keep ordinary development on Docker. For an explicit Supabase
connectivity test, configure ignored `backend/.env.supabase`, then from `backend`:

```powershell
uv run uvicorn app.main:app --reload --loop asyncio --env-file .env.supabase --host 127.0.0.1 --port 8000 --no-proxy-headers
```

This Windows command uses the asyncio loop for Psycopg compatibility. Full setup
and deployment details remain in the [database reference](reference/IMPLEMENTATION.md#database-configuration).

### Enable authentication locally

Backend guest/account endpoint flags default to **false**, independently of one
another. Enable only the flows being tested in ignored private configuration,
restart FastAPI after changes, and keep production defaults disabled.

For local HTTP, set `CSRF_TRUSTED_ORIGINS=["http://127.0.0.1:5173"]`; origins have
no trailing slash. Use `GUEST_COOKIE_SECURE=false` / `ACCOUNT_COOKIE_SECURE=false`
only for local HTTP, and restore secure cookies for HTTPS. Guest setup requires
`TURNSTILE_SECRET_KEY` and `TURNSTILE_ALLOWED_HOSTNAMES=["127.0.0.1"]`; the frontend
uses public `VITE_TURNSTILE_SITE_KEY`. New guest attempts also require the backend
`AUTH_RATE_LIMIT_HMAC_SECRET` and use `GUEST_CREATION_IP_MAX_REQUESTS=10` per rolling
`GUEST_CREATION_IP_WINDOW_SECONDS=600`. Active-session reuse bypasses this budget;
the initial challenge request and subsequent proof submission each count when a
new session is needed. A local cap returns 429 with `Retry-After` seconds.

Use a separate development Turnstile widget with hostname `127.0.0.1`, Managed
mode and pre-clearance disabled. Hostnames exclude scheme, port and path; trusted
origins include scheme and port. Account CAPTCHA is enabled/configured in
Supabase Auth; account proofs go to Supabase and are not separately consumed
through application Siteverify. The guest verifier uses Siteverify with
`guest_start` and exact allowed hostnames. Challenges are submitted once and
retries require fresh proofs. See the [guest flow](reference/IMPLEMENTATION.md#local-frontend-guest-flow)
and [Turnstile reference](reference/IMPLEMENTATION.md#internal-turnstile-verification).

Accounts also require the Supabase issuer/audience/publishable key, database,
signing-key resources and an independent `ACCOUNT_SESSION_ENCRYPTION_KEY` (Fernet).
Keep Supabase email confirmation and CAPTCHA enabled. For code-entry flows,
**Confirm signup** and **Reset password** email templates must contain
`{{ .Token }}`. Confirmation/reset does not sign the user in automatically.
The validated mail setup uses Resend custom SMTP in Supabase, verified sending
subdomain, unconfigured tracking and enforced TLS. Credentials belong in
Supabase's SMTP settings. Resend processes recipient/email data; its documented
US storage location is not changed by choosing an EU sending region. Review
privacy/data flows before public use; see the [SMTP reference](reference/IMPLEMENTATION.md#frontend-registration-api-foundation).

Google access requires `VITE_GOOGLE_OAUTH_ENABLED=true` and a valid public
`VITE_SUPABASE_AUTH_ISSUER`. In development it appears in both account dialogs;
production sign-in additionally requires `VITE_ACCOUNT_AUTH_ENABLED=true`.
These are build-time controls. The account-creation view also requires the
registration switch described below in production.
Enable `ACCOUNT_GOOGLE_OAUTH_API_ENABLED`, and set the exact
`ACCOUNT_GOOGLE_OAUTH_CALLBACK_URL`. Local URLs differ by provider:

| Configuration location | Callback |
| --- | --- |
| Supabase redirect allowlist / application | `http://127.0.0.1:5173/api/v1/account/google/callback` |
| Google Cloud web client | `https://YOUR_PROJECT_REF.supabase.co/auth/v1/callback` |

Store Google's client ID/secret in Supabase's Google settings. First-time and
returning users use the same OAuth flow; the application uses Supabase's verified
subject rather than matching accounts by email. No guest data is automatically
transferred. Callback setup, cookie binding, error/logging boundaries and known
limitations are covered in the [Google reference](reference/IMPLEMENTATION.md#google-sign-in--local-development).

## API overview

Guest/account mutation routes require exactly one trusted Origin; OAuth callback
authorization uses its browser-bound attempt. Handled auth/session responses use
`Cache-Control: no-store`. Provider tokens and opaque cookie credentials are not
returned in JSON. Feature flags and full contracts are in the
[technical reference](reference/IMPLEMENTATION.md).

| Method and path | Behavior |
| --- | --- |
| `GET /api/v1/health` | Process liveness; public health proxy supports this route only |
| `GET /api/v1/ready` | Direct-backend connectivity check: 200 / 503 |
| `POST /api/v1/guest/session` | Refresh valid guest session or verify a fresh challenge before creation |
| `GET /api/v1/account/me` | Bearer JWT identity; not a live provider-revocation check |
| `POST /api/v1/account/sign-up` | 202 neutral acknowledgement and temporary Terms receipt; no login |
| `POST /api/v1/account/confirm-email` | 200 confirmation metadata; separate sign-in required |
| `POST /api/v1/account/sign-in` | CAPTCHA-protected credentials; cookie/session metadata after commit |
| `POST /api/v1/account/session` | Verify existing cookie, live-check provider session, refresh credentials as needed |
| `POST /api/v1/account/terms/accept` | Default-disabled; explicitly accept the current Terms after session verification and database commit |
| `POST /api/v1/account/terms/status` | Default-disabled; verify the cookie and report whether current Terms acceptance is missing |
| `POST /api/v1/account/sign-out` | 204 after current application-session deletion commits; provider logout is separate |
| `POST /api/v1/account/password-recovery` | 202 neutral acknowledgement; no guarantee of account existence or email delivery |
| `POST /api/v1/account/password-reset` | Recovery code/new password, provider cleanup, committed application-session invalidation; fresh sign-in required |
| `POST /api/v1/account/google/start` | Enforce IP limit, commit pending PKCE attempt; return authorization URL/expiry |
| `GET /api/v1/account/google/callback` | Consume bound attempt once; verify/commit account session; fixed-origin 303 outcome |

Common request limits include 16 KiB of actual JSON bytes, strict field allowlists
and bounded values. Provider adapters reject redirects, bound calls to five
seconds and uncompressed JSON to 64 KiB. Guest/account total operation deadlines
normally default to 15 seconds (configurable 1–30); see individual contracts.
There are no automatic credential/proof/code retries. Controlled failures omit
provider details; HTTP status and cookie effects vary by route.

## Security and behavior

- **Cookies:** host-only, HttpOnly, SameSite=Lax, Path=/; secure mode uses
  `__Host-askm6_guest`, `__Host-askm6_account` and `__Host-askm6_oauth`. Local HTTP
  uses separate nonsecure names. Cookies are issued/renewed only after commit.
- **Identity/storage:** server-verified subjects, hashed browser tokens, Fernet
  provider-token encryption, foreign keys, expiry constraints and least-privilege
  grants. Ciphertext validity is not proof of identity; authorization still
  belongs to the backend. Provider sessions are unique per application session.
- **Expiry:** guest inactivity defaults to 30 days; account inactivity/absolute
  lifetime default to 7/30 days. Activity cannot move backward or exceed absolute
  expiry. JWT expiry/not-before remain strict; configurable `iat` skew defaults
  to five seconds. Session refresh rechecks identity and deadlines under a lock.
- **Frontend:** native modal, keyboard/focus handling, rectangular Turnstile,
  sensitive-field clearing, one pending submission, 15-second browser deadlines
  and cancellation/late-result guards. Credentials are not persisted in browser
  storage/logs; session metadata stays in memory, credentials in HttpOnly cookies.
- **Failure semantics:** cancellation/rollback cannot undo sent emails, provider
  password changes or token rotation, nor guarantee an uncertain commit failed.
  Reset success requires temporary provider-session cleanup plus committed local
  session invalidation. Already-authorized work in flight cannot be recalled.
- **Secrets:** use ignored backend files or server-side environment/secret stores;
  never place database credentials, private keys or provider secrets in `VITE_*`,
  Git, logs or test fixtures. Masked settings do not make raw structured validation
  errors safe: explicitly exclude inputs when reporting them. Key rotation needs
  deliberate handling while stored data depends on a key.

### Recovery rate limiter

Defaults are 10 attempts per rolling 600 seconds, configurable through
`ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS` (1–1,000) and
`ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS` (60–86,400).
`AUTH_RATE_LIMIT_HMAC_SECRET` accepts 64 ASCII hexadecimal characters encoding
an independent 32-byte key. The example placeholder stays empty; local development
uses a separately generated key in ignored configuration. Format validation does
not establish randomness. The five enabled throttled auth routes require this secret.

Sign-in enforces a separate counter, configured for 30 attempts per rolling 600
seconds by default through `ACCOUNT_SIGN_IN_IP_MAX_REQUESTS` and
`ACCOUNT_SIGN_IN_IP_WINDOW_SECONDS`, with the same bounds as recovery.
Sign-up independently defaults to 10 attempts per rolling 600 seconds through
`ACCOUNT_SIGN_UP_IP_MAX_REQUESTS` and `ACCOUNT_SIGN_UP_IP_WINDOW_SECONDS`, with
the same bounds. Email confirmation has its own 10-attempt/600-second budget through
`ACCOUNT_EMAIL_CONFIRMATION_IP_MAX_REQUESTS` and
`ACCOUNT_EMAIL_CONFIRMATION_IP_WINDOW_SECONDS`, with the same bounds.
Password reset separately defaults to 10 attempts per rolling 600 seconds through
`ACCOUNT_PASSWORD_RESET_IP_MAX_REQUESTS` and `ACCOUNT_PASSWORD_RESET_IP_WINDOW_SECONDS`,
with the same bounds and no shared budget with recovery-email requests.
Guest creation and Google initiation each default to 10 attempts per rolling 600
seconds, using `GUEST_CREATION_IP_*` and `ACCOUNT_GOOGLE_OAUTH_IP_*` respectively.
These are configurable starting policies.

Validated client IPs become versioned HMAC-SHA256 fingerprints; raw IP/email fields
are absent from `app.auth_rate_limits`. PostgreSQL locks each operation/fingerprint row,
reads time after lock acquisition, expires attempts individually and commits
before returning a decision. Denials do not extend the block; retry seconds round
up and account for a lowered cap. Allowed attempts remain counted after later
provider failures; this differs from future AI-message quotas. Policy changes
must be consistent across processes; a longer window cannot recover pruned data.

Recovery, sign-in, sign-up, email confirmation and password reset count before parsing
or provider work, return 429 with `Retry-After` when capped, and fail closed with 503
on limiter failure under their request deadlines. They require the migrated runtime database and a configured
HMAC secret; these prerequisites have been validated locally. Invalid Origins/configuration do not
reach counting; invalid bodies/provider failures after counting retain the attempt.
Guest creation and Google initiation validate bodies before counting. Google
starts and replacements share their own IP budget; a denial preserves pending
login state. Callback completion does not consume this initiation budget.
Development sign-in, sign-up, email confirmation, password reset and Google access display validated
retry seconds, with a generic wait message when unavailable. Retries remain manual;
sign-in/sign-up require fresh human verification, and confirmation/reset clear the
submitted secrets. Provider limits without a known wait stay generic.
An internal cleanup helper deletes expired rows for all seven operations in one shared
bounded batch and skips locked rows. Its wrapper owns the transaction and a caller-supplied deadline,
returning the count only after commit. Optional FastAPI-owned scheduling is
disabled by default. With `AUTH_RATE_LIMIT_CLEANUP_ENABLED=true` and a configured
runtime engine, it waits 300 seconds before each pass: one batch each for limiters,
[Google attempts](reference/IMPLEMENTATION.md#expired-pending-attempt-cleanup),
then [guest and account sessions](reference/IMPLEMENTATION.md#expired-local-session-cleanup).
Each operation has its own 100-row cap, five-second deadline and transaction;
failure does not block later operations. Passes never overlap within a process;
shutdown stops cleanup before closing the engine. Active records and account
profiles remain intact. Guest-history retention integration and production proxy
verification remain pending. See the [scheduling settings](reference/IMPLEMENTATION.md#automatic-authentication-cleanup).
A local maintenance command also provides explicit
one-batch execution with target/role checks; see the
[command instructions](reference/IMPLEMENTATION.md#backend-password-recovery-requests).
Ignoring headers in a helper is insufficient if
Uvicorn rewrites the ASGI client first.
See the [full accounting and validation reference](reference/IMPLEMENTATION.md#backend-password-recovery-requests).

## Deployment boundary

The Pages Function permits `GET /api/v1/health` by default. Existing-account
session checks have a [separate default-off proxy](reference/IMPLEMENTATION.md#account-session-proxy-request-policy)
with exact HTTPS origins, cookie filtering and bounded response validation.
An optional [authenticated visitor-IP assertion](reference/IMPLEMENTATION.md#trusted-proxy-client-addresses)
connects Pages to the backend's seven IP-based abuse limits. It defaults off;
hosted ingress and secret configuration still require deployment verification.
Guest creation/refresh has an [independently gated proxy](reference/IMPLEMENTATION.md#guest-session-pages-proxy)
with bounded JSON, secure guest cookies, verification and retry signals.
Email sign-in has a [separate default-off proxy](reference/IMPLEMENTATION.md#email-sign-in-pages-proxy)
that preserves credentials and requires explicit sign-out before another login.
[Sign-out forwarding](reference/IMPLEMENTATION.md#account-sign-out-pages-proxy) clears only a backend-confirmed account cookie.
[Sign-up forwarding](reference/IMPLEMENTATION.md#sign-up-pages-proxy) has its own default-off gate,
returns generic email-verification instructions and only a validated Terms receipt.
[Email-confirmation forwarding](reference/IMPLEMENTATION.md#email-confirmation-pages-proxy) is independently gated
and confirms the code without signing in; it can bind the temporary Terms receipt.
[Recovery-request forwarding](reference/IMPLEMENTATION.md#password-recovery-request-pages-proxy) has its own default-off gate,
requires CAPTCHA and returns neutral acceptance without changing cookies.
[Password-reset forwarding](reference/IMPLEMENTATION.md#password-reset-pages-proxy) is independently gated,
returns only completion metadata and preserves the backend's separate sign-in requirement.
[Google-start forwarding](reference/IMPLEMENTATION.md#google-start-pages-proxy) has its own default-off gate,
validating the authorization URL and short-lived OAuth binding cookie.
[Google-callback forwarding](reference/IMPLEMENTATION.md#google-callback-pages-proxy) is independently gated,
with fixed return destinations and strict OAuth/account cookie validation.
Production account controls default to off. Building with
`VITE_ACCOUNT_AUTH_ENABLED=true` enables email sign-in, session restoration,
sign-out and the existing Terms setup flow; development keeps its current behavior.
Google sign-in additionally requires its own flag and public issuer as described
above. `VITE_ACCOUNT_REGISTRATION_ENABLED=true` additionally enables production
email sign-up and code confirmation together, with a separate sign-in afterward.
`VITE_ACCOUNT_RECOVERY_ENABLED=true` additionally enables Forgot password and
code-based password reset together, requiring the account flag too. Backend
`ACCOUNT_PASSWORD_RECOVERY_API_ENABLED` / `ACCOUNT_PASSWORD_RESET_API_ENABLED`
and Pages `ACCOUNT_PASSWORD_RECOVERY_PROXY_ENABLED` /
`ACCOUNT_PASSWORD_RESET_PROXY_ENABLED` must be enabled separately. Reset ends
with a separate sign-in. `VITE_GUEST_ACCESS_ENABLED=true` independently enables
guest-session access. It also requires backend `GUEST_SESSION_API_ENABLED=true`,
Pages `GUEST_SESSION_PROXY_ENABLED=true` and real Turnstile configuration.
Guest sessions start only on a click; reloading and clicking again can reuse a
valid HttpOnly cookie without a fresh challenge. Chat remains in development.
These switches are public build configuration, not authorization: matching backend/proxy
gates and a real Turnstile site key must be configured separately. Account flows
also require the Terms endpoints.
Changing it requires a new frontend build; set it to `false` and rebuild to close
these browser controls. Hosted guest validation remains a separate rollout step.
A frontend build does not provide an API server.

Render uses root directory `backend`, build command `uv sync --locked --no-dev`,
and start command `.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 1 --no-proxy-headers`.
Provide the database CA as secret file `supabase-ca.crt`, referenced through
`/etc/secrets/supabase-ca.crt`. Set `DATABASE_URL` as a server environment value,
without dotenv quotes or the `DATABASE_URL=` prefix; do not give the runtime
service administrator/migration credentials. Review proxy trust and hosting logs
before enabling authentication; the Uvicorn callback filter alone does not
sanitize hosting, reverse-proxy or custom logs.

## Checks

From `backend`:

```powershell
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked mypy migrations
```

PostgreSQL tests are opt-in: `TEST_DATABASE_URL` must target
`127.0.0.1:15432/askm6_test` as `mazda6_admin`, use `postgresql+psycopg://`, and
contain no query parameters. Store it in ignored `backend/.env.integration.local`,
using `URL.create()` to encode credentials. Apply migrations first; tests verify
database identity/head and do not create tables or apply migrations themselves.
Application operations run as restricted `askm6_app`; tests roll back or commit
synthetic records and remove only their own rows. Admin inspection/setup is
separate from runtime operations. From `backend`:

```powershell
# Integration tests only
uv run --locked --env-file .env.integration.local pytest tests/integration -p no:cacheprovider
# Full suite including integration tests
uv run --locked --env-file .env.integration.local pytest -p no:cacheprovider
```

From `frontend`:

```powershell
npm run lint
npm test
npm run build
```

`npm test` runs API/proxy tests, isolated Workers-runtime tests, then Vitest/jsdom
UI tests; `build` includes strict TypeScript checking. `npm run test:runtime` runs
the pinned Miniflare/workerd suite alone with synthetic bindings and outbound
network connections blocked. No live paid APIs are needed. Local runtime and
jsdom checks do not replace deployed browser validation.
CI runs backend tests/lint/format/types and frontend tests/lint/build without
provider secrets. A separate PostgreSQL job creates a disposable database with
synthetic credentials, bootstraps restricted roles, applies all migrations, checks
schema drift, runs integration tests, and type-checks migrations. Local PostgreSQL
tests still require explicit configuration.

Earlier disposable Linux database validation passed **376 integration tests**, with no
schema drift and all seven migration files typed. The sign-in constraint upgrade
preserved recovery data and permissions; rollback refused while sign-in records
existed and succeeded after removing only the synthetic sign-in test record.

The guest browser checkpoint passed **523 UI/hook tests**, frontend lint,
strict TypeScript and four production builds. Three isolated browser variants
checked guest off/on and independent guest access with accounts off, including
one verification proof and reuse of a synthetic local HttpOnly cookie after reload.
APIs and verification were mocked; production cookie/Turnstile validation is pending.

The earlier recovery browser checkpoint passed **500 UI/hook tests**, frontend lint,
strict TypeScript and four production builds. Three isolated browser variants
verified recovery off/on and account access off, including reset followed by
separate sign-in, refresh and sign-out. Provider and verification calls were mocked.

The earlier registration browser checkpoint passed **475 UI/hook tests**, **86 registration
API tests**, frontend lint, strict TypeScript and four production builds
(default-off, email-only, Google and registration opt-ins). Isolated browser checks
covered sign-up consent, code confirmation without automatic login, separate sign-in,
Terms results, Google navigation, restoration and sign-out. APIs, provider/receipt
results and Turnstile are mocked; these checks do not verify live authentication
or receipt cryptography. Earlier Google API validation passed 53 tests.
Separate hosted manual checks confirmed email sign-in and Google new-account and
returning login, Terms setup, persistence after refresh, sign-out and repeat login
without a repeated agreement prompt. Hosted email registration, code confirmation,
separate sign-in, refresh, sign-out and returning sign-in were also manually confirmed
after correcting quoted Terms-receipt cookie forwarding. Hosted recovery/reset
was also confirmed: new-password sign-in works, the old password fails, existing
application sessions are invalidated, and refresh/sign-out behavior is preserved.

The earlier backend/transport checkpoint passed **3,929 offline backend tests**, **41 affected
PostgreSQL integration tests**, **1,622 API/proxy tests**, **75 Workers runtime tests**
and **393 UI/hook tests**. Backend lint, formatting (242 files), typing (229 app/test
files) and migration typing (13 files) passed, along with frontend lint, strict
TypeScript and production build. Earlier complete backend validation passed 4,732
tests including PostgreSQL; the current PostgreSQL run covers the affected Terms
and signup-limiter suites. Rollback, expiry, cancellation, account isolation and
confirmed-email-to-Google agreement are covered with mocked providers.
Automated limiter coverage includes concurrency, expiry,
transaction failures, cancellation, restricted maintenance targets and disposal.
Local manual checks confirmed guest verification, registration/email confirmation,
email/Google sign-in, Terms setup and returning-account skip behavior, and
confirmed email signup followed by password or Google as the first login. Earlier
checks covered restoration/sign-out and recovery/reset with old-password
rejection and new-password sign-in. After local migration/key setup, recovery
returned 202 with email delivery; maintenance completed, and a bounded invalid-body
test reached 429 with a positive `Retry-After`. These checks do not establish live
failure, concurrency, every identity-linking case or public-deployment behavior.

## Remaining work and detailed reference

Public authentication still needs deployment validation of abuse controls and
cleanup, provider/linking/method-assurance and partial-session failure review, production
proxy/cookie/redirect integration, and security/privacy/provider data-flow review.
Conversation ownership, vehicle context, persistence, message quotas, retrieval
and AI functionality remain separate unfinished work. Turnstile does not prove
a unique person or replace rate limiting; conversation isolation is not covered
by the current identity/storage tests.

All previous detailed contracts, settings, edge cases, test coverage and caveats
are retained in the [technical reference](reference/IMPLEMENTATION.md):

| Topic | Reference |
| --- | --- |
| Guest access and challenges | [Guest endpoint](reference/IMPLEMENTATION.md#guest-session-endpoint), [Turnstile](reference/IMPLEMENTATION.md#internal-turnstile-verification) |
| JWT, encrypted sessions and refresh | [Token verification](reference/IMPLEMENTATION.md#account-token-verification-foundation), [sessions](reference/IMPLEMENTATION.md#account-session-foundation), [refresh](reference/IMPLEMENTATION.md#provider-refresh-foundation) |
| Email access | [Registration](reference/IMPLEMENTATION.md#internal-registration-foundation), [confirmation](reference/IMPLEMENTATION.md#internal-email-confirmation-foundation), [sign-in](reference/IMPLEMENTATION.md#account-sign-in-endpoint) |
| Recovery and revocation | [Recovery/rate limits](reference/IMPLEMENTATION.md#backend-password-recovery-requests), [reset service](reference/IMPLEMENTATION.md#internal-password-reset-service), [reset endpoint](reference/IMPLEMENTATION.md#password-reset-endpoint-foundation) |
| Browser flows | [Account dialog](reference/IMPLEMENTATION.md#development-sign-in-interface), [Google](reference/IMPLEMENTATION.md#google-sign-in--local-development), [reset forms](reference/IMPLEMENTATION.md#development-password-recovery-and-reset-forms) |
| Setup and validation | [Database/deployment](reference/IMPLEMENTATION.md#database-configuration), [complete checks](reference/IMPLEMENTATION.md#checks) |

## License

Project code uses the [MIT License](LICENSE). Dependencies and automotive source
material retain their own licenses; no manufacturer manuals or proprietary
diagrams are included. Google artwork has a separate
[source/brand notice](frontend/src/assets/README.md).
