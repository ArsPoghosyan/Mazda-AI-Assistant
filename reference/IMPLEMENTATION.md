# Technical reference

[Back to the project README](../README.md)

Detailed implementation contracts, setup notes, validation coverage and
limitations. Test counts refer to the checkpoints described in each section,
not a fresh complete-suite run. The README provides the compact entry point.

The public product name is **askm6**, matching the Google sign-in display name.
Website metadata, policy-page titles/navigation, API documentation and the README
use that name. The original `a6` favicon uses the site palette; Mazda 6 remains
vehicle coverage. Repository/package names and runtime identifiers remain stable.

## Website not-found routing

The Vite multi-page build emits `index.html` and `404.html`. The latter mounts
only the branded NotFound component, supplies a no-JavaScript home link, and
does not start account, guest, health or Turnstile requests. Unknown website
paths return the static 404; exact `_redirects` rules rewrite `/privacy`,
`/privacy/`, `/terms` and `/terms/` to `/` with status 200. No wildcard SPA
rewrite is installed, and the existing `/api/*` Functions manifest is unchanged.
Local Miniflare tests exercise real built assets plus the API handler; a hosted
Pages deployment still needs its own post-deployment status check.

The 28 October availability correction describes supported guest/account access
and inactive AI chat. Both Terms constants now identify revision `2026-10-28`;
old acceptance is retained as historical evidence and does not satisfy the new
revision. Old signup receipts cannot silently accept revised Terms. Coordinate
backend and frontend deployment; a version mismatch fails closed during rollout.

## Contents

- [Engineering workflow](#engineering-workflow)
- [Working now](#working-now)
- [Windows local setup](#windows-local-setup)
- [Database configuration](#database-configuration)
- [Guest session endpoint](#guest-session-endpoint)
- [Internal Turnstile verification](#internal-turnstile-verification)
- [Account-token verification foundation](#account-token-verification-foundation)
- [Account-session foundation](#account-session-foundation)
- [Internal registration foundation](#internal-registration-foundation)
- [Internal email-confirmation foundation](#internal-email-confirmation-foundation)
- [Provider sign-in adapter](#provider-sign-in-adapter)
- [Internal sign-in service](#internal-sign-in-service)
- [Account sign-in endpoint](#account-sign-in-endpoint)
- [Development sign-in interface](#development-sign-in-interface)
- [Backend password-recovery requests](#backend-password-recovery-requests)
- [Internal provider-session response validation](#internal-provider-session-response-validation)
- [Internal password-reset adapters](#internal-password-reset-adapters)
- [Internal password-reset service](#internal-password-reset-service)
- [Password-reset endpoint foundation](#password-reset-endpoint-foundation)
- [Google sign-in — local development](#google-sign-in--local-development)
- [Frontend registration API foundation](#frontend-registration-api-foundation)
- [Account sign-out endpoint](#account-sign-out-endpoint)
- [Account session endpoint](#account-session-endpoint)
- [Provider refresh foundation](#provider-refresh-foundation)
- [Trusted proxy client addresses](#trusted-proxy-client-addresses)
- [Guest-session Pages proxy](#guest-session-pages-proxy)
- [Email sign-in Pages proxy](#email-sign-in-pages-proxy)
- [Sign-up Pages proxy](#sign-up-pages-proxy)
- [Email-confirmation Pages proxy](#email-confirmation-pages-proxy)
- [Password-recovery request Pages proxy](#password-recovery-request-pages-proxy)
- [Password-reset Pages proxy](#password-reset-pages-proxy)
- [Google-start Pages proxy](#google-start-pages-proxy)
- [Google-callback Pages proxy](#google-callback-pages-proxy)
- [Account sign-out Pages proxy](#account-sign-out-pages-proxy)
- [Account-session proxy request policy](#account-session-proxy-request-policy)
- [Checks](#checks)
- [License](#license)

---

[![Checks](https://github.com/ArsPoghosyan/Mazda-AI-Assistant/actions/workflows/ci.yml/badge.svg)](https://github.com/ArsPoghosyan/Mazda-AI-Assistant/actions/workflows/ci.yml)

An independent, unofficial Mazda information assistant in early development.
Unaffiliated with Mazda.

The first version will support Mazda 6, starting with verified information for
the 2021 model year. Additional Mazda models may be added later.

**Status: early development.** The frontend and API health-check foundation
are deployed at [askm6.com](https://askm6.com). The full assistant is not available yet.

## Engineering workflow

This is a personal project with publicly available code, tests, and development
history. External contributions are not being accepted.

Development proceeds in small, testable changes. GitHub Actions is configured for
backend tests/lint/types and frontend tests/lint/build. Results are available in the
[Actions tab](https://github.com/ArsPoghosyan/Mazda-AI-Assistant/actions).

## Working now

- React/TypeScript/Vite/Tailwind landing page with live API connectivity status.
- FastAPI `GET /api/v1/health` with a typed JSON contract.
- Docker Compose PostgreSQL/pgvector for local development.
- Configurable SQLAlchemy database pooling with remote TLS verification.
- `GET /api/v1/ready` checks database connectivity, returning 200 or 503.
- Tests for database configuration, readiness, timeouts, and pool lifecycle.
- Alembic migration setup and initial account/guest tables verified on local PostgreSQL.
- Opt-in PostgreSQL tests for identity constraints and restricted-role permissions.
- Guest session creation and expiry-safe refresh with configurable inactivity expiry.
- A default-disabled guest session endpoint with exact Origin checks and HttpOnly cookies.
- Guest HTTP tests for session reuse, invalid/expired cookies, and database failures.
- Development-only frontend guest session creation/refresh with loading, success,
  error/retry feedback, request cancellation, and a bounded timeout. New sessions
  use an on-demand Turnstile widget; valid existing sessions refresh without it.
- Development-only email/password sign-in form in a native modal dialog, with
  a dimmed backdrop, initial focus, Escape/Close dismissal, and focus restoration.
  Turnstile uses a rectangular flexible-width widget for guest and account access.
  Sign-in submissions consume each proof once, clear the password field, and use
  bounded requests with controlled error feedback. Manual local validation confirmed
  successful CAPTCHA-protected sign-in and a subsequent cookie-authenticated session
  check after a backend restart. In development, the page restores account state
  from the cookie session and updates immediately after a successful sign-in.
  Development sign-out waits for server confirmation before clearing account state.
  Local browser checks confirmed sign-in, account restoration on refresh, and sign-out.
- Offline ES256 account-token verification with typed identity claims and
  generated-key tests for invalid signatures, claims, algorithms, and token sizes.
- Bounded HTTPS signing-key retrieval, P-256 key selection, and a shared
  process-local cache with lazy fetching and application-managed cleanup.
- Protected `GET /api/v1/account/me` with Bearer-token verification, typed
  account identity, generic 401/503 responses, and no-store caching headers.
- Optional validated account-session encryption key and a standalone Fernet
  helper for provider tokens, with tamper detection and generated-key tests.
- Account-session model and migration verified on local PostgreSQL, with account
  foreign keys, bounded ciphertext fields, expiry constraints, and restricted grants.
- Internal account-session creation with verified identity, encrypted provider
  credentials, browser-token hashing, capped deadlines, and transactional recovery.
- One application session per provider session, enforced by a database constraint,
  with controlled duplicate rejection and concurrent creation tests.
- Internal account-session lookup with expiry checks after row-lock acquisition
  and activity updates capped at the stored absolute deadline.
- Non-mutating locked session loading and stored access-token verification against
  the recorded account, provider session, and token expiry.
- Internal authentication using stored access credentials, with expiry rechecks
  after verification and guarded activity updates in the caller's transaction.
- Internal provider-token refresh adapter with bounded HTTP requests, masked
  credentials, and distinct credential-rejection and unavailability errors.
- Refreshed access-token verification against the expected account and provider
  session, tested with generated signing keys and mocked provider requests.
- Internal stored-refresh exchange and encrypted replacement helpers, with
  configuration, identity, stale-snapshot, and expiry guards.
- Internal account-session authentication coordinating current-token verification
  or one provider refresh attempt under a caller-owned row lock, with PostgreSQL
  tests for concurrent requests, rollback recovery, and rejected recovery.
- An internal authentication transaction boundary that commits and releases the
  connection before returning identity, with commit-failure and rollback tests.
- Internal account-cookie helpers for setting, reading, and clearing opaque
  browser tokens, with independent HTTPS defaults and offline policy tests.
- A default-disabled account-session HTTP endpoint with exact Origin checks,
  committed authentication, cookie renewal, controlled failures, and PostgreSQL
  tests using generated credentials and mocked provider responses.
- An internal email/password sign-in adapter with bounded requests, masked token
  results, generic provider errors, and mocked HTTP/timeout/cancellation tests.
- An internal sign-in service connecting that adapter to verified, encrypted
  account-session creation, with results returned only after database commit.
- A default-disabled HTTP sign-in endpoint with bounded JSON credential parsing,
  trusted-Origin checks, a required CAPTCHA proof forwarded to Supabase Auth,
  a total deadline, and cookie issuance after commit, verified by offline route
  tests and local PostgreSQL integration tests.
- A default-disabled current-session sign-out endpoint with hashed-cookie deletion,
  cookie clearing after commit, replay rejection, and PostgreSQL isolation and
  rollback tests. Provider-session revocation is separate and not implemented.
- Internal registration parsing and a bounded Supabase sign-up adapter, with
  required CAPTCHA input, generic outcomes, and mocked failure/cancellation tests.
- A default-disabled registration HTTP endpoint with trusted-Origin checks, a
  total deadline, and generic acknowledgements. It issues no application cookies;
  its interface is available only in development.
- Internal email-code confirmation parsing and a bounded Supabase verification
  adapter, with masked credentials, response validation, and mocked HTTP tests.
  Provider session credentials are discarded; application sign-in remains separate.
- A default-disabled confirmation HTTP endpoint with trusted-Origin and resource
  checks, a total deadline, and cookie-free responses. Mocked HTTP tests cover
  confirmation, malformed input, provider failures, configuration gates, and deadlines.
- Frontend registration and email-confirmation API helpers with explicit request
  fields, validated acknowledgement responses, controlled errors, cancellation,
  and mocked API tests. Development forms connect these helpers inside the
  existing account dialog, with a separate sign-in after email confirmation.
- Development-only Forgot password flow in the same dialog: CAPTCHA-protected
  recovery email request, code/new-password form and explicit return to sign-in.
  Mocked tests cover validation, cancellation, single-use proofs, sensitive-field
  clearing and navigation races. Recovery email delivery, reset, old-password
  rejection and new-password sign-in have been manually validated locally.
- An internal Turnstile verifier with exact hostname/action checks, bounded
  Siteverify requests, controlled failures, and offline HTTP/cancellation tests.
- Guest first-use verification before session creation, bounded optional JSON
  input, and a total operation deadline. Active sessions refresh without another
  challenge; cookies are issued only after commit. The browser submits each proof
  once and requires a fresh attempt after a failed submission.
- Python lint/type checks and frontend proxy tests/lint/type/build checks.

Chat, conversation persistence, vehicle selection,
retrieval, and AI calls are not implemented. Expired guest
sessions are rejected before refresh; automated guest-history cleanup is not implemented.
Embeddings are planned with OpenAI `text-embedding-3-small` (1536 dimensions);
answer generation is planned with Groq.

## Windows local setup

Prerequisites: Python 3.12, uv, and Node.js 24 LTS with npm. Verify `py -3.12
--version`, `uv --version`, `node --version`, and `npm --version` in a new PowerShell
window. A listed Python installation may still have an invalid launcher/path;
select a working interpreter in PyCharm rather than editing an existing venv.

On the original development machine, portable Node 24.22.0 and uv 0.13.1 were
installed under the ignored `.tools` directory to verify this slice. If those
directories are present, run this from the repository root in **each terminal**
before following the commands below (this changes only that terminal's PATH):

```powershell
$taskRoot = (Get-Location).Path
$env:Path = (Join-Path $taskRoot '.tools/node-v24.22.0-win-x64') + ';' + (Join-Path $taskRoot '.tools/bootstrap/Scripts') + ';' + $env:Path
```

These local tools are not included in Git; a fresh clone needs the prerequisites
installed separately. The Node archive was verified against its official SHA-256
checksum. The existing root virtual environment was preserved.

From the repository root, install the locked backend dependencies:

```powershell
Set-Location backend
uv sync --locked
uv run uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 --no-proxy-headers
```

In a second PowerShell terminal, from the repository root:

```powershell
Set-Location frontend
npm ci
npm run dev
```

Open http://127.0.0.1:5173. It should report **API connected**. Stop the backend
and use **Try again** after reloading to see the unavailable state. API docs are
at http://127.0.0.1:8000/docs. The health response checks process liveness only.

Vite forwards `/api` to `127.0.0.1:8000`; no broad CORS permission is needed.
Local startup explicitly disables Uvicorn proxy-header processing so incoming
forwarding headers cannot replace the peer address or scheme. Requests through
Vite may share a loopback address; this is not production visitor identification.
Both servers bind to loopback. The production build does not supply an API server;
production uses Cloudflare Pages and a FastAPI backend on Render. The Pages
proxy permits `GET /api/v1/health` by default, with separately gated existing
account-session forwarding described below. Readiness is backend-only.

For PyCharm, use `backend/.venv/Scripts/python.exe` after `uv sync`, with `backend`
as the working directory. The pre-existing root `.venv` is not used by this setup.

## Database configuration

For the optional local database, create an ignored root `.env` using the root
`.env.example` and set a strong local `POSTGRES_PASSWORD`. From the repository
root, run `docker compose up -d --wait db`. PostgreSQL binds to
`127.0.0.1:15432` and stores data in the `postgres_data` Docker volume.

Backend configuration is documented in `backend/.env.example`. Settings read
`backend/.env` and environment variables; environment variables take precedence.
Without `DATABASE_URL`, `/api/v1/health` returns 200 and `/api/v1/ready` returns 503.
The health endpoint checks process liveness; readiness executes `SELECT 1` and
checks connectivity, not migration status or application-table permissions.

Apply migrations independently to the development database and the integration-test
database using the restricted migration role. Upgrading `askm6_test` does not upgrade
the website's local `mazda6` database. Account sign-in needs the account-session table
and the provider-session uniqueness constraint through migration `08cad124d60b`.
Use migration credentials for Alembic; keep the runtime database role restricted.

Database URLs use `postgresql+psycopg://`. Remote connections require
`sslmode=verify-full` and an `sslrootcert` path pointing to the downloaded CA
certificate. Local Docker connections use port 15432. The application pool
defaults to two connections per process, with no overflow.

Keep real credentials in ignored backend environment files or Render environment
variables, never in frontend `VITE_*` variables. Use a restricted application
database role; administrator or migration credentials are managed separately.
Construct URLs with SQLAlchemy `URL.create()` or percent-encode reserved
characters in passwords when building a URL manually.

For an explicitly configured Supabase connectivity test, create an ignored
`backend/.env.supabase` containing the database URL and run from `backend`:

```powershell
uv run uvicorn app.main:app --reload --loop asyncio --env-file .env.supabase --host 127.0.0.1 --port 8000 --no-proxy-headers
```

The Windows development command uses reload with the asyncio loop so Psycopg
runs with a compatible Selector event loop. Keep normal local development on
Docker rather than using the production database for development data.

For Render, provide the CA certificate as a secret file named `supabase-ca.crt`
and use `/etc/secrets/supabase-ca.crt` as the URL's `sslrootcert` value. Configure
`DATABASE_URL` as a server-side environment variable, without dotenv quotes or
the `DATABASE_URL=` prefix. The native Python service uses root directory
`backend`, build command `uv sync --locked --no-dev`, and start command
`.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 1`.

## Guest session endpoint

`POST /api/v1/guest/session` refreshes an existing, unexpired guest session or
requires Turnstile verification before creating a new one. Missing, malformed,
unknown, and expired cookies require a fresh challenge for new-session creation.
Only the browser token's hash is stored in PostgreSQL. The token is issued in an
HttpOnly cookie after commit and is never returned in JSON. Successful responses
contain `status` and `expires_at` and use `Cache-Control: no-store`.

For creation, send `Content-Type: application/json` with
`{"turnstile_token":"token-from-the-widget"}`. The backend requires the verified
hostname to match its configured allowlist and the challenge action to be
`guest_start`. Empty bodies, `{}`, and a null `turnstile_token` carry no challenge;
they support refresh but cannot authorize creation. Nonempty bodies require JSON,
extra fields are rejected, and tokens must be strings of one to 2048 characters.
The parser enforces a 16 KiB limit on actual streamed bytes, independent of the
claimed Content-Length.

The service commits the refresh attempt before returning an active session or
counting a new-session attempt. New creation requires committed IP accounting
before contacting Cloudflare. Verification runs without holding a database
transaction or connection. A new creation transaction opens only after verification succeeds,
and cookie material is returned only after commit. Active sessions can refresh
even when the Turnstile client is unavailable. Verification does not establish a
unique human identity or replace rate limits and message quotas.

### Guest-creation abuse limit

New-session attempts use the shared PostgreSQL rolling-window counter with fixed
purpose `guest_creation` and HMAC namespace
`askm6:auth-rate-limit:v1:guest_creation:ip:`. The starting policy is 10 attempts per
rolling 600 seconds, configured through `GUEST_CREATION_IP_MAX_REQUESTS` (1–1,000)
and `GUEST_CREATION_IP_WINDOW_SECONDS` (60–86,400). The backend needs the independent
`AUTH_RATE_LIMIT_HMAC_SECRET`; raw peer addresses are not stored. Forwarding headers,
challenge values and cookie clearing cannot select another budget. IPv4-mapped
IPv6 uses the same canonical address. The optional authenticated assertion below
adds proxy integration; live ingress verification remains pending.

Origin/feature/database guards and bounded body parsing run first. An active
cookie refresh commits and returns without resolving a fingerprint or charging
the budget, even at the creation cap or without creation-verification resources.
For missing, malformed, unknown or expired cookies, creation requires configured
Turnstile resources and a usable peer/HMAC key. The limiter transaction commits
and releases before any challenge verification or guest insert. A missing or
rejected challenge, verification failure or later creation failure retains that
attempt. The first challenge-triggering request and proof submission each count;
malformed bodies and unavailable creation configuration do not. These are abuse
attempt limits, separate from future accepted-AI-message quotas.

A committed denial returns 429, `Cache-Control: no-store` and rounded-up
`Retry-After` seconds, without verification, insertion, cookie changes or a
verification-required header. Denied requests do not extend the window. Key,
accounting, commit and deadline failures return generic 503 without creating a
session. There are no automatic retries. The existing operation deadline covers
parsing, refresh, accounting/lock waits, verification and creation.

Migration `aefd9866f033` follows `0ffc842c5360`, broadening only the supported-purpose
CHECK. It preserves records, indexes and restricted grants; downgrade refuses
while guest-creation rows exist. Both guarded local databases are upgraded with
no schema drift or private environment changes. Shared expired-row cleanup now
includes guest creation under one total batch cap; optional application-owned
scheduling is described below. The development frontend shows dedicated guest retry guidance for 429.

This checkpoint passed all 4,316 backend tests, including guarded PostgreSQL
integration tests; Ruff, formatting and application/migration type checks passed.
Coverage includes concurrent creation, active-cookie reuse at the cap, canonical
IP identity, retry expiry, failed commits, lock deadlines, separate account
budgets and six-purpose cleanup. Provider traffic is mocked in automated tests.

`GUEST_SESSION_TIMEOUT_SECONDS` defaults to 15 and accepts one to 30 seconds.
It bounds body reading, verification, and database work. Invalid input returns
400, oversized input 413, and unsupported nonempty-body media types 415. Missing
or rejected challenges return a generic 403; unavailable verification, database
errors, and timeouts return a generic 503. These errors use no-store headers and
do not issue or clear a guest cookie. Provider details are not returned. Requests
are not automatically retried; after verification has been attempted, obtain a
fresh challenge before retrying creation. Database rollback cannot undo consumed
verification, and an uncertain commit does not guarantee that no row was created.

The endpoint defaults to disabled through `GUEST_SESSION_API_ENABLED=false`.
Keep public guest access disabled until abuse controls and production integration
are ready.
Cloudflare Pages supports separately gated guest creation/refresh and validated
guest cookies; public enablement and hosted validation remain pending.
The frontend guest action is
enabled only in Vite development and remains disabled in normal production builds.

Requests require exactly one Origin matching `CSRF_TRUSTED_ORIGINS`, configured
as a JSON array such as `["https://askm6.com"]`. Missing, null, duplicate, and
unlisted origins return 403 before session database work. The default allowlist
is empty. Local Vite development uses `["http://127.0.0.1:5173"]`; origins have
no trailing slash. Origin validation complements authentication and abuse controls.

`GUEST_COOKIE_SECURE=true` uses the host-only `__Host-askm6_guest` cookie with
Secure, HttpOnly, SameSite=Lax, and Path=/. Set it false only for local HTTP
development, which uses the separate `askm6_guest` name. Guest inactivity expiry
defaults to 30 days through `GUEST_SESSION_INACTIVITY_DAYS`.

### Local frontend guest flow

The Vite development frontend first requests a guest session without a challenge.
A 403 response with `X-Guest-Verification: required` opens an explicit Turnstile
widget. Ordinary Origin-related 403 responses do not trigger a challenge.
Completing the widget submits its proof once as JSON. The backend verifies it
before creating a session; a valid existing guest cookie skips the challenge.

HTTP 429 becomes a dedicated guest rate-limit error. Only decimal `Retry-After`
delta-seconds from 1 to 86,400 are accepted; missing, malformed, duplicate, date,
or out-of-range values use generic try-later feedback. Error bodies and raw header
values are never displayed. Other response statuses ignore `Retry-After`, and a
verification-required header on 429 cannot open a challenge.

The existing accessible status region announces the wait with correct singular
or plural wording. This is static guidance from the last response, not a countdown
or browser-enforced cooldown; the server remains authoritative. Retries require
an explicit **Try again** action. No timer retries, proof replay or automatic
widget submission is added. A rate-limited proof submission removes its widget;
manual retry starts without a proof and requests a fresh challenge if required.
API, hook and rendered App tests cover these paths with mocked network traffic.
Frontend validation passed all 642 tests (307 API and 335 UI/hook), lint,
TypeScript checking and the production build. Backend source is unchanged by
this UI slice; its preceding 4,316-test result is recorded above.

The local guest flow requires a running, migrated local database and a backend
`DATABASE_URL` using the restricted application role. In the ignored `backend/.env`,
enable the endpoint and configure the exact frontend origin and widget hostname:

```ini
GUEST_SESSION_API_ENABLED=true
GUEST_COOKIE_SECURE=false
CSRF_TRUSTED_ORIGINS=["http://127.0.0.1:5173"]
TURNSTILE_SECRET_KEY=your-development-widget-secret
TURNSTILE_ALLOWED_HOSTNAMES=["127.0.0.1"]
```

Use a separate Cloudflare development widget with `127.0.0.1` as an allowed
hostname, Managed mode, and pre-clearance disabled. Copy `frontend/.env.example`
to the ignored `frontend/.env.development.local` and set its public site key:

```ini
VITE_TURNSTILE_SITE_KEY=your-development-widget-site-key
```

The site key is public; the secret belongs only in backend configuration. Never
put the secret in a `VITE_*` variable. Hostnames contain no scheme, port, or path;
trusted origins include the scheme and port. Keep local hostnames out of the
production widget. Cloudflare's documented dummy-key response uses the action
`test`, whereas this flow requires `guest_start`; use the separate development
widget for the live browser check rather than weakening action validation.
See Cloudflare's [widget setup](https://developers.cloudflare.com/turnstile/get-started/widget-management/dashboard/)
and [testing documentation](https://developers.cloudflare.com/turnstile/troubleshooting/testing/).

Restart FastAPI and Vite after changing the local environment files. Open
`http://127.0.0.1:5173` in a fresh private browser window and select **Try as Guest**.
Complete the challenge if prompted; Managed mode may finish without interaction.
The widget disappears when its proof is submitted. Wait for **Guest session ready**
to confirm that the backend accepted it and completed the database transaction.
Reload in the same private window and select the action again: an unexpired guest
cookie should refresh without another challenge. Reloading alone does not submit
a guest-session request. The browser manages the HttpOnly cookie; the frontend
does not read or store its credential, and challenge proofs are not persisted.

The SDK loads only when a challenge is requested, with a ten-second loading
deadline and a shared loading attempt. The dynamically inserted script uses
`async=false` because Cloudflare's `ready()` rejects async/defer-marked scripts.
Widget cleanup ignores late callbacks after retry or unmount. Loading and
challenge failures offer an explicit retry; a failed proof submission stops and
requires a new attempt rather than automatically reusing the token.

Success confirms a guest session, not a working chat. Production builds keep the
guest action disabled unless `VITE_GUEST_ACCESS_ENABLED=true` at build time;
only that exact value enables it. Development retains its existing behavior even
with the flag false. Guest access is independent of `VITE_ACCOUNT_AUTH_ENABLED`.
The existing guest hook owns this gate for both the button and submissions.
When accounts are enabled, guest access waits for a confirmed signed-out state
and stays blocked while signed in, while session checks fail, or while the account
dialog is open. No automatic guest-data transfer is added.

Enable backend `GUEST_SESSION_API_ENABLED` and Pages `GUEST_SESSION_PROXY_ENABLED`
separately, with secure production cookies, trusted ingress/origins, the guest
creation limiter and real Turnstile hostname/action configuration. Changing the
browser flag requires a new build; unset it or use `false` and rebuild to close
guest browser access. No guest-session request is made on page load or reload.
This UI gate is not authorization; backend checks still apply. Keep insecure
cookies and the local endpoint configuration out of production. Guest chats,
conversation persistence and ownership transfer remain separate unfinished work.

The guest browser checkpoint passed 523 UI/hook tests, including 44 focused guest
tests, plus lint, strict TypeScript and four production builds. Three isolated
compiled-browser variants cover guest closed/open and account access off, one
proof submission, no automatic requests, and returning-session reuse after reload.
The cookie is a synthetic local HTTP HttpOnly fixture; this does not validate
production Secure/`__Host-` scope, real Siteverify or backend cookie ownership.
All API/verification responses are mocked and external network is blocked.
Separate hosted manual checks confirmed first-use verification and guest readiness,
then reload in the same browser followed by the guest action reached readiness
without a new challenge. This confirms the tested guest access flow, not chat
persistence, ownership transfer or resistance to every abuse case.

## Internal Turnstile verification

`verify_turnstile_token` submits a challenge once to Cloudflare's fixed HTTPS
Siteverify endpoint using a caller-owned HTTP client. Successful verification
requires `success: true`, an exact hostname from `TURNSTILE_ALLOWED_HOSTNAMES`,
and an exact match for the action supplied by backend code.

`TURNSTILE_SECRET_KEY` is backend-only and defaults to unset. The hostname
allowlist defaults to empty; configure it as a JSON array of exact hostnames,
without schemes, ports, paths, or wildcards. `TURNSTILE_TIMEOUT_SECONDS` defaults
to five seconds and accepts values from one to 30. Missing configuration prevents
verification before any provider request.

Requests accept only nonempty printable ASCII challenge tokens of at most 2048
characters. The total deadline covers the request and response reading, with a
64 KiB response limit. Redirects and compressed or non-JSON responses are rejected.
The helper does not retry or forward a visitor IP. Known challenge failures raise
`TurnstileRejected`; configuration, transport, unknown provider, or malformed
response failures raise `TurnstileUnavailable`. Both prevent successful
verification, expose generic messages, and preserve caller cancellation.

Token expiration and single use are enforced by Cloudflare's live Siteverify
service. The helper does not cache successful challenges or establish an identity.
After an uncertain verification result, obtain a fresh challenge. Do not verify
one token here and then submit it to Supabase's CAPTCHA verification as well.

FastAPI owns a dedicated Turnstile HTTP client when a secret and nonempty hostname
allowlist are configured. It is independent of the Supabase client, does not
contact Cloudflare at startup or during health checks, and is closed on shutdown.
Startup and cleanup failures still release previously registered resources and
clear application state. The client disables redirects and environment-provided
proxy settings and allows at most two connections.

The guest-session service calls this verifier before new-session creation, using
proofs supplied by the development frontend widget. Account sign-in instead sends
a separate proof to Supabase Auth for verification during the password exchange;
it does not call this guest verifier first. The development sign-in form uses the
`account_sign_in` widget action. The internal registration adapter also forwards
its proof to Supabase through the default-disabled registration route. Public
access still requires abuse controls and production guest-route/cookie forwarding.

Offline tests use synthetic secrets/tokens and mocked HTTP. They cover request
contents, exact hostname/action matching, rejection versus unavailability,
malformed responses, redirects, response-size boundaries, transport failures,
total deadlines, cancellation, and response cleanup. They make no Cloudflare
requests and do not test live challenge issuance, expiration, or replay handling.
Lifecycle tests cover incomplete configuration, operation without Supabase,
separate clients, and cleanup failures. Service tests cover transaction ordering,
refresh without a challenge, rejected verification, cancellation, and commit
failures. Local PostgreSQL tests verify committed creation from a separate
connection and rollback after an injected SQL error before commit. Guest HTTP
tests exercise verified creation and challenge-free reuse for missing, malformed,
unknown, and expired initial cookies, using mocked Cloudflare responses.

## Account-token verification foundation

The backend provides an offline account-token verifier using PyJWT and
cryptography. Its caller supplies a trusted P-256 public key and the expected
issuer and audience. It accepts only ES256, validates required identity and time
claims, rejects anonymous/non-account identities, and limits token length.
Account authentication allows a configurable five-second difference for the
signed `iat` (issued-at) claim through `SUPABASE_AUTH_IAT_CLOCK_SKEW_SECONDS`
(0–30 seconds; zero restores exact issued-at timing). The verifier requires a
strict integer issued-at value, rejects values beyond that bound and requires
issued-at to precede expiry. Expiry and optional not-before checks retain zero
leeway; signature, issuer, audience and account checks are unchanged. This avoids
intermittent rejection of freshly issued tokens when the provider clock is
slightly ahead. Direct verifier callers remain strict unless they pass a bound.

Successful verification also returns the access token's expiry as a
timezone-aware UTC timestamp for future account-session handling. Expiry comes
from the verified `exp` claim; unrepresentable timestamps produce the generic
invalid-token error. The `/api/v1/account/me` response still exposes only
`user_id`. Provider access-token expiry is separate from the application's
inactivity and absolute session deadlines.

`SUPABASE_AUTH_ISSUER` configures the expected HTTPS Auth issuer ending in
`/auth/v1`; `SUPABASE_AUTH_AUDIENCE` defaults to `authenticated`.
The issuer remains optional. When configured, FastAPI creates one dedicated HTTP
client and key cache per application lifespan. Startup and health checks do not
fetch signing keys. Shutdown closes
the client and disposes the database engine, including when later startup work fails.

The separate key fetcher uses the configured issuer's `/.well-known/jwks.json`
endpoint, rejects redirects and compressed responses, and requires a successful
JSON response within five seconds and 64 KiB. Key selection accepts P-256 public
keys for ES256 verification and rejects ambiguous IDs and private-key material.

The cache retains one downloaded key set for five minutes and permits refreshes
at most once every 30 seconds. Concurrent lookups share refresh work. Failed
refreshes do not extend key expiry; expired cached keys are not used. Unknown
keys may be rejected during the cooldown. Provider-side caching also affects
key rotation and revocation; local caching does not provide immediate revocation.

`GET /api/v1/account/me` requires exactly one Authorization header containing a
Bearer token. Successful verification returns only the verified `user_id`.
Missing or invalid credentials return 401 with `WWW-Authenticate: Bearer`;
unconfigured or unavailable verification returns 503. Successful responses and
these authentication failures use `Cache-Control: no-store`. Tokens in query
parameters or cookies are not accepted.

This endpoint does not implement sign-up/sign-in UI, create account profiles,
check live session revocation or account suspension, or grant resource ownership
or administrator permissions. Pages does not forward this Bearer-token endpoint;
only the separately gated cookie-session check is supported alongside health.

Tests generate temporary signing keys in memory and mock downloads and lifecycle
failures. They require no Supabase requests, real user tokens, or database access.
An HTTP test exercises real authentication and caching with generated signed
tokens, mocks only the key download, and verifies rejection of forged signatures.

## Account-session foundation

`ACCOUNT_SESSION_ENCRYPTION_KEY` is an optional backend-only Fernet key, documented
in `backend/.env.example`. Missing or empty environment values leave it
unconfigured; malformed keys fail settings validation. Configured keys use
`SecretStr` to mask ordinary settings display and JSON serialization. Human-readable
validation messages omit input values; structured validation errors must explicitly
exclude inputs before being logged or returned.

`AccountTokenCipher` accepts an explicitly supplied key and encrypts nonempty ASCII
provider tokens of up to 8,192 characters into bytes. Decryption verifies integrity,
limits ciphertext input to 12,288 bytes, and returns a `SecretStr`. Wrong keys,
tampered or malformed ciphertext, and invalid decrypted content produce a generic
error without including token values. Encryption tests use temporary keys and synthetic
tokens, with no private environment files, database, or provider requests.

The `app.account_sessions` model and migration `b87f3f661f93` provide storage for a
unique 32-byte browser-token hash, an account-profile reference, a provider session
ID, encrypted access/refresh tokens, and timezone-aware activity and expiry
timestamps. Database constraints require nonempty ciphertext fields of at most
12,288 bytes and consistent timestamps, including inactivity expiry no later than
absolute expiry. These constraints do not encrypt data or verify token identity.
Deleting an account profile cascades to its sessions; deleting a session preserves
the account profile.

Migration `08cad124d60b` adds the unique constraint
`uq_account_sessions_provider_session_id`, allowing one application session per
provider session. An account can still have multiple application sessions when
each has a distinct provider session ID. Existing duplicates require review before
applying this migration; it does not delete or merge rows. Session creation
requires this migration because its conflict handling names the constraint.

The application role can select, insert, and delete session rows. Updates are
limited to encrypted provider tokens, access-token expiry, last activity, and
inactivity expiry. Session identity, ownership, creation time, and the absolute
deadline cannot be updated by that role. These grants do not isolate accounts
from each other; backend authorization remains necessary.

`ACCOUNT_SESSION_INACTIVITY_DAYS` defaults to 7 and
`ACCOUNT_SESSION_ABSOLUTE_LIFETIME_DAYS` defaults to 30; both accept positive
integers. These application-session deadlines are separate from provider
access-token expiry.
Session creation uses these settings to calculate deadlines and caps inactivity
expiry at the absolute deadline.

The internal `create_account_session` service verifies the provider access token,
encrypts provider credentials, generates a random browser token, and stores only
its hash. It creates or reuses the verified account profile and checks access-token
expiry against fresh database time after any wait on profile creation. A savepoint
makes profile/session creation atomic within the caller's transaction. The caller
must commit successfully before issuing the browser token.

If the provider session already exists, creation raises
`AccountSessionAlreadyExists` without returning a browser token. The existing
session's credentials, ownership, token hash, and deadlines remain unchanged;
any new profile inserted by the failed attempt is rolled back with its savepoint.
Only the provider-session uniqueness conflict is handled this way; other database
errors are not silently ignored. The stored browser-token hash cannot reconstruct
the original token, so a future login flow may require a fresh sign-in if the
initial response is lost before the browser receives its credential.

The refresh token must come from the same trusted provider authentication response.
The service validates its format but does not independently verify refresh-token
ownership. The internal sign-in service connects the provider adapter to this
creation flow, and a default-disabled HTTP sign-in endpoint issues its browser
cookie after successful commit. The separate session-check endpoint authenticates
existing sessions only.

Local PostgreSQL tests cover encrypted storage, verified identity, configurable
deadlines, account-profile reuse, invalid inputs, expiry after initial verification,
outer-transaction rollback, and savepoint recovery after an insertion failure.
Schema tests reject duplicate provider sessions within and across accounts while
allowing distinct provider sessions for one account. Service tests verify duplicate
rejection preserves existing rows and rolls back a newly inserted profile. Real
two-connection tests observe PostgreSQL blocking before committing or rolling back
the first creation attempt: after commit the second attempt reports a duplicate;
after rollback it can create the sole committed session.
Tests use generated credentials and mocked signing-key retrieval; the
post-verification expiry test also mocks the verified identity to simulate expiry.

The internal `touch_account_session` service validates and hashes the browser
token, locks the matching row, and checks both application-session deadlines using
fresh statement time after acquiring the lock. Expired sessions are rejected
without updates, including when expiry occurs during a lock wait. For active
sessions, last activity cannot move backward, and inactivity expiry is recalculated
from the configured period, capped at the stored absolute deadline. The caller
controls commit and rollback.

Lookup returns internal session metadata, including provider access-token expiry;
it does not decrypt, verify, or refresh provider credentials, or establish a
completed authentication result. An active application session can still need
provider-token refresh before authorizing a protected operation. Offline tests
cover malformed and unknown tokens and transaction requirements. Local PostgreSQL
tests cover activity updates, expiry rejection, rollback, unchanged credentials
and other sessions, and expiry during a real row-lock wait.

The internal `load_locked_account_session` helper locks the matching row and
checks application-session expiry using fresh database statement time after any
lock wait. It returns an internal snapshot without changing activity or encrypted
credentials. Missing, malformed, or unknown browser tokens and expired application
sessions return no snapshot. An expired provider access token does not prevent
loading an otherwise active application session for subsequent refresh. The caller
owns the transaction; the snapshot does not prove that its row lock remains held
after the transaction ends. Ciphertext fields are omitted from its ordinary
representation.

`verify_locked_account_access` decrypts only the stored access token and uses the
existing JWT verifier and signing-key cache. Verified account ID, provider session
ID, and token expiry must match the stored metadata, and token expiry must be later
than the snapshot's database check time. Invalid ciphertext, invalid JWTs, metadata
mismatches, or unavailable configuration/signing keys fail with a generic
authentication-unavailable error. Refresh credentials remain encrypted. This helper
does not update the database or complete application-session authentication on its
own.

Offline tests cover loader input guards and stored-token verification using
generated encryption/signing keys and mocked signing-key downloads. Local
PostgreSQL tests cover unchanged rows, expired sessions, and real lock waits that
commit expiry or replacement credentials before loading resumes. No live provider
requests are required.

The internal `authenticate_stored_account_session` service combines locked loading
and stored access-token verification. Its final SQL update uses fresh database
statement time after verification, including any signing-key download. The update
requires matching account/provider identity and recorded token expiry, and requires
both application-session deadlines and access-token expiry to remain in the future.
Missing or expired application sessions return no result; verification failures
raise the existing generic authentication-unavailable error. If a deadline expires
after verification, the guarded update returns no result without changing the row.

Successful authentication updates only last activity and inactivity expiry. Activity
cannot move backward, inactivity expiry is capped at the stored absolute deadline,
and provider credentials remain unchanged. The result contains verified identity
and session deadlines, with no provider tokens. The caller retains control of the
transaction and must commit successfully before using the result outside it. This
path requires a valid stored access token and does not refresh expired credentials.

Offline orchestration tests cover missing sessions, verification failure and
cancellation, and returned database results. Local PostgreSQL tests use real
encryption and JWT verification with mocked signing-key retrieval. They check
activity updates, unchanged credentials and other accounts' rows, caller savepoint
rollback, and unchanged rows on verification failure. Post-verification expiry
tests change a synthetic inactivity deadline or simulate a later final SQL check
time. Access-token and absolute-boundary cases cover the exact deadline and one
second afterward; at the absolute boundary, inactivity expiry coincides with the
absolute deadline as required by the schema.

Provider-session revocation and encryption-key rotation are not implemented.
Local expiry cleanup is available through the optional housekeeping task below.
HTTP sign-in/session creation, application-session sign-out,
and cookie-authenticated session checking are available through the separate
default-disabled endpoints described below.
Provider identity and expiry require JWT verification in addition to ciphertext
decryption. Keep real encryption keys in ignored backend environment files or a
server-side secret manager, never in frontend variables or Git. Retain the key
while encrypted data depends on it; replacing it without a rotation process makes
existing ciphertext unreadable.

The internal `app.account_cookies` helpers set, read, and clear the opaque browser
token. `ACCOUNT_COOKIE_SECURE=true` is the default and selects
`__Host-askm6_account`; `false` selects `askm6_account` for local HTTP development
only. This setting is independent of guest-cookie configuration. Cookies use
`HttpOnly`, `SameSite=Lax`, `Path=/`, no Domain attribute, and `Secure` when enabled.
Setting and clearing a cookie also mark the response `Cache-Control: no-store`.

The reader accepts only the configured cookie name and a 43-character ASCII
URL-safe token, returned as a `SecretStr`. Missing or malformed tokens return no
result; guest cookies and the alternative account-cookie name are ignored.
Format validation does not authenticate a session. Database lookup, expiry checks,
and provider-credential verification remain necessary.

Cookie issuance requires a valid token and timezone-aware expiry, normalized to
UTC. The caller must supply the committed database session's inactivity deadline,
already capped at its absolute deadline, and issue the cookie only after commit.
The helpers do not calculate or enforce database deadlines themselves. Offline
tests cover header policy, malformed tokens, expiry conversion, matching deletion
scope, and HTTP/HTTPS cookie round trips in an in-memory test application. These
tests make no database or provider requests and do not enable account endpoints.

## Internal registration foundation

Registration currently consists of configuration, bounded credential parsing,
provider-response interpretation, and an internal `sign_up_with_password` adapter.
The application request additionally requires literal `accepted: true` and the
current `terms_version`; these are validated before the provider call and are
never sent to Supabase. The Terms feature and existing session encryption key
must be configured for registration.
`POST /api/v1/account/sign-up` connects these helpers without creating an
application session. Sign-up and email-confirmation interfaces are available only
in development; the complete flow has been manually validated locally with the
live provider, including email delivery and separate application sign-in.
`ACCOUNT_SIGN_UP_API_ENABLED` defaults to false. The route's total timeout setting,
`ACCOUNT_SIGN_UP_TIMEOUT_SECONDS`, defaults to 15 and accepts one to 30 seconds;
it does not change the adapter's independent five-second provider deadline.

Registration also uses the shared PostgreSQL abuse limiter. Configurable starting
defaults are 10 attempts per rolling 600 seconds, using
`ACCOUNT_SIGN_UP_IP_MAX_REQUESTS` (1–1,000) and
`ACCOUNT_SIGN_UP_IP_WINDOW_SECONDS` (60–86,400). The route requires a runtime
database migrated through `bcae4df0f56a` and the independent
`AUTH_RATE_LIMIT_HMAC_SECRET`, along with its provider resources. It checks Origin,
the feature flag and readiness before counting. A fixed sign-up HMAC namespace
(`askm6:auth-rate-limit:v1:sign_up:ip:`) and database purpose isolate its budget
from sign-in and recovery; emails and forwarding headers cannot select a budget.

Accounting commits before credential parsing or provider work under the existing
total deadline. A local cap returns no-store 429 with `Retry-After` and no provider
request or cookie. Limiter/key/database/deadline failures return generic 503.
Allowed attempts remain counted after invalid input, CAPTCHA rejection or provider
failure. Upstream provider rate limits retain the existing generic 503 mapping;
only local caps supply a retry time. Existing-account and new-account responses
retain the same generic 202 acknowledgement; registration creates no application
session. The development frontend displays validated retry seconds after a local
429, with a generic wait message when the header is unavailable or invalid.

Migration `bcae4df0f56a` broadens the purpose constraint to recovery/sign-in/sign-up,
without changing rows, indexes, ownership or grants. Downgrade validates the older
constraint first and refuses while sign-up records exist. Both guarded local
databases are upgraded with no drift or private configuration changes. Shared
cleanup and the local maintenance command include all three purposes within one
total batch cap; recovery-only helper APIs retain their original scope. Automatic
cleanup scheduling and production proxy trust remain pending. Google OAuth and
email confirmation are unaffected by this password-registration limiter.

Validation passed 954 selected backend cases, including 21 new PostgreSQL sign-up
HTTP cases, with provider HTTP mocked. Two further transactional migration probes
passed: downgrade refusal preserves sign-up data, and a safe round trip preserves
older rows, indexes and grants. All probe DDL/data is rolled back. Repository lint,
formatting (209 Python files), typing (201 app/test sources) and all eight migration
sources passed. Final checkpoint validation then passed all 3,763 backend tests,
including PostgreSQL integration tests, with lint, formatting and typing clean.
The combined backend/frontend diff and private-file exclusions were reviewed with
no blocking findings; configured secrets were absent from all 28 checkpoint files
and the existing frontend build.

The parser requires JSON containing only `email`, `password`, and `captcha_token`.
It limits actual streamed input to 16 KiB, masks all three fields with `SecretStr`,
and preserves password whitespace and Unicode. Email and password have resource
bounds of 1–320 and 1–1,024 characters; Supabase remains responsible for semantic
email validation and password policy. CAPTCHA input is required and accepts
1–2,048 printable ASCII characters without whitespace. Parsing does not verify
the proof; its caller must enforce the total request deadline.

The adapter submits those credentials once to the configured issuer's `/signup`
endpoint with the publishable key and `gotrue_meta_security.captcha_token`. It
uses a caller-owned HTTP client, disables redirects, and accepts only uncompressed
JSON responses of at most 64 KiB. The five-second deadline covers the provider
request and response streaming. It performs no automatic retries, and cancellation
propagates while the response stream is closed.

Accepted response shapes and recognized existing-account errors have the same
generic outcome. Provider user details are discarded; acceptance does not prove
that a new account was created or an email was delivered. Responses containing
session or access/refresh-token fields are rejected. Known input and CAPTCHA
errors remain distinct, controlled exceptions; rate limits, outages, unknown
errors, and malformed responses produce generic unavailability without provider
messages. The adapter does not create an application session, write application
database rows, or issue browser cookies.

The HTTP route requires an exact trusted Origin before reading credentials.
Its total deadline covers committed rate accounting, body parsing and the provider exchange. Accepted
outcomes return HTTP 202 with `status: "accepted"` and a generic message that
does not confirm account existence or email delivery. Invalid/rejected input
returns 400, oversized bodies 413, and unsupported media types 415. Provider
CAPTCHA rejection returns 403 with `X-Account-Verification: required`; an Origin
rejection has no verification marker. Disabled or incomplete configuration,
provider/limiter unavailability, and timeouts return 503. Local rate caps return
429 with `Retry-After`. These responses use no-store headers and do not set or
clear account or guest cookies. Registration requires the limiter's database
connection and HMAC key, but no session-encryption key or JWT lookup.

Supabase email confirmation and CAPTCHA protection must be configured before
registration is enabled. The development interface uses one password field, an emailed
verification code, and then the existing sign-in flow. Manual local validation
on 2026-10-22 covered registration, email delivery, code confirmation, separate
sign-in, session restoration after refresh, sign-out, and signing in again. Offline tests
use synthetic credentials and mocked HTTP to cover parsing, configuration,
response classification, size limits, redirects, transport failures, deadlines,
cancellation, and stream cleanup; they send no registration emails. HTTP tests
exercise the registered route with mocked provider requests, including Origin
and feature gates, generic duplicate-account outcomes, credential forwarding,
cookie preservation, and cancellation of stalled body/provider work.

## Internal email-confirmation foundation

Email confirmation currently provides configuration, bounded JSON parsing,
provider-response interpretation, and the internal `confirm_email_code` adapter.
`POST /api/v1/account/confirm-email` connects these helpers without issuing an
application session or cookie. The frontend confirmation interface is available
only in development and requires a separate sign-in after confirmation.
The independent `ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED` flag defaults to false.
The route's total timeout setting, `ACCOUNT_EMAIL_CONFIRMATION_TIMEOUT_SECONDS`,
defaults to 15 seconds and accepts one to 30; the adapter has its own five-second deadline.

The parser requires only `email` and `code`, stored as masked `SecretStr` fields.
It accepts an email of 1–320 characters representable as UTF-8 and a string of
6–10 ASCII digits, preserving leading zeros. These code lengths are structural
bounds; Supabase checks the actual issued code and its expiry. Non-JSON input,
extra fields, malformed credentials, and actual streamed bodies over 4 KiB are
rejected with generic no-store errors. Parsing does not verify a code, and its
caller must bound the complete request duration.

`confirm_email_code` posts the email and unchanged code once to the configured
issuer's `/verify` endpoint with the publishable key and a fixed `type: "signup"`.
Callers cannot select recovery or other verification types through this helper.
It uses a caller-owned HTTP client, disables redirects, accepts only uncompressed
JSON responses up to 64 KiB, and bounds the provider request and response streaming
to five seconds. There are no automatic retries. Caller cancellation propagates,
and response streams close on completion, failure, timeout, or cancellation.

An accepted response requires a user UUID and a timezone-aware
`email_confirmed_at` timestamp. Known invalid/expired-code, input-validation, and
banned-user responses produce the same controlled rejection. Unknown or conflicting
error codes, rate limits, provider outages, and malformed responses remain generic
unavailability. Provider error messages are not exposed. This response validation
does not authenticate an application identity or verify a JWT.

Supabase may create a provider session during verification. Returned provider
identity and credentials are discarded; this helper does not revoke that provider
session, write application database rows, or issue a browser cookie. The planned
flow requires a separate application sign-in after confirmation. A timeout or
unusable response does not undo provider-side confirmation or code consumption.

The HTTP endpoint requires an exact trusted Origin before reading credentials,
then checks its feature flag, provider configuration, runtime database and HMAC secret.
It commits a separate IP attempt before parsing or provider work, using the fixed
`askm6:auth-rate-limit:v1:email_confirmation:ip:` namespace and database purpose
`email_confirmation`. The configurable starting policy is 10 attempts per rolling
600 seconds: `ACCOUNT_EMAIL_CONFIRMATION_IP_MAX_REQUESTS` accepts 1–1,000 and
`ACCOUNT_EMAIL_CONFIRMATION_IP_WINDOW_SECONDS` accepts 60–86,400. Existing recovery,
sign-in and sign-up fingerprints and budgets remain independent.
Its total deadline covers accounting, body reading and provider work.
Successful responses contain only
`{"status":"confirmed","message":"Email confirmed. You can now sign in."}`.
Invalid input and known provider rejections return 400, an untrusted Origin 403,
an oversized body 413, and an unsupported media type 415. Disabled/incomplete
configuration, limiter/key failure, provider unavailability, and timeouts return a generic 503.
A local cap returns 429 with rounded-up `Retry-After` seconds before parsing or
provider work; denied requests do not extend the block. Invalid input and provider
failures remain counted after an allowed attempt commits. Upstream 429 responses
remain generic 503 without inventing a retry time. These
responses use `Cache-Control: no-store` and never set or clear guest/account cookies.
Confirmation requires a migrated runtime database and fingerprint secret, but no
session-encryption key or signing-key lookup. It does not automatically retry a code submission.

Migration `6ef221a79f00` follows `bcae4df0f56a` and broadens only the limiter purpose
CHECK to include email confirmation. It preserves records, keys, indexes and grants.
Downgrade validates the earlier three-purpose constraint first and refuses while
confirmation records exist. Both guarded local databases were upgraded with no
schema drift; private configuration files were unchanged. Shared cleanup now
includes every supported purpose under one total batch bound, retaining recovery-only APIs.
Optional limiter cleanup scheduling is implemented; public proxy trust remains pending.
The development confirmation UI displays validated retry seconds on local 429 responses,
with safe fallback text when the header is unavailable or invalid. Codes clear on
submission and retries remain manual; rate limiting never advances to sign-in.

Validation passed all 3,943 backend tests, including 21 PostgreSQL confirmation HTTP
cases and four rollback-only migration probes for the sign-up/confirmation extensions.
Coverage includes concurrent caps, exact retry/expiry, failed accounting commits,
bounded lock waits, namespace independence and shared cleanup limits. Backend lint,
formatting (211 files), typing (202 app/test sources) and nine migration files passed.
No live provider calls were needed; frontend code was unchanged in this checkpoint.

Offline tests use synthetic credentials, in-memory parser endpoints, and mocked
provider HTTP. They cover feature defaults, timeout bounds, input masking and size
limits, response classification, exact request forwarding, redirects, transport
errors, cumulative response bounds, stalled requests/streams, cancellation, and
cleanup. Separate manual local checks validated live email delivery and confirmation.
Route tests use the real adapter with mocked provider HTTP to cover successful
confirmation, exact credential forwarding, unchanged cookie headers, and
Origin/feature/resource gates. They also check malformed input, rejected
verification types, provider rejection/outage handling without retries, malformed
success responses, unsupported methods, and cancellation of stalled accounting/body/provider
work at the total deadline.
Keep public registration and confirmation disabled until their complete flows,
abuse controls, email configuration, and deployment behavior have been validated.

## Provider sign-in adapter

The internal `sign_in_with_password` adapter exchanges email/password credentials
once at the configured Auth issuer's `/token?grant_type=password` endpoint, using
the configured publishable key and a caller-owned HTTP client. Requests have a
five-second total deadline, do not follow redirects, and make no automatic retry.
Only uncompressed JSON responses up to 64 KiB are accepted.

Email and password inputs use `SecretStr`, must be representable as UTF-8, and
are limited to 1–320 and 1–1,024 characters respectively. Input values, including
password whitespace and Unicode, are sent unchanged. These are resource bounds;
the adapter does not validate complete email syntax or define password-strength
policy. Returned access and refresh tokens must be nonempty printable ASCII,
at most 8,192 characters each, with a bearer token type. `SignedInAccountTokens`
keeps both values masked in its ordinary representation.

An optional masked `captcha_token` accepts 1–2,048 printable ASCII characters
without whitespace. When supplied, it is sent unchanged in
`gotrue_meta_security.captcha_token` in the same password-exchange request. When
omitted, the internal adapter preserves its existing email/password-only body;
the HTTP route independently requires a proof. The adapter does not verify the
proof itself or store it in an application session.

Recognized invalid-credential, unconfirmed-email, banned-user, and input-validation
responses produce the same generic `AccountSignInRejected` error. An explicit
`captcha_failed` code produces `AccountSignInCaptchaRejected`, a distinct subclass.
Both legacy `error_code` and newer string `code` responses are supported; a
numeric legacy HTTP `code` is not treated as an error identifier. Conflicting
string codes and malformed or unknown codes remain unavailable. Classification
does not search provider messages for keywords.

Missing configuration, unknown provider errors, rate limits, server/transport
failures, timeouts, and malformed responses produce `AccountSignInUnavailable`.
In particular, a 429 or server-error response remains unavailable even if its
body contains `captcha_failed`. Provider messages are not included in these
errors. Responses close on success, failure, and caller cancellation;
cancellation propagates to the caller.

The adapter does not persist passwords, verify JWT identity, create database
sessions, or issue browser cookies. The returned pair must still pass the existing
JWT-verification/session-creation flow before establishing an application session.
The HTTP sign-in route described below connects that flow but is disabled by
default. Additional abuse controls and production authentication deployment
remain outstanding. The recovery/reset endpoints, development forms and Google
sign-in flow are described below.

Offline tests use synthetic credentials and mocked HTTP. They cover request
headers/body, credential preservation, missing configuration, input guards,
provider error classification, malformed/missing response fields, token and
response-size boundaries, response cleanup, transport failures, total deadlines,
and cancellation. CAPTCHA cases cover exact metadata forwarding, input bounds,
legacy/current error formats, generic rejection, conflicting codes, and absence
of retries. They require no live Supabase requests or database access.

## Internal sign-in service

`sign_in_account` checks that the Auth issuer, publishable key, session encryption
key, and signing-key cache are configured before sending credentials. It performs
the provider password exchange, forwarding any supplied masked CAPTCHA proof
unchanged, before opening a database transaction. CAPTCHA rejection propagates
without opening a transaction. The service then passes the token pair directly
to `create_account_session`. That existing helper verifies the access JWT,
creates or reuses the verified account profile, encrypts provider
credentials, and stores a hash of the new random browser token. Signing-key
retrieval may still occur during JWT verification inside the transaction.

The service returns `CreatedAccountSession` only after the outer transaction has
committed and the connection has been released. Provider rejection, verification
failures, duplicate sessions, database errors, and cancellation propagate without
automatic retries. No browser credential is returned when session creation or
commit fails. The service does not issue cookies, enable routes, or change the
existing account-session check endpoint.

A database rollback cannot undo a successful provider sign-in. Provider-session
cleanup and recovery from an uncertain database commit are not implemented here;
callers must not assume that failure means the provider created no session.
The provider adapter's deadline does not bound the entire service operation.
The HTTP sign-in route adds an outer deadline; public enablement still requires
abuse controls and deployment checks.

Unit tests cover configuration preflight, operation ordering, exact token-pair
forwarding, rejection, verification/persistence failures, cancellation, and commit
failure. Two opt-in local PostgreSQL cases use generated ES256 credentials and
mocked provider/JWKS responses to exercise the actual verification and storage
flow. They confirm committed encrypted credentials and hashed browser tokens, or
rollback of both newly inserted profile and session rows after a deliberate SQL
error before commit completes. Additional uncertainty coverage is described below;
all provider requests are mocked.

### Provider success and local failure

Email and Google session services emit a fixed warning when completion fails after
receiving provider credentials. The only variable is one of four internal stages:
`verify_provider_session`, `open_local_transaction`, `persist_local_session`, or
`commit_or_release`. Exception text/tracebacks, email addresses, tokens and user/session
identifiers are excluded. The original exception or cancellation still propagates;
logging never converts an incomplete operation into a login success.

The existing fail-closed contract is retained: no browser credential returns until
commit and release finish, and HTTP handlers issue no replacement account cookie
after an unavailable result. A commit acknowledgement can be lost after the data
has committed. Retrying the same provider-session ID cannot overwrite its stored
browser-token hash; a new provider login can establish a separate local session.
The bounded local expiry cleanup can remove an unreachable local session later.

A local rollback does not revoke a Supabase session. This slice deliberately
preserves the current no-automatic-compensation behavior: an uncertain commit or
duplicate binding is insufficient evidence that a provider session is unused.
Blind logout could invalidate an existing binding. Provider-side orphan sessions
may remain; cleanup of local rows does not revoke them. Any future compensating
logout needs verified credential/session ownership, concurrency coordination and
a bounded failure policy. Supabase's [local logout scope](https://supabase.com/docs/guides/auth/signout)
targets one provider session, while access JWTs can remain valid until expiry.
No automatic provider revocation or guaranteed cross-system atomicity is claimed.

Application identity remains the cryptographically verified Supabase `sub`, never
an email address or `user_metadata.user_id`. Supabase manages
[identity linking](https://supabase.com/docs/guides/auth/auth-identity-linking);
when it returns the same subject for email/Google, one application profile is reused.
Different subjects remain separate even with identical email metadata. The app
adds no manual linking or automatic guest-data transfer. Supabase's
[JWT claims reference](https://supabase.com/docs/guides/auth/jwt-fields)
defines `aal1` for both password and OAuth and `amr.method=oauth` for OAuth generally;
these values do not independently prove a specific upstream Google method.
An additional read-only hosted-provider check confirmed an active verified subject
with both email and Google identities linked. This is evidence for that account,
not every provider/linking scenario or proof of a specific upstream method.
Broader hosted linking and method assurance still need release validation.

Password sign-in now matches the Google start/callback rule: presence of the
configured account cookie, including an empty or malformed value, blocks a new
login. Password sign-in returns `409` with `Cache-Control: no-store` before body
parsing, IP accounting or provider requests, and does not issue/clear cookies.
The frontend maps this status to a fixed sign-out instruction without reading the
error body or automatically retrying. An explicit successful application sign-out
allows another login; a failed sign-out preserves the old cookie and keeps the
guard in force. The normal session check can clear an invalid/expired cookie.
Guest cookies and identities remain independent. This guard protects requests
that carry an account cookie; it does not serialize separate tabs or simultaneous
requests that were sent before either browser received a cookie.

This is an application-session switching rule, not manual provider identity
linking or proof of Google's upstream authentication method.

Six new PostgreSQL cases use generated ES256 credentials, actual commit/release
and mocked provider replies. They inject an error or cancellation after a real
commit, confirm the row exists despite no returned credential, preserve it across
a duplicate retry through the other login service, and allow a fresh session.
They also verify same-subject reuse and distinct-subject isolation across both
flows. This simulates post-commit failure; it does not reproduce a physical
network partition. Sixteen new offline cases cover stage-only diagnostics and
unchanged exceptions/cancellation at verification, acquisition, persistence and commit.

Validation passed 981 selected backend authentication tests, including guarded
PostgreSQL coverage, plus all 333 frontend API and 356 UI/hook tests. Ruff, all
230 Python files' formatting, 218 application/test sources and 12 migration
sources passed checks, as did frontend lint, TypeScript and the production build.
Private-file/secret checks and all 68 local documentation links passed. Automated
provider requests were mocked; the separate read-only hosted-provider check is
described above. No provider settings, schema or revocation behavior changed.

## Account sign-in endpoint

`POST /api/v1/account/sign-in` connects bounded credential parsing to the internal
sign-in service. It creates an application session and issues its opaque browser
cookie only after successful database commit. `ACCOUNT_SIGN_IN_API_ENABLED`
defaults to `false` and is independent of `ACCOUNT_SESSION_API_ENABLED`. Keep
public sign-in disabled until Supabase CAPTCHA enforcement, additional abuse controls,
and deployment checks are ready.
The development frontend calls this route through Vite's same-origin proxy. The
Pages password sign-in and account-session checks use independent default-off
proxies; production frontend account controls default to disabled and require
the explicit build-time opt-in described below.

```dotenv
ACCOUNT_SIGN_IN_API_ENABLED=false
ACCOUNT_SIGN_IN_TIMEOUT_SECONDS=15
```

The route requires exactly one trusted Origin before reading credentials. The
feature flag and required engine, HTTP client, and signing-key cache are also
checked before body parsing. Enabled requests require `application/json` and a
JSON object containing `email`, `password`, and `captcha_token`, with no extra
fields. Credentials use `SecretStr`, retain their exact values, and must be
representable as UTF-8. Email length is 1–320 characters; password length is
1–1,024 characters. A supplied proof is masked and must contain 1–2,048 printable
ASCII characters without whitespace. The parser represents omitted/null proofs
as `None` so the route can return a verification-specific 403 before calling the
sign-in service. The parser enforces a 16 KiB body limit against received bytes,
including when `Content-Length` is missing or inaccurate. These are structural
and resource checks rather than full email-syntax or password-strength policy.

Enable CAPTCHA protection in the Supabase project's Authentication settings,
select Turnstile, and configure the secret matching the frontend widget's site
key. This is a project-wide Auth setting and also affects relevant signup and
password-reset flows. The Supabase publishable key is separate from both
Turnstile keys. The application's `TURNSTILE_SECRET_KEY` configures guest
Siteverify requests; it does not enable CAPTCHA protection in Supabase.

The account route checks proof presence, while Supabase verifies authenticity
during the password exchange. Presence alone does not prove successful human
verification. Do not first redeem an account proof through the guest verifier:
Turnstile proofs are single-use. Obtain a fresh proof after any attempted sign-in,
including credential rejection or an uncertain provider result. See Supabase's
[CAPTCHA setup](https://supabase.com/docs/guides/auth/auth-captcha).

The configurable total deadline defaults to 15 seconds, accepts 1–30 seconds,
and covers rate-limit accounting, body reading, provider exchange, JWT verification, and database
completion. The provider adapter retains its own five-second deadline. Successful
responses contain only `user_id`, `expires_at`, and `absolute_expires_at`.
The browser token is sent only in the account cookie; provider tokens and submitted
credentials are not returned in JSON. The cookie follows `ACCOUNT_COOKIE_SECURE`,
uses `HttpOnly`, `SameSite=Lax`, `Path=/`, no Domain attribute, and the committed
idle deadline. Responses use `Cache-Control: no-store`.

| Condition | HTTP status |
| --- | --- |
| Invalid JSON, missing email/password, extra fields, or invalid supplied values | 400 |
| Recognized provider credential rejection | 401 |
| Missing, duplicate, null, or untrusted Origin | 403 |
| Omitted/null CAPTCHA proof, or explicit provider CAPTCHA rejection | 403 with `X-Account-Verification: required` |
| Account cookie present; explicit sign-out required | 409 |
| Body over 16 KiB | 413 |
| Missing or unsupported content type | 415 |
| Application sign-in limit reached | 429 with `Retry-After` |
| Disabled/unconfigured route, provider/verification/database failure, duplicate provider session, or timeout | 503 |

Input errors use generic messages instead of Pydantic validation details that
could expose submitted credentials. Rejections do not reveal provider error
messages or send a Bearer authentication challenge. Controlled failures do not
set or clear an existing account cookie, and sign-in is not automatically retried.
Only missing/rejected CAPTCHA verification sets `X-Account-Verification: required`;
Origin failures, ordinary credential rejection, and unavailable services do not.
Sessions in other browsers/devices are not revoked when a new sign-in succeeds.
Database rollback cannot undo provider-side sign-in, and uncertain commit outcomes
remain unresolved as described above.

Offline parser and route tests cover credential preservation and masking, invalid
documents and fields, extra-field rejection, body boundaries, unpaired Unicode
surrogates, Origin/feature/resource guards, cookie policy, generic failures, and
actual deadline cancellation during body reading and service execution. They
also cover proof forwarding, missing-proof guards, and distinct CAPTCHA response
headers without changing cookies. Two opt-in PostgreSQL HTTP cases exercise
actual verification and storage using
generated ES256 credentials and mocked provider/JWKS responses. They verify that
the returned cookie matches the committed token hash, or that a deliberate SQL
error before commit leaves neither new profile nor session visible and issues no
cookie, while asserting that the proof reaches the provider exchange unchanged.
Automated tests require no live Supabase requests. Separate manual local validation
confirmed a successful CAPTCHA-protected sign-in against Supabase Auth, account-cookie
storage, credential rejection with HTTP 401, and HTTP 200 from the cookie-authenticated
session endpoint after restarting the backend. This is local integration evidence;
production account access is not enabled or validated by these checks.

## Development sign-in interface

The landing page opens sign-in in a native modal dialog outside the hero grid.
The navy/teal design is retained, with a dimmed backdrop, email focus on opening,
focus guards around the verification iframe, Escape/Close dismissal, body scroll
restoration, and focus returned to the trigger on dismissal. Successful sign-in
closes the dialog and focuses the signed-in status message, since the original
trigger is then disabled. The dialog does not increase the hero's layout height.
Turnstile uses its rectangular `flexible` size with a 65px
height and 300px minimum width; narrow layouts accommodate that minimum.

The form uses labeled email/password inputs with password-manager autocomplete,
an optional password visibility toggle, and native required/email validation.
It sends only email, the exact password, and a CAPTCHA proof to the same-origin
API, with redirects rejected and cookies included. It clears the password field
and consumes the proof when submitting. Every failed submission requires a fresh
proof; callbacks from an earlier widget cannot authorize a later attempt.
Credentials and proofs are not saved in browser storage or logs.

The controller allows one pending request, has a 15-second browser deadline,
discards results after unmount, and exposes controlled error messages. Neither
credential rejection nor transport/provider failure triggers automatic retries.
Closing the dialog cancels the browser request; cancellation does not guarantee
that a provider exchange or database commit was undone, and it is not sign-out.

HTTP 429 becomes a dedicated sign-in rate-limit error. Only decimal `Retry-After`
seconds from 1 through 86,400 are accepted, matching the backend's maximum window;
missing, malformed, oversized or unsupported date values use a generic wait
message. Other statuses ignore this header. The existing status region announces
the wait time without exposing or parsing the error body. This is the wait quoted
at the failed attempt, not a live countdown or a browser-enforced lock. It schedules
no retry and saves no credentials; a manual retry still requires a re-entered
password and fresh proof, and the backend decides whether the limit has expired.
Google access, registration and password recovery retain their existing behavior.
The retry-feedback checkpoint passed 60 account API cases and 34 focused hook/form
cases, then all 514 frontend tests (218 API and 296 UI/hook), lint, TypeScript and
production build. Tests cover header bounds/fallbacks, status isolation, safe
messages, no automatic retry, password clearing, proof renewal and Google access
regressions. No live sign-in attempts were made for these tests.

For local HTTP testing only, enable the required backend endpoints in the ignored
`backend/.env`, retain a configured session encryption key, and use
`ACCOUNT_COOKIE_SECURE=false`. The sign-in flag and session-check flag are
independent. Restart FastAPI after environment changes. Keep public examples and
production defaults disabled until the remaining release checks are complete.

API tests mock fetch and cover request allowlists, metadata-only responses,
controlled failures, malformed responses, and cancellation. Controller/form tests
cover duplicate submissions, deadlines, cleanup, proof expiration, fresh retries,
password clearing, and default-disabled production availability. App tests cover opening and
closing, native cancel handling, focus restoration/guards, and pending-request
cancellation. Integration tests use the real account hooks and API helpers with
mocked network responses to cover successful sign-in updating the landing page
without another session request, controlled failure, and ignored late results.
jsdom's native dialog methods and layout are stubbed in those tests;
they do not replace browser checks of native modal behavior or the real widget.

On page load, the health check allows up to 75 seconds for backend startup,
shows a waiting message and offers manual retry on failure. It bypasses browser
caching, rejects redirects and ignores late success after cancellation or timeout.
In development, only after health succeeds does the page check
`POST /api/v1/account/session`, with its own full 15-second deadline and cleanup
on unmount. Guest access and sign-in stay disabled during both stages. Health
failure sends no session or guest requests. HTTP 401 enables signed-out access; an unavailable service
or invalid response keeps guest access blocked and offers an explicit retry.
There is no automatic polling. A successful sign-in supplies validated session
metadata directly to the page's account state without another session request.
Account-session metadata is held in React memory; the opaque session credential
remains in an HttpOnly cookie and provider tokens stay on the backend. Session
restoration and sign-in remain disabled outside development.

The frontend entry point renders a standalone Privacy Notice for `/privacy` and
`/privacy/` (including query/fragment navigation). It does not mount the App or
start health/authentication requests on that page. Other paths retain the existing
landing behavior; no routing dependency was added. The notice uses the existing
visual tokens, a skip link, semantic headings, a return-home link and the approved
public contact address. Footer navigation stays in the same tab; registration
links explicitly open a new tab with `noopener noreferrer` to keep
in-progress credentials in the original form. They neither submit the form nor
record consent. The copy describes current development status and approved
retention choices. The development-stage notice does not establish legal
clearance or manual-process readiness for activation of hosted authentication;
those release checks remain separate.

Development-stage Terms are prepared at `/terms` and `/terms/`, with reciprocal
Privacy Notice navigation and links in the landing footer and account-creation form.
Registration places both policy links below verification, above the submit button;
the sign-in form contains neither policy link.
The Terms page also renders without mounting App or sending backend requests.
Form links open a labelled new tab with `noopener noreferrer`, preserving form
entries. The content covers current availability, responsible use, account
security, privacy/contact and unofficial status. The Terms page itself records
no agreement and adds no liability cap, governing-law clause or public auth activation.
Content review/publication and Google branding verification remain separate steps.

The additive migration `b4d7e2806a12` introduces `app.account_terms_acceptances`:
composite account/revision primary key, database-generated `accepted_at`, and a
profile foreign key with `ON DELETE CASCADE`. It backfills no agreement for
existing accounts. Runtime privileges are SELECT/INSERT only; duplicates preserve
the original timestamp, including concurrent submissions. A populated table
prevents downgrade rather than silently discarding acceptance records.

`POST /api/v1/account/terms/accept` is independently disabled by default through
`ACCOUNT_TERMS_API_ENABLED=false`. It requires a trusted Origin, opaque account
cookie and live session verification. The 1 KiB JSON body accepts only literal
boolean `accepted: true` and the exact current `terms_version` (`2026-10-28`);
client account IDs, timestamps, privacy-consent fields and query options are
rejected. Parsing, verification and commit share the existing account-session
deadline. The response contains only revision and acceptance time, renews the
cookie after commit and uses no-store; failures cannot report successful
acceptance. Invalid sessions clear the account cookie, while temporary failures
preserve it. Provider metadata is never treated as agreement.

`POST /api/v1/account/terms/status` accepts an empty, trusted-Origin POST with the
same verified account cookie. It shares `ACCOUNT_TERMS_API_ENABLED` and the total
session-authentication deadline. The response contains the server-controlled
`terms_version`, nullable `accepted_at`, and derived `acceptance_required`.
Missing/old revisions require acceptance; another account's record never counts.
The status transaction performs live authentication and a subject-scoped lookup,
commits before returning/renewing the cookie, and creates no acceptance record.
Bodies and query options are rejected before authentication. Invalid sessions
clear the cookie; unavailable storage/provider/commit results remain generic 503.
The existing three-field `/account/session` and sign-in response contracts stay
unchanged, preserving their strict proxy validators.

`TermsAccountDependency` is the reusable resource gate. It requires enabled Terms
support, cookie authentication and current acceptance before yielding a verified
subject and its active transaction connection. Account resource handlers must
use that connection and still enforce per-resource ownership. Missing agreement
returns 428 with `X-Account-Setup: terms-required`, without clearing a valid cookie.
Disabled/unavailable support never bypasses the gate. Mutation requests require
a trusted Origin. Its function-scoped FastAPI dependency commits before sending
HTTP success, rolls back consumer failures/cancellation and cannot release a
successful response after a failed commit. Work must finish before the handler
returns; the connection cannot be used by later streaming/background work.
No synthetic resource endpoint is added to the application; tests register a
temporary protected probe only. Account resources will use this dependency when
implemented. Status, acceptance, identity bootstrap and sign-out intentionally
remain outside the Terms prerequisite.

Development account UI mounts setup only after successful session restoration
or email sign-in, including a verified Google return. `useAccountSetup` reads
the separate status endpoint; missing/unavailable status never marks setup ready.
First use opens `AccountSetupFlow` in a native modal styled like sign-in, with
an initially unchecked Terms checkbox, separate policy links in safe new tabs,
and explicit submission. Returning accepted accounts skip the modal. Escape or
Close dismisses without agreement and leaves a reopen action; sign-out is still
available. Authentication and setup remain distinct states; future account
resources must use the server access dependency as well as ownership checks.

Status and acceptance requests have 15-second client deadlines, cancellation on
session change/unmount, duplicate-submit protection and stale-response guards.
Timeout or unconfirmed acceptance stays blocked and offers manual retry; there
are no automatic retries or localStorage agreement records. A verified 401
offers a return to sign-in. Shared frontend/proxy validation pins revision
`2026-10-28`, exact fields, consistent required/accepted state and UTC timestamps;
changing the Terms requires coordinated revision updates, never relabeling old
acceptance records. The Privacy Notice now describes the agreement record and
its removal with the application profile, separately from privacy consent.

Pages forwards only `/account/terms/status` and `/account/terms/accept`, behind
the independent default-off `ACCOUNT_TERMS_PROXY_ENABLED=true` gate. Origin,
exact method/path and edge assertion rules are shared with the other proxies.
Status requires an empty body; acceptance allows only the current revision and
literal `accepted: true` in at most 1 KiB of JSON. Requests and metadata responses
are bounded, redirects rejected, errors rebuilt, and unrelated cookies/headers
stripped. Secure account-cookie renewal must preserve the original token, valid
scope and future expiry; this endpoint's JSON has no expiry metadata to compare.
Bounded acceptance JSON may use chunked framing only when Content-Length is
absent; status remains empty-only and ambiguous framing is rejected.
Only a validated backend deletion cookie can clear a session on 401. A 20-second
proxy deadline and cancellation cover request reading, upstream and response
validation. Existing session/sign-in response formats remain unchanged.

Both setup endpoints and the resource dependency require `X-Account-Subject`
containing the account ID from the previously verified session response. This
is an account-match precondition, never identity or authorization authority.
The backend locks the cookie's existing session and rejects a mismatch with 409
before provider refresh, lookup or acceptance writes; live verification is still
required for a matching account. The same lock is retained throughout the
operation. This avoids recording a stale tab's agreement for an account selected
in another tab, or rotating that other account's provider credentials first.
Missing/malformed preconditions return 400; a changed account preserves its valid
cookie and offers a fresh session check. The proxy forwards only the validated
UUID-shaped precondition; the browser cannot choose the acceptance record owner.

The local website and test databases now have the Terms migration. A verified
private database snapshot preceded local website activation, and existing table
counts stayed unchanged. `ACCOUNT_TERMS_API_ENABLED=true` is set only in the
ignored local backend environment; the development reloader loaded it. FastAPI
and Vite readiness/unauthenticated rejection checks passed, with zero acceptance
records before human testing. Archive decoding was checked; no restore rehearsal
was performed. Manual email/Google interaction and visual review remain pending.
Hosted database/provider settings, public authentication and Google branding
publication are unchanged. Real agreement must be submitted by the user.
Terms agreement is distinct from consent to personal-data processing. Only the
local website and test databases have received this migration, with unchanged
pre-existing table counts and no model drift; the hosted target is unchanged.

A guarded local PostgreSQL rehearsal exercises manual provider-first deletion
steps using synthetic records and mocked provider outcomes. It checks committed
removal of one profile and all its sessions (including expired sessions), exact
preservation of another account plus guest/OAuth/limiter records, provider failure,
local rollback and deliberate local repair, absent-profile no-op, and read-back
of simulated unknown commit outcomes. Each case cleans only its random fixture
IDs and verifies their absence after cleanup. A separate counterexample calls
the existing session-creation helper with a mocked previously verified identity:
it can recreate a profile inside a later transaction unless auth writes have
been paused and drained. That hypothetical late write is rolled back. This
supports the manual maintenance requirement; no new deletion endpoint, per-account
deletion lock or provider administration service is implemented. Mocked provider
and acknowledgement outcomes are not live-provider or network-fault tests.

The frontend sign-out API helper sends a cookie-authenticated POST without a body
and accepts only HTTP 204 as confirmed success. It preserves cancellation, masks
server/transport details, and does not retry automatically; its tests use mocked
network responses. In development, a Sign out button appears for a restored or
newly signed-in account. Its controller allows one request at a time, uses a
15-second deadline, and cancels pending work on unmount. Account state and blocked
guest access are retained while sign-out is pending or fails; failures offer a
manual retry. Confirmed success clears account metadata and returns keyboard
focus to Sign In. Guest access can then be started explicitly. App tests cover
pending, success, failure/retry, timeout, cancellation, and repeat sign-in/sign-out
cycles using mocked network responses. Separate local browser checks confirmed
successful sign-in, automatic dialog dismissal, account restoration after a page
refresh, and successful sign-out. These checks validate the local development
flow; they do not validate hosted account access.

### Production email account controls

`VITE_ACCOUNT_AUTH_ENABLED` defaults to `false`. Only the exact string `true`
enables production email sign-in, session restoration and sign-out through the
shared `isAccountAuthEnabled` policy. Development retains its existing behavior
regardless of this flag. Signed-in accounts also use the existing Terms status
and explicit acceptance flow; ordinary sign-in does not imply acceptance.

The switch controls browser availability, not backend authorization. Enable the
matching backend and Pages proxy routes, Terms endpoints and a valid public
Turnstile site key separately. Rebuild after changing this public variable; to
close the browser controls, rebuild with it unset or `false`. Recovery navigation
requires its own production switch described below; guest access has its independent switch described earlier. Production
Google access also requires `VITE_GOOGLE_OAUTH_ENABLED=true` and a valid public
`VITE_SUPABASE_AUTH_ISSUER`; the account flag alone does not enable it.
No provider secrets belong in `VITE_` variables.

Production regression tests cover absent/invalid flags without account or widget
requests, successful email sign-in, unchecked Terms acceptance, restoration after
remount, sign-out, safe sign-in rejection and manual retry after sign-out failure.
All 475 UI/hook tests and 86 registration API tests passed; earlier Google API
validation passed 53 tests. Isolated Edge checks exercised default-off, email-only,
Google and registration compiled production variants. The registration fixture
requires unchecked-by-default Terms consent and a verification proof, preserves
leading zeros in the code, stays signed out after confirmation and waits for a
separate sign-in. Backend agreement results are mocked; receipt cryptography and
live registration/email delivery are not tested by this fixture.
The Google fixture validates the redirect, simulates return to the
application, verifies the session through the mocked backend and requires explicit
Terms acceptance when missing. Page reload and sign-out also work in the fixture.
APIs, providers and Turnstile are mocked and external network is blocked; these
tests do not establish successful hosted provider authentication, live cookie
behavior or public-release readiness.

Production email registration and code confirmation require the additional
`VITE_ACCOUNT_REGISTRATION_ENABLED=true` build flag. The shared
`isAccountRegistrationEnabled` policy requires the account flag too; development
preserves its existing behavior. One flag keeps both steps available together.
It exposes Create account navigation without opening password recovery. Backend
and Pages sign-up/confirmation gates, Terms endpoints and CAPTCHA/email settings
must be configured separately. Rebuild with the registration flag unset or
`false` to close these browser controls while keeping sign-in available.
Confirmation does not create an app session: users continue to a separate sign-in,
which relies on backend receipt verification before reporting Terms acceptance.

Production password recovery and code-based reset share the default-off
`VITE_ACCOUNT_RECOVERY_ENABLED=true` build flag. The shared
`isAccountRecoveryEnabled` policy also requires the account flag; development
remains available even when both public flags are false. It gates Forgot password
navigation and both hooks, without depending on registration or Google flags.
Opening a form or using an existing recovery code does not send an email.
Recovery requires a fresh Turnstile proof; reset preserves leading code zeros,
clears the code/password fields on submission and requires separate sign-in.
Backend `ACCOUNT_PASSWORD_RECOVERY_API_ENABLED` and
`ACCOUNT_PASSWORD_RESET_API_ENABLED`, Pages `ACCOUNT_PASSWORD_RECOVERY_PROXY_ENABLED`
and `ACCOUNT_PASSWORD_RESET_PROXY_ENABLED`, the recovery code email template and
provider CAPTCHA configuration remain separate deployment prerequisites.
Changing the public flag requires a rebuild; unset it or use `false` and rebuild
to close the browser flow while keeping account sign-in available. Automated
production-flow tests mock provider/email transport; hosted recovery/reset still
requires a controlled deployment and a human-owned account test.
The checkpoint passed all 500 UI/hook tests (including 67 focused recovery tests),
lint, strict TypeScript and four production builds. Three isolated compiled-browser
variants verified recovery closed/open and account access off; the open variant
covered recovery, reset, separate sign-in, refresh and sign-out with external
network blocked and APIs/verification mocked.

The Google option appears in both development sign-in and create-account views
when explicitly configured. Production sign-in requires both the account and Google
flags plus the valid public issuer. Google return hints are handled through the existing
backend session check. Local and hosted Google sign-in have been manually confirmed,
including new-account setup, refresh, sign-out and returning login. Local password recovery has
also been manually validated through email delivery, reset and separate sign-in.
Chat remains in development.

## Backend password-recovery requests

Recovery IP-limit settings configure the application-side limiter:
`ACCOUNT_PASSWORD_RECOVERY_IP_MAX_REQUESTS` defaults to 10 (range 1–1,000), and
`ACCOUNT_PASSWORD_RECOVERY_IP_WINDOW_SECONDS` defaults to 600 (range 60–86,400).
These are configurable starting values for an exact rolling window. Settings
validation alone does not enforce limits. The recovery route now uses the limiter;
production proxy trust remains pending. Optional scheduling invokes the bounded,
tested expired-row cleanup helper described below.

`AUTH_RATE_LIMIT_HMAC_SECRET` is an optional backend-only `SecretStr` setting
for the IP-fingerprint helpers; enabled recovery, sign-in, sign-up, confirmation,
password reset, new guest creation and Google initiation require it. It must contain exactly
64 ASCII hexadecimal characters encoding a separate 32-byte key; validation
checks format, not randomness. The example value is empty, and no real secret
is published. Local development uses a generated key in ignored configuration,
independent of the session encryption key. Setting this key does not enable an
endpoint or enforce a limit by itself.
Thirty-one focused tests cover accepted/rejected formats, environment loading
and precedence, masked representations/JSON, validation messages and independence
from session encryption. Together with the recovery configuration suite, 67 tests
passed without reading private environment files or contacting services.

The standalone `get_password_recovery_ip_key` helper uses HMAC-SHA256 with the
decoded secret and a versioned password-recovery/IP context. It returns 32 bytes
from the validated client address (ASGI peer by default), so equivalent IPv6
spellings and mapped IPv4 addresses share the same key. It reads no request body,
emits no logs, and performs no storage or network operations. Its resolver uses
only the authenticated assertion when trusted proxy mode is enabled. Missing
or malformed secret configuration fails with a generic error; unusable client
addresses retain the IP helper's controlled error. Changing the secret changes
the keys and therefore requires deliberate handling before active enforcement.

The standalone `get_sign_in_ip_key` helper shares the validated key/address
handling and uses the separate fixed context `askm6:auth-rate-limit:v1:sign_in:ip:`.
The same peer and secret therefore produce distinct sign-in and recovery
fingerprints. Recovery's context and existing fingerprints are preserved; request
paths and headers cannot select the context. Sign-in policy configuration defaults
to 30 requests per rolling 600 seconds, with count bounds 1–1,000 and window bounds
60–86,400 seconds, independently of recovery settings. The schema and counter are
implemented and locally verified, with route enforcement and bounded cleanup for
both purposes.
Setting the policy does not enable any endpoint.

Both helpers pass 73 focused cases covering fixed synthetic HMAC references,
normalization, operation/identity/secret separation, spoofed headers, invalid
configuration, and unchanged inputs/no output. Together with secret/sign-in
configuration, IP/proxy and recovery-route regressions, 241 tests passed; lint,
formatting and typing (198 source files) passed. Both routes use their respective
helpers before counting.
Production proxy trust is still required because Uvicorn can rewrite the ASGI
client first.

The shared authentication counting service uses a PostgreSQL
transaction and row lock per operation/fingerprint. It creates missing rows
without overwriting existing state, reads fresh database time after locking,
discards attempts at or before the rolling cutoff, and records an allowed
attempt. Denials leave stored state unchanged and return a retry deadline with
seconds rounded up; a lowered configured cap waits for enough entries to expire.
Each operation's commit wrapper returns its decision only after successful commit and releases
the connection before any future provider work. Database errors and cancellation
propagate without automatic retries; the caller must enforce a request deadline
and handle failures without allowing the request through.

An allowed limiter decision counts an authentication attempt even if the later
provider operation fails. This abuse budget is separate from future AI-message
quotas. All processes must use a consistent policy; increasing a window cannot
reconstruct already-pruned history, and secret rotation changes limiter keys.
Policy/key changes therefore need deliberate rollout handling. Existing
`count_password_recovery_attempt` and `commit_password_recovery_attempt` retain
their signatures and recovery-only purpose. The new `count_sign_in_attempt` and
`commit_sign_in_attempt` use a fixed sign-in purpose through the same private
counting implementation. Insertion, locking and update always include both
purpose and fingerprint, so the same binary key can have separate caps, windows
and locks. No public helper accepts a client-selected operation.

All three routes call their respective commit wrappers before parsing credentials or
contacting providers, within their existing request deadlines. Shared cleanup supports all three purposes.
Automatic inactive-row cleanup invocation remains outstanding for all three purposes.

Sign-in checks Origin, its feature flag and required runtime configuration before
accounting. A capped request returns no-store HTTP 429 with `Retry-After`, without
reading credentials, invoking providers or setting a session cookie. Fingerprint,
database and deadline failures return the existing generic 503. Malformed bodies,
CAPTCHA rejection and provider/session failures after accounting retain the attempt.
Upstream provider 429 responses retain the existing generic 503 mapping; only a
local limiter decision supplies a retry interval. Google OAuth uses separate entry
points and is unaffected by this email/password sign-in policy.

The route checkpoint passed 323 focused tests: configuration, fingerprints,
counters, recovery regressions, 41 offline sign-in route cases and 22 PostgreSQL
sign-in HTTP cases. These cover committed accounting before provider work,
concurrent caps, expiry, purpose separation, commit rollback, real lock deadlines
and successful session issuance. Provider HTTP is mocked. Repository lint,
changed-file formatting and typing of 199 source files passed; this was a focused
run, not a complete backend-suite run. Final checkpoint validation subsequently
passed all 3,581 backend tests, including PostgreSQL integration tests, repository
lint, formatting of all 206 Python files, typing of 199 app/test sources and all
seven migration sources. The final diff, documentation links and private-file
exclusions were reviewed; configured secrets were absent from the 23 checkpoint
files and existing frontend build. Frontend sources were unchanged.

The shared counter checkpoint passed 31 offline failure-boundary cases and 34
guarded PostgreSQL cases across both purposes. Tests cover exact expiry, retry
rounding, lowered caps, existing/new-row concurrency, transaction rollback,
cancellation and fresh time after a real lock wait. Additional same-fingerprint
cases verify different per-purpose caps/windows, independent row locks and
simultaneous enforcement of both caps. The combined configuration, fingerprint,
schema, counter, cleanup and recovery HTTP regression run passed 397 cases, with
3,046 tests deselected; lint, changed-file formatting and typing of 198 app/test
files passed. Only test-owned synthetic keys are removed after committed tests.

The standalone `delete_expired_password_recovery_limits` helper requires an active
caller transaction and returns a provisional deleted-row count. It selects only
expired password-recovery rows using PostgreSQL statement time, locks candidates
with `FOR UPDATE SKIP LOCKED`, and deletes at most one batch with `RETURNING`.
The default batch is 100, with validated bounds 1–1,000. Expiry order and then
fingerprint order make selection deterministic. Statement time avoids retaining
rows merely because a transaction began before they expired. Locked candidates
are skipped; active rows and counters remain intact. The caller must commit or
roll back, enforce a deadline and handle errors. A row bound is not a time bound:
scans or other database locks can still take time. No retries, scheduling, HTTP
route changes, retention guarantee or website database/configuration changes were
introduced by this helper.

The `commit_expired_password_recovery_cleanup` wrapper validates batch size and
a caller-supplied timeout greater than zero and at most 30 seconds, including
fractional seconds. It rejects booleans, nonnumeric and nonfinite values before
acquiring a connection. An asyncio deadline surrounds engine acquisition,
deletion, commit and connection release. The deleted count returns only after
successful transaction exit. Database errors, timeouts and external cancellation
propagate without automatic retries. Cancellation is cooperative: unwinding may
take longer than the nominal deadline, and an interruption during commit cannot
establish that no changes committed. The local command below is an explicit caller;
the optional application scheduler is described next.

The `delete_expired_auth_rate_limits` and
`commit_expired_auth_rate_limit_cleanup` helpers use the same validation,
transaction, deadline and failure behavior for a shared batch across recovery,
sign-in, sign-up, confirmation, password reset, guest creation and Google initiation.
The existing recovery-only APIs retain their signatures and scope. Shared
selection is ordered by expiry, fingerprint and purpose, with one total batch
limit across all supported purposes. Deletion matches both key columns and rechecks expiry,
so an expired record cannot delete an active record under another purpose with
the same fingerprint. Duplicate fingerprints under different purposes count as
separate deleted records.

The shared cleanup/maintenance checkpoint passed 80 offline cleanup contract
cases and 90 PostgreSQL cleanup/maintenance cases across recovery-only,
shared-recovery and shared-sign-in fixtures. It covers mixed-purpose batch caps,
deterministic ties, independent records, skipped locks, disjoint cleaners,
counter overlap, rollback, cancellation and deadline failures. The combined
cleanup, maintenance, counter and recovery-route regression run passed 367 tests
(3,181 deselected); lint, changed-file formatting and typing of 198 app/test files
passed. Existing database rows are protected by locks, and tests delete only
their own synthetic keys. No schema or private configuration change was needed.

### Expired local-session cleanup

`app.session_cleanup` provides separate guest/account batch helpers:

| Operation | Caller-owned transaction | Own transaction and required deadline |
| --- | --- | --- |
| Guest sessions | `delete_expired_guest_sessions` | `commit_expired_guest_session_cleanup` |
| Account sessions | `delete_expired_account_sessions` | `commit_expired_account_session_cleanup` |

Each operation accepts an integer batch size of 1–1,000, default 100. Guests are
eligible when `expires_at <= statement_timestamp()`; accounts when either idle
or absolute expiry reaches that inclusive boundary. Access-token expiry alone
does not qualify an otherwise active account session, which can still refresh.
The stored guest expiry already reflects the configured inactivity period;
cleanup introduces no new retention duration.

Selection orders by expiry/ID (idle expiry for accounts, capped by absolute expiry
in the schema), locks at most the batch size with `FOR UPDATE SKIP LOCKED`, and
rechecks eligibility during deletion. Existing activity locks are skipped; a
committed activity extension survives subsequent passes. A lookup waiting behind
committed deletion finds no session and cannot revive it. Concurrent cleaners can
take disjoint batches. Existing runtime grants permit locking; no new privileges,
migrations or provider calls are required.

Low-level helpers require an active transaction and a caller-owned deadline;
their counts are provisional. Commit wrappers require a deadline greater than
zero through 30 seconds covering acquisition, deletion, commit and release, and
return only after successful completion. Errors/cancellation propagate without
retries or draining. Connection cleanup may outlast the nominal deadline; a
timeout during commit does not prove rollback.

Deletion affects local session credentials only: account profiles and the other
session table are preserved. No ciphertext is decrypted, provider session revoked,
browser cookie changed or user history deleted. Neither session table currently
has dependent tables; a database regression check requires retention/ownership
review when such tables are introduced. Guest-history deletion/transfer must be
defined before applying this mechanism to future guest-owned chats or vehicles.

The optional [housekeeping task](#automatic-authentication-cleanup) invokes these
committed helpers after limiter and Google-attempt cleanup. There is no public
cleanup endpoint; enablement remains off by default. Website data/private
configuration and existing expiry settings are unchanged.

Validation passed 193 cleanup-related cases, including 60 new offline boundary
cases and 26 new PostgreSQL cases for both modes. Coverage includes strict limits,
acquisition/commit/release deadlines, cancellation/rollback, exact expiry and fresh
statement time, default batch caps/order, disjoint concurrent batches, active-row
and cross-mode preservation, profile retention, and cleanup/activity lock races.
Tests use only tracked synthetic records on the guarded local database; existing
sessions are protected with locks, and no live provider operations are required.
An additional 47 existing guest refresh/concurrency and account loading/activity/
authentication regressions passed. Lint, formatting, 217 application/test sources
and 12 migration sources passed checks; no schema or grant changes were made.

### Automatic authentication cleanup

FastAPI owns an optional asynchronous task through its existing lifespan. It uses
the runtime database engine to run one batch each for expired limiter records,
Google/sign-in pending attempts, guest sessions and account sessions, in that
order, serially. The existing setting names are retained; enablement covers all
four operations. No new service, dependency, schema or public endpoint is introduced.

| Setting | Default / bounds |
| --- | --- |
| `AUTH_RATE_LIMIT_CLEANUP_ENABLED` | `false`; explicitly opt in |
| `AUTH_RATE_LIMIT_CLEANUP_INTERVAL_SECONDS` | `300`; 60–86,400 |
| `AUTH_RATE_LIMIT_CLEANUP_BATCH_SIZE` | `100`; 1–1,000 per table; limiter batch spans all seven purposes |
| `AUTH_RATE_LIMIT_CLEANUP_TIMEOUT_SECONDS` | `5`; 1–30 per operation, including transaction completion |

No task starts without both enablement and a configured engine. The first pass
waits one interval; each completed or failed pass waits another interval before
the next four batches. Each operation owns a separate transaction and deadline;
failure leaves later operations and the next pass available. The default total
is at most 400 selected/deleted rows per pass and four five-second deadlines;
connection cleanup may outlast any deadline.
A full batch never triggers immediate draining, and passes do not
overlap within the same task. Each application process owns its own task;
limiter and local-session cleanup use `SKIP LOCKED`, while attempt cleanup uses
ordinary DELETE locks with its own deadline to preserve immutable runtime grants. A contended
attempt batch may time out and wait until the next interval. Only expired rows
are eligible; active windows/attempts/sessions and user profiles
are outside this scheduler's scope.

Failures leave authentication available and emit a fixed warning without
exception text or tracebacks. Success logs only the aggregate nonzero deleted
count. Cancellation propagates so shutdown can stop and await the task before
disposing the database engine; driver cleanup may outlast the nominal deadline.
No connection is held while waiting for the next interval.

This is best-effort housekeeping while FastAPI is running, not a guaranteed
retention deadline or a server keep-alive. Stopped/sleeping processes do no work,
and restart begins a new initial wait. Private runtime configuration was not
changed or enabled by this implementation. Guest history is not implemented;
review retention, transfer and foreign keys before adding guest-owned records.

The initial limiter-only scheduling slice passed 63 focused configuration/lifecycle cases, all 3,564 offline
backend tests, and 24 scheduled-cleanup PostgreSQL cases across all supported
purposes. The database cases protect pre-existing rows, verify committed batch
caps and skipped locks, and inject failed commits to confirm rollback and
interval-delayed recovery. Ruff, formatting and application/migration typing
passed. No migrations, private configuration changes or live provider calls were
needed; the scheduler remains opt-in.

The four-operation scheduling slice passed 297 focused cleanup regressions plus
22 health/readiness/client-lifecycle checks. Eight new real PostgreSQL scenarios
verify one-row caps for all four tables, preserved active rows/profiles, skipped
session locks, and independent guest/account commit-failure or timeout recovery
on the next interval. Application tests cover shutdown during all four operations
and continued health after a failure; failed operations log only fixed warnings.
Lint, formatting, application/migration typing, private-file/secret checks and
documentation links passed. No private configuration or website data was changed.

Final accumulated-checkpoint validation passed all 4,732 backend tests, including
guarded PostgreSQL integration tests, with no skips. Ruff, all 229 Python files'
formatting, 217 application/test sources and 12 migration sources passed checks.
The 16-file diff and staged privacy boundaries were reviewed; no blocking
implementation findings, schema changes or expanded grants were required.

The `app.auth_rate_limit_maintenance` command loads runtime `Settings` and runs
one shared batch across recovery, sign-in, sign-up, email confirmation, password
reset, guest creation and Google initiation. It accepts `--batch-size`
(default 100 total rows, range 1–1,000) and
`--timeout-seconds` (default 5, greater than zero through 30). Invalid arguments
are rejected before loading private settings; `--help` does not connect. Direct
calls also validate policy values before engine creation. `DATABASE_URL` must use
`postgresql+psycopg`, host `127.0.0.1`, port `15432`, database `mazda6` or
`askm6_test`, user `askm6_app`, and no query parameters. A dedicated NullPool
engine pins `hostaddr=127.0.0.1` so libpq environment settings cannot redirect its
network address. A live preflight verifies the expected database/current role
and absence of superuser/RLS-bypass privileges before cleanup. The overall
deadline covers preflight and cleanup; engine disposal runs in `finally` even
after failure or cancellation. Disposal/unwinding can extend wall-clock duration.

After migrating the intended local runtime database, from `backend`:

```powershell
# Safe help only; no database connection
uv run --locked python -m app.auth_rate_limit_maintenance --help
# Explicitly deletes one batch from the checked local DATABASE_URL target
uv run --locked python -m app.auth_rate_limit_maintenance --batch-size 100 --timeout-seconds 5
```

Success prints only the committed deletion count and exits 0. Configuration,
database and timeout failures print a fixed message with uncertain-commit wording
and exit 1; keyboard interruption exits 130. No URL, password, fingerprint or row
content is printed. Argument errors exit 2 with a fixed message, without echoing
unknown arguments or invalid values that could contain credentials. The command
does not migrate, loop, schedule future work, enable features or contact providers.
Earlier recovery-only manual execution against the migrated website database completed successfully.
That command checkpoint passed 75 cases: 72 offline command/guard/lifecycle cases and three
PostgreSQL cases. They cover rejected URLs, pinned engine parameters, malformed
policy values, real deadline/external cancellation, disposal/failures, generic
output/exit codes, help without settings and fresh module startup. Database cases
inject the guarded test engine to exercise actual identity/permissions and one
committed batch, and reject a mismatched database or administrator without cleanup.
Automated cases do not test a real command login using the website's private
credentials; the separate manual command check covers the local runtime setup.

The original recovery-only checkpoint passed 62 cleanup cases: 40 validation/failure-boundary cases and 22 real
PostgreSQL cases. Database tests cover exact expiry, minimum/maximum/default
batches, oldest-first order, committed visibility, rollback and cancellation,
skipped locks, disjoint overlapping cleanup transactions, a counter renewing an
expired row, a counter waiting for cleanup then recreating the row, and fresh
statement time in an older transaction. Wrapper coverage includes ordering,
errors and real deadline cancellation during acquisition/deletion/commit/release,
plus PostgreSQL errors at the pre-commit event, conflicting table-lock waits,
pool exhaustion and rollback after actual deletion before commit. Recovery after
each tested database failure is checked; these are not lost-connection or
uncertain-commit recovery tests. They run as the restricted application
role after existing target/revision guards. Existing records are protected with
row locks so cleanup skips them; final teardown deletes only each test's own
synthetic keys. The combined focused suite, including the maintenance command,
passed 439 cases; lint, changed-file formatting and typing of 197 app/test files
passed. Final complete validation passed 3,316 backend cases including PostgreSQL,
with 203 files formatted and all six migration sources typed. Frontend lint, all
486 tests, strict TypeScript and production build passed as well.

All 31 new service cases passed (17 failure-boundary tests and 14 guarded
PostgreSQL cases). Database coverage includes exact expiry, staggered aging,
retry rounding, lowered caps, independent fingerprints, concurrent creation and
updates, rollback, cancellation and a real row-lock wait crossing expiry. Real
commit tests remove only their own synthetic rows. The combined focused
checkpoint passed 242 tests, plus lint, changed-file formatting and typing
(191 source files); no provider calls or website database changes were made.

The SQLAlchemy `AuthRateLimit` model defines `app.auth_rate_limits`, with a
composite operation/fingerprint key, a required timezone-aware timestamp array
bounded to 1,000 entries, and an indexed cleanup deadline. Constraints restrict
the operation to password recovery, sign-in, sign-up, email confirmation or password
reset, require a 32-byte fingerprint, and reject
NULL array entries and nonstandard array shapes. Raw IP addresses and email
addresses are not fields in this table. The model imports and compiles to
PostgreSQL DDL; lint, formatting, typing and 112 existing regression tests passed.
Twenty dedicated offline schema tests also passed, covering the composite key,
required fields, binary fingerprint, timezone-aware timestamp array, declared
constraints, explicit state and cleanup index. These verify the compiled schema
contract; they do not execute constraints against PostgreSQL. Backend lint,
formatting of the new test file and typing (184 files) passed.

Migration `0826d9fbcef3` has been generated against the guarded local test
database, following `b731b533d299`. Autogeneration was restricted to creating
`app.auth_rate_limits` and its expiry index. Both local `askm6_test` and website
`mazda6` databases were verified at that revision before the sign-in extension.
The application role has SELECT, INSERT and DELETE, with UPDATE
restricted to `request_times` and `expires_at`; PUBLIC has no table grants.

Migration `0f42bd53f47a` follows `0826d9fbcef3` and replaces the recovery-only
purpose constraint with `purpose IN ('password_recovery', 'sign_in')`. It changes
no rows, keys, indexes, ownership or grants. The composite key permits independent
state for the same fingerprint under each purpose. Downgrade first validates the
old recovery-only constraint and refuses if any sign-in rows remain, preserving
data rather than deleting it. Disposable Linux validation passed all 376
integration cases, including 52 limiter schema cases covering both purposes,
unchanged permissions and independent state under the same fingerprint. A
populated migration check confirmed recovery rows, grants, indexes and other
constraints survive upgrade, refused downgrade and a safe downgrade/re-upgrade.
The 181 focused offline cases, application/test typing and all seven migration
sources passed too. The local website `mazda6` and test `askm6_test` databases
were guarded and upgraded to `0f42bd53f47a` before the sign-up extension. Each live target's database,
migration role and previous revision were verified before upgrading; both report
the new head with no schema drift and unchanged restricted application grants.
The website connects as `askm6_app` and can read limiter storage. Private runtime,
migration and integration environment files were unchanged.
The focused local schema, limiter, cleanup and recovery HTTP regression run
passed 106 tests (270 integration cases deselected).

All 28 PostgreSQL constraint/permission cases and 20 offline schema cases passed.
Coverage includes round-trip state changes and row locking, duplicate keys,
required fields, fingerprint length, operation restrictions, array bounds and
NULL entries, invalid shapes, timezone preservation, and denied key updates and
TRUNCATE. PostgreSQL may reject multidimensional input in `array_position` before
evaluating the shape constraint. Integration tests roll back their fixture data;
they do not establish concurrent limiter behavior. Backend lint, changed-file
formatting, typing (185 source files) and migration typing (six files) passed.
Enabled recovery needs the migration in its own runtime database plus a configured
HMAC secret. Both are prepared for the local website. Expired limiter cleanup can
run through the optional application scheduler or an explicit helper/command call.
Configuration tests cover defaults, inclusive bounds, invalid values, environment
overrides and precedence, empty values, and unchanged endpoint feature flags.

Manual local validation after migration and private key setup confirmed recovery
202/email delivery, reset 200, old-password rejection, new-password sign-in and
session restoration after refresh. The maintenance command completed against the
local website. A bounded invalid-body test then produced nine 400 responses and
a 429 with `Retry-After: 149`, consistent with one earlier accepted recovery
attempt and the exact rolling window. Invalid bodies never reached the provider;
this test sent no additional recovery emails. These checks do not establish
production proxy trust, automatic retention cleanup or all live failure cases.

By default, the standalone `get_client_ip` helper validates and normalizes the ASGI
client address, including IPv4-mapped IPv6, without reading forwarding headers. Missing,
malformed, oversized or scoped addresses raise a generic `ClientIPUnavailable`
error rather than falling back to a header. Its 39 focused tests cover canonical
addresses, source ports, invalid inputs and ignored forwarding headers. The helper
is used for recovery-route fingerprinting and does not store or log addresses.

Uvicorn can rewrite the ASGI client address before the helper runs. Ignoring
headers in the helper therefore does not establish a trusted proxy boundary.
Use `--no-proxy-headers` for local peer-only validation; requests through Vite
may then share a loopback address. Production client identification still requires
reviewing the actual proxy chain and its header handling before enabling the
[optional authenticated assertion](#trusted-proxy-client-addresses).
See [Uvicorn proxy settings](https://uvicorn.dev/settings/).

An additional 22 in-process tests exercise the helper through Uvicorn's actual
configured middleware stack. They reproduce rewriting from a trusted peer,
preserve the peer with proxy processing disabled even under wildcard/environment
trust, ignore forwarding from untrusted peers, check trusted-chain ordering and
duplicate headers, and reject an invalid rewritten address. The three focused
suites pass 97 tests in total. These tests open no listener, add no application
endpoint, and do not verify Render or Cloudflare's deployed proxy behavior.
Use the documented local startup flags when starting the development server.

`POST /api/v1/account/password-recovery` accepts only JSON containing email and
CAPTCHA proof. It requires exactly one trusted browser origin, limits the actual
request body to 16 KiB, masks input in validation errors, and rejects extra fields
such as passwords, user IDs, codes, and redirect destinations. It returns HTTP 202
with a generic acknowledgement and never creates an application session or issues
a cookie. Acceptance does not confirm account existence or email delivery.

`ACCOUNT_PASSWORD_RECOVERY_API_ENABLED` defaults to false. The route checks its
feature flag, provider configuration, database engine and configured HMAC secret
before counting. Inside the total deadline it creates the protected IP key and
awaits committed counting before reading the body or contacting Supabase. Invalid
Origins or missing configuration never count. An allowed limiter decision counts
even if subsequent parsing or provider work fails. A local denial returns 429
with the computed `Retry-After`, no-store headers and no cookies/challenge header;
it neither parses input nor contacts the provider. Missing/invalid IP/key material,
limiter errors, SQLAlchemy errors and timeouts fail closed with a generic 503.
`ACCOUNT_PASSWORD_RECOVERY_TIMEOUT_SECONDS` defaults to 15 seconds, accepts one
to 30 seconds, and bounds limiter transactions, body reading and provider work. The adapter submits
email and CAPTCHA proof once to Supabase, refuses redirects, and limits the
provider operation to five seconds and 64 KiB of uncompressed JSON response data.
Supabase performs account CAPTCHA verification; the application does not consume
the proof separately through Siteverify.

Known account-dependent outcomes and address-specific email cooldowns receive
the same generic acknowledgement without retrying. CAPTCHA rejection returns
HTTP 403 with `X-Account-Verification: required`; rejected input returns 400;
client-wide provider rate limits return 429; unavailable or unexpected responses
return 503. No retry/reset time is invented when the provider has not supplied
one. Handled responses use `Cache-Control: no-store` and omit provider details
and credentials. Cancellation propagates and provider responses close.

Offline tests cover parser boundaries, configuration, response classification,
HTTP request/response limits, redirects, transport errors, cancellation, route
guards, and total deadlines. Tests also exercise the real application startup,
route, and adapter together with mocked limiter/database resources and Supabase
responses, including resource cleanup. All 45 route cases passed, covering limiter
denial, missing engine/secret, invalid peer/key, failure masking, no provider call
after limiter failure, operation order and cancellation of a stalled counter.
The complete backend run passed 2,852 tests with 312 opt-in PostgreSQL tests
skipped; lint, changed-file formatting and typing (191 files) passed. These route
tests send no emails and require no database. A separate 15-case PostgreSQL HTTP
suite now exercises the actual route, HMAC helper, counting/commit service and
provider adapter with only delivery HTTP mocked. It verifies committed counts
visible to a separate connection before provider work, capped requests without
mutations, invalid input/provider failures retaining counts, neutral unknown-account
responses, Origin rejection without counting, spoofed headers/mapped IPv4 handling
and distinct peers. Eight simultaneous HTTP requests under a cap of two produce
two accepted responses and six denials. A real SQL error at the commit boundary
rolls back inserted or updated state and prevents provider work; a real row-lock
wait is cancelled by the HTTP deadline. One expiry/retry scenario uses a fixed
database-time helper for deterministic boundary assertions. Runtime SQL executes
as restricted askm6_app; tests validate askm6_test/head, commit synthetic rows and
delete only their own two fingerprints. Fixtures inject test-owned application
resources rather than exercising the production deployment/startup configuration.
The combined focused suite passed 302 cases with 2,877 unrelated tests deselected;
lint, new test formatting and typing (192 files) passed. This does not simulate
an uncertain lost connection during commit or live email/provider behavior.
Separate manual local checks have
validated recovery email delivery and a complete password-reset flow, as recorded
under the development forms below. The internal verification and
password-update adapters are described below. The default-disabled request
endpoint does not establish complete account-enumeration or abuse protection;
public enablement still requires the remaining abuse controls and deployment
review.

### Frontend recovery-request helper

`requestAccountPasswordRecovery` sends only email and CAPTCHA proof to the
existing recovery endpoint, once, with same-origin credentials, no caching and
redirects rejected. It accepts only HTTP 202 with `status: "accepted"`, returns
only that neutral metadata and ignores untrusted server messages or credentials.
Acceptance does not confirm account existence or delivery.

Rejected requests, explicit CAPTCHA rejection and rate limiting have distinct
error classes. Other failures use controlled messages; error bodies and private
transport/parser details are not exposed. No retry delay is invented. An optional
`AbortSignal` preserves cancellation during the request and response reading;
the development-only hook below owns the deadline and duplicate-start guard.

All 32 focused recovery-helper tests and the full 197-test API suite passed with mocked
requests. Frontend lint, TypeScript and production build also passed. No recovery
emails were sent by these tests. Development recovery/reset controls use this
helper; public enablement remains outstanding.

### Frontend recovery-request hook

`useAccountPasswordRecovery` is development-only and exposes idle, loading,
accepted and error feedback. Mounting does not request recovery. Ref-based guards
block duplicate starts before a React render and after acceptance. It passes an
abort signal to the request helper and aborts at 15 seconds; timers are cleared
after completion or failure. Unmounting aborts a pending request, prevents later
starts through old callbacks and ignores late replies.

Accepted feedback stays neutral about account existence and email delivery.
Rejected input, verification failures and rate limits use controlled messages;
unknown errors omit private details. Retries require a new explicit start and
are never automatic. Timeout feedback suggests checking email before trying
again, because cancelling a request cannot recall an email already sent. The
recovery form consumes each CAPTCHA proof and obtains a fresh proof for retry.

All 13 focused hook tests passed, including StrictMode, immediate duplicates,
typed errors, explicit retries, the exact deadline, late responses and timer/
unmount cleanup. The full frontend suite passed 486 tests (197 API and 289
UI/hook cases); lint, TypeScript and production build passed. These requests are
mocked; separate manual local validation is recorded under the development forms.

## Internal provider-session response validation

The provider-session response interpreter accepts a successful raw user reply
only when it identifies the expected backend-verified, non-anonymous account.
Known session rejections remain distinct from unavailable verification; malformed
replies, unexpected statuses and rate limits cannot authorize access. Errors omit
provider details. Offline tests cover identity mismatches, response boundaries
and current and legacy error formats.

The separate HTTP helper checks the configured provider's authenticated user
endpoint once, refuses redirects, and bounds network work to five seconds and
64 KiB of uncompressed JSON. Mocked HTTP tests cover request headers, response
limits, timeouts, cancellation and response cleanup.

`authenticate_active_account_token` composes existing JWT verification with this
live check, requires a nonzero provider session ID, and preserves the existing
invalid-token versus unavailable-authentication errors. It checks the provider
on every call, even when signing keys are cached. Sign-in uses this combined
check before opening the session-creation transaction; rejection, provider
unavailability and cancellation prevent database work. Session creation retains
its own JWT verification, and browser credentials are returned only after commit.
Existing application-session authentication also requires a live check before
updating activity or storing refreshed credentials, while retaining the row lock
and existing database deadline guards.

The internal `verify_active_account_session_token` helper verifies JWT identity,
requires matching account and nonzero provider-session IDs from a locked session,
then performs the live check. Invalid stored credentials or identity mismatches
remain unavailable verification; explicit provider rejection uses the existing
rejected-session error. Unit tests cover ordering, identity binding, error mapping
and cancellation. This helper does not write activity or credentials. The
coordinator uses it for both current and refreshed access tokens; failures stop
before activity or credential writes without retry or fallback.

Guarded local PostgreSQL tests exercise these paths with real JWT verification
and mocked provider HTTP. They check unchanged rows on live-check failure,
concurrent refresh/rollback behavior, and expiry guards using a simulated later
database check time. HTTP integration tests verify that provider rejection clears
the cookie with a generic 401, while outages return 503 without clearing it, and
commit failures cannot renew cookies. These tests do not verify live hosted
Supabase revocation behavior.

The Bearer-only `/api/v1/account/me` identity endpoint retains its existing JWT
verification behavior; this checkpoint's live checks cover sign-in and cookie
session authentication. The identity endpoint is not a live revocation check.

The internal `invalidate_account_sessions` helper deletes application-session
rows belonging to a backend-verified account within a caller-owned transaction
and returns the number deleted. Unit and local database tests cover owner
isolation, expired rows, repeated calls and rollback, preserving other accounts,
profiles and guest sessions. It does not revoke provider sessions or complete a
password reset; recovery authorization and commit remain the caller's duties.

## Internal password-reset adapters

The reset-input parser accepts only email, a six-to-ten-digit ASCII recovery
code, and a new password. It limits the actual JSON body to 16 KiB, masks these
values in model representations and validation errors, and rejects extra fields
such as client-supplied user IDs, access tokens, and verification types. Leading
zeros in codes and all password characters are preserved. Passwords have a
structural length bound of one to 1,024 characters; Supabase remains responsible
for enforcing the configured password-strength policy.

The recovery-verification adapter submits email and code once to Supabase's
`POST /verify` endpoint with the server-fixed type `recovery`. It validates the
response structure and retains only a masked access token and provider account
ID; refresh tokens and other provider data are discarded. The separate recovery
identity helper uses the existing signing-key/JWT verification flow and requires
the signed account ID to match the provider response. JWT validity alone does
not establish recovery purpose: these credentials must originate from the
server-controlled recovery-code exchange, never browser-supplied tokens.

The password-update adapter accepts those credentials and the verified identity,
rejects mismatched account IDs before sending a request, and submits only the
unchanged new password to Supabase's `PUT /user` endpoint using the recovery
bearer token. A successful response must identify the same non-anonymous account
and contain no unexpected session-credential fields. Known password-policy or
verification requirements produce controlled rejection errors; recognized
client-wide rate limits remain distinct; unknown, malformed, transport, or server
failures remain unavailable. Provider details are not returned in these errors.

The recovery-verification and password-update HTTP adapters refuse redirects,
make no automatic retry, limit provider work to five seconds, and read at most
64 KiB of uncompressed JSON response data.
Responses close on success, failure, and caller cancellation; cancellation
propagates. A timeout or malformed reply can occur after a provider-side change,
so an unavailable result does not establish that the password stayed unchanged.

Offline tests cover input preservation and limits, response contracts, identity
mismatches, masked errors, exact provider requests, redirect refusal, stream
limits, deadlines, cancellation, and cleanup. They use synthetic credentials and
mocked provider HTTP/authentication boundaries; existing account-authentication
tests cover JWT verification. The internal reset service, default-disabled HTTP
route and development forms described below connect these helpers. Separate
manual local checks validated the live reset success path.

The separate recovery-session cleanup response interpreter accepts a no-content
204 acknowledgement or an explicit 403 `session_not_found` reply from the
provider's local-scope logout endpoint. An already absent session satisfies
cleanup; expired/invalid credentials, unknown errors, conflicting error codes,
rate limits and outages do not confirm it. Focused offline tests cover response
classification and generic errors. This interpreter makes no HTTP request and
is used by the cleanup HTTP helper below.

The cleanup HTTP helper accepts credentials from the server's recovery exchange
and their previously verified identity. It rejects mismatched account IDs, a
zero provider-session ID, and malformed tokens before sending a request. The
caller must have verified the exact access token supplied. It submits one
`POST /logout?scope=local` request with the recovery bearer token, refuses
redirects, and bounds network work to five seconds and error JSON to 64 KiB.
A 204 reply must have no body. Responses close on success, failure and
cancellation; cancellation propagates and no automatic retry is performed.
Offline HTTP tests cover scope, identity guards, error handling, actual byte
limits, deadlines and cancellation. An unavailable result can occur after
provider revocation; it does not establish that the session remains active.
The helper does not delete application sessions or complete a password reset.

## Internal password-reset service

The internal reset service verifies the recovery code and JWT identity, requires
a nonzero provider-session ID, updates the password once and ends the temporary
provider session. It then deletes the account's application sessions in a
transaction, returning only after successful commit. It returns no credentials,
creates no application login and issues no cookies; fresh sign-in is required.

Known password-update rejection, rate limiting or unavailability triggers one
cleanup attempt. Successful cleanup preserves the original update error; failed
cleanup produces a generic reset-unavailable error. These failure paths do not
delete application sessions. Cancellation and caller deadlines interrupt the
operation without starting additional cleanup work or automatic retries.
Provider-side changes cannot be undone by PostgreSQL rollback, and cleanup is
not guaranteed when cancellation, outages or deadline expiry interrupt it.

Mocked service tests cover operation order, exact helper arguments, configuration
guards, nil session IDs, failures at each stage, transaction-open/commit failures,
cleanup failures and cancellation. Guarded local PostgreSQL integration tests use
real signing-key/JWT verification and mocked provider HTTP to cover committed
account-session deletion, owner/guest/profile isolation, rejected recovery,
identity mismatch, update errors, cleanup errors and real commit failure.
Independent connections check transaction visibility and rollback. Tests also
model provider-side changes surviving a database failure and verify that a
surviving local session is refused when the provider reports it revoked.
These scenarios model provider behavior; they do not validate live Supabase
password changes or revocation.
Live provider checks establish session validity at the time of the check; they
cannot cancel work already authorized before a reset. The scenarios below cover
selected reset/sign-in/refresh orderings with mocked provider behavior.
A focused PostgreSQL concurrency test verifies that account-session invalidation
waits for a session row lock, then deletes the row after a simulated credential
write commits while preserving the profile. It observes actual database blocking;
it does not exercise the complete provider refresh or sign-in flow.
An additional deterministic integration scenario pauses the actual sign-in
service at its live provider check, completes reset through the service or HTTP
route, then models provider revocation. Sign-in is rejected before opening a
database transaction, without retrying or recreating a session. This covers a
provider check that finishes after reset.
Another scenario pauses persistence after an initial successful live provider
check, completes reset, then lets the already approved sign-in commit a new
local row. Using that row's opaque cookie through the session HTTP route performs
a fresh provider check and returns 401 with cookie clearing when revocation is
reported. The rejected check does not update activity or credentials; other
accounts, guests and profiles remain unchanged. This documents the stale-row
possibility rather than promising every overlapping sign-in is cancelled.
A further service/HTTP scenario starts a real refresh from an expired stored
access token and pauses verification of its replacement token. After reset
changes the password, the mocked provider rejects that session. Refresh rolls
back without committing replacement credentials or activity; reset then commits
session deletion. Events coordinate the ordering, and the pending task is cleaned
up on failure. A separate approved-refresh scenario pauses immediately before
storage after a successful live provider check, then lets the real refresh
storage and transaction commit during reset. Independent connections verify the
replacement credentials and activity become visible before reset commits their
deletion. A subsequent session HTTP request rejects the deleted session with 401
and cookie clearing. This does not revoke an authentication result already
authorized in flight or validate hosted Supabase behavior.

## Password-reset endpoint foundation

The route now requires the independent fingerprint secret and a database migrated
through `0ffc842c5360`. It commits an IP attempt before reading credentials or
starting the reset service, using fixed purpose `password_reset` and namespace
`askm6:auth-rate-limit:v1:password_reset:ip:`. Its configurable starting policy is
10 attempts per rolling 600 seconds: `ACCOUNT_PASSWORD_RESET_IP_MAX_REQUESTS`
accepts 1–1,000 and `ACCOUNT_PASSWORD_RESET_IP_WINDOW_SECONDS` accepts 60–86,400.
Recovery-email, sign-in, sign-up and confirmation budgets remain separate.

A local cap returns no-store 429 with rounded-up `Retry-After` seconds, without
parsing or provider work; denial leaves state unchanged. An allowed attempt stays
counted after invalid input, provider failure or later reset transaction failure.
Origin/readiness guards precede counting, and key/limiter/database failures return
generic 503 under the total request deadline. Accounting commits before the reset
service runs; its later session-invalidation commit still gates a successful response.
Provider rate limits preserve their existing 429 without inventing a retry time.

Migration `0ffc842c5360` follows `6ef221a79f00` and broadens only the purpose CHECK.
It changes no records, indexes or grants; downgrade validates the four-purpose
constraint first and refuses while password-reset records exist. Both guarded local
databases were upgraded without drift or private configuration changes. Shared
cleanup now covers all seven purposes under one total batch cap, with optional
application scheduling. Production proxy verification remains pending. The frontend displays validated
retry seconds for local caps, preserving generic text for provider limits without
a known wait. Retries remain manual and never advance to successful completion.

Validation passed 560 focused offline tests and 57 focused PostgreSQL cases
(23 reset-limit HTTP/accounting cases, 28 real reset-service/HTTP cases and six
rollback-only migration probes). The full backend suite then passed all 4,127
tests, including PostgreSQL, with no skips. Lint, formatting (213 files), typing
(203 app/test sources) and ten migration files passed. Provider HTTP is mocked;
these checks send no live recovery requests or password changes.

`POST /api/v1/account/password-reset` is registered but disabled by default
(`ACCOUNT_PASSWORD_RESET_API_ENABLED=false`). It requires a trusted origin before
parsing and accepts only email, recovery code and new password as JSON, capped
at 16 KiB of actual request bytes. Browser-supplied account IDs, provider tokens
and recovery-purpose fields are rejected. Password characters and leading zeros
in the recovery code are preserved. No account cookie or bearer login is needed;
authorization comes from the server's recovery exchange and verified identity.

The route requires database, provider-client and signing-key resources before
reading credentials. Its total deadline includes parsing and the reset service,
defaults to 15 seconds, and is configurable from 1–30 seconds through
`ACCOUNT_PASSWORD_RESET_TIMEOUT_SECONDS`. Successful completion returns only
`status: completed` and an instruction to sign in with the new password, after
the service finishes provider cleanup and commits application-session deletion.
It creates no login, returns no credentials and sets no cookies.

Invalid or rejected resets return controlled 400 errors; unsupported content
types return 415, oversized bodies return 413, and rejected origins return 403.
Known provider rate limits return 429 without an invented retry time. Missing
resources, a disabled endpoint, provider/cleanup failures, database errors and
deadline expiry return generic 503 errors. Handled responses use
`Cache-Control: no-store`. Cancellation propagates and no retry is added. As
with the service, an unavailable response may follow an actual password change.

Offline route tests cover registration, guards before parsing, exact service
arguments, invalid input, metadata-only responses, error masking, deadlines,
cancellation and waiting for service completion. They mock the reset service;
guarded PostgreSQL tests separately run the reset scenarios through
both the service and HTTP route with real JWT verification and mocked provider
HTTP. They verify committed session deletion, ownership isolation, rollback,
controlled HTTP errors and omission of credentials/cookies. The HTTP integration
injects test-owned resources rather than exercising application startup.
Development recovery/reset controls are connected and the success path has been
manually validated locally with the live provider. Live failure, cancellation
and concurrent-session behavior are not established by that manual check.
Private feature flags are not enabled by these tests or example settings.

### Frontend password-reset helper

`resetAccountPassword` sends only email, recovery code and `new_password` to the
existing reset endpoint, once, with same-origin credentials, no caching and
redirects rejected. It preserves password characters and leading zeros in codes.
Only HTTP 200 with `status: "completed"` confirms completion; the returned object
contains no identity, session or provider credentials and does not establish login.

Rejected input and rate limits have distinct error classes. Error responses and
private transport/parser details are not exposed, and no retry time is invented.
Only HTTP 429 reads `Retry-After`; `AccountPasswordResetRateLimitedError` accepts
integer delta-seconds from 1 through 86,400 into `retryAfterSeconds`. Missing,
malformed, oversized, unsupported date and out-of-range headers yield null and
fixed fallback text. Other statuses ignore the header, and error bodies stay unread.
Network, unavailable and malformed-response messages preserve uncertainty: the
backend may already have changed the password. They suggest trying the new
password before starting recovery again. No automatic retries are made.
An optional `AbortSignal` preserves cancellation during request/response reading;
cancellation does not guarantee that a password change was prevented or undone.
The development-only reset hook below owns the deadline and duplicate-submit guard.

All 55 focused reset-helper tests and the full 285-test API suite passed with
mocked requests; frontend lint, TypeScript and production build passed too. Tests
changed no real passwords and sent no emails. Separate manual local recovery/reset
validation is recorded below; public enablement remains outstanding.

### Frontend password-reset hook

`useAccountPasswordReset` is development-only and exposes idle, loading,
completed and error feedback. It sends no request on mount, guards duplicate
starts before a render and after confirmed completion, and returns only a
success boolean. Completion instructs the user to sign in; it does not log in
or expose the email, recovery code or password in the returned state.

The hook passes an abort signal and aborts at 15 seconds, clears timers on every
settled outcome, cancels on unmount and ignores late responses or saved callbacks
after unmount. Only a response confirmed before the deadline reports completion.
Known rejections have fixed feedback; rate limits show validated singular/plural
retry seconds or safe generic text. This quotes the server's wait at the failed
attempt, with no countdown, client lock or automatic password-change request.
The existing status region announces the message; code and password clear, and
visibility resets. A manual retry uses newly entered credentials, and only a
confirmed reset reveals "Continue to sign in". Unknown errors and timeouts
preserve uncertainty and suggest trying the new password before starting recovery
again. Cancelling a request cannot guarantee preventing or undoing a password
change. No automatic retries or invented retry delays are added.

Focused reset validation passed 55 API cases and 57 hook/form/recovery-dialog cases,
including StrictMode, immediate duplicates,
typed/private errors, explicit retry, the exact deadline, late resolve/reject,
timer cleanup, unmount cancellation and production gating. The full frontend
suite passed 608 tests (285 API and 323 UI/hook cases), plus lint, TypeScript and
production build. Provider calls are mocked; these tests changed no real passwords.
The hooks are connected to the development forms below.

### Development password-recovery and reset forms

The sign-in dialog offers "Forgot password?" beside the password-visibility
control. It opens recovery in the same modal, preserving the typed email and
discarding the sign-in password and proof. The recovery form uses the existing
rectangular Turnstile widget with `account_password_recovery`, consumes each
proof once and requires fresh verification after failure. A neutral accepted
reply moves to code entry; "I already have a recovery code" supports an existing
email without automatically requesting another one.

The reset form accepts a six-to-ten-digit code (including leading zeros) and
one new-password field with a visibility toggle. It clears code/password before
submitting and when unmounted, and never stores either in the parent flow.
Only confirmed completion offers "Continue to sign in"; resetting does not log
in. Error feedback preserves uncertainty. Returning to sign-in or requesting
another code is explicit and never sends a new recovery email automatically.

Both forms guard duplicate starts and stale submit events during navigation,
block competing navigation while pending, keep Close available, and cancel
through hook cleanup when dismissed. The dialog retains its focus guards,
scroll behavior and native-cancel handler; closing/reopening resets its flow.
Email/code focus and explicit post-reset sign-in focus are covered in tests.

All 33 new form/dialog cases and the full 486-test frontend suite passed (197 API,
289 UI/hook cases), plus lint, TypeScript and production build. Provider calls
are mocked. Browser automation was unavailable; these tests do not establish
live browser or provider behavior.

Manual local checks on 2026-10-24 validated recovery email delivery, code-based
password reset, explicit return to sign-in, rejection of the old password,
successful sign-in with the new password, and session restoration after refresh.
These checks used a user-controlled account and do not establish live failure,
concurrent-session or production behavior.

Local live validation requires explicit backend
`ACCOUNT_PASSWORD_RECOVERY_API_ENABLED=true` and
`ACCOUNT_PASSWORD_RESET_API_ENABLED=true`, with the existing database/auth/
encryption/origin/CAPTCHA settings configured. These flags stay false in examples;
local private settings were enabled manually for the live check. The Supabase
Reset password email template must show the recovery code (`{{ .Token }}`) for
this code-entry flow; a link-only
template is insufficient. See [Supabase email templates](https://supabase.com/docs/guides/auth/auth-email-templates).
Dashboard/email-template changes and live account operations remain manual steps.

## Google sign-in — local development

The development sign-in and create-account dialogs both offer a full-width
"Continue with Google" button alongside email/password access. Both use the same
Google flow for first-time and returning users; Google access does not require
the local email/password fields or an email-registration confirmation code.
Local browser checks confirmed matching controls in both dialogs, successful
Google access from the create-account dialog, and Escape/Close dismissal.
Supabase manages Google's authorization flow; FastAPI
exchanges the PKCE code, verifies the Supabase JWT and active provider session,
and stores an encrypted account session before issuing an opaque HttpOnly cookie.
No Google client secret or provider token belongs in the frontend. Google login
does not automatically transfer guest data or match application accounts by email.

Manual local checks confirmed successful Google sign-in, session persistence
after refresh, sign-out, cancellation/retry, and the same account ID when using
Google and an existing confirmed email/password account with the same email.
Supabase owns [automatic identity linking](https://supabase.com/docs/guides/auth/auth-identity-linking);
the application uses its verified subject ID. These checks cover one local test
setup, not every provider error, account-linking case or production deployment.
First-time Google access uses the same OAuth flow: Supabase creates the managed
account, then the verified callback creates its local profile/session. A callback
failure can therefore leave a Supabase user without a completed application
login. A fresh-token clock-skew regression has been reproduced and addressed.
After the fix, a local live retest no longer reproduced the reported intermittent
rejection; this does not establish reliability across all provider error cases.

### Configuration

Examples remain disabled. Local Google access requires existing database,
Supabase issuer/publishable-key, session-encryption, fingerprint-secret, trusted-origin and account
session/sign-out configuration, plus:

| Setting | Default / requirement |
| --- | --- |
| `ACCOUNT_GOOGLE_OAUTH_API_ENABLED` | `false`; explicitly enable for the local test |
| `ACCOUNT_GOOGLE_OAUTH_IP_MAX_REQUESTS` | `10`, allowed range 1–1,000; initiation/replacement attempts per IP |
| `ACCOUNT_GOOGLE_OAUTH_IP_WINDOW_SECONDS` | `600`, allowed range 60–86,400; rolling window |
| `ACCOUNT_GOOGLE_OAUTH_CALLBACK_URL` | Unset; exact externally visible application callback |
| `ACCOUNT_GOOGLE_OAUTH_TIMEOUT_SECONDS` | `15`, allowed range 1–30; backend work only |
| `ACCOUNT_GOOGLE_OAUTH_ATTEMPT_LIFETIME_SECONDS` | `600`, allowed range 60–900; includes time on Google |
| `VITE_GOOGLE_OAUTH_ENABLED` | `false`; production also requires `VITE_ACCOUNT_AUTH_ENABLED=true`; a valid public issuer is required in either mode |
| `VITE_SUPABASE_AUTH_ISSUER` | Public `https://YOUR_PROJECT_REF.supabase.co/auth/v1` |

The application callback is
`http://127.0.0.1:5173/api/v1/account/google/callback` for the Vite local setup.
Add that exact URL to Supabase's
[redirect allowlist](https://supabase.com/docs/guides/auth/redirect-urls).
Google Cloud instead uses the hosted Supabase callback
`https://YOUR_PROJECT_REF.supabase.co/auth/v1/callback`; store the Google web
client ID/secret in Supabase's Google provider settings. See the
[Google provider setup guide](https://supabase.com/docs/guides/auth/social-login/auth-google).

Callback configuration rejects credentials, query/fragment components, wildcard
hosts and ambiguous path spellings. HTTPS is required except explicit loopback
HTTP development with `ACCOUNT_COOKIE_SECURE=false`. The frontend validates the
configured HTTPS issuer, exact authorization destination, fixed callback, future
expiry and four unique Google/S256 parameters before navigating.

### API and security boundaries

| Endpoint | Behavior |
| --- | --- |
| `POST /api/v1/account/google/start` | Trusted Origin, empty body and no query; commits IP accounting before pending-attempt creation/replacement and returns authorization URL/expiry metadata |
| `GET /api/v1/account/google/callback` | Checks the browser binding, consumes the attempt once, exchanges the code and commits the verified account session |

The migration `b731b533d299` adds `app.oauth_login_attempts`, a unique browser-token
hash and expiry index, and grants `askm6_app` only SELECT/INSERT/DELETE on the new
table. Browser tokens and PKCE verifiers are independent high-entropy values;
only the token hash and encrypted verifier are stored. Consumption uses atomic
DELETE/RETURNING and fresh database time after row-lock waits. Replacement proves
the previous binding and uses a savepoint; failed/uncertain operations require a
fresh flow and never automatically replay a code exchange.

Google initiation uses the shared atomic rolling-window limiter with its own
`google_start` purpose and `askm6:auth-rate-limit:v1:google_start:ip:` HMAC namespace.
The key comes from the canonical ASGI peer by default, or the authenticated
visitor-IP assertion when proxy trust is explicitly enabled (see below).
Ordinary forwarding headers and browser cookie changes cannot select a different
budget. Limiter rows store no raw IP. Resource,
Origin, signed-in-cookie, query and body guards precede accounting. Once allowed,
the count remains committed even if binding validation, attempt persistence,
replacement or destination construction later fails.

Accounting commits and releases its connection before reading the pending binding
or creating/replacing an attempt. A committed denial returns 429 with bounded
`Retry-After` seconds, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
It does not generate a destination, alter a pending attempt, set/clear cookies or
contact the provider. Failed accounting, missing fingerprint configuration,
unusable peer identity and deadline expiry return controlled 503 responses. The
existing overall start deadline covers body reading, row-lock waits and both
commits. Callback completion has no new initiation charge or HMAC requirement.

Migration `46250b6b2d17` follows `aefd9866f033`, adding only the supported-purpose
CHECK value; existing records, indexes and restricted grants are preserved.
Downgrade refuses while Google-start rows exist instead of deleting them. Both
guarded local databases are upgraded without drift or private configuration
changes. Shared bounded cleanup includes all seven purposes under one total cap;
optional application scheduling now handles these expired limiter rows. The development frontend displays validated
retry guidance for Google-start 429 responses, with explicit manual retries.

The short-lived binding cookie is HttpOnly, SameSite=Lax, host-only and root-path;
secure mode uses `__Host-askm6_oauth`. Malformed/duplicate bindings are rejected.
An existing account-cookie name requires explicit sign-out before another login,
even if that cookie is stale. Guest cookies and data are preserved.

The callback accepts one bounded `code` parameter and uses the fixed configured
return origin, never request Host, forwarded headers or a browser return URL.
It returns 303 with a fixed noncredential outcome fragment and clears the pending
cookie on handled terminal responses. Codes/tokens are not reflected in errors.
Account cookies are issued only after session commit. The exchange is bounded
to five seconds and 64 KiB of uncompressed JSON, with no redirects or retries.

Frontend return fragments are untrusted status hints: only the backend session
check establishes sign-in. The dialog blocks simultaneous Google/email starts,
clears typed passwords and prior CAPTCHA proofs on Google start, cancels pending
starts on close/unmount, and permits explicit retries. The full-width Google
button has one boundary, matching form alignment and balanced idle spacing;
sign-in/sign-up omit redundant verification instructions and empty status rows.
Original Google icon proportions, visible keyboard focus and meaningful feedback
are preserved. Artwork has a separate [source and brand notice](../frontend/src/assets/README.md).

For initiation HTTP 429, the API raises a dedicated Google rate-limit error without
reading the response body or accepting a destination. Only decimal `Retry-After`
delta-seconds from 1 to 86,400 are used; missing, malformed, multiple, date or
out-of-range values show a generic try-later message. Other statuses ignore this
header. Both account dialogs announce the wait in the Google button's existing
accessible status region, including singular/plural wording. This is static
guidance from the last response, not a countdown or browser-enforced cooldown.
The server owns enforcement; another click is required for every retry, and only
a validated successful response can trigger navigation. There are no automatic
requests, redirects or retained proof/credential submissions after a denial.
Switching to email still requires a fresh password and verification proof. The
existing timeout, cancellation, duplicate-start and production gates are retained.

### Expired pending-attempt cleanup

`app.account_oauth_cleanup.delete_expired_oauth_login_attempts` deletes one batch
of expired pending Google/sign-in attempts in a caller-owned transaction. It
requires an active transaction and an integer batch size of 1–1,000 (default 100).
Selection uses database statement time, inclusive expiry and stable ordering by
expiry/ID. The delete rechecks eligibility, returns IDs only internally and
reports a provisional count. Active attempts and all session/profile/limiter
tables are outside its scope. No cookie, token decryption or provider call is involved.

`commit_expired_oauth_login_attempt_cleanup` owns a transaction and a required
deadline greater than zero through 30 seconds, including acquisition, deletion,
commit and release. It returns the count only after successful completion;
errors and cancellation propagate without retries. An interrupted commit may
already have taken effect, so a timeout does not prove rollback.

The runtime role keeps its existing SELECT/INSERT/DELETE grants and no column
UPDATE privilege. PostgreSQL also requires UPDATE privilege for
[SELECT row-locking clauses](https://www.postgresql.org/docs/17/sql-select.html).
This helper therefore uses DELETE's ordinary locking with a caller-owned deadline.
It may wait for a contended row; timeout cancels and rolls back that batch so a
caller can leave cleanup for another pass. Concurrent cleaners can select the
same candidates; a waiter can return zero after the first cleaner commits.
There is no automatic draining or retry, and no extra grants or migration.

PostgreSQL regression tests cover active-attempt consumption, batch/default
bounds, exact expiry, fresh statement time, overlapping cleaners, lock deadlines,
commit failure, cancellation, and replacement/consumption races. They use the
guarded test database and restricted runtime role with synthetic records. Tests
decline to run if pre-existing attempts would prevent isolated cleanup, and
teardown deletes only their own tracked IDs.

Validation passed 43 focused cleanup cases (30 offline and 13 PostgreSQL), followed
by 732 Google/OAuth/scheduler regressions with no skips. Ruff, all 226 Python files'
formatting, 214 application/test sources and 12 migration sources passed checks.
No schema, grant, private configuration or frontend changes were needed.

The optional [housekeeping task](#automatic-authentication-cleanup) now invokes this
committed helper after each limiter batch, with a separate deadline and failure
boundary. Cancellation stops the task even during a database operation and is
awaited before engine disposal. Enablement remains off by default; private
website configuration is unchanged.

The scheduling integration passed 397 cleanup regressions, including restricted
PostgreSQL tests, plus 22 health/readiness/client-lifecycle checks. Coverage verifies
serial operation, independent failures/deadlines, no immediate draining/retries,
shutdown during either operation, and real committed one-row batches in both
tables. A locked attempt times out without undoing limiter cleanup; releasing
the lock allows cleanup on the next scheduled pass while active rows survive.
Existing limiter rows are protected with locks; OAuth tests require an unused
test table and remove only their own tracked records. Lint, formatting and
application/migration typing passed. No migrations or new grants were needed.

### Validation and remaining release work

The Google-initiation limiter checkpoint passed all 4,499 backend tests, including
guarded PostgreSQL integration tests. The focused run passed 181 cases; coverage
includes concurrent starts, canonical peer identity, pending-attempt preservation,
failed accounting/creation/replacement commits, lock deadlines, other-operation
budget isolation, seven-purpose cleanup and safe migration downgrade refusal.
Ruff, formatting, application types and all 12 migration sources passed checks.
This backend slice did not change frontend code. Its following UI slice adds
the retry guidance described above; automated validation uses no live provider calls.

The Google retry-guidance UI slice passed all 685 frontend tests (331 API and
354 UI/hook), lint, TypeScript checking and the production build. Focused checks
passed 53 Google API tests and 80 hook/dialog tests. Coverage includes safe header
fallback, no navigation or automatic retries after 429, explicit successful retry,
timeout precedence, unmount cancellation and fresh email credentials/proofs after
Google denial. Backend code is unchanged by this UI slice.

The earlier Google backend checkpoint passed 2,924 tests, including opt-in guarded
PostgreSQL tests. The preceding frontend checkpoint passed 642 tests (307 API and
335 UI/hook cases), including Google access from both account dialogs.
Backend lint, formatting and typing checks, frontend lint, TypeScript and the
production build also passed. External provider operations are mocked in
automated tests. Coverage includes expiry/locking, single-use consumption,
rollback/commit ordering, cookies, bounded exchange, callback rejection,
destination validation, cancellation, retries, StrictMode and forged return hints.

The standard Uvicorn access-log filter removes callback query values, including
rejected callback subpaths. Hosting, reverse-proxy, custom access/error logging
need separate review. Pages has separately gated account-session and Google
start/callback forwarding, including validated OAuth/account cookies and fixed
return destinations. Hosted flow and logging validation remain outstanding.

Before public Google enablement, verify cleanup scheduling in the target
environment, complete broader provider/linking checks, upstream provider-method assurance,
partial-provider-session failure/cleanup review, and deployment/security/privacy
review. Cancellation cannot guarantee delivery of a cookie-clearing response to
a disconnected browser. Local success does not establish production readiness.
Rejected callback completion logs only a fixed stage and exception category;
token rejection logs only a category. Codes, token values, account identifiers,
provider error text and exception tracebacks are excluded from those diagnostics.

## Frontend registration API foundation

`signUpAccount` submits email, password, and CAPTCHA proof once. It requires
HTTP 202 and an accepted acknowledgement. Acceptance does not confirm that a new
account was created or an email was delivered.

`confirmAccountEmail` submits only email and the unchanged verification code.
It requires HTTP 200 and a confirmed acknowledgement. Confirmation does not
establish an application login.

Both helpers support caller-provided cancellation, disable redirects and caching,
and return only allowlisted status metadata. They do not persist credentials or
automatically retry. Mocked tests cover request fields, controlled errors,
malformed responses, unexpected statuses, and cancellation.

Sign-up 429 responses become a dedicated rate-limit error. Only integer
`Retry-After` seconds from 1 through 86,400 are accepted; missing, malformed,
oversized, unsupported date and out-of-range values use a safe fallback. Error
bodies are not parsed, and other statuses ignore the header. The existing status
region announces the quoted wait, using singular/plural seconds. It is a snapshot
from the failed attempt, with no live countdown, client lock or automatic retry;
the backend remains responsible for enforcement. Password clearing and fresh-proof
requirements apply, and rate limiting never advances to confirmation. Google access
and sign-in keep their existing contracts.

Email confirmation uses its own `AccountEmailConfirmationRateLimitedError` for HTTP
429 and validates the same 1–86,400 second range without reading the error body.
Missing or unsafe retry information uses fixed fallback text. Its hook reports a
static wait message through the existing accessible status region; no countdown or
automatic request is scheduled. The submitted code clears, a manual retry can use
a replacement code, and only a successful confirmation reveals "Continue to sign in".

Confirmation retry-feedback validation passed 86 registration/confirmation API
cases and 30 focused confirmation hook/form cases. The full frontend suite passed
574 cases (261 API and 313 UI/hook), plus lint, TypeScript and production build.
Tests cover header bounds/fallbacks, status isolation, safe messages, manual retry,
password/code clearing, proof renewal and no flow advance on failure. These
checks mock requests and send no registration emails.

The development account dialog switches between sign-in, registration, and
email confirmation without replacing its native modal shell. Registration has
one password field with a visibility toggle and a Turnstile check. Each proof is
consumed once; failed submissions require a fresh check. Confirmation reuses the
registration email and accepts a pasted or autofilled six-to-ten-digit code,
preserving leading zeros. Codes and passwords are cleared from their inputs when
submitted. The request hooks cancel after 15 seconds and on unmount, reject
duplicate submissions, and do not automatically retry.

After confirmation, an explicit "Continue to sign in" action opens a fresh
sign-in form with the email prefilled. It does not establish an application
session. Closing the dialog resets the flow and restores focus to its trigger.
Automated tests mock provider requests. Manual local checks on 2026-10-22
validated live registration, email delivery, code confirmation, separate sign-in,
refresh restoration, sign-out, and signing in again. Both backend endpoint flags
still default to false, and production registration is not enabled by these UI changes.

For local registration testing, enable `ACCOUNT_SIGN_UP_API_ENABLED=true` and
`ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED=true` in the ignored `backend/.env`, then
restart FastAPI. Keep Supabase's email provider, email confirmation, and CAPTCHA
protection enabled. The **Confirm signup** email template must contain
`{{ .Token }}` so the recipient can enter the code in the confirmation form.
Use a new email address you control; the generic registration acknowledgement
does not guarantee a new account or a delivered email.

The validated email-delivery setup uses Resend custom SMTP configured in
Supabase Auth, with a verified authentication sending subdomain, tracking left
unconfigured, and enforced TLS. SMTP credentials belong in Supabase's SMTP
settings, not in frontend variables or repository files. Resend processes the
recipient address and email content as part of delivery. Its documented storage
location is the United States; selecting an EU sending region does not change
that storage location. Provider data flows, retention, privacy notices, and
production deployment checks still require review before enabling public
registration. See [Resend's data-handling documentation](https://resend.com/security/gdpr).
Setup references:
[Supabase custom SMTP](https://supabase.com/docs/guides/auth/auth-smtp),
[email templates](https://supabase.com/docs/guides/auth/auth-email-templates), and
[Resend's Supabase SMTP guide](https://resend.com/docs/send-with-supabase-smtp).

## Account sign-out endpoint

`POST /api/v1/account/sign-out` signs out the current browser's application session.
`ACCOUNT_SIGN_OUT_API_ENABLED` defaults to `false` and is independent of the
sign-in and session-check flags. Keep it disabled until endpoint testing and
deployment checks are complete. The development frontend calls the route through
Vite's local API proxy; Cloudflare Pages forwarding has its own default-off gate.

```dotenv
ACCOUNT_SIGN_OUT_API_ENABLED=false
ACCOUNT_SIGN_OUT_TIMEOUT_SECONDS=15
```

The route requires exactly one trusted Origin before processing the cookie. It
accepts no client-supplied user or session ID. Missing or malformed account cookies
produce an empty 204 response and expire the configured account cookie without
database work. Correctly shaped cookies require an available database engine and
a successfully completed deletion transaction, including when the session is
already absent. Repeated sign-out therefore remains harmless and returns 204.

`delete_account_session` hashes the opaque browser credential and deletes only the
matching `app.account_sessions` row in a caller-owned transaction. It requires no
JWT verification, provider refresh, publishable key, signing-key cache, or token
decryption. Expired application sessions can also be deleted. The account profile,
other sessions for the same account, and sessions for other accounts remain
unchanged. The transaction wrapper returns only after commit and connection
release; the route clears the cookie afterward using its existing name, path,
Secure/HttpOnly/SameSite policy, and no Domain attribute.

All controlled responses use `Cache-Control: no-store`. Invalid Origins return
403. A disabled route, a missing engine for a correctly shaped cookie, database
failure, or timeout returns a generic 503 without setting or clearing the cookie.
The database-operation deadline defaults to 15 seconds, accepts 1–30 seconds,
and cancels stalled deletion. Failures and cancellation are not automatically
retried. A timeout or transport error can leave commit outcome uncertain; a later
request can repeat sign-out rather than assuming the deletion rolled back.

This operation invalidates the application cookie for subsequent database-backed
session lookups. It makes no Supabase logout request, does not revoke provider
access/refresh tokens, and does not cancel already authorized in-flight requests.
The Bearer-only `/api/v1/account/me` endpoint still verifies provider JWTs
independently. Do not describe this endpoint as provider-wide or all-device logout.

Unit tests cover token guards and hashed query targeting, transaction ordering,
rollback/error/cancellation propagation, Origin and feature gates, HTTPS and
development cookie deletion, unknown cookies, unavailable databases, generic
errors, and real deadline cancellation. Local PostgreSQL tests verify deletion
of active/expired sessions, idempotence, profile and cross-session isolation, and
savepoint rollback. Two HTTP integration cases verify committed deletion and
cookie clearing, rejection of a replayed deleted cookie, and repeated sign-out,
or restoration of the original rows without cookie clearing after a deliberate
SQL error before commit. Provider requests are blocked in these HTTP tests;
uncertain network failures during commit are not simulated.

## Account session endpoint

`POST /api/v1/account/session` authenticates an existing opaque account cookie;
it does not sign in or create a session. `ACCOUNT_SESSION_API_ENABLED` defaults
to `false`. Keep it disabled until abuse controls and deployment checks are ready.
The existing Bearer-only `GET /api/v1/account/me` contract is unchanged, and the
Cloudflare Pages account-session forwarding has its own default-off gate.

The endpoint requires exactly one Origin matching `CSRF_TRUSTED_ORIGINS` before
processing credentials. Missing, null, duplicate, or untrusted origins return 403
without changing cookies. With a trusted Origin, a disabled endpoint returns 503
without authenticating or changing cookies.

When enabled, the endpoint reads the configured account cookie and authenticates
through the transaction helper. Successful authentication commits before renewing
the cookie with the stored inactivity deadline. The JSON response contains only
`user_id`, `expires_at`, and `absolute_expires_at`; provider and browser tokens are
not returned in the response body. Current access credentials are verified, and
expired access credentials use the bounded provider refresh flow.

Missing or malformed cookies, unknown or expired application sessions, and explicit
provider credential rejection return a generic 401 and clear the account cookie.
Unavailable verification, missing application resources, provider outages, database
errors, and authentication timeouts return a generic 503 without replacing or
clearing the cookie. Origin failures, authentication failures, and successful
responses use `Cache-Control: no-store`. No automatic authentication retry is made.

`ACCOUNT_SESSION_AUTH_TIMEOUT_SECONDS` defaults to 15 and accepts 1 through 30.
It sets a cancellation deadline around authentication, including transaction
completion. The application shares its lifecycle-managed HTTP client between
signing-key downloads and provider refresh requests. Startup/shutdown tests cover
resource closure and clearing application-state references, including failures.

Offline HTTP tests mock the authentication transaction helper and cover request
guards, response/cookie contracts, temporary failures, missing resources, and
cancellation of stalled authentication. Local PostgreSQL HTTP tests exercise the
actual route, session services, encrypted storage, JWT verification, and signing-key
cache, with only provider HTTP responses mocked. Independent database connections
confirm committed updates. SQL errors injected at the pre-commit boundary return
503, restore the entire original session row, and send no replacement cookie.
Both current-token and refreshed-token paths are covered. These tests do not
contact Supabase or simulate an uncertain commit after a lost network connection.

## Provider refresh foundation

`SUPABASE_AUTH_PUBLISHABLE_KEY` is optional and documented in
`backend/.env.example`. Missing or empty environment values leave it unconfigured.
The setting requires the `sb_publishable_` prefix and a nonempty suffix, limits the
complete key to 512 printable ASCII characters without whitespace, and uses
`SecretStr` to mask ordinary display. These are configuration sanity checks, not
verification that the key belongs to the configured project.

The internal `refresh_account_tokens` adapter posts a refresh token to the
configured issuer's `/token?grant_type=refresh_token` endpoint using the publishable
key. It disables redirects, applies a five-second total request/body deadline,
and accepts only uncompressed JSON responses of at most 64 KiB. Returned access
and refresh tokens must be nonempty printable ASCII strings of at most 8,192
characters with a Bearer token type; both are wrapped in `SecretStr`.

Recognized credential-rejection codes on supported client-error responses produce
`AccountRefreshRejected`. Rate limits, server/transport failures, malformed
responses, and other errors produce generic `AccountRefreshUnavailable` errors
without provider response details. The adapter performs no automatic retries.
Caller cancellation propagates, and response streams close on failure or
cancellation. A returned token pair still requires identity verification.

`verify_refreshed_account_tokens` uses the existing JWT verifier and signing-key
cache, then requires both the verified account ID and provider session ID to match
the expected stored session. Expected IDs must come from server-side session
records, not browser-supplied ownership fields. Identity and expiry come from the
verified JWT, not other JSON fields in the refresh response. Invalid JWTs, identity
mismatches, and unavailable signing keys produce `AccountRefreshUnavailable`.
The opaque refresh token's ownership is not independently verified; both tokens
must originate from the same trusted provider exchange.

The HTTP adapter and JWT verification helper above do not write to the database
or extend application-session deadlines.
Tests use synthetic credentials, generated ES256 keys, mocked HTTP transport and
signing-key downloads, and no live Supabase requests. They cover response and token
bounds, error classification, deadlines, cancellation, forged signatures, identity
mismatches, and the adapter-to-verifier flow.

The internal `refresh_locked_account_tokens` helper decrypts a stored refresh
token, exchanges it once, and verifies the returned identity against the locked
session snapshot. It checks encryption, issuer, publishable-key, and key-cache
configuration before making the provider request. Unreadable or malformed stored
credentials produce `AccountRefreshUnavailable` before the exchange. Provider
rejection remains distinct, cancellation propagates, and no automatic retry is
performed. The result contains verified identity and masked replacement tokens;
this helper does not save credentials or complete session authentication. The
caller must retain the row lock and check application-session deadlines before
and after the exchange.

`store_verified_account_refresh` accepts that verified provider result within an
active caller-owned transaction. It checks account/provider identity, encrypts
both replacement tokens, and performs one guarded SQL update. Stored access and
refresh ciphertext and the previous access-token expiry must still match the
snapshot. Fresh database statement time must precede both application-session
deadlines and the new access-token expiry. A failed SQL guard returns no result
without changing the row.

Successful storage replaces both encrypted tokens and access-token expiry together
with last activity and inactivity expiry. Activity cannot move backward, and
inactivity expiry stays capped at the unchanged absolute deadline. Ownership,
browser-token hash, and other sessions remain unchanged. The returned authentication
result contains identity and session deadlines, with no provider tokens. The helper
does not commit or roll back; the caller must commit successfully before using the
result outside the transaction. Database errors propagate to the caller.

Offline tests cover configuration and encryption guards, exchange/verification
with generated signing keys, identity mismatches, provider rejection, outages,
rate limits, cancellation, and absence of automatic retries. Local PostgreSQL
tests cover encrypted replacement, inactivity caps, unchanged fields and other
accounts' rows, and rollback to the original credentials and activity. Stale
snapshots are simulated by changing one credential field in the test transaction;
expiry cases simulate the final SQL check at and one second after each deadline.
At the absolute boundary, inactivity expiry coincides with the absolute deadline
as required by the schema. These tests make no live provider requests.

The internal `authenticate_account_session` coordinator loads and locks the
application session, rejecting missing or expired sessions before any provider
request. A current stored access token uses the existing verification and activity
update service. An expired access token triggers one exchange, identity
verification, and guarded encrypted replacement. Verification failure on the
current-token path does not fall back to refresh. Rejection, unavailability,
cancellation, and database errors propagate without automatic retries.

The caller retains the row lock throughout verification, any bounded provider
request, and storage, and owns commit or rollback. The current-token path reloads
the same locked row to reuse the existing service. An authentication result must
be discarded if its transaction rolls back or commit fails. Holding the lock
during network work also occupies a database connection.

`authenticate_account_session_transaction` supplies a short transaction around
the coordinator. It returns identity only after successful commit and connection
release, so subsequent protected application work can use a separate transaction.
Authentication errors, cancellation, and database errors propagate without
automatic retries. The account-session HTTP endpoint uses this helper and renews
the cookie only after it returns successfully.

Offline tests model successful transaction completion, no authenticated result,
commit failure, authentication errors, and cancellation. PostgreSQL tests run
authentication as the restricted application role and use an independent
connection to confirm committed activity and replacement credentials. Rollback
cases cause a real SQL error after successful authentication writes and verify
that the entire original session row is restored. Both current-token and
refreshed-token paths are covered. Offline commit failure is mocked; these tests
do not simulate a lost connection during commit.

Offline coordinator tests cover branch selection, failure propagation, and caller
transaction ownership. Local PostgreSQL tests use generated signing/encryption
keys and mocked provider responses. They cover current and expired credentials,
unchanged data on provider failure, unrelated sessions, and caller rollback.
Concurrent tests confirm a real PostgreSQL lock wait: after the first request
commits, the waiter reuses its replacement credentials without another exchange.
If the first request rolls back, the waiter reloads the original credentials and
attempts recovery once. Mocked recovery either returns the active replacement
pair or rejects the credentials; rejection leaves the committed row unchanged.

These recovery tests model provider responses rather than verify live Supabase
reuse behavior. PostgreSQL rollback cannot undo provider-side token rotation, and
an uncertain database commit is not resolved by these tests. A later request must
reload committed state before attempting recovery; fresh sign-in may be required.

## Trusted proxy client addresses

All seven IP-based auth/guest limiter purposes use `app.client_ip.get_client_ip`.
By default it uses only the ASGI peer, normalizing IPv6 and mapped IPv4, and ignores
all forwarding headers. `AUTH_PROXY_TRUST_ENABLED=true` switches the resolver to a
single authenticated assertion with **no peer or standard-header fallback**:

| Setting | Backend | Pages server binding |
| --- | --- | --- |
| `AUTH_PROXY_TRUST_ENABLED` | Boolean, default `false` | Exact `true` to enable; unset/`false` disables |
| `AUTH_PROXY_SHARED_SECRET` | `SecretStr`, empty by default | Secret binding, never `VITE_*` |

Generate a dedicated random 32-byte key represented by 64 hexadecimal characters;
use the same value on both servers, separate from the limiter HMAC key. No key or
live setting is supplied by the repository. Keep the backend destination HTTPS
and redirects disabled; the secret is a bearer credential protected by TLS, not
a request signature or a user credential. A leaked key permits forged assertions
and requires coordinated rotation. Exclude these headers, cookies and raw IPs
from application/hosting logs; the existing access filter is not a blanket header
logging sanitizer.

`frontend/server/proxy-client-ip.ts` reads only the Pages ingress
`CF-Connecting-IP`, validates a single bounded IPv4/IPv6 address and sets
`X-AskM6-Client-IP` plus `X-AskM6-Proxy-Secret` from its private binding. It never
copies browser-supplied custom assertions, Authorization, Forwarded or
X-Forwarded-For. Missing/invalid source, secret or an unrecognized flag returns
a fixed no-store 503 before fetching and without changing cookies. Disabled mode
emits neither header. The session proxy filters both headers from replies.

FastAPI accepts exactly one of each custom header, validates the secret format,
compares decoded key bytes in constant time and canonicalizes the supplied IP.
Missing/forged/duplicate/combined/malformed assertions raise the existing fixed
client-address error, producing a controlled 503 at the limiter boundary before
accounting/provider work. Fingerprint namespaces, rolling windows, stored HMAC
keys and account/session authentication remain unchanged. Shared visitor IPs share
a purpose's budget; distinct visitor IPs behind one proxy receive separate budgets.

This is **not global backend access control**. Only routes using these limiter
keys require the assertion in enabled mode. Session lookup currently has no IP
limiter; its gated Pages helper emits the contract for subsequent auth-route
integration. Other routes still enforce their own authentication and Origin
rules. Public auth controls remain disabled; the guest proxy below has its own
default-off gate and requires the assertion whenever enabled.

Before enabling, verify that the actual Pages ingress supplies an unspoofable
visitor address, including custom-domain and preview routing. Cloudflare documents
[different Worker-subrequest and Pseudo IPv4 behaviour](https://developers.cloudflare.com/fundamentals/reference/http-headers/):
same-zone Workers can affect the source, cross-zone requests can use a shared
sentinel, and header-removal/overwrite transforms can change it. Do not run this
producer on a directly reachable generic server that trusts a browser's CF header.
The dedicated secret authenticates the Pages-to-backend hop; it does not establish
the integrity of an incorrectly configured Pages ingress. Missing source headers
must be fixed at ingress, not replaced with X-Forwarded-For or the Render peer.
Keep [Uvicorn proxy-header rewriting disabled](https://uvicorn.dev/settings/)
(`--no-proxy-headers`) for this application-level contract. The repository tests
use synthetic ingress headers and isolated workerd; they do not validate live
Cloudflare/Render routing, TLS termination, logs or secret provisioning.

Validation: the focused offline resolver/fingerprint/sign-in guards passed 386
tests. The broader guarded configuration/rate-limiter run passed 1,233 tests,
including all seven PostgreSQL limiter route suites and Uvicorn boundary tests
(these runs overlap). The complete frontend pipeline passed 512 API/proxy tests,
13 workerd tests and 356 UI tests, plus lint, strict types and production build.
Backend lint and mypy passed; private-config/build audits and documentation links
passed. No live proxy secret, trust flag, schema or hosting setting was changed.

## Guest-session Pages proxy

The Pages handler dispatches exact `POST /api/v1/guest/session` to
`frontend/server/guest-session-proxy.ts`. Its independent
`GUEST_SESSION_PROXY_ENABLED` server binding must be exactly `true`; other/unset
values return 404 without fetching. Enabled requests also require the configured
HTTPS backend/public origins, matching URL/Origin and same-origin Fetch Metadata
when present, plus `AUTH_PROXY_TRUST_ENABLED=true` and a valid private proxy key
and ingress IP. Enable backend trusted-IP mode with the same key before enabling
this route. No live binding is configured by adding the implementation.

The total 20-second deadline covers input, fetch and output; cancellation aborts
work and returns no cookie, even if a late transport ignores its signal. There
are no retries or redirect following. Limits are 16 KiB actual request bytes and
4 KiB actual response bytes. Declared lengths must be valid and match actual
bytes. Workers' decoded chunked input is accepted only without Content-Length;
other/combined framing, queries, fragments and compressed input are rejected.
The validated JSON is rebuilt, and incoming framing headers are never copied.
See the [Workers body/length contract](https://developers.cloudflare.com/workers/runtime-apis/request/#set-the-content-length-header).

Empty input carries no proof. Nonempty input requires JSON with only optional
`turnstile_token` (null or 1–2,048 Unicode characters, valid UTF-8). Arrays,
unknown fields and invalid input fail before contacting the backend. Only the
validated `__Host-askm6_guest` cookie is forwarded; duplicate/oversized cookie
headers fail, missing/malformed/development credentials are omitted, and account,
OAuth, Authorization and browser-supplied IP assertions are stripped. The server
adds its authenticated visitor-IP assertion. The backend retains responsibility
for guest refresh/create decisions, Turnstile verification and creation budgets.

Success requires exactly `status: "ok"` and future UTC `expires_at`, plus exactly
one correctly scoped secure/HttpOnly/SameSite=Lax guest cookie with a 43-character
opaque token and matching expiry to whole seconds. A newly created token may
differ from an expired/unknown incoming credential. No Domain, Max-Age, unknown
or duplicate cookie attributes are accepted. Metadata and cookie are rebuilt;
upstream CORS, redirects, unrelated cookies and private headers are dropped.

All replies are no-store. Errors preserve the existing browser cookie. Only an
exact 403 `X-Guest-Verification: required` signals a new challenge; 429 forwards
only validated Retry-After delta-seconds from 1–86,400. Backend 400/413/415/503
become fixed safe errors; unexpected statuses, invalid success contracts,
network failures and timeouts become 502. No backend error body is forwarded.

The account-session proxy reuses the extracted origin policy, cookie parser,
UTC validation and bounded stream reader while retaining its own empty-body and
renewal/deletion contracts. Public UI/auth feature flags and live settings remain
unchanged. Tests exercise the real Pages handler in Node and isolated workerd,
including native chunked bodies and Set-Cookie APIs; live deployment and automatic
browser-disconnect delivery are still separate verification gates.

Validation: all 630 API/proxy tests, 18 workerd tests and 356 UI tests passed,
along with frontend lint, strict types and production build. The unchanged
backend guest parsing/cookie/HTTP/refresh/creation-limit contracts passed 89 tests,
including guarded PostgreSQL checks. No new dependency, migration or private
configuration was introduced.

## Email sign-in Pages proxy

Exact `POST /api/v1/account/sign-in` is independently gated by the server-only
`ACCOUNT_SIGN_IN_PROXY_ENABLED=true` binding. Unset/other values return 404;
backend `ACCOUNT_SIGN_IN_API_ENABLED` remains independent. The same canonical
HTTPS origins, request URL/Origin and Fetch Metadata checks apply as for guest
creation. Proxy trust must be explicitly enabled with the matching backend secret
and verified ingress IP before use. Public controls and live bindings stay off.

Only JSON containing required `email` (1–320 Unicode characters) and `password`
(1–1,024) plus optional `captcha_token` is accepted. Credentials retain exact case,
whitespace and Unicode; no email-format or password-policy rule is added by the
proxy. Provided proof must be null or 1–2,048 printable non-space ASCII characters.
Omitted/null proof reaches the backend, which enforces verification and its
attempt budget. Invalid UTF-8, unknown fields and invalid schemas fail before
forwarding. Edge-rejected requests do not reach backend accounting; forwarded
attempts retain the backend's accounting-before-authentication policy.

Limits are 16 KiB actual input and 4 KiB actual output with a 20-second total
deadline covering body reading, fetch and response consumption. Decoded chunked
input is accepted without Content-Length; ambiguous framing and compressed input
are rejected. Validated JSON is rebuilt and incoming framing headers are omitted.
Credentials are submitted once, with no redirect following or automatic retry.
Cancellation produces no browser cookie, including after a late transport result.

Any `__Host-askm6_account` cookie presence returns fixed no-store 409 before
parsing credentials or fetching, including stale, malformed, empty or quoted-empty
values. Duplicate/oversized cookie headers return 400. This preserves explicit
sign-out before switching accounts rather than silently omitting an invalid
credential. Guest, OAuth, development and unrelated cookies and Authorization
are never forwarded or cleared; guest-history transfer remains separate work.
Only fixed JSON headers, configured Origin and authenticated visitor-IP headers
accompany the validated credentials.

Success must contain exactly a canonical-shaped UUID `user_id`, future UTC idle
expiry and absolute expiry no earlier than idle expiry. Metadata validation is
shared with account-session lookup. A newly issued account cookie must be the
only Set-Cookie, carry a correctly shaped opaque token and match idle expiry to
whole seconds, with Path=/, Secure, HttpOnly and SameSite=Lax and no Domain,
Max-Age, duplicate or unknown attributes. Lookup still requires renewal of the
same incoming token; sign-in validates a new token without exposing it in JSON.

All replies are no-store. 401 is a fixed rejection without cookie deletion; 409
requires sign-out; only exact 403 `X-Account-Verification: required` signals a
challenge. 429 preserves only validated Retry-After delta-seconds 1–86,400.
400/413/415/503 become fixed safe responses; unexpected statuses, redirects,
network failures and malformed success/cookie contracts become 502. Upstream
error bodies, CORS, Location, secrets and cookies on errors are not forwarded.

Tests exercise the real Pages handler in Node and isolated workerd, including
actual credential-body bytes and cookie preservation. Hosted ingress/TLS/logging,
secret provisioning and automatic browser-disconnect delivery remain separate
deployment checks. No dependencies, schema or private/live configuration changed.

Validation: the final frontend pipeline passed 762 API/proxy tests, 24 workerd
tests and 356 UI tests, plus lint, strict types and production build. Existing
backend sign-in parsing, sign-out-first guards, account cookies and PostgreSQL
limits passed 139 tests. The shared metadata validator also rejects UUID strings
with trailing newlines. These checks use synthetic credentials/provider mocks;
they do not establish deployed end-to-end behavior.

## Sign-up Pages proxy

Exact `POST /api/v1/account/sign-up` has an independent server-only
`ACCOUNT_SIGN_UP_PROXY_ENABLED=true` gate; unset/other values return 404.
Backend `ACCOUNT_SIGN_UP_API_ENABLED` remains separate. Canonical HTTPS origins,
matching request URL/Origin, same-origin Fetch Metadata when present and explicit
trusted-IP mode with a matching private key/verified ingress IP are required.
No public controls or live settings are enabled by this implementation.

Sign-up and sign-in share `account-credential-proxy-request.ts`: 16 KiB actual
request limit, JSON only, required email/password bounded at 320/1,024 Unicode
characters, exact credential preservation and no unknown fields. Sign-up also
requires literal `accepted: true` and the current Terms revision. Sign-up requires
a 1–2,048-character printable non-space ASCII CAPTCHA proof; sign-in retains its
optional/null proof contract so the backend can require verification. No email
normalization, password policy or client-supplied identity/redirect is added.
Malformed input fails before backend accounting; forwarded requests remain subject
to backend IP accounting and Supabase verification. Decoded chunked input is
bounded and rebuilt without forwarding incoming framing headers.

The proxy sends only fixed JSON headers, the configured Origin, authenticated
visitor-IP assertion and validated credentials. It never forwards browser cookies
or Authorization. An existing account/guest cookie is preserved; registration
does not sign in, switch accounts, transfer guest data or create a local session.

Acceptance requires 202, bounded UTF-8 JSON within 4 KiB, exactly `status: accepted`
and the backend's generic message asking the user to check email for a verification
code. Success additionally requires exactly one bounded, Secure/HttpOnly,
SameSite=Lax, root-scoped `__Host-askm6_signup_terms` receipt with at most one
hour lifetime. Unexpected cookies or identity/provider fields fail with 502. The
returned acceptance is rebuilt from fixed values, and never confirms
whether the email already has an account. All responses are no-store; only a
validated successful receipt may set a cookie. Backend 400/413/415/503 become
fixed safe messages; exact 403
`X-Account-Verification: required` and bounded 429 Retry-After seconds (1–86,400)
are preserved. Other statuses, redirects, transport failures and invalid success
contracts become 502; provider details and unrelated headers are dropped.

A 20-second total deadline includes request/fetch/response consumption, with
cancellation and stream/timer/listener cleanup. There are no retries or redirect
following. A failed/cancelled request cannot return late acceptance, but cannot
undo a registration/email already processed by the provider. Retrying is manual
with a fresh proof. Tests use synthetic credentials and mocked providers, including
native Workers streams and explicit post-ingress missing/empty-IP fixtures.
Email-confirmation forwarding has its own gate below; hosted deployment checks
remain pending.

Validation: the full Linux Node 24 frontend pipeline passed 942 API/proxy tests,
36 workerd tests and 356 UI tests, plus lint, strict TypeScript and production
build. Windows focused sign-up/sign-in tests passed 231 cases and the six new
Workers cases passed. Existing backend sign-up request/response/provider/route/
configuration and PostgreSQL limiter contracts passed 224 tests. Tests use mocks
and synthetic credentials; no live registration/email was sent. No dependency,
schema, private configuration or live feature-flag changes were introduced.

## Email-confirmation Pages proxy

Exact `POST /api/v1/account/confirm-email` uses the independent server-only
`ACCOUNT_EMAIL_CONFIRMATION_PROXY_ENABLED=true` gate; unset/other values return
404. Backend `ACCOUNT_EMAIL_CONFIRMATION_API_ENABLED` remains separate. The
shared canonical HTTPS origins, matching request URL/Origin and same-origin
Fetch Metadata rules apply, with mandatory trusted-IP mode, a valid shared
secret and verified ingress address. Public authentication remains disabled.

`account-email-confirmation-proxy.ts` accepts only JSON with email (1–320 Unicode
characters) and code (6–10 ASCII digits), bounded to 4 KiB actual UTF-8 input.
Email case/whitespace/Unicode and leading code zeros are preserved; the backend
alone verifies the code. Unknown fields, malformed UTF-8, queries, fragments,
compression, ambiguous framing and mismatched declared lengths are rejected.
Decoded chunked input is bounded and rebuilt without forwarding browser framing.

The upstream request contains only validated email/code, fixed JSON headers,
configured Origin and the authenticated visitor-IP assertion. Only a bounded
signup Terms receipt may be forwarded from browser cookies; Authorization,
client-supplied identities and unrelated forwarding headers are omitted. This confirms email without creating a local login, replacing an
account or transferring guest data. A matching registration receipt may be
reissued with the provider-confirmed subject, preserving its original time and
expiry; invalid receipts are cleared. Sign-in remains
a separate explicit action.

Success requires HTTP 200 and at most 4 KiB of valid UTF-8 JSON containing exactly
`status: confirmed` and `message: Email confirmed. You can now sign in.` Any
unexpected Set-Cookie, extra identity/provider fields or changed response
contract fails with 502. With an incoming receipt, success must return exactly
one validated receipt rotation/deletion; without one no cookies are allowed.
Only the fixed success body is returned. Backend 400/403/413/415/
503 become safe fixed messages; 429 retains only bounded Retry-After seconds
(1–86,400). CAPTCHA headers are not part of this endpoint. Other statuses,
redirects, network errors and malformed success become 502. All replies are
no-store, without provider details or unrelated headers; only the validated
receipt rotation/deletion may change a cookie.

A 20-second total deadline includes body reading, fetch and response consumption.
Client cancellation and deadline expiry abort upstream work, cancel streams and
clean up timers/listeners; late success cannot reach the browser. There are no
automatic retries or redirect following. Cancellation cannot undo confirmation
already processed by Supabase; a lost reply does not establish that the code
remains unused. Tests use synthetic codes and mocked providers; no live email,
account changes, deployment or private configuration changes are made.

Validation: 104 focused Node proxy tests and six native Workers cases passed.
The complete Linux Node 24 frontend run passed 1,046 API/proxy tests, 42 Workers
tests and 356 UI tests, with lint, strict TypeScript and production build passing.
Existing backend confirmation adapter/request/response/configuration/route and
local PostgreSQL limiter contracts passed 241 tests. Private-file, configured-secret,
documentation-link and whitespace audits passed. These results validate mocked
transport contracts; hosted authentication still requires deployment checks.

## Password-recovery request Pages proxy

Exact `POST /api/v1/account/password-recovery` is independently gated by the
server-only `ACCOUNT_PASSWORD_RECOVERY_PROXY_ENABLED=true`; unset/other values
return 404. Backend `ACCOUNT_PASSWORD_RECOVERY_API_ENABLED` remains separate.
Shared canonical HTTPS origins, matching request URL/Origin, same-origin Fetch
Metadata when present, explicit trusted-IP mode, a valid private shared key and
verified ingress address are required. No public access or live setting is enabled.

`account-password-recovery-proxy.ts` accepts only email and CAPTCHA proof, bounded
to 16 KiB actual UTF-8 JSON. Email is 1–320 Unicode characters; the required proof
is 1–2,048 printable non-space ASCII characters. Case, whitespace and Unicode in
the email are preserved; only the backend/provider verifies credentials. Unknown
fields (including passwords, reset codes, identities and redirects), malformed
UTF-8/JSON, query/fragment, compression, ambiguous framing and mismatched declared
lengths fail before upstream work. Decoded chunked input is bounded and rebuilt.

The upstream request contains only validated email/proof, fixed JSON headers,
configured Origin and an authenticated visitor-IP assertion. Browser cookies,
Authorization and unrelated/forged forwarding headers are omitted. No response
sets or clears a browser cookie; requesting recovery does not sign in, change a
password, invalidate application sessions or transfer guest history.

Acceptance requires 202 with at most 4 KiB of valid UTF-8 JSON containing exactly
`status: accepted` and the fixed message asking the user to check email for the
next steps if recovery can proceed. This confirms neither account existence nor
email delivery. Success with any visible Set-Cookie or identity/provider field
fails with 502. Backend 400/413/415/503 become controlled messages; exact 403
`X-Account-Verification: required` and bounded 429 Retry-After seconds (1–86,400)
are preserved. Other statuses, redirects, transport errors and malformed success
become 502. All replies are no-store and omit private details/unrelated headers.

A 20-second total deadline covers request input, fetch and response reading.
Cancellation aborts upstream work, cleans up streams/timers/listeners and prevents
late acceptance; it cannot recall an email already sent. Requests are never
automatically retried and redirects are not followed. Any retry is a separate
explicit action with a fresh proof. Tests use synthetic credentials and mocked
providers. Password-reset forwarding has its own gate below; hosted deployment
validation remains pending. These tests send no emails and change no live accounts.

Validation: 101 focused proxy tests and six native Workers cases passed. The
full Linux Node 24 frontend pipeline passed 1,147 API/proxy tests, 48 Workers tests
and 356 UI tests, plus lint, strict TypeScript and production build. Existing
backend recovery adapter/request/response/configuration/route and guarded local
PostgreSQL limiter contracts passed 234 tests. Diff/privacy and documentation-link
audits passed. This validates mocked transport contracts, not hosted email delivery.

## Password-reset Pages proxy

Exact `POST /api/v1/account/password-reset` uses the independent server-only
`ACCOUNT_PASSWORD_RESET_PROXY_ENABLED=true` gate; unset/other values return 404.
Backend `ACCOUNT_PASSWORD_RESET_API_ENABLED` remains separate. Shared canonical
HTTPS origins, matching request URL/Origin, same-origin Fetch Metadata when
present and mandatory trusted-IP mode/private shared key/verified ingress apply.
Public authentication remains disabled.

`account-password-reset-proxy.ts` accepts only email (1–320 Unicode characters),
code (6–10 ASCII digits) and new_password (1–1,024 Unicode characters), within
16 KiB actual UTF-8 JSON. It preserves password characters, email case/whitespace
and code zeros. Backend/provider verification owns code validity and password
strength; no password normalization or extra CAPTCHA is introduced. Invalid
UTF-8/JSON, extra fields, queries/fragments, compression, ambiguous framing and
mismatched lengths fail before upstream work. Decoded chunked input is bounded
and rebuilt without forwarding incoming framing headers.

Only validated email/code/new password, fixed JSON headers, configured Origin and
the authenticated visitor-IP assertion reach FastAPI. Browser Cookie,
Authorization and client-supplied identities are omitted. Completion requires 200
with at most 4 KiB of valid UTF-8 JSON containing exactly `status: completed` and
`message: Password reset completed. Sign in with your new password.` Extra
identity/provider fields, changed messages or any visible Set-Cookie fail with
502. The backend returns completion only after recovery verification, password
update, temporary provider-session cleanup and committed account-session
invalidation; the proxy does not perform those operations independently.

Reset does not create a login or clear/change browser cookies. A later session
check may clear an invalidated account cookie only after backend confirmation;
the reset email can belong to a different account than the browser's current
cookie. Guest/OAuth cookies remain untouched and no history transfer occurs.
Backend 400/403/413/415/503 become safe fixed messages. 429 preserves only bounded
Retry-After seconds (1–86,400), without CAPTCHA signals. Unexpected statuses,
redirects, network failures and malformed success become 502. All replies are
no-store and omit private credentials/provider details and unrelated headers.

A 20-second total deadline covers request reading, fetch and response consumption.
Cancellation aborts upstream work, cleans up streams/timers/listeners and prevents
late success. There are no automatic retries or redirect following. A failure can
occur after the provider has changed the password; cancellation/rollback cannot
undo that change or establish whether a recovery code remains usable. Tests use
synthetic credentials and mocked providers. Google start has its own proxy below;
callback forwarding is independently gated below; hosted flow validation remains pending.
No live account is changed by tests.

Validation: 110 focused proxy cases and seven native Workers scenarios passed,
including mocked recovery/reset followed by backend-confirmed session rejection
and cookie clearing. The full Linux Node 24 frontend run passed 1,257 API/proxy,
55 Workers and 356 UI tests; lint, strict TypeScript and production build passed.
Existing reset/verification/password-update/provider-cleanup/session-invalidation
contracts and guarded PostgreSQL integration checks passed 562 tests. Diff/privacy
and documentation audits passed. These mocked transport and local database
checks do not establish hosted password-reset behavior.

## Google-start Pages proxy

Exact `POST /api/v1/account/google/start` has the independent server-only
`ACCOUNT_GOOGLE_START_PROXY_ENABLED=true` gate; unset/other values return 404.
Backend `ACCOUNT_GOOGLE_OAUTH_API_ENABLED` remains separate. Pages additionally
requires `SUPABASE_AUTH_ISSUER` as a canonical HTTPS URL ending exactly in
`/auth/v1`, without credentials, trailing slash, query or fragment. This server
binding is separate from the development UI's `VITE_SUPABASE_AUTH_ISSUER`; no
provider key belongs in the browser bundle. Existing HTTPS public/backend origin,
actual URL/Origin, same-origin Fetch Metadata and mandatory trusted-IP assertion
rules apply. No live flag or public control is enabled by this implementation.

`account-google-start-proxy.ts` accepts only an empty POST without query/fragment,
compression, nonzero/ambiguous Content-Length or Transfer-Encoding. A declared-zero
stream must reach actual EOF before forwarding. Presence of any account cookie,
including stale/empty/malformed values, requires explicit sign-out and returns
409 before starting/replacing an OAuth attempt. Ambiguous account cookies and
cookie headers above 8 KiB are rejected.

Only `__Host-askm6_oauth` entries from the browser reach FastAPI, alongside fixed
Accept/Origin headers and an authenticated visitor-IP assertion. Authorization,
guest/account/development cookies and unrelated forwarding headers are omitted.
Duplicate/malformed OAuth bindings are preserved for the backend's strict rejection
and confirmed clearing rather than silently omitted as a new attempt. Filtering
preserves value whitespace before cookie separators despite HTTP field trimming.

HTTP 200 requires at most 4 KiB of uncompressed UTF-8 JSON with exactly
`authorization_url` and a future valid UTC `expires_at`. The destination must
match the configured issuer's `/auth/v1/authorize`, with four unique parameters:
`provider=google`, `redirect_to=<AUTH_PUBLIC_ORIGIN>/api/v1/account/google/callback`,
a 43-character base64url code challenge and `code_challenge_method=s256`.
Credentials, fragments, alternate providers/callbacks, duplicate/extra parameters
and identity/provider-token fields fail closed. The validated URL is rebuilt
from fixed parameters; the proxy neither navigates nor follows redirects.

Success must also carry exactly one secure, HttpOnly, host-only, root-path,
SameSite=Lax OAuth cookie with a valid opaque token, no Max-Age and an expiry
matching the metadata to the second. Only that normalized cookie is returned,
after the backend's pending-attempt transaction has committed. It may replace the
previous browser binding; it does not create an authenticated account session.

Backend 400 may clear only a validated OAuth cookie with Max-Age=0. Invalid or
unrelated clearing cookies become 502. Other 403/409/429/503 replies preserve all
browser cookies and use safe fixed messages; only 429 retains bounded Retry-After
seconds (1–86,400). Unexpected statuses, redirects, transport errors and malformed
success become 502. Replies are no-store/no-referrer, without private bodies,
Location, echoed assertions or unrelated headers. The 20-second total deadline
covers input EOF, fetch and metadata consumption; cancellation cleans up streams,
timers/listeners and cannot return a late URL/cookie. There are no retries. A
failed reply cannot undo an attempt creation/replacement already committed.

Callback forwarding has its own gate below, and public Google controls remain
disabled. Enabling this start proxy alone does not establish a hosted login flow;
the callback gate, issuer/callback alignment and ingress/deployment checks must
be completed first. Tests use synthetic PKCE/binding values and mocked providers;
no Google/Supabase requests or account changes occur during these checks.

Validation: 124 focused Node proxy tests and seven native Workers scenarios
passed, including malformed/duplicate binding preservation and backend-confirmed
clearing. The full Linux Node 24 pipeline passed 1,381 API/proxy, 62 Workers and
356 UI tests; lint, strict TypeScript and production build passed. Existing
Google-start, authorization URL, OAuth cookie/material/transaction and guarded
PostgreSQL attempt/rate-limit contracts passed 219 tests. Diff/private-file,
configured-secret and documentation-link audits passed. These checks validate
mocked proxy transport and local persistence, not a hosted Google login flow.

## Google-callback Pages proxy

`GET /api/v1/account/google/callback` uses the independent server-only
`ACCOUNT_GOOGLE_CALLBACK_PROXY_ENABLED=true` gate; unset/other values return 404.
Backend `ACCOUNT_GOOGLE_OAUTH_API_ENABLED` remains separate. Canonical distinct
HTTPS API/public origins are required, and the actual request URL must match the
public origin. Forwarded Host cannot authorize a preview deployment. A provider
callback is a cross-site navigation, so it does not require a trusted Origin or
visitor-IP assertion; FastAPI verifies the browser binding, PKCE and provider
identity. Origin/Authorization/proxy-secret/IP headers are not forwarded.

`account-google-callback-proxy.ts` accepts one code parameter within 4 KiB of
printable ASCII query, with strict percent decoding and a 1–1,024-character
printable ASCII decoded code. Duplicate/unknown fields, malformed encodings,
fragments, callback suffix paths, body/framing/compression errors and missing
binding are rejected before exchange. The code is rebuilt as a single encoded
parameter for the fixed backend callback, never used as a redirect destination.
Only the bounded `__Host-askm6_oauth` cookie entries reach FastAPI; malformed or
duplicate bindings retain their evidence for backend rejection. Shared OAuth
cookie selection/validation now lives in `account-oauth-proxy-cookies.ts`.

Any account-cookie presence returns fixed `sign-out-required` before exchange;
ambiguous cookie headers return `rejected`. Local rejections preserve all cookies,
including the pending binding, which a subsequent explicit start can replace or
have the backend clear. They return only a fixed home-page outcome fragment,
without echoing callback credentials. Invalid deployment configuration, host or
method returns controlled no-store errors; other methods receive Allow: GET.

Backend completion requires an empty 303 to exactly
`<AUTH_PUBLIC_ORIGIN>/#google-sign-in=success|rejected|unavailable|sign-out-required`.
No alternate host/path/query/fragment spelling, redirect chaining or body is
accepted. Success requires exactly two separate Set-Cookie fields: validated
OAuth deletion and one unexpired secure HttpOnly root-path SameSite=Lax host-only
account cookie, without Max-Age. Other outcomes require exactly OAuth deletion,
with no account/guest/unrelated cookie. Duplicate or malformed fields reject the
whole response without changing browser cookies. Each cookie is validated alone
and appended separately so Expires commas cannot collapse the success pair.

A disabled backend's 503 may clear only a validated OAuth cookie and returns a
controlled JSON error; its body is discarded. Network failure, unexpected replies
and cancellation return the fixed `unavailable` fragment without cookie changes.
The proxy follows no redirects and performs no automatic retry/code replay. Its
20-second deadline covers input EOF, fetch and redirect-body EOF; streams,
timers/listeners are cleaned up and late cookies are discarded. Failure cannot
undo provider operations or a callback transaction already committed. Every
reply is no-store/no-referrer, without raw codes, provider bodies or echoed headers.

Native runtime tests use an explicit manual-redirect outbound mock adapter:
Miniflare's default fetchMock Node transport follows redirects even when workerd
requests manual handling. The adapter exposes the actual 303 and separate cookie
fields, with network access disabled. Empty redirect fixtures match FastAPI's
Content-Length: 0 behavior. A mocked start/callback/session-check/sign-out sequence
exercises the complete proxy boundary; it does not establish live hosted login.
Public controls remain disabled and deployment/ingress/logging checks are pending.

Validation: focused callback/start Node tests passed 220 cases (96 callback,
124 start), and seven native callback scenarios passed. The complete Linux Node
24 pipeline passed 1,477 API/proxy, 69 Workers and 356 UI tests, plus lint, strict
TypeScript and production build. Existing Google/OAuth callback, exchange,
single-use attempts, cleanup, logging and guarded PostgreSQL contracts passed
746 tests. Diff/private-file, configured-secret and documentation audits passed.
No live provider call, account change, private setting or deployment was made.

Combined checkpoint validation also passed all 4,807 backend tests: 3,751 offline
cases and 1,056 guarded local PostgreSQL integration cases. Ruff lint/format,
strict typing of 218 application/test sources and 12 migration sources passed.
All 108 public frontend files still match the Linux snapshot that passed 1,902
tests, lint, strict TypeScript and production build. Full diff review corrected
stale deployment descriptions; private configuration remains ignored and the
public authentication gates remain disabled by default. Hosted end-to-end and
logging/ingress validation are still required before public enablement.

## Account sign-out Pages proxy

Exact `POST /api/v1/account/sign-out` uses an independent server-only
`ACCOUNT_SIGN_OUT_PROXY_ENABLED=true` gate; unset/other values return 404.
Backend `ACCOUNT_SIGN_OUT_API_ENABLED` is separate. The shared canonical HTTPS
origins, request URL/Origin and Fetch Metadata rules apply. Only an empty request
without query, fragment, compression, nonzero/ambiguous Content-Length or
Transfer-Encoding is accepted. Workers' declared-zero stream must reach actual
EOF before forwarding; an unfinished zero-byte chunk is insufficient.

Only a correctly shaped `__Host-askm6_account` cookie is forwarded. Missing,
malformed, empty and development credentials are omitted so the backend can
confirm safe clearing; duplicate/oversized cookie headers fail before fetching.
Guest/OAuth/development cookies and Authorization are neither forwarded nor
cleared. The optional authenticated visitor-IP assertion follows session lookup's
settings; sign-out has no IP limiter. Enabled but invalid proxy configuration
fails closed without a deletion cookie.

Success requires an empty backend 204 and exactly one correctly scoped account
clearing cookie: empty or quoted-empty value, Max-Age=0, canonical expiry syntax,
Path=/, Secure, HttpOnly, SameSite=Lax and no Domain, duplicate/unknown attributes
or unrelated cookies. Nonzero/combined response lengths, Transfer-Encoding,
compression or non-EOF response streams fail validation. The proxy constructs
one canonical account deletion cookie with epoch expiry and returns an empty
no-store 204. It does not blindly forward Set-Cookie or Content-Type.

403/503 become fixed safe errors; other statuses, redirects, malformed success
contracts and transport failures become 502, with no cookie changes. A 20-second
total deadline includes input confirmation, fetch and checking an empty response.
Cancellation/late responses cannot return a clearing cookie. There are no retries
or redirect following; streams/timers/listeners are cleaned up. Cancellation or
network failure does not promise rollback of deletion already committed by the
backend. Manual retry or a later session check can resolve uncertain browser state.

This signs out only the current local application session. The backend commits
its deletion before returning 204 for a valid token; absent/malformed tokens need
no database deletion. It does not revoke Supabase provider sessions or other local
account sessions. No dependency, schema, live setting, public control or private
configuration is changed. The shared empty-body and clearing-cookie helpers also
retain existing account-session lookup behaviour.

Validation: the final frontend pipeline passed 843 API/proxy tests, 30 isolated
workerd tests and 356 UI tests, plus lint, strict types and production build.
The backend sign-out/cookie/committed-deletion contracts passed 84 tests, including
guarded PostgreSQL. Runtime coverage includes a complete mocked email sign-in,
session-check and sign-out cycle; this does not establish live hosted behaviour.

Checkpoint-wide validation passed the complete 4,807-test backend suite with
guarded PostgreSQL integration enabled, backend lint/format and app/test/migration
type checks, and the full 1,229-test frontend pipeline with lint/types/build.
Private-file and configured-secret audits passed for the exact 28-file scope
and generated browser assets. Hosted authentication remains disabled by default.

## Account-session proxy request policy

`frontend/server/account-session-proxy-policy.ts` supplies the routing policy used
by the Pages handler through the forwarding helper. It does not authenticate
users. Pages permits `GET /api/v1/health` by default; an explicit flag can also
permit only `POST /api/v1/account/session`, subject to every policy/transport check.

The policy accepts only `POST /api/v1/account/session` when
`AUTH_SESSION_PROXY_ENABLED` is exactly `true`. Missing/other values and all other
routes return no-store 404; unsupported methods return 405 with `Allow: POST`.
Its server environment inputs are `API_ORIGIN` and `AUTH_PUBLIC_ORIGIN`, both
canonical HTTPS origins (an optional trailing slash is accepted). Credentials,
paths, queries, fragments, whitespace-normalized spellings and a backend origin
equal to the frontend origin are rejected with 503. These are server-side Pages
bindings, not browser `VITE_` settings. Leave the flag unset or false until the
target runtime and deployment gates have been verified. No live binding is set
by adding this code. The backend's session feature flag is independent.

The actual request URL origin and its single Origin header must match the
configured public origin exactly. Combined/duplicate origins fail. Fetch Metadata
may be absent for nonbrowser clients; when present, `Sec-Fetch-Site` must be
`same-origin`. Forwarded/Host headers cannot authorize another host or a preview
deployment. These checks protect a routing boundary; they do not establish a user.

This endpoint has no input payload: queries, fragments, nonzero/ambiguous
Content-Length, Transfer-Encoding and undeclared body streams are rejected with
400. Workers represents even an empty POST as a readable stream with explicit
Content-Length: 0. Only that declared-zero form may reach the transport's bounded
EOF check; any supplied bytes or ambiguous chunk are rejected before fetching.
The header alone is never trusted to prove emptiness. An allowed plan contains only the
fixed backend session URL and public origin, never copied browser headers,
credentials or client-supplied destinations. The policy makes no network calls,
does not authenticate sessions or set cookies, and issues no CORS permissions.

The forwarding helper below implements cookie filtering and bounded transport.
The Pages handler dispatches only the exact account-session path to this helper.
All other auth routes use independent gates above and remain closed when only
account-session forwarding is enabled.
Health retains its original method/origin handling and remains independent of
auth configuration. Live target-runtime and ingress verification remain separate
work before public authentication can be enabled.

Validation: 61 new policy cases plus 8 existing health-proxy cases passed; the
complete frontend API suite passed 394 cases. Frontend lint, strict TypeScript
and the production build passed. UI/backend code was unchanged and their suites
were not rerun for this isolated routing-policy slice. Node request/response
tests do not replace a deployed Pages runtime test.

### Account-session forwarding helper

`frontend/server/account-session-proxy.ts` applies the request policy itself, then
forwards one fixed `POST /api/v1/account/session` request. It sends only JSON Accept,
identity Accept-Encoding, the configured public Origin and, if correctly shaped,
the secure `__Host-askm6_account` cookie. Guest, OAuth, unrelated and development
account cookies, Authorization and browser-supplied forwarding/IP assertions are not
copied. The optional server-only visitor-IP assertion is described above.
Cookie headers are limited to 8,192 characters; duplicate account cookies
or oversized headers return 400 without fetching. Missing/malformed credentials
are omitted so the backend can confirm signed-out status and cookie deletion.

There are no retries. A 20-second deadline covers fetch and body consumption;
incoming cancellation aborts the upstream request and returns no session cookie.
A cancellation race also prevents returning late credentials when a transport
ignores its abort signal. Streams are cancelled and timers/listeners cleaned up.
Cancellation does not promise rollback of work already performed by the backend.
The deadline gives the backend's default 15-second session operation a margin;
frontend/backend/hosting deadlines still need alignment at deployment.

The helper uses no-store fetch and manual redirects, following the
[Workers request API](https://developers.cloudflare.com/workers/runtime-apis/request/).
Redirects are never followed or forwarded. Live delivery of browser disconnect
signals requires target-runtime compatibility validation; the request API documents
the `enable_request_signal` flag for incoming cancellation notification. The total
deadline remains a separate bound even without such notification.

Successful metadata must be UTF-8 JSON within 4,096 actual bytes, with only a valid
UUID `user_id` and UTC `expires_at`/`absolute_expires_at` strings. The idle deadline
must be future and no later than the absolute deadline. Declared length, if present,
must match received bytes. Extra fields, non-JSON, compression and malformed
metadata fail with a fixed 502 and no cookie. Only sanitized metadata is returned.

`account-session-proxy-cookies.ts` requires exactly one upstream account cookie.
It uses Workers `getAll('Set-Cookie')` or Node `getSetCookie()`, preserving separate
headers instead of splitting on the comma in Expires; see the
[Workers headers contract](https://developers.cloudflare.com/workers/runtime-apis/headers/).
The name, Path=/, Secure, HttpOnly, SameSite=Lax, canonical expiry and absence of
Domain/unknown/duplicate attributes are validated. On 200, the token must match
the forwarded browser credential and the cookie expiry must match the metadata
to whole seconds. This endpoint renews the existing token; it does not log in.
On 401, only an empty account cookie with Max-Age=0 authorizes deletion. A fresh
canonical cookie is constructed after validation rather than blindly copying it.

401 returns fixed signed-out text and a validated clearing cookie, without reading
provider error content. 403/503 return fixed messages and no cookies; other statuses,
redirects, network failures and invalid success/deletion contracts become 502.
All replies are no-store; upstream CORS, Location and unrelated headers are dropped.
An unavailable response preserves the current browser credential.

The Pages handler imports this helper for the exact account-session path. Without
`AUTH_SESSION_PROXY_ENABLED=true`, that path remains 404 before any backend request.
With the flag, invalid configuration/origin/method/body/cookie inputs fail closed.
Production frontend controls remain disabled; tests mock fetch and exercise both
header API shapes rather than establishing deployed runtime behavior.

The forwarding slice passed 68 focused transport tests and the complete 462-case
API/proxy suite, plus frontend lint, strict TypeScript and the production build.
Coverage includes credential/header filtering, renewed/cleared cookie contracts,
the Workers header API, actual byte bounds, metadata validation, redirects,
network failure, cancellation before headers/during body reading, total deadlines
and late responses after cancellation. UI and backend code was unchanged; those
suites were not rerun for this server helper.

### Gated Pages handler integration

`frontend/functions/api/[[path]].ts` dispatches the exact account-session path to
its forwarding helper; all other auth routes have independent gates.
It does not reimplement cookie, origin or transport rules.
The feature flag defaults off; an unset/false flag returns 404 without network
access or cookie changes. To exercise it in an isolated test environment, both
HTTPS origins and the exact `true` flag are required. Keep live bindings unset or
false until deployment validation is complete. This is existing-session lookup,
not a way to create an account session or enable the full sign-in experience.

29 new handler tests exercise the actual policy/transport chain with mocked fetch:
default-off behavior, successful renewal, confirmed 401 deletion, rejected origins,
preview hosts, methods and bodies, route isolation, invalid upstream contracts,
cancellation and health independence. The complete API/proxy suite passed 491
cases; focused policy/transport/handler/health coverage passed 166. Frontend lint,
strict TypeScript and the production build passed. No UI/backend code changed,
and no live provider, Cloudflare binding or deployment changes were made.
The local Workers runtime validation below supplements these Node tests.

### Local Workers runtime validation

`npm run test:runtime` bundles the real Pages handler and its imports into an
in-memory test adapter using the existing Vite build API. Configuration and dotenv
loading are disabled. Pinned development-only Miniflare `4.20260730.0` (MIT) runs
the bundle under workerd `1.20260730.1` (Apache-2.0), with compatibility date
`2026-07-30` and `enable_request_signal` in the test instance only. No Wrangler
login, deployment, live bindings, private environment files or database are used.
See Cloudflare's [Miniflare overview](https://developers.cloudflare.com/workers/testing/miniflare/)
and [outbound fetch mocking](https://developers.cloudflare.com/workers/testing/miniflare/core/standards/).
MockAgent disables network connections, the optional cf metadata fetch is disabled,
and temporary runtime listeners bind only to loopback and are disposed after tests.

This suite found a real compatibility defect: the prior null-body-only policy
rejected legitimate empty Workers POSTs. The policy now accepts a declared-zero
stream only for confirmation by the transport, which requires immediate EOF under
the same total deadline before any backend request. A false Content-Length: 0 with
actual content is rejected and cancelled; a stalled stream cannot bypass the bound.
Three additional Node regressions cover these cases.

Eleven runtime tests cover renewal, native cookie headers, confirmed deletion,
multiple separate cookies, credential/IP-header filtering, default-off routing,
origin/path/body rejection, redirect isolation, metadata masking and health.
An explicitly injected test signal verifies runtime abort handling. Another test
uses the real 20-second timer against a delayed mock upstream and confirms a 502
without cookies. The full frontend pipeline passed 494 API/proxy, 11 runtime and
356 UI tests (861 total), frontend lint, strict TypeScript and production build.
The standard `npm test` command includes this suite, so existing frontend CI runs it.

Automatic client-disconnect notification was not confirmed in this pinned local
runtime: investigation via simulated dispatch and a direct loopback connection
did not observe the incoming abort event. That failed expectation is not counted
as passing; explicit signal handling and fixed-deadline coverage are separate
evidence. Hosted/browser disconnect delivery still needs validation. The adapter
also does not exercise Pages' deployed file router, TLS/host/proxy chain, preview
configuration or real provider/database behavior. Public authentication remains
disabled pending those gates; no live compatibility date/flags were changed.

## Checks

From `backend`:

```powershell
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run mypy migrations
```

GitHub Actions has a separate `backend-integration` job using the same PostgreSQL
17/pgvector image as local development. It creates a disposable `askm6_test`
database, uses synthetic CI-only credentials, creates restricted migration and
application roles, and reuses `backend/sql/bootstrap_schema.sql`. Alembic upgrades
the empty database to head and checks for schema drift before integration tests
run. Migration files are also type-checked. The test URL preserves the existing
loopback, port, database and administrator guards; no provider secrets or private
environment files are used. This job checks database behavior independently of
the offline backend and frontend jobs.

Local PostgreSQL integration tests are skipped unless `TEST_DATABASE_URL` is explicitly
configured. They require the migrated local `askm6_test` database and the
`askm6_app` role. The test URL must use `postgresql+psycopg://`, administrator
`mazda6_admin`, host `127.0.0.1`, port `15432`, database `askm6_test`, and no query
parameters. Use the local bootstrap credentials configured through the root
ignored `.env`. Construct the URL with `URL.create()` so password characters are
encoded correctly, and store it as `TEST_DATABASE_URL` in an ignored
`backend/.env.integration.local` file.

From `backend`, after preparing the local database and applying the migrations:

```powershell
uv run --env-file .env.integration.local pytest tests/integration -p no:cacheprovider
```

To run the complete backend suite, including local PostgreSQL integration tests:

```powershell
uv run --env-file .env.integration.local pytest -p no:cacheprovider
```

Tests verify the database identity and migration revision before writing, execute
application operations as `askm6_app` through `SET LOCAL ROLE`, and normally roll
back test transactions. HTTP lifecycle and lock-wait tests commit synthetic rows
where necessary and delete only their own test rows in cleanup. Administrative
connections are used for setup, inspection, and cleanup. Tests do not create
tables automatically or apply migrations. They cover guest token/session behavior,
account-session storage and encrypted-token round trips, account-deletion cascades,
expiry-safe account-session activity updates, stored-session authentication,
guarded refresh credential storage, concurrent authentication and recovery,
authentication transaction commit and rollback, invalid session fields and
timestamps, and restricted-role permissions. Additional HTTP tests cover account
sign-in with mocked provider/JWKS responses and application-session sign-out with
provider requests blocked, including commit failures and cookie behavior.
These tests do not exercise live hosted authentication or provider logout.
Conversation ownership is not implemented or covered by these database tests.
Keep test administrator credentials separate from the running web service.

From `frontend`:

```powershell
npm run lint
npm test
npm run build
```

`build` includes the strict TypeScript check. Tests require no live APIs.
Dependency versions are recorded in `backend/uv.lock` and `frontend/package-lock.json`.
GitHub Actions runs these checks without provider secrets.

`npm test` runs Node API/proxy tests, the isolated Miniflare/workerd suite, then
Vitest React tests in jsdom. `npm run test:runtime` selects only the runtime suite.
UI tests render the app under Strict Mode and verify that loading the page checks
API health without creating a guest session. They also cover a guest-button click,
the disabled loading state, prevention of repeat requests while pending, success,
and recovery after a failed request. A fake-clock test checks that a stalled
request is still pending at 14,999 ms, aborts at 15,000 ms, and enables retry.
An unmount test verifies that leaving the page aborts a pending guest request
and clears its timeout. Production tests verify that the default-off guest flag
blocks both the button and direct hook calls without session/proof submissions.
Opt-in tests cover first-use verification, duplicate callbacks, returning-session
reuse, rejected proofs, private errors/rate limits and account-mode isolation.
Requests are mocked; the backend and database are not needed. These jsdom tests
do not replace browser checks of cookies, layout, or the built production bundle.

Additional tests cover the explicit verification response header and proof JSON,
shared SDK loading, loading/readiness failures and deadlines, and the non-async
script requirement. Widget tests cover Strict Mode, duplicate and late callbacks,
expiry/error/timeout feedback, explicit retry, and cleanup before or after SDK
loading. App tests cover the initial verification request, one proof submission,
and recovery with a fresh proof after rejected or unavailable verification.
Automated tests do not contact Cloudflare or prove live token replay protection.

Public guest access has a default-off browser opt-in. Its backend/proxy/browser
rollout was manually checked with real verification and cookie reuse after reload.
Account sign-in, session restoration, sign-out and Google have
production browser opt-ins; email registration and confirmation use a separate
default-off registration switch. Password recovery and reset share a separate
default-off production browser switch, with default-disabled backend and proxy
request/reset endpoints. Recovery email delivery, reset, old-password
rejection and separate new-password sign-in have been manually validated locally
and on the hosted site, alongside registration and confirmation. Hosted recovery
also invalidated existing application sessions. Chat and ownership features remain
separate unfinished work.

The authentication close-out review passed 345 focused offline regressions for
CSRF/origins, trusted-client-IP boundaries, guest/account/OAuth cookies, JWTs,
callback consumption, callback log redaction and signup Terms receipts. Together
with the hosted manual paths above, this covers the implemented core access flows;
it does not establish every live failure, concurrency or provider-linking case.
Ordinary sign-out invalidates the application session. General provider-session
revocation, self-service account deletion and future conversation authorization
are separate from the implemented flows.

## License

Project code is available under the [MIT License](../LICENSE).
Third-party dependencies and automotive source material retain their own licenses.
No Mazda manufacturer manuals or proprietary diagrams are included in this repository.


## Email signup Terms receipt

Email signup starts unchecked and requires an explicit Terms checkbox as well as
human verification. Terms is an underlined link within the agreement sentence;
Privacy Notice is separate. The links open safely in another tab without toggling
the checkbox, and only the checkbox control changes agreement. Sign-in has no
policy checkbox. Google registration retains first-time account setup unless a
confirmed email-signup receipt already records agreement for the same account.

A neutral registration response sets an encrypted, HttpOnly, SameSite=Lax receipt
for at most one hour (`__Host-askm6_signup_terms` on HTTPS, `askm6_signup_terms`
locally). It is provisional, not authentication or evidence that an account
exists. The payload records a purpose marker, current Terms revision, exact-input
email hash, server UTC acceptance time and original expiry. It contains neither
plaintext email/password nor provider credentials. It reuses the configured
Fernet session key; no new schema, service or provider metadata is required.

A successful signup-code confirmation internally returns the provider-confirmed
UUID, discards provider tokens and binds only a matching valid receipt. It never
creates an application login. A subsequent live/JWT-verified password login can
save acceptance only for that confirmed UUID and the same exact email input. A
Google callback may save the receipt only when its backend-verified subject is
the OTP-confirmed UUID; no email-address or provider-metadata matching is used.
Both paths persist acceptance inside the session-creation transaction. The first
recorded timestamp is preserved;
persistence failure/cancellation rolls the session transaction back and returns
no account cookie. Successful sign-in clears the receipt. Invalid, expired,
unconfirmed or other-account receipts grant no agreement; password login also
requires the original exact email input.
sign-in still works and missing agreement uses the normal setup dialog. A
receipt for another account never supplies agreement on a shared browser.

Proxies forward only the bounded receipt on confirmation/password sign-in, and
only OAuth binding plus that receipt on Google callback. They reject duplicate
receipt names, validate its one-hour lifetime/security scope, preserve other
browser cookies and require its deletion alongside the newly created account
cookie on successful sign-in. Receipt values accept Python's Base64url form with
one pair of double quotes and the unquoted form; forwarding removes only the outer quotes,
preserving padding and the 1536-character value limit. Embedded/escaped quotes
and malformed values are rejected. Google success requires exactly three cookies when
a receipt was forwarded: OAuth deletion, new account session and receipt deletion;
ordinary callback cookie validation remains unchanged. Failures preserve the
receipt while retaining the existing backend-confirmed OAuth deletion contract.
Providers remain mocked in automated tests; this addition does not enable hosted features.


### Terms checkpoint review

The additive Terms migration starts with no inferred acceptances and gives the
runtime role SELECT/INSERT only. Downgrade takes an exclusive table lock before
checking emptiness, so a concurrent acceptance cannot race the protected DROP.
A guarded local PostgreSQL probe verifies the writer is blocked, then aborts
before the check or DROP; its migration transaction always rolls back. Populated
records continue to make downgrade refuse. This does not run a live downgrade
or change the upgrade schema.
