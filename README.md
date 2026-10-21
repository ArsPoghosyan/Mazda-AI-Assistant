# Mazda 6 AI Assistant

[![Checks](https://github.com/ArsPoghosyan/Mazda6-AI-Assistant/actions/workflows/ci.yml/badge.svg)](https://github.com/ArsPoghosyan/Mazda6-AI-Assistant/actions/workflows/ci.yml)

An independent, unofficial Mazda 6 information assistant in early development.
Unaffiliated with Mazda.

**Status: early development.** The frontend and API health-check foundation
are deployed at [askm6.com](https://askm6.com). The full assistant is not available yet.

## Engineering workflow

This is a personal project with publicly available code, tests, and development
history. External contributions are not being accepted.

Development proceeds in small, testable changes. GitHub Actions is configured for
backend tests/lint/types and frontend tests/lint/build. Results are available in the
[Actions tab](https://github.com/ArsPoghosyan/Mazda6-AI-Assistant/actions).

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
- An internal Turnstile verifier with exact hostname/action checks, bounded
  Siteverify requests, controlled failures, and offline HTTP/cancellation tests.
- Guest first-use verification before session creation, bounded optional JSON
  input, and a total operation deadline. Active sessions refresh without another
  challenge; cookies are issued only after commit. The browser submits each proof
  once and requires a fresh attempt after a failed submission.
- Python lint/type checks and frontend proxy tests/lint/type/build checks.

Account sign-up UI, chat, conversation persistence, vehicle selection,
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
uv run uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
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
Both servers bind to loopback. The production build does not supply an API server;
production uses Cloudflare Pages, a health-only Pages Function proxy,
and a FastAPI backend on Render. The proxy currently permits only
`GET /api/v1/health`; readiness is available directly on the backend.

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
uv run uvicorn app.main:app --reload --loop asyncio --env-file .env.supabase --host 127.0.0.1 --port 8000
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
contacting Cloudflare. Verification runs without holding a database transaction
or connection. A new creation transaction opens only after verification succeeds,
and cookie material is returned only after commit. Active sessions can refresh
even when the Turnstile client is unavailable. Verification does not establish a
unique human identity or replace rate limits and message quotas.

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
The Cloudflare Pages proxy still forwards only health requests; production guest
route and cookie forwarding are not implemented. The frontend guest action is
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

Success confirms a guest session, not a working chat. The guest action remains
disabled in `npm run preview`, which serves the production build. The development
UI gate is not an authorization control; the backend's independent checks still
apply. Keep insecure cookies and this local endpoint configuration out of production.

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
`account_sign_in` widget action. Account sign-up is not implemented. Public access still requires abuse
controls and production guest-route/cookie forwarding.

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
or administrator permissions. The Cloudflare Pages proxy still forwards only
health requests; production account-route forwarding is not implemented.

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

Provider-session revocation, automated session cleanup, and encryption-key rotation
are not implemented. HTTP sign-in/session creation, application-session sign-out,
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
default. Additional abuse controls, signup, email verification, password recovery,
and Google sign-in remain unimplemented. The development-only frontend sign-in
flow is described below.

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
error before commit completes. These tests do not simulate an uncertain network
failure during commit and make no live Supabase requests.

## Account sign-in endpoint

`POST /api/v1/account/sign-in` connects bounded credential parsing to the internal
sign-in service. It creates an application session and issues its opaque browser
cookie only after successful database commit. `ACCOUNT_SIGN_IN_API_ENABLED`
defaults to `false` and is independent of `ACCOUNT_SESSION_API_ENABLED`. Keep
public sign-in disabled until Supabase CAPTCHA enforcement, additional abuse controls,
and deployment checks are ready.
The development frontend calls this route through Vite's same-origin proxy. The
Cloudflare Pages proxy still forwards health requests only, and account access
remains disabled in normal production frontend builds.

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
and covers body reading, provider exchange, JWT verification, and database
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
| Body over 16 KiB | 413 |
| Missing or unsupported content type | 415 |
| Disabled/unconfigured route, provider/verification/database failure, duplicate provider session, or timeout | 503 |

Input errors use generic messages instead of Pydantic validation details that
could expose submitted credentials. Rejections do not reveal provider error
messages or send a Bearer authentication challenge. Controlled failures do not
set or clear an existing account cookie, and sign-in is not automatically retried.
Only missing/rejected CAPTCHA verification sets `X-Account-Verification: required`;
Origin failures, ordinary credential rejection, and unavailable services do not.
The route does not revoke an earlier session when a new sign-in succeeds.
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

For local HTTP testing only, enable the required backend endpoints in the ignored
`backend/.env`, retain a configured session encryption key, and use
`ACCOUNT_COOKIE_SECURE=false`. The sign-in flag and session-check flag are
independent. Restart FastAPI after environment changes. Keep public examples and
production defaults disabled until the remaining release checks are complete.

API tests mock fetch and cover request allowlists, metadata-only responses,
controlled failures, malformed responses, and cancellation. Controller/form tests
cover duplicate submissions, deadlines, cleanup, proof expiration, fresh retries,
password clearing, and development-only availability. App tests cover opening and
closing, native cancel handling, focus restoration/guards, and pending-request
cancellation. Integration tests use the real account hooks and API helpers with
mocked network responses to cover successful sign-in updating the landing page
without another session request, controlled failure, and ignored late results.
jsdom's native dialog methods and layout are stubbed in those tests;
they do not replace browser checks of native modal behavior or the real widget.

In development, the page checks `POST /api/v1/account/session` on mount, with a
15-second deadline and cleanup on unmount. While checking, guest access and
sign-in are disabled. HTTP 401 enables signed-out access; an unavailable service
or invalid response keeps guest access blocked and offers an explicit retry.
There is no automatic polling. A successful sign-in supplies validated session
metadata directly to the page's account state without another session request.
Account-session metadata is held in React memory; the opaque session credential
remains in an HttpOnly cookie and provider tokens stay on the backend. Session
restoration and sign-in remain disabled outside development.

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
flow; production account access remains disabled and is not validated by them.

The frontend does not yet provide registration, email-confirmation,
password-recovery, or Google sign-in interfaces. Chat remains in development.

## Account sign-out endpoint

`POST /api/v1/account/sign-out` signs out the current browser's application session.
`ACCOUNT_SIGN_OUT_API_ENABLED` defaults to `false` and is independent of the
sign-in and session-check flags. Keep it disabled until endpoint testing and
deployment checks are complete. The development frontend calls the route through
Vite's local API proxy; the Cloudflare Pages proxy does not forward it yet.

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
Cloudflare Pages proxy does not forward the new endpoint yet.

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

## Checks

From `backend`:

```powershell
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run mypy migrations
```

PostgreSQL integration tests are skipped unless `TEST_DATABASE_URL` is explicitly
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

`npm test` runs the Node API/proxy tests followed by Vitest React tests in jsdom.
UI tests render the app under Strict Mode and verify that loading the page checks
API health without creating a guest session. They also cover a guest-button click,
the disabled loading state, prevention of repeat requests while pending, success,
and recovery after a failed request. A fake-clock test checks that a stalled
request is still pending at 14,999 ms, aborts at 15,000 ms, and enables retry.
An unmount test verifies that leaving the page aborts a pending guest request
and clears its timeout. Another test simulates development being disabled and
verifies that the guest button stays disabled without sending a session request.
Requests are mocked; the backend and database are not needed. These jsdom tests
do not replace browser checks of cookies, layout, or the built production bundle.

Additional tests cover the explicit verification response header and proof JSON,
shared SDK loading, loading/readiness failures and deadlines, and the non-async
script requirement. Widget tests cover Strict Mode, duplicate and late callbacks,
expiry/error/timeout feedback, explicit retry, and cleanup before or after SDK
loading. App tests cover the initial verification request, one proof submission,
and recovery with a fresh proof after rejected or unavailable verification.
Automated tests do not contact Cloudflare or prove live token replay protection.

Public guest access still requires abuse controls and production guest-route/cookie
forwarding. Frontend managed account login remains unimplemented.

## License

Project code is available under the [MIT License](LICENSE).
Third-party dependencies and automotive source material retain their own licenses.
No Mazda manufacturer manuals or proprietary diagrams are included in this repository.
