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
  error/retry feedback, request cancellation, and a bounded timeout.
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
- Python lint/type checks and frontend proxy tests/lint/type/build checks.

Account sign-in/sign-up, chat, conversation persistence, vehicle selection,
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

`POST /api/v1/guest/session` creates a guest session or refreshes an existing,
unexpired one. Missing, malformed, unknown, and expired cookies result in a new
session. Only the token hash is stored in PostgreSQL. The token is issued in an
HttpOnly cookie after the transaction commits, and is never returned in JSON.
Successful responses contain `status` and `expires_at` and use `Cache-Control: no-store`.
Database failures return a generic 503 without issuing a cookie.

The endpoint defaults to disabled through `GUEST_SESSION_API_ENABLED=false`.
Keep public guest access disabled until Turnstile and abuse controls are ready.
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

The local guest flow requires a running, migrated local database and a backend
`DATABASE_URL` using the restricted application role. In the ignored `backend/.env`,
enable the endpoint and use the exact frontend origin:

```ini
GUEST_SESSION_API_ENABLED=true
GUEST_COOKIE_SECURE=false
CSRF_TRUSTED_ORIGINS=["http://127.0.0.1:5173"]
```

Run the backend and `npm run dev`, then open `http://127.0.0.1:5173` and select
**Try as Guest**. The browser manages the HttpOnly cookie; the frontend does not
read or store its token. Reloading the page alone does not submit a guest-session
request. Selecting the action again after reload refreshes an unexpired session.

Success confirms that a guest session was established; it does not open a working
chat. A failed request allows an explicit retry. The action remains disabled in
`npm run preview`, which serves the production build. The development UI gate is
not an authorization control; the backend's independent checks still apply.
Keep insecure cookies and this local endpoint configuration out of production.

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
ownership. No provider login adapter or account-session HTTP endpoint is connected.

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

HttpOnly account cookies, database-coordinated provider-token refresh, logout,
automated session cleanup, and encryption-key rotation are not implemented.
Account-session authentication is not yet connected to HTTP routes.
Provider identity and expiry require JWT verification in addition to ciphertext
decryption. Keep real encryption keys in ignored backend environment files or a
server-side secret manager, never in frontend variables or Git. Retain the key
while encrypted data depends on it; replacing it without a rotation process makes
existing ciphertext unreadable.

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

These helpers do not write to the database or extend application-session
deadlines. Coordinating concurrent refresh attempts, encrypted credential
replacement, recovery after an interrupted exchange, and session-expiry checks
around the provider request remain pending. No refresh HTTP endpoint is connected.
Tests use synthetic credentials, generated ES256 keys, mocked HTTP transport and
signing-key downloads, and no live Supabase requests. They cover response and token
bounds, error classification, deadlines, cancellation, forged signatures, identity
mismatches, and the adapter-to-verifier flow.

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
invalid session fields and timestamps, and restricted-role permissions. Direct
session updates and deletions in schema tests do not implement provider-token
refresh or logout endpoints. Managed account
login and conversation ownership are not covered by these database tests.
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

Public guest access still requires Turnstile, abuse controls, and production
guest-route/cookie forwarding. Managed account login remains unimplemented.

## License

Project code is available under the [MIT License](LICENSE).
Third-party dependencies and automotive source material retain their own licenses.
No Mazda manufacturer manuals or proprietary diagrams are included in this repository.
