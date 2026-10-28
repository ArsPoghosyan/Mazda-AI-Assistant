# Security review — 28 October 2026

Repository and isolated local-test review of **askm6**. This is an engineering
assessment of the reviewed source and working tree, not certification or a
production penetration test. No public application, production database, Google,
Supabase or Turnstile endpoint was probed. Public package/advisory metadata was
queried for dependency checks. No credentials were rotated, migrations applied,
accounts changed, services deployed, commits created or branches pushed.

The working tree already contained an approved 404/policy checkpoint. That work
was completed and validated first; its files are distinguished below from audit
remediation. The live environment may differ from this source.

## Architecture and threat model

| Boundary | Actual implementation and exposure |
| --- | --- |
| Browser | React/TypeScript/Vite; home, privacy, Terms and branded unknown-page routes; credentials stay in transient form state, not local/session storage |
| Public ingress | Cloudflare Pages static assets and `/api/*` Functions; fixed route dispatch and independently default-off feature bindings |
| API | FastAPI modular monolith, hosted on Render according to project configuration; JSON routes under `/api/v1`; the separate Bearer `/account/me` identity diagnostic and default read-only `/docs`, `/redoc`, `/openapi.json` documentation routes are also registered; no interactive debug console |
| Provider identity | Supabase Auth email/password, signup/confirmation/recovery and Google OAuth; provider operations are server-side and bounded |
| Application identity | Separate opaque guest/account cookies; SHA-256 token verifiers in PostgreSQL; encrypted provider token pairs; versioned Terms records |
| Data store | SQLAlchemy/psycopg, Alembic, `app` schema, separate runtime/migration roles; remote URL validation requires certificate-verified TLS |
| Local containers | Compose runs PostgreSQL/pgvector, bound to `127.0.0.1:15432`; named persistent volume. There is no application Dockerfile or Redis service in this repository |
| Abuse protection | PostgreSQL row-locked rolling IP attempt counters, HMAC address keys, request/provider deadlines, streamed byte limits, CAPTCHA and feature gates |
| Delivery | Locked Python/npm dependencies and read-only-permission GitHub Actions jobs for backend, frontend and restricted-role PostgreSQL tests |

Assets at risk include account/session control, passwords while forwarded to
managed authentication, encrypted refresh credentials, agreement records, IP
fingerprints, provider budgets and availability. Relevant attackers include
unauthenticated clients, malicious websites, an authenticated account attempting
to act as another, and malicious/malformed upstream responses. Provider/dashboard
compromise, a stolen encryption key and a fully compromised runtime remain
separate trust-boundary risks.

**NOT IMPLEMENTED:** AI chat, model calls, vector retrieval, conversations,
vehicle resources, uploads, WebSockets/streaming chat, AI message quotas,
guest-chat transfer, administrative APIs, email-change/resend endpoints and
self-service account deletion. They were not treated as existing vulnerable APIs.

## Findings and disposition

No confirmed critical or high application vulnerability was established in this
review. Absence of a finding does not establish absence of vulnerabilities.

### A1 — vulnerable development-tool dependencies

- **Severity:** HIGH advisory severity; **confidence:** high for installed versions.
  Reachability of each advisory's exploit conditions was not established.
- **Preconditions/boundary:** exploitation would require reaching the affected
  development-tool HTTP/cache/image processing paths with attacker-controlled
  input. Exposure of those paths outside the isolated local test environment
  was not demonstrated; this finding concerns the development supply chain.
- **Evidence:** `frontend/package.json` originally pinned Miniflare
  `4.20260730.0`. Its transitive `sharp 0.35.2` and `undici 7.28.0` were flagged by
  `npm audit`; npm reported three affected package entries including Miniflare.
  The source uses Miniflare for isolated runtime tests. It is not a production
  frontend dependency; the registry result is not proof of an exposed production
  image-processing or Undici service.
- **Remediation:** scoped npm overrides under `miniflare` select `sharp 0.35.5`
  and `undici 7.30.1`, retaining the pinned Miniflare/workerd release and the same
  dependency release lines. The lockfile records exact packages/integrities.
  No `audit fix --force` or major-version migration was used.
- **Validation:** post-change npm audit reports zero advisories; all 89 native
  runtime tests pass with the patched packages. Keep the overrides under review
  when Miniflare publishes a compatible release incorporating these fixes.
- **Evidence locations:** `frontend/package.json:25`, `frontend/package-lock.json`.

### A2 — signup email syntax only checked by managed provider

- **Severity:** LOW validation gap; **confidence:** high. No confirmation bypass
  or account takeover was demonstrated.
- **Preconditions/boundary:** a client can bypass browser validation and submit
  malformed JSON field values to the signup API. Invalid email syntax crossed
  the application-to-provider boundary, consuming provider validation work;
  existing limits, CAPTCHA and ownership confirmation still applied.
- **Evidence:** `SignUpCredentials.email` previously checked only masked string
  type and a 1–320 character limit. Arbitrary non-email strings could reach the
  provider. The provider still performed its own validation and confirmation.
- **Remediation:** `backend/app/account_sign_up_requests.py:29` now uses
  `email-validator` with strict syntax/length checks and deliverability disabled.
  Invalid input gets a generic no-store 400 before provider contact or receipt
  creation. The attempt remains counted by the existing committed limiter.
- **Compatibility:** plus-addressing, case, Unicode and IDN syntax remain
  supported; unusual real domains are not blocked by a provider-name list.
  `user@gmai.com` can be syntactically valid and is deliberately not rewritten
  or rejected merely for resembling Gmail. Only control of the emailed code
  proves ownership. There is no DNS/MX query or automatic typo correction.
- **Identity/normalization:** existing flows preserve the submitted credential
  rather than inventing a new application's alias/case canonicalization policy.
  Supabase owns canonical uniqueness and linking. The application stores verified
  subject UUIDs rather than indexing accounts by guessed normalized email.
  Exact-input signup receipt matching remains intact; mismatches fall back to
  explicit setup. Password/login behavior is unchanged.
- **Validation:** focused tests include malformed syntax, header/control
  characters, long mailbox components, plus/case/Unicode/IDN, unfamiliar domains,
  no DNS lookup, masking and no provider contact. Reserved `.test` fixtures were
  replaced with IANA-reserved `example.org` addresses where real signup parsing
  is exercised; no production test-mode bypass was introduced.

### A3 — no repository-managed browser response-header baseline

- **Severity:** LOW defense-in-depth gap; **confidence:** high for source.
  Existing hosted headers were not inspected, so hosted exposure is unverified.
- **Preconditions/boundary:** a malicious site could attempt to frame the public
  application if the hosting layer also supplied no framing protection. User
  interaction and the existing session/verification controls would still be
  required. Actual hosted clickjacking exposure **needs verification**.
- **Evidence:** no static `_headers` policy, common Functions wrapper or FastAPI
  browser-header middleware existed. Browser framing was not prohibited by the
  repository configuration.
- **Remediation:** `frontend/public/_headers:2`,
  `frontend/functions/api/[[path]].ts:26` and
  `backend/app/security_headers.py:6` provide `nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, and CSP directives for `base-uri`, `object-src`,
  `frame-ancestors` and `form-action`. FastAPI registration is in
  `backend/app/main.py:121`. Explicit stricter backend route policies are retained.
- **Compatibility:** the policy allows existing Turnstile scripts/iframes and
  Google top-level navigation. It does not introduce a script-source allowlist,
  HSTS preload or subdomain policy. It is not a complete XSS-prevention policy.
  Static rules do not cover Pages Functions, which therefore set the baseline
  explicitly. Platform-generated failures outside these handlers/middleware
  are not guaranteed to carry these headers.
- **Validation:** local real-asset/runtime and ASGI tests cover normal/error
  statuses, closed CORS, streaming, separate cookies and existing cache/auth
  headers. Post-deployment provider/widget verification remains manual.

## Existing controls reviewed

| Area | Source evidence and local-test boundary |
| --- | --- |
| Password handling | Supabase manages password hashing/policy; this application does not implement a password database or local hash function. Masked request models, bounded body/credential lengths, no automatic password trimming, provider-only password update. Provider hashing algorithm/cost, leaked-password checks and current policy were not verified |
| Ownership confirmation | Signup creates no application session; generic acknowledgement for new/existing account outcomes; `/verify` exchange uses the signup type and requires confirmed-user response metadata. Email delivery, code entropy, expiry/single use and actual provider settings are managed externally; local tests simulate provider rejection/replay outcomes |
| Recovery | CAPTCHA-protected request, generic accepted response, IP limits; recovery-specific exchange, verified JWT/response UUID agreement, bound password update, temporary provider-session cleanup and account-scoped application-session invalidation. Partial provider success cannot be rolled back by a local transaction |
| JWT | `account_tokens.py`, `account_auth.py`, key fetch/cache: ES256/P-256, configured issuer/audience, required expiry/issued-at/session/account claims, anonymous identities rejected, bounded keys/tokens and refresh cooldown; no browser-supplied key URL |
| Account cookie authentication | `account_session_service.py`: hash lookup under lock, decryption, JWT/row identity matching, live provider check, expiry rechecks after waits/network operations, verified refresh once, cookies after transaction commit |
| Browser credentials | `token_urlsafe(32)` opaque values, hash at rest; Secure `__Host-` production names, HttpOnly, SameSite=Lax, Path=/, no Domain; independent browser-token issuance at sign-in. Explicit insecure local cookie names remain available only by configuration |
| Logout | committed deletion of the current application-session hash before clearing its cookie; no client-supplied user/session deletion target. This is not global Supabase/Google logout |
| OAuth | fixed provider/callback URL, S256 PKCE, encrypted verifier, hashed browser binding, short-lived purpose-bound row consumed once before exchange, one callback code, fixed return outcomes; sensitive callback query redacted by standard Uvicorn filter |
| CSRF/CORS | cookie state changes require exactly one configured Origin. Pages checks its canonical incoming/public origin and same-origin fetch metadata; callback uses its separate browser-binding/PKCE boundary. No permissive CORS middleware or credentialed wildcard allowlist |
| Direct API calls | UI feature switches do not authorize a request. Backend flags, Origin, provider/session verification and counters apply independently. Protected cookie resources require a valid server-derived session. Origin is a browser CSRF check, not client authentication |
| Proxy addresses | `client_ip.py`, `proxy-client-ip.ts`: ignore ordinary forwarded headers; configured shared-secret assertion uses constant-time comparison and one validated address. Pages relies on actual Cloudflare ingress replacing CF-Connecting-IP; generic deployments must not sign browser-supplied CF headers |
| Authorization | current Terms operations compare a backend-verified session/subject, including expected-account mismatch before refresh; SQL scoped to that UUID. Logout scoped by cookie hash; password reset invalidation scoped to verified recovery subject. No existing conversation/profile edit/list or admin endpoints to assess |
| Database | typed ORM/bound parameters; SQL text in runtime is fixed, not user-built SQL. FK/check/unique constraints; runtime column-limited grants; verified remote TLS; hidden SQL parameters. Real restricted-role local PostgreSQL tests exercise grants/locks/concurrent isolation |
| Injection/front end | no application `dangerouslySetInnerHTML`, DOM HTML injection, runtime shell execution or dynamic SQL from request strings found in targeted source searches; ordinary React text rendering and fixed/validated URLs. This is source review, not proof against every XSS/injection variant |
| Request resources | streamed body byte caps (not trusting Content-Length), strict extra-field rejection, generic errors, finite provider/request deadlines, response byte caps, no redirect following and no provider retry loops; account pool has fixed size/max overflow zero |
| Abuse counters | seven purposes use shared PostgreSQL state, row locking and fresh database time; address fingerprints are keyed, both mapped IPv4 spellings normalize; count attempts before provider work, preserve blocks/retry seconds, bounded cleanup. No claim of DDoS or distributed credential-stuffing immunity |
| Turnstile | guest first-use Siteverify validates success, configured hostname/action and error outcomes including timeout-or-duplicate. Existing sessions reuse without a challenge. Account CAPTCHA enforcement relies on Supabase configuration; tokens are not proof of a unique human |
| Logging | inspected runtime diagnostics report stages/error classes rather than credentials or exception bodies; callback query filter covers standard Uvicorn records. Hosting/edge logs and external monitoring were not inspected |

### Enumeration, resend and email correction

Signup maps provider duplicate-account responses to the same public 202 as an
accepted new registration; recovery does not expose whether the address exists.
Invalid password/identity replies remain generic. These code paths do not prove
constant-time responses, and inbox delivery is inherently observable to its owner.
Distributed enumeration/credential stuffing is not exhaustively tested.

There is no resend, unverified-address mutation or email-change endpoint. A user
can return to signup and enter a corrected address; existing registration limits
and provider mail limits still apply. Repeated signup is not a guaranteed resend
API. A future email-change design needs recent authentication and managed
reverification before changing the trusted address. Do not add a local token/hash
database alongside managed Auth without an approved requirement.

## Tests and tools

Commands are run from `backend/` or `frontend/`; the portable executables were used
on this Windows machine. External authentication/LLM services were mocked. Full
command output stays in ignored local `.tools/` files and is not published.

| Check | Result |
| --- | --- |
| 404 checkpoint: offline backend | 3,934 passed |
| 404 checkpoint: signup limiter + Terms PostgreSQL | 41 passed |
| 404 checkpoint: frontend API / runtime / UI | 1,648 / 89 / 528 passed; 33 UI files |
| Audit focused backend validation + headers | 120 passed |
| Audit full offline backend | Final complete run: 3,965 passed; JWT/header focused regression run: 81 passed |
| Audit full PostgreSQL | Final complete rerun: 1,083 passed. Earlier two failures were corrected and their affected modules also passed a 36-test focused rerun |
| Audit frontend API / native runtime | 1,653 / 89 passed |
| Python lint / format / mypy | Passed; 231 source files checked by mypy |
| Frontend lint / TypeScript / production build | Passed |
| `uv audit --locked --output-format json` | Before: 43 packages, zero known vulnerabilities. After: 45 packages, zero known vulnerabilities/adverse statuses |
| `npm audit --json` | Before: three affected dev package entries, high severity. After scoped overrides: zero known advisories |
| Current files/build scan | Private/generated tracked-file checks, eight ignored local env files, configured secret patterns and built assets checked; exact final scope is listed below |
| Reachable Git-history scan | 972 blobs, one explicitly synthetic provider-token-shaped test fixture; no configured-credential or private-key match found by this scanner |
| Browser | Local headless Edge, external requests blocked: desktop/390px/320px 404, no overflow, keyboard/home/policy navigation and no-JavaScript recovery; post-header browser check also passed: frame embedding and injected external base URL blocked, policy/home navigation and no-JavaScript fallback preserved |

Commands actually run (with focused reruns after corrections):

```text
uv run --locked pytest tests --ignore=tests/integration -p no:cacheprovider --tb=short
uv run --locked pytest tests/test_account_sign_up_requests.py tests/test_account_sign_up_routes.py tests/test_security_headers.py -p no:cacheprovider --tb=short
uv run --locked pytest tests/test_account_tokens.py tests/test_security_headers.py -p no:cacheprovider --tb=short
uv run --locked --env-file .env.integration.local pytest tests/integration -p no:cacheprovider --tb=no
uv run --locked --env-file .env.integration.local pytest tests/integration/test_account_oauth_cleanup_db.py tests/integration/test_sign_up_rate_limits.py -p no:cacheprovider --tb=no
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv audit --locked --output-format json
npm audit --json
npm run lint
npm run test:api
npm run test:runtime
npm run test:ui -- --maxWorkers=2
npm run build
```

The UI suite ran for the completed 404 checkpoint; no React UI source was changed
by audit remediation. The dependency/proxy changes were subsequently validated
with the complete API/runtime suites and a new lint/type/build pass. Test failures
during implementation included one strict mailbox-length assertion (enabled the
validator's strict option), a test-only Pydantic settings typing issue (isolated
settings subclass), and an overstrong header-parsing assertion (corrected to test
signature-based authentication). All focused corrections passed.

Integration guards enforce `127.0.0.1:15432/askm6_test`, expected database/user and
migration head before tests run. Existing tests clean up their own fixtures and
exercise the restricted application role. No production migration or database
operation was executed.

The two integration failures were one remaining synthetic `.test` signup address
and an existing 100 ms cleanup-test deadline racing connection/DELETE progress.
The address fixture was corrected. The timeout test now reschedules its real
timeout after the post-delete synchronization point; production deadlines and
rollback assertions are unchanged.

`pip-audit`, Bandit, Semgrep and Gitleaks were not installed and were not run or
silently installed. Available `uv audit` and `npm audit` supplied advisory checks;
targeted source/AST/pattern searches supplied additional review. The redacted
history scanner checks configured local credentials (minimum-length threshold)
and selected provider/private-key signatures; it is not an entropy-based scanner
or a guarantee that unknown/revoked secrets never entered history. GitHub Actions,
container OS vulnerability scanning, production browser tests and live provider
token behavior were not run in this audit.

## Files changed by this review

Audit remediation and regression coverage:

- `backend/app/account_sign_up_requests.py` — syntax validation, masked failure.
- `backend/pyproject.toml`, `backend/uv.lock` — validator and locked dependency.
- `backend/app/security_headers.py`, `backend/app/main.py` — browser baseline.
- `backend/tests/test_account_sign_up_requests.py`,
  `backend/tests/test_account_sign_up_routes.py` — valid/invalid/no-DNS/provider
  rejection coverage and compatible synthetic addresses.
- `backend/tests/test_security_headers.py` — auth/status/cookie/streaming/CORS.
- `backend/tests/test_account_tokens.py` — deeply nested unsigned token fails
  authentication; extracting a header hint does not confer identity.
- `backend/tests/integration/test_sign_up_rate_limits.py` — corrected synthetic
  email fixture; retains local cap, provider failure and spoofing assertions.
- `backend/tests/integration/test_account_oauth_cleanup_db.py` — synchronized
  timeout-after-delete regression without a wall-clock setup race.
- `frontend/package.json`, `frontend/package-lock.json` — scoped patched dev
  dependencies and security-header test registration.
- `frontend/public/_headers`, `frontend/functions/api/[[path]].ts` — static and
  Functions policies, preserving response/cookie/status behavior.
- `frontend/tests/security-headers.test.mjs`,
  `frontend/tests/page-routing-runtime.test.mjs` — baseline parity and real assets.
- `README.md`, `SECURITY_AUDIT.md` — behavior, findings and operational limits.

The pre-existing approved 404/policy checkpoint also changes
`frontend/404.html`, `frontend/public/_redirects`, `frontend/src/not-found.tsx`,
`frontend/src/components/NotFound.tsx`, `frontend/src/Page.tsx`, its tests,
`frontend/vite.config.ts`, `frontend/tests/fixtures/page-routing-worker.mjs`,
the Privacy/Terms components, both Terms-version constants, current-revision
signup/session/form/API fixtures, and `reference/IMPLEMENTATION.md`. Its Terms
revision is `2026-10-28`; old agreements are never silently relabelled.

## Required configuration and services

Secret **names** only; values must remain in ignored local configuration or the
hosting providers' secret stores:

- `DATABASE_URL`: restricted runtime role; remote connections require
  `sslmode=verify-full` and a valid CA file. `MIGRATION_DATABASE_URL` belongs only
  to the separate migration environment, not browser/runtime builds.
- `SUPABASE_AUTH_ISSUER`, `SUPABASE_AUTH_PUBLISHABLE_KEY`,
  `SUPABASE_AUTH_AUDIENCE`; verify publisher key type and ES256 signing setup.
  No service-role/admin key is needed for ordinary authentication.
- `ACCOUNT_SESSION_ENCRYPTION_KEY`: Fernet key (44-character encoded form).
  `AUTH_RATE_LIMIT_HMAC_SECRET` and `AUTH_PROXY_SHARED_SECRET`: independent
  64-hex-character secrets. Do not conflate their formats or rotate casually.
- `AUTH_PROXY_TRUST_ENABLED`, matching Pages trust configuration,
  `AUTH_PUBLIC_ORIGIN`, `API_ORIGIN`, exact `CSRF_TRUSTED_ORIGINS`, production
  secure cookie settings and the fixed Google callback URL.
- `TURNSTILE_SECRET_KEY`, allowed hostnames/action, and managed Auth CAPTCHA
  enforcement. Only the site key is appropriate in a public Vite variable.
- Individual backend `*_API_ENABLED`, Pages `*_PROXY_ENABLED` and public Vite
  access switches as documented in the README/reference. Their defaults are off;
  a frontend switch alone must not enable an endpoint.
- Supabase email confirmation/recovery, configured SMTP sending service, exact
  redirect allowlist and Google OAuth credentials remain external requirements.
  No replacement email provider or token service was added here.

## Remaining risks and manual release checklist

1. Review and approve the source diff, then run CI. No commit/push/deploy is part
   of this audit authorization. Ship matching backend/frontend Terms revisions
   together; old receipts/acceptance safely require explicit updated acceptance.
2. After deployment, verify actual HTTPS/TLS/HSTS and normal/error headers,
   direct policy URLs, a real unknown-page 404 and API JSON routing. Verify email,
   Google, recovery, guest Turnstile and cookies using controlled test accounts.
   Local mocks cannot verify Google/Supabase/Turnstile/SMTP configuration.
3. Confirm Auth disallows unconfirmed password sign-in, has appropriate OTP
   expiry/reuse and delivery rate limits, a strong password policy and appropriate
   breached-password controls where supported. Provider hashing/cost was not
   inspected; adding local Argon2 would not improve this managed-password flow.
4. Keep authenticated proxy assertions enabled for exposed abuse-sensitive
   routes and Uvicorn proxy rewriting disabled. Review dashboard origins,
   preview-host exclusion, ingress/header behavior and least-privilege database
   grants. No live dashboard state is attested here.
5. Normal sign-out ends one application session. Global provider logout/revocation
   is not implemented. Provider success followed by local failure/cancellation
   can leave provider sessions or an uncertain password-reset outcome; automatic
   retries are intentionally avoided. Lost-acknowledgement behavior remains an
   operational limitation rather than a distributed transaction guarantee.
6. The Bearer `/account/me` diagnostic verifies JWT claims without the live-cookie
   session/Terms dependency. It returns only that verified subject's ID. Do not
   reuse its JWT-only dependency for future protected user resources; use current
   active-session and ownership checks instead. Existing app sign-out does not
   purport to revoke separately held provider access tokens.
7. Verify runtime secret-store access, backup encryption/access/retention and
   credential-rotation history. A prior local-test credential rotation was not
   established by this audit. If any real secret was previously exposed, removing
   a file does not revoke it; rotate through an approved process. No real secret
   rotation was performed here.
8. Review hosting/edge query logging, monitoring exports and log retention. The
   Uvicorn callback filter cannot redact another provider's logs. Manual privacy
   request/deletion procedures and retention remain operational responsibilities;
   self-service account deletion is deferred.
9. Default rate limits are per address/purpose and allow shared networks; they
   are not distributed-bot or volumetric DDoS protection. No global request
   semaphore, per-account credential-stuffing counter or edge WAF configuration
   was added. Review actual load before increasing worker/connection counts.
10. Preserve the minimal CSP while reviewing a full script-source policy with
    real Turnstile/analytics behavior. No evidence of an existing XSS exploit was
    found; a limited policy is not a general XSS guarantee.

There is no newly demonstrated application exploit remaining as a release blocker
in the reviewed functionality. Review/CI, coordinated Terms rollout and manual
provider/deployment checks above remain prerequisites for publishing this change.
Unimplemented AI features must not be advertised as working or enabled merely
because authentication tests pass.

## Future LLM/RAG requirements

- Treat prompts, retrieved passages and tool output as untrusted data, never as
  permission to alter system policy, reveal secrets or execute arbitrary tools.
- Derive the owner from a verified guest/account credential for every SQL/vector
  query; enforce owner FK/check constraints and negative cross-account/chat tests.
  Public trusted documents and private future material require separate scopes.
- Keep conversation/vehicle context scoped to one conversation; send bounded
  recent relevant turns, not every user's history. Never log private prompt text
  by default or put secrets in model instructions.
- Implement server/database atomic reservations for **guest 3/hour + 10/day** and
  **account 4/hour + 12/day**, both rolling windows per identity; reserve before
  generation, define failure refunds and idempotency, accurate 429 retry time,
  one in-flight generation, IP defenses and a global provider token budget.
  Those AI quotas are **NOT IMPLEMENTED** by the authentication counters.
- Bound prompt, retrieved context, output, concurrency and total duration; handle
  Groq 429/unavailability with controlled retry/backoff and no blind replay of
  model-generating submissions. Do not silently weaken safety to save quota.
- Render Markdown/citations without raw HTML or unsafe URL schemes; validate
  source links, preserve applicability/provenance and use rights-cleared content.
- No arbitrary SQL, shell, network fetch, attachments or unrestricted tools for
  an LLM. Future fetching needs an approved SSRF boundary and content/size limits.
- Add prompt-injection, scope leakage, forged citation, unsafe diagnosis and
  provider-failure evaluations before enabling chat. Review actual provider data
  flows/retention and applicable terms before public use.

## Maintenance and references

Run locked dependency audits routinely and after dependency changes. Consider
Dependabot updates for npm/Python lockfiles and Actions, commit-SHA pinning for
Actions, CodeQL/default code scanning and secret scanning where supported. Action
tags and the PostgreSQL image tag remain mutable; image digest pinning and an OS
image scan are follow-ups. Do not force a non-root user into the upstream
PostgreSQL image without validating its initialization/volume permissions.

Advisory/source references consulted:

- [sharp libheif advisory](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c)
- [Undici retry-interceptor advisory](https://github.com/advisories/GHSA-8xcm-r25x-g524)
- [email-validator behavior/options](https://pypi.org/project/email-validator/)
- [Cloudflare Turnstile CSP](https://developers.cloudflare.com/turnstile/reference/content-security-policy/)
- [Cloudflare Pages header rules](https://developers.cloudflare.com/pages/configuration/headers/)

Advisory results are point-in-time registry responses, not proof that dependencies
have no unknown vulnerabilities. Re-run them at release time.

## Exact working-tree file inventory

Includes the prior approved 404/policy edits and this audit. Ignored local test
logs, screenshots and resume notes are excluded. Inventory captured before
checkpoint staging and commit.

- `README.md`
- `SECURITY_AUDIT.md`
- `backend/app/account_sign_up_requests.py`
- `backend/app/account_terms_requests.py`
- `backend/app/main.py`
- `backend/app/security_headers.py`
- `backend/pyproject.toml`
- `backend/tests/integration/test_account_oauth_cleanup_db.py`
- `backend/tests/integration/test_sign_up_rate_limits.py`
- `backend/tests/test_account_sign_up_requests.py`
- `backend/tests/test_account_sign_up_routes.py`
- `backend/tests/test_account_terms_requests.py`
- `backend/tests/test_account_tokens.py`
- `backend/tests/test_security_headers.py`
- `backend/uv.lock`
- `frontend/404.html`
- `frontend/functions/api/[[path]].ts`
- `frontend/package-lock.json`
- `frontend/package.json`
- `frontend/public/_headers`
- `frontend/public/_redirects`
- `frontend/shared/account-terms.ts`
- `frontend/src/App.session.test.tsx`
- `frontend/src/App.signInSession.test.tsx`
- `frontend/src/App.signOut.test.tsx`
- `frontend/src/App.startup.test.tsx`
- `frontend/src/Page.test.tsx`
- `frontend/src/Page.tsx`
- `frontend/src/components/AccountSignUpForm.google.test.tsx`
- `frontend/src/components/AccountSignUpForm.test.tsx`
- `frontend/src/components/NotFound.tsx`
- `frontend/src/components/PrivacyNotice.tsx`
- `frontend/src/components/TermsOfService.tsx`
- `frontend/src/hooks/useAccountSignUp.test.tsx`
- `frontend/src/not-found.tsx`
- `frontend/tests/account-registration-api.test.mjs`
- `frontend/tests/account-sign-up-proxy.test.mjs`
- `frontend/tests/fixtures/page-routing-worker.mjs`
- `frontend/tests/page-routing-runtime.test.mjs`
- `frontend/tests/security-headers.test.mjs`
- `frontend/vite.config.ts`
- `reference/IMPLEMENTATION.md`
