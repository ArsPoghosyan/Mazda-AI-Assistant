import { ACCOUNT_COOKIE } from './account-session-proxy-cookies.ts'
import { OAUTH_COOKIE, readOAuthProxyCookies, validatedClearingOAuthCookie } from './account-oauth-proxy-cookies.ts'
import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { parseProxyCookie, PROXY_COOKIE_SCOPE, PROXY_TOKEN, readProxyCookieValue } from './session-proxy-cookies.ts'
import { confirmEmptyProxyBody, proxyUtcTime, readProxyBytes } from './session-proxy-io.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'

export type AccountGoogleStartProxyEnvironment = SessionProxyEnvironment & {
  ACCOUNT_GOOGLE_START_PROXY_ENABLED?: string
  SUPABASE_AUTH_ISSUER?: string
}
const PATH = '/api/v1/account/google/start'
const UNAVAILABLE = 'Google sign-in is temporarily unavailable.'
const SIGN_OUT_FIRST = 'Sign out before starting another account login.'
const HEADERS = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }

function reply(detail: string, status: number, extra: Record<string, string> = {}): Response {
  return Response.json({ detail }, { status, headers: { ...HEADERS, ...extra } })
}

function issuerUrl(value: string | undefined): URL {
  if (!value || value.length > 2048) throw new Error('Missing Google issuer')
  const url = new URL(value)
  if (url.protocol !== 'https:' || value !== `${url.origin}/auth/v1`) throw new Error('Invalid Google issuer')
  return url
}

async function started(response: Response, signal: AbortSignal, issuer: URL, publicOrigin: string): Promise<Response> {
  const length = response.headers.get('Content-Length')
  if (response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
      !['', 'identity'].includes(response.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
      (length !== null && (!/^[0-9]{1,5}$/.test(length) || Number(length) > 4096))) {
    throw new Error('Invalid Google start response framing')
  }
  const bytes = await readProxyBytes(response.body, signal, 4096)
  if (length !== null && Number(length) !== bytes.byteLength) throw new Error('Response length mismatch')
  const payload: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes))
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('Invalid Google start response')
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'authorization_url,expires_at' ||
      typeof body.authorization_url !== 'string' || body.authorization_url.length > 4096) throw new Error('Invalid Google start metadata')
  const expiry = proxyUtcTime(body.expires_at)
  if (expiry <= Date.now()) throw new Error('Expired Google attempt')
  const destination = new URL(body.authorization_url)
  const parameters = destination.searchParams
  const keys = [...parameters.keys()]
  const challenge = parameters.get('code_challenge') ?? ''
  const callback = `${publicOrigin}/api/v1/account/google/callback`
  if (destination.protocol !== 'https:' || destination.origin !== issuer.origin ||
      destination.pathname !== '/auth/v1/authorize' || destination.username || destination.password || destination.hash ||
      body.authorization_url !== destination.href || keys.length !== 4 || new Set(keys).size !== 4 ||
      !keys.every((key) => ['provider', 'redirect_to', 'code_challenge', 'code_challenge_method'].includes(key)) ||
      parameters.get('provider') !== 'google' || parameters.get('redirect_to') !== callback ||
      parameters.get('code_challenge_method') !== 's256' || challenge.length !== 43 || !PROXY_TOKEN.test(challenge)) {
    throw new Error('Invalid Google authorization destination')
  }
  const cookie = parseProxyCookie(response.headers, OAUTH_COOKIE)
  if (!PROXY_TOKEN.test(cookie.value) || cookie.attributes.has('max-age') || cookie.expiry <= Date.now() ||
      cookie.expiry !== Math.floor(expiry / 1000) * 1000) throw new Error('Invalid OAuth binding cookie')
  const authorization = new URL('/auth/v1/authorize', issuer)
  authorization.search = new URLSearchParams({ provider: 'google', redirect_to: callback,
    code_challenge: challenge, code_challenge_method: 's256' }).toString()
  signal.throwIfAborted()
  return Response.json({ authorization_url: authorization.href, expires_at: body.expires_at }, {
    headers: { ...HEADERS, 'Set-Cookie': `${OAUTH_COOKIE}=${cookie.value}; Expires=${cookie.rawExpiry}; ${PROXY_COOKIE_SCOPE}` },
  })
}

export async function forwardAccountGoogleStart(request: Request, env: AccountGoogleStartProxyEnvironment): Promise<Response> {
  const decision = planSessionProxyOrigin(request, env, PATH, env.ACCOUNT_GOOGLE_START_PROXY_ENABLED)
  if (decision instanceof Response) {
    decision.headers.set('Referrer-Policy', 'no-referrer')
    return decision
  }
  const plan = decision
  let issuer: URL
  try { issuer = issuerUrl(env.SUPABASE_AUTH_ISSUER) }
  catch { return reply(UNAVAILABLE, 503) }
  const url = new URL(request.url)
  const length = request.headers.get('Content-Length')
  if (url.search || url.hash || (request.body !== null && length !== '0') ||
      (length !== null && length !== '0') || request.headers.has('Transfer-Encoding') ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')) {
    return reply('Invalid Google sign-in request.', 400)
  }
  let binding: string | null
  try {
    if (readProxyCookieValue(request, ACCOUNT_COOKIE) !== null) return reply(SIGN_OUT_FIRST, 409)
    binding = readOAuthProxyCookies(request)
  } catch { return reply('Invalid Google sign-in request.', 400) }
  if (env.AUTH_PROXY_TRUST_ENABLED !== 'true') return reply(UNAVAILABLE, 503)
  if (request.signal.aborted) return reply(UNAVAILABLE, 502)
  const controller = new AbortController()
  const abort = () => controller.abort()
  const cancelled = new Promise<never>((_resolve, reject) => {
    controller.signal.addEventListener('abort', () => reject(new Error('Cancelled')), { once: true })
  })
  request.signal.addEventListener('abort', abort, { once: true })
  const timer = setTimeout(abort, 20_000)
  let upstream: Response | undefined
  async function exchange(): Promise<Response> {
    try {
      if (!await confirmEmptyProxyBody(request.body, controller.signal)) return reply('Invalid Google sign-in request.', 400)
      const headers = proxyClientIPHeaders(request, env)
      headers.set('Accept', 'application/json')
      headers.set('Accept-Encoding', 'identity')
      headers.set('Origin', plan.publicOrigin)
      if (binding !== null) headers.set('Cookie', binding)
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, { method: 'POST', headers, redirect: 'manual',
        cache: 'no-store', credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 200) return await started(upstream, controller.signal, issuer, plan.publicOrigin)
      if (upstream.status === 400) return reply('Google sign-in must be started again.', 400,
        upstream.headers.has('Set-Cookie') ? { 'Set-Cookie': validatedClearingOAuthCookie(upstream.headers) } : {})
      if (upstream.status === 403) return reply('Request origin is not allowed.', 403)
      if (upstream.status === 409) return reply(SIGN_OUT_FIRST, 409)
      if (upstream.status === 429) {
        const raw = upstream.headers.get('Retry-After')
        const seconds = raw !== null && /^[0-9]{1,5}$/.test(raw) ? Number(raw) : NaN
        return reply('Google sign-in is temporarily rate limited.', 429,
          seconds >= 1 && seconds <= 86_400 ? { 'Retry-After': String(seconds) } : {})
      }
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      throw new Error('Unexpected backend response')
    } finally {
      if (upstream?.body && !upstream.body.locked) void upstream.body.cancel().catch(() => {})
    }
  }
  try {
    const response = await Promise.race([exchange(), cancelled])
    controller.signal.throwIfAborted()
    return response
  } catch (error) {
    controller.abort()
    return reply(UNAVAILABLE, error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
