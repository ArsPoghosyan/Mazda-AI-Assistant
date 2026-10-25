import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { parseProxyCookie, PROXY_COOKIE_SCOPE, PROXY_TOKEN, readProxyToken } from './session-proxy-cookies.ts'
import { ProxyBodyTooLarge, proxyUtcTime, readProxyBytes } from './session-proxy-io.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'

export type GuestSessionProxyEnvironment = SessionProxyEnvironment & { GUEST_SESSION_PROXY_ENABLED?: string }
const PATH = '/api/v1/guest/session'
const COOKIE = '__Host-askm6_guest'
const MAX_REQUEST_BYTES = 16 * 1024
const MAX_RESPONSE_BYTES = 4096
const TIMEOUT_MS = 20_000
const UNAVAILABLE = 'Guest sessions are temporarily unavailable.'

function reply(detail: string, status: number, extra: Record<string, string> = {}): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store', ...extra } })
}

class InvalidGuestRequest extends Error {
  readonly status: number
  constructor(status = 400) { super('Invalid guest-session request.'); this.status = status }
}

async function challengeBody(request: Request, signal: AbortSignal): Promise<string | undefined> {
  const length = request.headers.get('Content-Length')
  if (length !== null && !/^(0|[1-9][0-9]{0,4})$/.test(length)) throw new InvalidGuestRequest()
  if (length !== null && Number(length) > MAX_REQUEST_BYTES) throw new InvalidGuestRequest(413)
  let bytes: Uint8Array
  try { bytes = await readProxyBytes(request.body, signal, MAX_REQUEST_BYTES) }
  catch (error) {
    if (error instanceof ProxyBodyTooLarge) throw new InvalidGuestRequest(413)
    throw error
  }
  if (length !== null && Number(length) !== bytes.byteLength) throw new InvalidGuestRequest()
  if (!bytes.byteLength) return undefined
  if (request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    throw new InvalidGuestRequest(415)
  }
  let payload: unknown
  try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)) }
  catch { throw new InvalidGuestRequest() }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new InvalidGuestRequest()
  const body = payload as Record<string, unknown>
  if (Object.keys(body).some((key) => key !== 'turnstile_token')) throw new InvalidGuestRequest()
  const token = body.turnstile_token
  if (token !== undefined && token !== null) {
    if (
      typeof token !== 'string' || Array.from(token).length < 1 || Array.from(token).length > 2048 ||
      new TextDecoder().decode(new TextEncoder().encode(token)) !== token
    ) throw new InvalidGuestRequest()
  }
  // Rebuild only the validated field; no identity or destination comes from JSON.
  return JSON.stringify(token === undefined ? {} : { turnstile_token: token })
}

async function success(response: Response, signal: AbortSignal): Promise<Response> {
  const length = response.headers.get('Content-Length')
  if (
    response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
    !['', 'identity'].includes(response.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
    (length !== null && (!/^[0-9]{1,5}$/.test(length) || Number(length) > MAX_RESPONSE_BYTES))
  ) throw new Error('Invalid guest response')
  const bytes = await readProxyBytes(response.body, signal, MAX_RESPONSE_BYTES)
  if (length !== null && Number(length) !== bytes.byteLength) throw new Error('Response length mismatch')
  const payload: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes))
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('Invalid metadata')
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'expires_at,status' || body.status !== 'ok') throw new Error('Invalid metadata')
  const expires = proxyUtcTime(body.expires_at)
  const cookie = parseProxyCookie(response.headers, COOKIE)
  if (
    expires <= Date.now() || !PROXY_TOKEN.test(cookie.value) || cookie.attributes.has('max-age') ||
    cookie.expiry !== Math.floor(expires / 1000) * 1000 || cookie.expiry <= Date.now()
  ) throw new Error('Invalid guest cookie')
  signal.throwIfAborted()
  return Response.json({ status: 'ok', expires_at: body.expires_at }, { headers: {
    'Cache-Control': 'no-store', 'Set-Cookie': `${COOKIE}=${cookie.value}; Expires=${cookie.rawExpiry}; ${PROXY_COOKIE_SCOPE}`,
  } })
}

export async function forwardGuestSession(request: Request, env: GuestSessionProxyEnvironment): Promise<Response> {
  const decision = planSessionProxyOrigin(request, env, PATH, env.GUEST_SESSION_PROXY_ENABLED)
  if (decision instanceof Response) return decision
  const plan = decision
  const url = new URL(request.url)
  const transfer = request.headers.get('Transfer-Encoding')
  // Workers exposes decoded chunked bodies. Bound that stream and rebuild JSON;
  // never copy framing headers or accept conflicting length/transfer assertions.
  if (url.search || url.hash ||
      (transfer !== null && (transfer !== 'chunked' || request.headers.has('Content-Length'))) ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')) {
    return reply('Invalid guest-session request.', 400)
  }
  // New guest credentials must never be created using a shared proxy-peer budget.
  if (env.AUTH_PROXY_TRUST_ENABLED !== 'true') return reply(UNAVAILABLE, 503)
  let token: string | null
  try { token = readProxyToken(request, COOKIE) }
  catch { return reply('Invalid guest-session request.', 400) }
  if (request.signal.aborted) return reply(UNAVAILABLE, 502)

  const controller = new AbortController()
  const abort = () => controller.abort()
  const cancelled = new Promise<never>((_resolve, reject) => {
    controller.signal.addEventListener('abort', () => reject(new Error('Cancelled')), { once: true })
  })
  request.signal.addEventListener('abort', abort, { once: true })
  const timer = setTimeout(abort, TIMEOUT_MS)
  let upstream: Response | undefined
  async function exchange(): Promise<Response> {
    try {
      const headers = proxyClientIPHeaders(request, env)
      headers.set('Accept', 'application/json')
      headers.set('Accept-Encoding', 'identity')
      headers.set('Origin', plan.publicOrigin)
      if (token) headers.set('Cookie', `${COOKIE}=${token}`)
      const body = await challengeBody(request, controller.signal)
      if (body !== undefined) headers.set('Content-Type', 'application/json')
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, {
        method: 'POST', headers, body, redirect: 'manual', cache: 'no-store',
        credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 200) return await success(upstream, controller.signal)
      if (upstream.status === 403) {
        return upstream.headers.get('X-Guest-Verification') === 'required'
          ? reply('Human verification is required or was rejected.', 403, { 'X-Guest-Verification': 'required' })
          : reply('Request origin is not allowed.', 403)
      }
      if (upstream.status === 429) {
        const raw = upstream.headers.get('Retry-After')
        const seconds = raw !== null && /^[0-9]{1,5}$/.test(raw) ? Number(raw) : NaN
        return reply('Guest session creation is temporarily rate limited.', 429,
          seconds >= 1 && seconds <= 86_400 ? { 'Retry-After': String(seconds) } : {})
      }
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      if ([400, 413, 415].includes(upstream.status)) return reply('Invalid guest-session request.', upstream.status)
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
    if (error instanceof InvalidGuestRequest) return reply('Invalid guest-session request.', error.status)
    return reply(UNAVAILABLE, error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
