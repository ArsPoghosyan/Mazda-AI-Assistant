import { ACCOUNT_COOKIE, validatedCreatedAccountCookie } from './account-session-proxy-cookies.ts'
import { readAccountProxyMetadata } from './account-session-proxy-response.ts'
import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { readProxyCookieValue } from './session-proxy-cookies.ts'
import { ProxyBodyTooLarge, readProxyBytes } from './session-proxy-io.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'

export type AccountSignInProxyEnvironment = SessionProxyEnvironment & { ACCOUNT_SIGN_IN_PROXY_ENABLED?: string }
const PATH = '/api/v1/account/sign-in'
const MAX_REQUEST_BYTES = 16 * 1024
const UNAVAILABLE = 'Account sign-in is temporarily unavailable.'
const SIGN_OUT_FIRST = 'Sign out before starting another account login.'

function reply(detail: string, status: number, extra: Record<string, string> = {}): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store', ...extra } })
}

class InvalidSignInRequest extends Error {
  readonly status: number
  constructor(status = 400) { super('Invalid sign-in request.'); this.status = status }
}

function validCredential(value: unknown, maximum: number): value is string {
  if (typeof value !== 'string') return false
  const length = Array.from(value).length
  return length >= 1 && length <= maximum &&
    new TextDecoder('utf-8', { ignoreBOM: true }).decode(new TextEncoder().encode(value)) === value
}

async function credentialsBody(request: Request, signal: AbortSignal): Promise<string> {
  if (request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    throw new InvalidSignInRequest(415)
  }
  const length = request.headers.get('Content-Length')
  if (length !== null && !/^(0|[1-9][0-9]{0,4})$/.test(length)) throw new InvalidSignInRequest()
  if (length !== null && Number(length) > MAX_REQUEST_BYTES) throw new InvalidSignInRequest(413)
  let bytes: Uint8Array
  try { bytes = await readProxyBytes(request.body, signal, MAX_REQUEST_BYTES) }
  catch (error) {
    if (error instanceof ProxyBodyTooLarge) throw new InvalidSignInRequest(413)
    throw error
  }
  if (length !== null && Number(length) !== bytes.byteLength) throw new InvalidSignInRequest()
  let payload: unknown
  try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)) }
  catch { throw new InvalidSignInRequest() }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new InvalidSignInRequest()
  const body = payload as Record<string, unknown>
  if (
    Object.keys(body).some((key) => !['email', 'password', 'captcha_token'].includes(key)) ||
    !validCredential(body.email, 320) || !validCredential(body.password, 1024)
  ) throw new InvalidSignInRequest()
  const proof = body.captcha_token
  if (proof !== undefined && proof !== null &&
      (typeof proof !== 'string' || proof.length < 1 || proof.length > 2048 || /[^\x21-\x7e]/.test(proof))) {
    throw new InvalidSignInRequest()
  }
  // Preserve credential case/whitespace/Unicode. Only the backend authenticates.
  return JSON.stringify({ email: body.email, password: body.password,
    ...(proof === undefined ? {} : { captcha_token: proof }),
  })
}

export async function forwardAccountSignIn(request: Request, env: AccountSignInProxyEnvironment): Promise<Response> {
  const decision = planSessionProxyOrigin(request, env, PATH, env.ACCOUNT_SIGN_IN_PROXY_ENABLED)
  if (decision instanceof Response) return decision
  const plan = decision
  const url = new URL(request.url)
  const transfer = request.headers.get('Transfer-Encoding')
  if (url.search || url.hash ||
      (transfer !== null && (transfer !== 'chunked' || request.headers.has('Content-Length'))) ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')) {
    return reply('Invalid sign-in request.', 400)
  }
  // Presence, not token validity: never bypass explicit sign-out by omitting a
  // malformed/stale credential. No other browser cookies belong on this request.
  try {
    if (readProxyCookieValue(request, ACCOUNT_COOKIE) !== null) return reply(SIGN_OUT_FIRST, 409)
  } catch { return reply('Invalid sign-in request.', 400) }
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
      const headers = proxyClientIPHeaders(request, env)
      headers.set('Accept', 'application/json')
      headers.set('Accept-Encoding', 'identity')
      headers.set('Content-Type', 'application/json')
      headers.set('Origin', plan.publicOrigin)
      const body = await credentialsBody(request, controller.signal)
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, { method: 'POST', headers, body,
        redirect: 'manual', cache: 'no-store', credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 200) {
        const metadata = await readAccountProxyMetadata(upstream, controller.signal)
        const cookie = validatedCreatedAccountCookie(upstream.headers, metadata.idle)
        controller.signal.throwIfAborted()
        return Response.json(metadata.body, { headers: { 'Cache-Control': 'no-store', 'Set-Cookie': cookie } })
      }
      if (upstream.status === 401) return reply('Sign-in was rejected.', 401)
      if (upstream.status === 409) return reply(SIGN_OUT_FIRST, 409)
      if (upstream.status === 403) {
        return upstream.headers.get('X-Account-Verification') === 'required'
          ? reply('Human verification is required or was rejected.', 403, { 'X-Account-Verification': 'required' })
          : reply('Request origin is not allowed.', 403)
      }
      if (upstream.status === 429) {
        const raw = upstream.headers.get('Retry-After')
        const seconds = raw !== null && /^[0-9]{1,5}$/.test(raw) ? Number(raw) : NaN
        return reply('Sign-in is temporarily rate limited.', 429,
          seconds >= 1 && seconds <= 86_400 ? { 'Retry-After': String(seconds) } : {})
      }
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      if ([400, 413, 415].includes(upstream.status)) return reply('Invalid sign-in request.', upstream.status)
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
    if (error instanceof InvalidSignInRequest) return reply('Invalid sign-in request.', error.status)
    return reply(UNAVAILABLE, error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
