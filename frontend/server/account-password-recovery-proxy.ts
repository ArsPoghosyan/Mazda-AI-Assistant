import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { ProxyBodyTooLarge, readProxyBytes } from './session-proxy-io.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'

export type AccountPasswordRecoveryProxyEnvironment = SessionProxyEnvironment & { ACCOUNT_PASSWORD_RECOVERY_PROXY_ENABLED?: string }
const PATH = '/api/v1/account/password-recovery'
const UNAVAILABLE = 'Password recovery is temporarily unavailable.'
const ACCEPTED_MESSAGE = 'If password recovery can proceed, check your email for the next steps.'

function reply(detail: string, status: number, extra: Record<string, string> = {}): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store', ...extra } })
}

class InvalidRecoveryRequest extends Error {
  readonly status: number
  constructor(status = 400) { super('Invalid password recovery request.'); this.status = status }
}

async function readRecoveryCredentials(request: Request, signal: AbortSignal): Promise<string> {
  if (request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    throw new InvalidRecoveryRequest(415)
  }
  const length = request.headers.get('Content-Length')
  if (length !== null && !/^(0|[1-9][0-9]{0,4})$/.test(length)) throw new InvalidRecoveryRequest()
  if (length !== null && Number(length) > 16 * 1024) throw new InvalidRecoveryRequest(413)
  let bytes: Uint8Array
  try { bytes = await readProxyBytes(request.body, signal, 16 * 1024) }
  catch (error) {
    if (error instanceof ProxyBodyTooLarge) throw new InvalidRecoveryRequest(413)
    throw error
  }
  if (length !== null && Number(length) !== bytes.byteLength) throw new InvalidRecoveryRequest()
  let payload: unknown
  try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)) }
  catch { throw new InvalidRecoveryRequest() }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new InvalidRecoveryRequest()
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'captcha_token,email' ||
      typeof body.email !== 'string' || Array.from(body.email).length < 1 || Array.from(body.email).length > 320 ||
      new TextDecoder('utf-8', { ignoreBOM: true }).decode(new TextEncoder().encode(body.email)) !== body.email ||
      typeof body.captcha_token !== 'string' || body.captcha_token.length < 1 || body.captcha_token.length > 2048 ||
      /[^\x21-\x7e]/.test(body.captcha_token)) {
    throw new InvalidRecoveryRequest()
  }
  // Preserve email and proof exactly; only the backend/provider verifies them.
  return JSON.stringify({ email: body.email, captcha_token: body.captcha_token })
}

async function accepted(response: Response, signal: AbortSignal): Promise<Response> {
  const length = response.headers.get('Content-Length')
  if (
    response.headers.has('Set-Cookie') ||
    response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
    !['', 'identity'].includes(response.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
    (length !== null && (!/^[0-9]{1,5}$/.test(length) || Number(length) > 4096))
  ) throw new Error('Invalid password recovery response framing')
  const bytes = await readProxyBytes(response.body, signal, 4096)
  if (length !== null && Number(length) !== bytes.byteLength) throw new Error('Response length mismatch')
  const payload: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes))
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('Invalid password recovery response')
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'message,status' || body.status !== 'accepted' || body.message !== ACCEPTED_MESSAGE) {
    throw new Error('Invalid password recovery response')
  }
  signal.throwIfAborted()
  return Response.json({ status: 'accepted', message: ACCEPTED_MESSAGE }, { status: 202, headers: { 'Cache-Control': 'no-store' } })
}

export async function forwardAccountPasswordRecovery(request: Request, env: AccountPasswordRecoveryProxyEnvironment): Promise<Response> {
  const decision = planSessionProxyOrigin(request, env, PATH, env.ACCOUNT_PASSWORD_RECOVERY_PROXY_ENABLED)
  if (decision instanceof Response) return decision
  const plan = decision
  const url = new URL(request.url)
  const transfer = request.headers.get('Transfer-Encoding')
  if (url.search || url.hash ||
      (transfer !== null && (transfer !== 'chunked' || request.headers.has('Content-Length'))) ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')) {
    return reply('Invalid password recovery request.', 400)
  }
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
      const body = await readRecoveryCredentials(request, controller.signal)
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, { method: 'POST', headers, body,
        redirect: 'manual', cache: 'no-store', credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 202) return await accepted(upstream, controller.signal)
      if (upstream.status === 400) return reply('Password recovery was rejected.', 400)
      if (upstream.status === 403) {
        return upstream.headers.get('X-Account-Verification') === 'required'
          ? reply('Human verification is required or was rejected.', 403, { 'X-Account-Verification': 'required' })
          : reply('Request origin is not allowed.', 403)
      }
      if (upstream.status === 429) {
        const raw = upstream.headers.get('Retry-After')
        const seconds = raw !== null && /^[0-9]{1,5}$/.test(raw) ? Number(raw) : NaN
        return reply('Password recovery is temporarily rate limited.', 429,
          seconds >= 1 && seconds <= 86_400 ? { 'Retry-After': String(seconds) } : {})
      }
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      if ([413, 415].includes(upstream.status)) return reply('Invalid password recovery request.', upstream.status)
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
    if (error instanceof InvalidRecoveryRequest) return reply('Invalid password recovery request.', error.status)
    return reply(UNAVAILABLE, error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
