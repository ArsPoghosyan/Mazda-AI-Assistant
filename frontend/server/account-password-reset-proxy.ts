import { ProxyBodyTooLarge, readProxyBytes } from './session-proxy-io.ts'
import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'

export type AccountPasswordResetProxyEnvironment = SessionProxyEnvironment & { ACCOUNT_PASSWORD_RESET_PROXY_ENABLED?: string }
const PATH = '/api/v1/account/password-reset'
const UNAVAILABLE = 'Password reset is temporarily unavailable.'
const COMPLETED_MESSAGE = 'Password reset completed. Sign in with your new password.'
const MAX_BYTES = 4096

class InvalidResetRequest extends Error {
  readonly status: number
  constructor(status = 400) { super('Invalid password reset request.'); this.status = status }
}

function reply(detail: string, status: number, extra: Record<string, string> = {}): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store', ...extra } })
}

async function readCredentials(request: Request, signal: AbortSignal): Promise<string> {
  if (request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    throw new InvalidResetRequest(415)
  }
  const length = request.headers.get('Content-Length')
  if (length !== null && !/^(0|[1-9][0-9]{0,4})$/.test(length)) throw new InvalidResetRequest()
  if (length !== null && Number(length) > 16 * 1024) throw new InvalidResetRequest(413)
  let bytes: Uint8Array
  try { bytes = await readProxyBytes(request.body, signal, 16 * 1024) }
  catch (error) {
    if (error instanceof ProxyBodyTooLarge) throw new InvalidResetRequest(413)
    throw error
  }
  if (length !== null && Number(length) !== bytes.byteLength) throw new InvalidResetRequest()
  let payload: unknown
  try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)) }
  catch { throw new InvalidResetRequest() }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new InvalidResetRequest()
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'code,email,new_password' ||
      typeof body.email !== 'string' || Array.from(body.email).length < 1 || Array.from(body.email).length > 320 ||
      new TextDecoder('utf-8', { ignoreBOM: true }).decode(new TextEncoder().encode(body.email)) !== body.email ||
      typeof body.new_password !== 'string' || Array.from(body.new_password).length < 1 || Array.from(body.new_password).length > 1024 ||
      new TextDecoder('utf-8', { ignoreBOM: true }).decode(new TextEncoder().encode(body.new_password)) !== body.new_password ||
      typeof body.code !== 'string' || body.code.length < 6 || body.code.length > 10 || /[^0-9]/.test(body.code)) {
    throw new InvalidResetRequest()
  }
  // Preserve credentials exactly. The backend verifies proof and password policy.
  return JSON.stringify({ email: body.email, code: body.code, new_password: body.new_password })
}

async function completed(response: Response, signal: AbortSignal): Promise<Response> {
  const length = response.headers.get('Content-Length')
  if (response.headers.has('Set-Cookie') ||
      response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
      !['', 'identity'].includes(response.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
      (length !== null && (!/^[0-9]{1,5}$/.test(length) || Number(length) > MAX_BYTES))) {
    throw new Error('Invalid reset response framing')
  }
  const bytes = await readProxyBytes(response.body, signal, MAX_BYTES)
  if (length !== null && Number(length) !== bytes.byteLength) throw new Error('Response length mismatch')
  const payload: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes))
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('Invalid reset response')
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'message,status' || body.status !== 'completed' || body.message !== COMPLETED_MESSAGE) {
    throw new Error('Invalid reset response')
  }
  signal.throwIfAborted()
  return Response.json({ status: 'completed', message: COMPLETED_MESSAGE }, { headers: { 'Cache-Control': 'no-store' } })
}

export async function forwardAccountPasswordReset(request: Request, env: AccountPasswordResetProxyEnvironment): Promise<Response> {
  const decision = planSessionProxyOrigin(request, env, PATH, env.ACCOUNT_PASSWORD_RESET_PROXY_ENABLED)
  if (decision instanceof Response) return decision
  const plan = decision
  const url = new URL(request.url)
  const transfer = request.headers.get('Transfer-Encoding')
  if (url.search || url.hash ||
      (transfer !== null && (transfer !== 'chunked' || request.headers.has('Content-Length'))) ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')) {
    return reply('Invalid password reset request.', 400)
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
      const body = await readCredentials(request, controller.signal)
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, { method: 'POST', headers, body,
        redirect: 'manual', cache: 'no-store', credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 200) return await completed(upstream, controller.signal)
      if (upstream.status === 400) return reply('Password reset was rejected.', 400)
      if (upstream.status === 403) return reply('Request origin is not allowed.', 403)
      if (upstream.status === 429) {
        const raw = upstream.headers.get('Retry-After')
        const seconds = raw !== null && /^[0-9]{1,5}$/.test(raw) ? Number(raw) : NaN
        return reply('Password reset is temporarily rate limited.', 429,
          seconds >= 1 && seconds <= 86_400 ? { 'Retry-After': String(seconds) } : {})
      }
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      if ([413, 415].includes(upstream.status)) return reply('Invalid password reset request.', upstream.status)
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
    if (error instanceof InvalidResetRequest) return reply('Invalid password reset request.', error.status)
    return reply(UNAVAILABLE, error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
