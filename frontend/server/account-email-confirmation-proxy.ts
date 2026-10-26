import { ProxyBodyTooLarge, readProxyBytes } from './session-proxy-io.ts'
import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'
import { readSignupTermsProxyCookie, validatedSignupTermsCookie } from './signup-terms-proxy-cookies.ts'

export type AccountEmailConfirmationProxyEnvironment = SessionProxyEnvironment & { ACCOUNT_EMAIL_CONFIRMATION_PROXY_ENABLED?: string }
const PATH = '/api/v1/account/confirm-email'
const UNAVAILABLE = 'Email confirmation is temporarily unavailable.'
const CONFIRMED_MESSAGE = 'Email confirmed. You can now sign in.'
const MAX_BYTES = 4096

class InvalidConfirmationRequest extends Error {
  readonly status: number
  constructor(status = 400) { super('Invalid email confirmation request.'); this.status = status }
}

function reply(detail: string, status: number, extra: Record<string, string> = {}): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store', ...extra } })
}

async function readCredentials(request: Request, signal: AbortSignal): Promise<string> {
  if (request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    throw new InvalidConfirmationRequest(415)
  }
  const length = request.headers.get('Content-Length')
  if (length !== null && !/^(0|[1-9][0-9]{0,4})$/.test(length)) throw new InvalidConfirmationRequest()
  if (length !== null && Number(length) > MAX_BYTES) throw new InvalidConfirmationRequest(413)
  let bytes: Uint8Array
  try { bytes = await readProxyBytes(request.body, signal, MAX_BYTES) }
  catch (error) {
    if (error instanceof ProxyBodyTooLarge) throw new InvalidConfirmationRequest(413)
    throw error
  }
  if (length !== null && Number(length) !== bytes.byteLength) throw new InvalidConfirmationRequest()
  let payload: unknown
  try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)) }
  catch { throw new InvalidConfirmationRequest() }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new InvalidConfirmationRequest()
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'code,email' ||
      typeof body.email !== 'string' || Array.from(body.email).length < 1 || Array.from(body.email).length > 320 ||
      new TextDecoder('utf-8', { ignoreBOM: true }).decode(new TextEncoder().encode(body.email)) !== body.email ||
      typeof body.code !== 'string' || body.code.length < 6 || body.code.length > 10 || /[^0-9]/.test(body.code)) {
    throw new InvalidConfirmationRequest()
  }
  // The backend verifies the code. Do not trim email or convert away leading zeros.
  return JSON.stringify({ email: body.email, code: body.code })
}

async function confirmed(response: Response, signal: AbortSignal, hadReceipt: boolean): Promise<Response> {
  const length = response.headers.get('Content-Length')
  if ((!hadReceipt && response.headers.has('Set-Cookie')) ||
      response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
      !['', 'identity'].includes(response.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
      (length !== null && (!/^[0-9]{1,5}$/.test(length) || Number(length) > MAX_BYTES))) {
    throw new Error('Invalid confirmation response framing')
  }
  const bytes = await readProxyBytes(response.body, signal, MAX_BYTES)
  if (length !== null && Number(length) !== bytes.byteLength) throw new Error('Response length mismatch')
  const payload: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes))
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('Invalid confirmation response')
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'message,status' || body.status !== 'confirmed' || body.message !== CONFIRMED_MESSAGE) {
    throw new Error('Invalid confirmation response')
  }
  signal.throwIfAborted()
  return Response.json({ status: 'confirmed', message: CONFIRMED_MESSAGE }, { headers: {
    'Cache-Control': 'no-store', ...(hadReceipt ? { 'Set-Cookie': validatedSignupTermsCookie(response.headers, true) } : {}),
  } })
}

export async function forwardAccountEmailConfirmation(request: Request, env: AccountEmailConfirmationProxyEnvironment): Promise<Response> {
  const decision = planSessionProxyOrigin(request, env, PATH, env.ACCOUNT_EMAIL_CONFIRMATION_PROXY_ENABLED)
  if (decision instanceof Response) return decision
  const plan = decision
  let receipt: string | null
  try { receipt = readSignupTermsProxyCookie(request) } catch { return reply('Invalid email confirmation request.', 400) }
  const url = new URL(request.url)
  const transfer = request.headers.get('Transfer-Encoding')
  if (url.search || url.hash ||
      (transfer !== null && (transfer !== 'chunked' || request.headers.has('Content-Length'))) ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')) {
    return reply('Invalid email confirmation request.', 400)
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
      if (receipt) headers.set('Cookie', receipt)
      const body = await readCredentials(request, controller.signal)
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, { method: 'POST', headers, body,
        redirect: 'manual', cache: 'no-store', credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 200) return await confirmed(upstream, controller.signal, receipt !== null)
      if (upstream.status === 400) return reply('Email confirmation was rejected.', 400)
      if (upstream.status === 403) return reply('Request origin is not allowed.', 403)
      if (upstream.status === 429) {
        const raw = upstream.headers.get('Retry-After')
        const seconds = raw !== null && /^[0-9]{1,5}$/.test(raw) ? Number(raw) : NaN
        return reply('Email confirmation is temporarily rate limited.', 429,
          seconds >= 1 && seconds <= 86_400 ? { 'Retry-After': String(seconds) } : {})
      }
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      if ([413, 415].includes(upstream.status)) return reply('Invalid email confirmation request.', upstream.status)
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
    if (error instanceof InvalidConfirmationRequest) return reply('Invalid email confirmation request.', error.status)
    return reply(UNAVAILABLE, error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
