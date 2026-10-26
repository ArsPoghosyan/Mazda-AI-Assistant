import { InvalidCredentialProxyRequest, readCredentialProxyBody } from './account-credential-proxy-request.ts'
import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { readProxyBytes } from './session-proxy-io.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'

export type AccountSignUpProxyEnvironment = SessionProxyEnvironment & { ACCOUNT_SIGN_UP_PROXY_ENABLED?: string }
const PATH = '/api/v1/account/sign-up'
const UNAVAILABLE = 'Account registration is temporarily unavailable.'
const ACCEPTED_MESSAGE = 'If registration can proceed, check your email for a verification code.'

function reply(detail: string, status: number, extra: Record<string, string> = {}): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store', ...extra } })
}

async function accepted(response: Response, signal: AbortSignal): Promise<Response> {
  const length = response.headers.get('Content-Length')
  if (
    response.headers.has('Set-Cookie') ||
    response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
    !['', 'identity'].includes(response.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
    (length !== null && (!/^[0-9]{1,5}$/.test(length) || Number(length) > 4096))
  ) throw new Error('Invalid registration response framing')
  const bytes = await readProxyBytes(response.body, signal, 4096)
  if (length !== null && Number(length) !== bytes.byteLength) throw new Error('Response length mismatch')
  const payload: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes))
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('Invalid registration response')
  const body = payload as Record<string, unknown>
  if (Object.keys(body).sort().join(',') !== 'message,status' || body.status !== 'accepted' || body.message !== ACCEPTED_MESSAGE) {
    throw new Error('Invalid registration response')
  }
  signal.throwIfAborted()
  return Response.json({ status: 'accepted', message: ACCEPTED_MESSAGE }, { status: 202, headers: { 'Cache-Control': 'no-store' } })
}

export async function forwardAccountSignUp(request: Request, env: AccountSignUpProxyEnvironment): Promise<Response> {
  const decision = planSessionProxyOrigin(request, env, PATH, env.ACCOUNT_SIGN_UP_PROXY_ENABLED)
  if (decision instanceof Response) return decision
  const plan = decision
  const url = new URL(request.url)
  const transfer = request.headers.get('Transfer-Encoding')
  if (url.search || url.hash ||
      (transfer !== null && (transfer !== 'chunked' || request.headers.has('Content-Length'))) ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')) {
    return reply('Invalid registration request.', 400)
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
      const body = await readCredentialProxyBody(request, controller.signal, { requireCaptcha: true })
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, { method: 'POST', headers, body,
        redirect: 'manual', cache: 'no-store', credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 202) return await accepted(upstream, controller.signal)
      if (upstream.status === 400) return reply('Registration was rejected.', 400)
      if (upstream.status === 403) {
        return upstream.headers.get('X-Account-Verification') === 'required'
          ? reply('Human verification is required or was rejected.', 403, { 'X-Account-Verification': 'required' })
          : reply('Request origin is not allowed.', 403)
      }
      if (upstream.status === 429) {
        const raw = upstream.headers.get('Retry-After')
        const seconds = raw !== null && /^[0-9]{1,5}$/.test(raw) ? Number(raw) : NaN
        return reply('Account registration is temporarily rate limited.', 429,
          seconds >= 1 && seconds <= 86_400 ? { 'Retry-After': String(seconds) } : {})
      }
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      if ([413, 415].includes(upstream.status)) return reply('Invalid registration request.', upstream.status)
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
    if (error instanceof InvalidCredentialProxyRequest) return reply('Invalid registration request.', error.status)
    return reply(UNAVAILABLE, error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
