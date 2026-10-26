import { readTermsMetadata, CURRENT_TERMS_VERSION } from '../shared/account-terms.ts'
import { ACCOUNT_COOKIE, readProxyAccountToken, validatedSessionCookie } from './account-session-proxy-cookies.ts'
import { parseProxyCookie } from './session-proxy-cookies.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'
import { confirmEmptyProxyBody, ProxyBodyTooLarge, readProxyBytes } from './session-proxy-io.ts'
import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'

export type AccountTermsProxyEnvironment = SessionProxyEnvironment & { ACCOUNT_TERMS_PROXY_ENABLED?: string }
const PREFIX = '/api/v1/account/terms/'
const UNAVAILABLE = 'Account setup is temporarily unavailable.'

function reply(detail: string, status: number): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store' } })
}

class InvalidRequest extends Error {
  readonly status: number
  constructor(status = 400) { super('Invalid account setup request.'); this.status = status }
}

export async function forwardAccountTerms(request: Request, env: AccountTermsProxyEnvironment): Promise<Response> {
  const incoming = new URL(request.url)
  const operation = incoming.pathname === `${PREFIX}accept` ? 'accept' : 'status'
  const endpoint = `${PREFIX}${operation}` as '/api/v1/account/terms/status' | '/api/v1/account/terms/accept'
  const decision = planSessionProxyOrigin(request, env, endpoint, env.ACCOUNT_TERMS_PROXY_ENABLED)
  if (decision instanceof Response) return decision
  const plan = decision
  const length = request.headers.get('Content-Length')
  const transfer = request.headers.get('Transfer-Encoding')
  const subject = request.headers.get('X-Account-Subject')
  if (!subject || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(subject)) return reply('Invalid account setup request.', 400)
  if (incoming.search || incoming.hash ||
      (transfer !== null && (operation === 'status' || transfer !== 'chunked' || length !== null)) ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
      (length !== null && !/^(0|[1-9][0-9]{0,4})$/.test(length))) return reply('Invalid account setup request.', 400)
  if (length !== null && Number(length) > 1024) return reply('Account setup request is too large.', 413)
  if (operation === 'status' && ((length !== null && length !== '0') || (request.body !== null && length !== '0'))) {
    return reply('Invalid account setup request.', 400)
  }
  let token: string | null
  try { token = readProxyAccountToken(request) } catch { return reply('Invalid account setup request.', 400) }
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
      let body: string | undefined
      if (operation === 'status') {
        if (!await confirmEmptyProxyBody(request.body, controller.signal)) throw new InvalidRequest()
      } else {
        if (request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') throw new InvalidRequest(415)
        const bytes = await readProxyBytes(request.body, controller.signal, 1024)
        if (length !== null && Number(length) !== bytes.byteLength) throw new InvalidRequest()
        let value: unknown
        try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)) }
        catch { throw new InvalidRequest() }
        if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new InvalidRequest()
        const data = value as Record<string, unknown>
        if (Object.keys(data).sort().join(',') !== 'accepted,terms_version' || data.accepted !== true || data.terms_version !== CURRENT_TERMS_VERSION) throw new InvalidRequest()
        body = JSON.stringify({ accepted: true, terms_version: CURRENT_TERMS_VERSION })
      }
      const headers = proxyClientIPHeaders(request, env)
      headers.set('Origin', plan.publicOrigin)
      headers.set('Accept', 'application/json')
      headers.set('Accept-Encoding', 'identity')
      headers.set('X-Account-Subject', subject!)
      if (body !== undefined) headers.set('Content-Type', 'application/json')
      if (token) headers.set('Cookie', `${ACCOUNT_COOKIE}=${token}`)
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, { method: 'POST', headers, body,
        redirect: 'manual', credentials: 'omit', cache: 'no-store', signal: controller.signal })
      controller.signal.throwIfAborted()
      if (upstream.status === 403) return reply('Request origin is not allowed.', 403)
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      if (upstream.status === 400) return reply('Please review the current Terms and try again.', 400)
      if (upstream.status === 409) return reply('Account session changed. Please check it again.', 409)
      if (upstream.status !== 200 && upstream.status !== 401) throw new Error('Unexpected backend status')
      if (upstream.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
          !['', 'identity'].includes(upstream.headers.get('Content-Encoding')?.toLowerCase() ?? '')) throw new Error('Invalid response framing')
      if (upstream.status === 401) {
        const cookie = validatedSessionCookie(upstream.headers, 401, token)
        const response = reply('Invalid or expired account session.', 401)
        response.headers.set('Set-Cookie', cookie)
        return response
      }
      const responseLength = upstream.headers.get('Content-Length')
      if (upstream.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
          !['', 'identity'].includes(upstream.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
          (responseLength !== null && (!/^\d+$/.test(responseLength) || Number(responseLength) > 1024))) throw new Error('Invalid response framing')
      const bytes = await readProxyBytes(upstream.body, controller.signal, 1024)
      if (responseLength !== null && Number(responseLength) !== bytes.byteLength) throw new Error('Invalid response length')
      const metadata = readTermsMetadata(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), operation)
      // This endpoint has no expiry metadata. Validate the backend's cookie expiry,
      // scope and original token directly, rather than accepting another credential.
      const parsed = parseProxyCookie(upstream.headers, ACCOUNT_COOKIE)
      const cookie = validatedSessionCookie(upstream.headers, 200, token, parsed.expiry)
      controller.signal.throwIfAborted()
      return Response.json(operation === 'status' ? metadata : {
        terms_version: metadata.terms_version, accepted_at: metadata.accepted_at,
      }, { headers: { 'Cache-Control': 'no-store', 'Set-Cookie': cookie } })
    } finally {
      if (upstream?.body && !upstream.body.locked) void upstream.body.cancel().catch(() => {})
    }
  }
  try {
    const result = await Promise.race([exchange(), cancelled])
    controller.signal.throwIfAborted()
    return result
  } catch (error) {
    controller.abort()
    if (error instanceof InvalidRequest) return reply(error.message, error.status)
    if (error instanceof ProxyBodyTooLarge && !upstream) return reply('Account setup request is too large.', 413)
    return reply(UNAVAILABLE, error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
