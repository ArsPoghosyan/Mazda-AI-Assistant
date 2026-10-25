import { ACCOUNT_COOKIE, readProxyAccountToken, validatedClearingAccountCookie } from './account-session-proxy-cookies.ts'
import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { confirmEmptyProxyBody } from './session-proxy-io.ts'
import { planSessionProxyOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'

export type AccountSignOutProxyEnvironment = SessionProxyEnvironment & { ACCOUNT_SIGN_OUT_PROXY_ENABLED?: string }
const PATH = '/api/v1/account/sign-out'
const UNAVAILABLE = 'Account sign-out is temporarily unavailable.'

function reply(detail: string, status: number): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store' } })
}

export async function forwardAccountSignOut(request: Request, env: AccountSignOutProxyEnvironment): Promise<Response> {
  const decision = planSessionProxyOrigin(request, env, PATH, env.ACCOUNT_SIGN_OUT_PROXY_ENABLED)
  if (decision instanceof Response) return decision
  const plan = decision
  const url = new URL(request.url)
  const length = request.headers.get('Content-Length')
  if (
    url.search || url.hash || (request.body !== null && length !== '0') ||
    (length !== null && length !== '0') || request.headers.has('Transfer-Encoding') ||
    !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')
  ) return reply('Invalid sign-out request.', 400)
  let token: string | null
  try { token = readProxyAccountToken(request) }
  catch { return reply('Invalid sign-out request.', 400) }
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
      if (request.body !== null && !await confirmEmptyProxyBody(request.body, controller.signal)) return reply('Invalid sign-out request.', 400)
      const headers = proxyClientIPHeaders(request, env)
      headers.set('Accept', 'application/json')
      headers.set('Accept-Encoding', 'identity')
      headers.set('Origin', plan.publicOrigin)
      if (token) headers.set('Cookie', `${ACCOUNT_COOKIE}=${token}`)
      controller.signal.throwIfAborted()
      upstream = await fetch(plan.upstreamUrl, {
        method: 'POST', headers, redirect: 'manual', cache: 'no-store',
        credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 403) return reply('Request origin is not allowed.', 403)
      if (upstream.status === 503) return reply(UNAVAILABLE, 503)
      const responseLength = upstream.headers.get('Content-Length')
      if (
        upstream.status !== 204 || (responseLength !== null && responseLength !== '0') ||
        upstream.headers.has('Transfer-Encoding') ||
        !['', 'identity'].includes(upstream.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
        !await confirmEmptyProxyBody(upstream.body, controller.signal)
      ) throw new Error('Unexpected sign-out response')
      const cookie = validatedClearingAccountCookie(upstream.headers)
      controller.signal.throwIfAborted()
      return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store', 'Set-Cookie': cookie } })
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
