import { ACCOUNT_COOKIE, readProxyAccountToken, validatedSessionCookie } from './account-session-proxy-cookies.ts'
import { planAccountSessionProxy, type AccountSessionProxyEnvironment } from './account-session-proxy-policy.ts'
import { proxyClientIPHeaders, ProxyClientIPUnavailable } from './proxy-client-ip.ts'
import { readAccountProxyMetadata } from './account-session-proxy-response.ts'
import { confirmEmptyProxyBody } from './session-proxy-io.ts'

const TIMEOUT_MS = 20_000

function reply(detail: string, status: number): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store' } })
}

export async function forwardAccountSession(
  request: Request,
  env: AccountSessionProxyEnvironment,
): Promise<Response> {
  const decision = planAccountSessionProxy(request, env)
  if (decision instanceof Response) return decision
  const plan = decision
  let token: string | null
  try { token = readProxyAccountToken(request) }
  catch { return reply('Invalid account-session request.', 400) }
  if (request.signal.aborted) return reply('Account session check was cancelled.', 502)

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
      if (request.body !== null && !await confirmEmptyProxyBody(request.body, controller.signal)) {
        return reply('Invalid account-session request.', 400)
      }
      controller.signal.throwIfAborted()
      const headers = new Headers({
        Accept: 'application/json', 'Accept-Encoding': 'identity', Origin: plan.publicOrigin,
      })
      proxyClientIPHeaders(request, env).forEach((value, name) => headers.set(name, value))
      if (token) headers.set('Cookie', `${ACCOUNT_COOKIE}=${token}`)
      upstream = await fetch(plan.upstreamUrl, {
        method: 'POST', headers, cache: 'no-store', redirect: 'manual',
        credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 403) return reply('Request origin is not allowed.', 403)
      if (upstream.status === 503) return reply('Account sessions are temporarily unavailable.', 503)
      if (
        (upstream.status !== 200 && upstream.status !== 401) ||
        upstream.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
        !['', 'identity'].includes(upstream.headers.get('Content-Encoding')?.toLowerCase() ?? '')
      ) {
        throw new Error('Unexpected backend response')
      }
      if (upstream.status === 401) {
        const cookie = validatedSessionCookie(upstream.headers, 401, token)
        const response = reply('Invalid or expired account session.', 401)
        response.headers.set('Set-Cookie', cookie)
        return response
      }
      const { body, idle } = await readAccountProxyMetadata(upstream, controller.signal)
      const cookie = validatedSessionCookie(upstream.headers, 200, token, idle)
      controller.signal.throwIfAborted()
      return Response.json(body, {
        headers: { 'Cache-Control': 'no-store', 'Set-Cookie': cookie },
      })
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
    return reply('Account sessions are temporarily unavailable.', error instanceof ProxyClientIPUnavailable ? 503 : 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
