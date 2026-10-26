import { ACCOUNT_COOKIE } from './account-session-proxy-cookies.ts'
import { readOAuthProxyCookies, validatedOAuthCallbackCookies } from './account-oauth-proxy-cookies.ts'
import { readProxyCookieValue } from './session-proxy-cookies.ts'
import { readSignupTermsProxyCookie, validatedGoogleSignupTermsCookies } from './signup-terms-proxy-cookies.ts'
import { confirmEmptyProxyBody } from './session-proxy-io.ts'
import { httpsOrigin, type SessionProxyEnvironment } from './session-proxy-policy.ts'

export type AccountGoogleCallbackProxyEnvironment = SessionProxyEnvironment & { ACCOUNT_GOOGLE_CALLBACK_PROXY_ENABLED?: string }
const PATH = '/api/v1/account/google/callback'
const HEADERS = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }
type Outcome = 'success' | 'rejected' | 'unavailable' | 'sign-out-required'

function reply(status: number, detail: string, extra: Record<string, string> = {}): Response {
  return Response.json({ detail }, { status, headers: { ...HEADERS, ...extra } })
}

function returned(origin: string, outcome: Outcome, cookies: string[] = []): Response {
  const headers = new Headers({ ...HEADERS, Location: `${origin}/#google-sign-in=${outcome}` })
  for (const cookie of cookies) headers.append('Set-Cookie', cookie)
  return new Response(null, { status: 303, headers })
}

function callbackCode(url: URL): string {
  const query = url.search.slice(1)
  if (!query || query.length > 4096 || /[^\x21-\x7e]/.test(query) || /%(?![0-9a-fA-F]{2})/.test(query) || query.includes('&')) {
    throw new Error('Invalid callback query')
  }
  const equals = query.indexOf('=')
  if (equals < 0) throw new Error('Missing callback code')
  const key = decodeURIComponent(query.slice(0, equals).replace(/\+/g, ' '))
  const code = decodeURIComponent(query.slice(equals + 1).replace(/\+/g, ' '))
  if (key !== 'code' || code.length < 1 || code.length > 1024 || /[^\x21-\x7e]/.test(code)) throw new Error('Invalid callback code')
  return code
}

export async function forwardAccountGoogleCallback(request: Request, env: AccountGoogleCallbackProxyEnvironment): Promise<Response> {
  if (env.ACCOUNT_GOOGLE_CALLBACK_PROXY_ENABLED !== 'true') return reply(404, 'API route not found.')
  if (request.method !== 'GET') return reply(405, 'Method not allowed.', { Allow: 'GET' })
  const origin = httpsOrigin(env.AUTH_PUBLIC_ORIGIN)
  const backend = httpsOrigin(env.API_ORIGIN)
  if (!origin || !backend || origin === backend) return reply(503, 'Google sign-in is temporarily unavailable.')
  const url = new URL(request.url)
  // Top-level provider returns have no same-origin Origin requirement. Binding
  // and PKCE are verified by FastAPI; forwarded host/Origin headers are ignored.
  if (url.origin !== origin) return reply(403, 'Request origin is not allowed.')
  const length = request.headers.get('Content-Length')
  if (url.pathname !== PATH || url.hash || (request.body !== null && length !== '0') ||
      (length !== null && length !== '0') || request.headers.has('Transfer-Encoding') ||
      !['', 'identity'].includes(request.headers.get('Content-Encoding')?.toLowerCase() ?? '')) {
    return returned(origin, 'rejected')
  }
  let code: string
  let binding: string | null
  let receipt: string | null
  try {
    if (readProxyCookieValue(request, ACCOUNT_COOKIE) !== null) return returned(origin, 'sign-out-required')
    code = callbackCode(url)
    binding = readOAuthProxyCookies(request)
    if (binding === null) return returned(origin, 'rejected')
    receipt = readSignupTermsProxyCookie(request)
  } catch { return returned(origin, 'rejected') }
  if (request.signal.aborted) return returned(origin, 'unavailable')
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
      if (!await confirmEmptyProxyBody(request.body, controller.signal)) return returned(origin!, 'rejected')
      const target = new URL(PATH, backend!)
      target.search = new URLSearchParams({ code }).toString()
      const headers = new Headers({ Accept: 'application/json', 'Accept-Encoding': 'identity',
        Cookie: [binding, receipt].filter(Boolean).join('; '),
      })
      controller.signal.throwIfAborted()
      upstream = await fetch(target, { method: 'GET', headers, redirect: 'manual', cache: 'no-store',
        credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 503) {
        const cookies = validatedOAuthCallbackCookies(upstream.headers, false)
        return reply(503, 'Google sign-in is temporarily unavailable.', { 'Set-Cookie': cookies[0]! })
      }
      const location = upstream.headers.get('Location')
      const outcome = (['success', 'rejected', 'unavailable', 'sign-out-required'] as const)
        .find((value) => location === `${origin}/#google-sign-in=${value}`)
      const responseLength = upstream.headers.get('Content-Length')
      if (upstream.status !== 303 || !outcome || (responseLength !== null && responseLength !== '0') ||
          upstream.headers.has('Transfer-Encoding') ||
          !['', 'identity'].includes(upstream.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
          !await confirmEmptyProxyBody(upstream.body, controller.signal)) throw new Error('Invalid callback response')
      const cookies = validatedGoogleSignupTermsCookies(upstream.headers, outcome === 'success', receipt !== null)
      controller.signal.throwIfAborted()
      return returned(origin!, outcome, cookies)
    } finally {
      if (upstream?.body && !upstream.body.locked) void upstream.body.cancel().catch(() => {})
    }
  }
  try {
    const response = await Promise.race([exchange(), cancelled])
    controller.signal.throwIfAborted()
    return response
  } catch {
    controller.abort()
    return returned(origin, 'unavailable')
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
