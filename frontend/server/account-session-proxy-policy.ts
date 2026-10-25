import { planSessionProxyOrigin, type SessionProxyEnvironment, type SessionProxyPlan } from './session-proxy-policy.ts'

// Pages session forwarding is disabled unless this policy explicitly permits it.
export type AccountSessionProxyEnvironment = SessionProxyEnvironment & {
  AUTH_SESSION_PROXY_ENABLED?: string
}

export type AccountSessionProxyPlan = SessionProxyPlan

const SESSION_PATH = '/api/v1/account/session'

function reject(message: string, status: number, allow?: string): Response {
  const headers = new Headers({ 'Cache-Control': 'no-store' })
  if (allow) headers.set('Allow', allow)
  return Response.json({ error: message }, { status, headers })
}

export function planAccountSessionProxy(
  request: Request,
  env: AccountSessionProxyEnvironment,
): AccountSessionProxyPlan | Response {
  const plan = planSessionProxyOrigin(request, env, SESSION_PATH, env.AUTH_SESSION_PROXY_ENABLED)
  if (plan instanceof Response) return plan
  const incoming = new URL(request.url)

  // This one endpoint has no request payload or query parameters. In particular,
  // do not accept browser-supplied provider tokens or an upstream destination.
  const length = request.headers.get('Content-Length')
  if (
    incoming.search ||
    incoming.hash ||
    (request.body !== null && length !== '0') ||
    (length !== null && length !== '0') ||
    request.headers.has('Transfer-Encoding')
  ) {
    return reject('Invalid account-session request.', 400)
  }

  // Workers exposes an empty POST stream with Content-Length: 0. The transport
  // must confirm that stream is actually empty before contacting the backend.
  // This is routing permission, not authentication. Cookie filtering, bounded
  // transport and response/cookie validation must precede Pages integration.
  return plan
}
