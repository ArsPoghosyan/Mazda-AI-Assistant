// Pages session forwarding is disabled unless this policy explicitly permits it.
export type AccountSessionProxyEnvironment = {
  API_ORIGIN?: string
  AUTH_SESSION_PROXY_ENABLED?: string
  AUTH_PUBLIC_ORIGIN?: string
}

export type AccountSessionProxyPlan = {
  upstreamUrl: URL
  publicOrigin: string
}

const SESSION_PATH = '/api/v1/account/session'

function reject(message: string, status: number, allow?: string): Response {
  const headers = new Headers({ 'Cache-Control': 'no-store' })
  if (allow) headers.set('Allow', allow)
  return Response.json({ error: message }, { status, headers })
}

function httpsOrigin(value: string | undefined): string | null {
  if (!value || value.length > 2048) return null

  try {
    const url = new URL(value)
    // Require a canonical origin; reject credentials, paths, queries, fragments,
    // whitespace and parser-normalized spellings instead of silently fixing them.
    if (
      url.protocol !== 'https:' ||
      (value !== url.origin && value !== `${url.origin}/`)
    ) {
      return null
    }
    return url.origin
  } catch {
    return null
  }
}

export function planAccountSessionProxy(
  request: Request,
  env: AccountSessionProxyEnvironment,
): AccountSessionProxyPlan | Response {
  const incoming = new URL(request.url)

  if (
    incoming.pathname !== SESSION_PATH ||
    env.AUTH_SESSION_PROXY_ENABLED !== 'true'
  ) {
    return reject('API route not found.', 404)
  }

  if (request.method !== 'POST') {
    return reject('Method not allowed.', 405, 'POST')
  }

  const publicOrigin = httpsOrigin(env.AUTH_PUBLIC_ORIGIN)
  const backendOrigin = httpsOrigin(env.API_ORIGIN)
  if (!publicOrigin || !backendOrigin || publicOrigin === backendOrigin) {
    return reject('Authentication proxy is not configured correctly.', 503)
  }

  // A forged forwarding header cannot authorize a preview or unrelated host.
  const fetchSite = request.headers.get('Sec-Fetch-Site')
  if (
    incoming.origin !== publicOrigin ||
    request.headers.get('Origin') !== publicOrigin ||
    (fetchSite !== null && fetchSite !== 'same-origin')
  ) {
    return reject('Request origin is not allowed.', 403)
  }

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
  return {
    upstreamUrl: new URL(SESSION_PATH, backendOrigin),
    publicOrigin,
  }
}
