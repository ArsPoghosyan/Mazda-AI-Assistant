import type { ProxyClientIPEnvironment } from './proxy-client-ip.ts'

export type SessionProxyEnvironment = ProxyClientIPEnvironment & {
  API_ORIGIN?: string
  AUTH_PUBLIC_ORIGIN?: string
}

export type SessionProxyPlan = { upstreamUrl: URL; publicOrigin: string }

function reject(message: string, status: number, allow?: string): Response {
  const headers = new Headers({ 'Cache-Control': 'no-store' })
  if (allow) headers.set('Allow', allow)
  return Response.json({ error: message }, { status, headers })
}

function httpsOrigin(value: string | undefined): string | null {
  if (!value || value.length > 2048) return null
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' || (value !== url.origin && value !== `${url.origin}/`)) return null
    return url.origin
  } catch { return null }
}

export function planSessionProxyOrigin(
  request: Request,
  env: SessionProxyEnvironment,
  endpoint: '/api/v1/account/session' | '/api/v1/guest/session' | '/api/v1/account/sign-in' | '/api/v1/account/sign-out',
  enabled: string | undefined,
): SessionProxyPlan | Response {
  const incoming = new URL(request.url)
  if (incoming.pathname !== endpoint || enabled !== 'true') return reject('API route not found.', 404)
  if (request.method !== 'POST') return reject('Method not allowed.', 405, 'POST')
  const publicOrigin = httpsOrigin(env.AUTH_PUBLIC_ORIGIN)
  const backendOrigin = httpsOrigin(env.API_ORIGIN)
  if (!publicOrigin || !backendOrigin || publicOrigin === backendOrigin) {
    return reject('Authentication proxy is not configured correctly.', 503)
  }
  const fetchSite = request.headers.get('Sec-Fetch-Site')
  if (
    incoming.origin !== publicOrigin || request.headers.get('Origin') !== publicOrigin ||
    (fetchSite !== null && fetchSite !== 'same-origin')
  ) return reject('Request origin is not allowed.', 403)
  return { upstreamUrl: new URL(endpoint, backendOrigin), publicOrigin }
}
