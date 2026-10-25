import { parseProxyCookie, PROXY_COOKIE_SCOPE, PROXY_TOKEN, readProxyToken } from './session-proxy-cookies.ts'

export const ACCOUNT_COOKIE = '__Host-askm6_account'

export function readProxyAccountToken(request: Request): string | null {
  // Invalid/missing credentials are omitted, so the backend can reject them
  // and confirm cookie deletion through its ordinary signed-out response.
  return readProxyToken(request, ACCOUNT_COOKIE)
}

function persistentCookie(cookie: ReturnType<typeof parseProxyCookie>, idleExpiry: number | undefined): string {
  if (
    !PROXY_TOKEN.test(cookie.value) || cookie.attributes.has('max-age') ||
    idleExpiry === undefined || cookie.expiry !== Math.floor(idleExpiry / 1000) * 1000 ||
    cookie.expiry <= Date.now()
  ) throw new Error('Invalid persistent account cookie')
  return `${ACCOUNT_COOKIE}=${cookie.value}; Expires=${cookie.rawExpiry}; ${PROXY_COOKIE_SCOPE}`
}

export function validatedCreatedAccountCookie(headers: Headers, idleExpiry: number): string {
  return persistentCookie(parseProxyCookie(headers, ACCOUNT_COOKIE), idleExpiry)
}

export function validatedClearingAccountCookie(headers: Headers): string {
  const { value, attributes } = parseProxyCookie(headers, ACCOUNT_COOKIE)
  if ((value !== '' && value !== '""') || attributes.get('max-age') !== '0') {
    throw new Error('Invalid clearing cookie')
  }
  return `${ACCOUNT_COOKIE}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; ${PROXY_COOKIE_SCOPE}`
}

export function validatedSessionCookie(
  headers: Headers,
  status: 200 | 401,
  token: string | null,
  idleExpiry?: number,
): string {
  if (status === 401) return validatedClearingAccountCookie(headers)
  const cookie = parseProxyCookie(headers, ACCOUNT_COOKIE)
  if (!token || cookie.value !== token) {
    throw new Error('Invalid renewal cookie')
  }
  return persistentCookie(cookie, idleExpiry)
}
