import { ACCOUNT_COOKIE, validatedCreatedAccountCookie } from './account-session-proxy-cookies.ts'
import { parseProxyCookie, PROXY_COOKIE_SCOPE } from './session-proxy-cookies.ts'

export const OAUTH_COOKIE = '__Host-askm6_oauth'

export function readOAuthProxyCookies(request: Request): string | null {
  const header = request.headers.get('Cookie') ?? ''
  if (header.length > 8192) throw new Error('Oversized cookie header')
  // Preserve malformed/duplicate evidence for the backend's strict parser.
  const bindings = header.split(';').map((part) => part.replace(/^[ \t]+/, ''))
    .filter((part) => part.split('=', 1)[0] === OAUTH_COOKIE)
  if (!bindings.length) return null
  const selected = bindings.join('; ')
  // Prevent Headers from trimming malformed value whitespace at the field edge.
  return /[ \t]$/.test(selected) ? selected + ';' : selected
}

export function validatedClearingOAuthCookie(headers: Headers): string {
  const { value, attributes } = parseProxyCookie(headers, OAUTH_COOKIE)
  if ((value !== '' && value !== '""') || attributes.get('max-age') !== '0') throw new Error('Invalid clearing cookie')
  return `${OAUTH_COOKIE}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; ${PROXY_COOKIE_SCOPE}`
}

export function validatedOAuthCallbackCookies(headers: Headers, success: boolean): string[] {
  const workerHeaders = headers as Headers & { getAll?: (name: string) => string[] }
  const fields = typeof workerHeaders.getAll === 'function' ? workerHeaders.getAll('Set-Cookie') : headers.getSetCookie()
  if (fields.length !== (success ? 2 : 1)) throw new Error('Invalid callback cookie count')
  const isolated = new Map<string, Headers>()
  for (const field of fields) {
    const name = field.split('=', 1)[0]!
    if (![OAUTH_COOKIE, ACCOUNT_COOKIE].includes(name) || isolated.has(name)) throw new Error('Unexpected callback cookie')
    isolated.set(name, new Headers({ 'Set-Cookie': field }))
  }
  const binding = isolated.get(OAUTH_COOKIE)
  if (!binding || isolated.has(ACCOUNT_COOKIE) !== success) throw new Error('Invalid callback cookie set')
  const cookies = [validatedClearingOAuthCookie(binding)]
  if (success) {
    const account = isolated.get(ACCOUNT_COOKIE)!
    // Callback metadata is a redirect, so the validated cookie supplies expiry.
    const parsed = parseProxyCookie(account, ACCOUNT_COOKIE)
    cookies.push(validatedCreatedAccountCookie(account, parsed.expiry))
  }
  return cookies
}
