export const ACCOUNT_COOKIE = '__Host-askm6_account'
const TOKEN = /^[A-Za-z0-9_-]{43}$/

export function readProxyAccountToken(request: Request): string | null {
  const header = request.headers.get('Cookie') ?? ''
  if (header.length > 8192) throw new Error('Invalid cookie header')
  const matches = header.split(';').map((part) => part.trim()).filter((part) =>
    part.split('=', 1)[0]?.trim() === ACCOUNT_COOKIE,
  )
  if (matches.length > 1) throw new Error('Ambiguous account cookie')
  const value = matches[0]?.slice(matches[0].indexOf('=') + 1)
  // Invalid/missing credentials are omitted, so the backend can reject them
  // and confirm cookie deletion through its ordinary signed-out response.
  return value && TOKEN.test(value) ? value : null
}

export function validatedSessionCookie(
  headers: Headers,
  status: 200 | 401,
  token: string | null,
  idleExpiry?: number,
): string {
  // Workers exposes getAll for Set-Cookie; Node uses getSetCookie. Never split
  // folded cookie strings on commas: Expires itself contains a comma.
  const workerHeaders = headers as Headers & { getAll?: (name: string) => string[] }
  const cookies = typeof workerHeaders.getAll === 'function'
    ? workerHeaders.getAll('Set-Cookie')
    : headers.getSetCookie()
  if (cookies.length !== 1) throw new Error('Invalid session cookie count')
  const cookie = cookies[0]!
  if (cookie.length > 2048 || /[^\x20-\x7e]/.test(cookie)) {
    throw new Error('Invalid session cookie')
  }
  const parts = cookie.split(';').map((part) => part.trim())
  const first = parts.shift()!
  if (!first.startsWith(ACCOUNT_COOKIE + '=')) throw new Error('Unexpected cookie')
  const value = first.slice(ACCOUNT_COOKIE.length + 1)
  const attributes = new Map<string, string | null>()
  for (const part of parts) {
    const equals = part.indexOf('=')
    const name = (equals < 0 ? part : part.slice(0, equals)).toLowerCase()
    if (attributes.has(name)) throw new Error('Duplicate cookie attribute')
    attributes.set(name, equals < 0 ? null : part.slice(equals + 1))
  }
  const allowed = new Set(['path', 'secure', 'httponly', 'samesite', 'expires', 'max-age'])
  if (
    [...attributes.keys()].some((name) => !allowed.has(name)) ||
    attributes.get('path') !== '/' ||
    attributes.get('secure') !== null ||
    attributes.get('httponly') !== null ||
    attributes.get('samesite')?.toLowerCase() !== 'lax'
  ) {
    throw new Error('Invalid session cookie scope')
  }
  const rawExpiry = attributes.get('expires')
  const expiry = typeof rawExpiry === 'string' ? Date.parse(rawExpiry) : NaN
  if (!Number.isFinite(expiry) || new Date(expiry).toUTCString() !== rawExpiry) {
    throw new Error('Invalid cookie expiry')
  }
  const scope = 'Path=/; Secure; HttpOnly; SameSite=Lax'
  if (status === 401) {
    if ((value !== '' && value !== '""') || attributes.get('max-age') !== '0') {
      throw new Error('Invalid clearing cookie')
    }
    return `${ACCOUNT_COOKIE}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; ${scope}`
  }
  if (
    !token || value !== token || !TOKEN.test(value) || attributes.has('max-age') ||
    idleExpiry === undefined || expiry !== Math.floor(idleExpiry / 1000) * 1000 ||
    expiry <= Date.now()
  ) {
    throw new Error('Invalid renewal cookie')
  }
  return `${ACCOUNT_COOKIE}=${token}; Expires=${rawExpiry}; ${scope}`
}
