export const PROXY_TOKEN = /^[A-Za-z0-9_-]{43}$/
export const PROXY_COOKIE_SCOPE = 'Path=/; Secure; HttpOnly; SameSite=Lax'

export function readProxyCookieValue(request: Request, name: string): string | null {
  const header = request.headers.get('Cookie') ?? ''
  if (header.length > 8192) throw new Error('Invalid cookie header')
  const matches = header.split(';').map((part) => part.trim()).filter((part) =>
    part.split('=', 1)[0]?.trim() === name,
  )
  if (matches.length > 1) throw new Error('Ambiguous session cookie')
  return matches[0]?.slice(matches[0].indexOf('=') + 1) ?? null
}

export function readProxyToken(request: Request, name: string): string | null {
  const value = readProxyCookieValue(request, name)
  return value && PROXY_TOKEN.test(value) ? value : null
}

export function parseProxyCookie(headers: Headers, name: string) {
  // Preserve separate Set-Cookie fields; Expires itself contains a comma.
  const workerHeaders = headers as Headers & { getAll?: (name: string) => string[] }
  const cookies = typeof workerHeaders.getAll === 'function'
    ? workerHeaders.getAll('Set-Cookie') : headers.getSetCookie()
  if (cookies.length !== 1) throw new Error('Invalid session cookie count')
  const cookie = cookies[0]!
  if (cookie.length > 2048 || /[^\x20-\x7e]/.test(cookie)) throw new Error('Invalid session cookie')
  const parts = cookie.split(';').map((part) => part.trim())
  const first = parts.shift()!
  if (!first.startsWith(name + '=')) throw new Error('Unexpected cookie')
  const value = first.slice(name.length + 1)
  const attributes = new Map<string, string | null>()
  for (const part of parts) {
    const equals = part.indexOf('=')
    const key = (equals < 0 ? part : part.slice(0, equals)).toLowerCase()
    if (attributes.has(key)) throw new Error('Duplicate cookie attribute')
    attributes.set(key, equals < 0 ? null : part.slice(equals + 1))
  }
  const allowed = new Set(['path', 'secure', 'httponly', 'samesite', 'expires', 'max-age'])
  if (
    [...attributes.keys()].some((key) => !allowed.has(key)) ||
    attributes.get('path') !== '/' || attributes.get('secure') !== null ||
    attributes.get('httponly') !== null || attributes.get('samesite')?.toLowerCase() !== 'lax'
  ) throw new Error('Invalid session cookie scope')
  const rawExpiry = attributes.get('expires')
  const expiry = typeof rawExpiry === 'string' ? Date.parse(rawExpiry) : NaN
  if (!Number.isFinite(expiry) || new Date(expiry).toUTCString() !== rawExpiry) {
    throw new Error('Invalid cookie expiry')
  }
  return { value, attributes, rawExpiry: rawExpiry as string, expiry }
}
