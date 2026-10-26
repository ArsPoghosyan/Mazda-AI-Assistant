import { ACCOUNT_COOKIE, validatedCreatedAccountCookie } from './account-session-proxy-cookies.ts'
import { validatedOAuthCallbackCookies } from './account-oauth-proxy-cookies.ts'
import { parseProxyCookie, PROXY_COOKIE_SCOPE, readProxyCookieValue } from './session-proxy-cookies.ts'

export const SIGNUP_TERMS_COOKIE = '__Host-askm6_signup_terms'
const RECEIPT = /^[A-Za-z0-9_-]{100,1534}={0,2}$/

export function readSignupTermsProxyCookie(request: Request): string | null {
  const value = readProxyCookieValue(request, SIGNUP_TERMS_COOKIE)
  return value !== null && value.length <= 1536 && RECEIPT.test(value) ? `${SIGNUP_TERMS_COOKIE}=${value}` : null
}

export function validatedSignupTermsCookie(headers: Headers, allowClear = false): string {
  const cookie = parseProxyCookie(headers, SIGNUP_TERMS_COOKIE)
  if (allowClear && (cookie.value === '' || cookie.value === '""') && cookie.attributes.get('max-age') === '0') {
    return `${SIGNUP_TERMS_COOKIE}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; ${PROXY_COOKIE_SCOPE}`
  }
  const age = cookie.attributes.get('max-age')
  if (!RECEIPT.test(cookie.value) || cookie.value.length > 1536 || typeof age !== 'string' ||
      !/^[1-9][0-9]{0,3}$/.test(age) || Number(age) > 3600 ||
      cookie.expiry <= Date.now() || cookie.expiry > Date.now() + 3_605_000) throw new Error('Invalid registration agreement cookie')
  return `${SIGNUP_TERMS_COOKIE}=${cookie.value}; Expires=${cookie.rawExpiry}; Max-Age=${age}; ${PROXY_COOKIE_SCOPE}`
}

export function validatedSigninTermsCookies(headers: Headers, expiry: number, hadReceipt: boolean): string[] {
  const worker = headers as Headers & { getAll?: (name: string) => string[] }
  const fields = worker.getAll ? worker.getAll('Set-Cookie') : headers.getSetCookie()
  if (fields.length !== (hadReceipt ? 2 : 1)) throw new Error('Invalid sign-in cookie count')
  const isolated = new Map<string, Headers>()
  for (const field of fields) {
    const name = field.split('=', 1)[0]!
    if (![ACCOUNT_COOKIE, SIGNUP_TERMS_COOKIE].includes(name) || isolated.has(name)) throw new Error('Unexpected sign-in cookie')
    isolated.set(name, new Headers({ 'Set-Cookie': field }))
  }
  const account = isolated.get(ACCOUNT_COOKIE)
  if (!account || isolated.has(SIGNUP_TERMS_COOKIE) !== hadReceipt) throw new Error('Invalid sign-in cookie set')
  const result = [validatedCreatedAccountCookie(account, expiry)]
  if (hadReceipt) {
    const receipt = isolated.get(SIGNUP_TERMS_COOKIE)!
    const parsed = parseProxyCookie(receipt, SIGNUP_TERMS_COOKIE)
    if ((parsed.value !== '' && parsed.value !== '""') || parsed.attributes.get('max-age') !== '0') throw new Error('Agreement receipt was not cleared')
    result.push(validatedSignupTermsCookie(receipt, true))
  }
  return result
}

export function validatedGoogleSignupTermsCookies(headers: Headers, success: boolean, hadReceipt: boolean): string[] {
  if (!success || !hadReceipt) return validatedOAuthCallbackCookies(headers, success)
  const worker = headers as Headers & { getAll?: (name: string) => string[] }
  const fields = typeof worker.getAll === 'function' ? worker.getAll('Set-Cookie') : headers.getSetCookie()
  if (fields.length !== 3) throw new Error('Invalid callback cookie count')
  const other = new Headers()
  let receipt: Headers | undefined
  for (const field of fields) {
    if (field.split('=', 1)[0] === SIGNUP_TERMS_COOKIE) {
      if (receipt) throw new Error('Duplicate signup agreement cookie')
      receipt = new Headers({ 'Set-Cookie': field })
    } else other.append('Set-Cookie', field)
  }
  if (!receipt) throw new Error('Missing signup agreement clearing')
  const parsed = parseProxyCookie(receipt, SIGNUP_TERMS_COOKIE)
  if ((parsed.value !== '' && parsed.value !== '""') || parsed.attributes.get('max-age') !== '0') {
    throw new Error('Agreement receipt was not cleared')
  }
  return [...validatedOAuthCallbackCookies(other, true), validatedSignupTermsCookie(receipt, true)]
}
