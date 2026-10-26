import { ProxyBodyTooLarge, readProxyBytes } from './session-proxy-io.ts'
import { CURRENT_TERMS_VERSION } from '../shared/account-terms.ts'

const MAX_REQUEST_BYTES = 16 * 1024

export class InvalidCredentialProxyRequest extends Error {
  readonly status: number
  constructor(status = 400) { super('Invalid authentication request.'); this.status = status }
}

function validCredential(value: unknown, maximum: number): value is string {
  if (typeof value !== 'string') return false
  const length = Array.from(value).length
  return length >= 1 && length <= maximum &&
    new TextDecoder('utf-8', { ignoreBOM: true }).decode(new TextEncoder().encode(value)) === value
}

export async function readCredentialProxyBody(
  request: Request,
  signal: AbortSignal,
  options: { requireCaptcha: boolean; requireTerms?: boolean },
): Promise<string> {
  if (request.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    throw new InvalidCredentialProxyRequest(415)
  }
  const length = request.headers.get('Content-Length')
  if (length !== null && !/^(0|[1-9][0-9]{0,4})$/.test(length)) throw new InvalidCredentialProxyRequest()
  if (length !== null && Number(length) > MAX_REQUEST_BYTES) throw new InvalidCredentialProxyRequest(413)
  let bytes: Uint8Array
  try { bytes = await readProxyBytes(request.body, signal, MAX_REQUEST_BYTES) }
  catch (error) {
    if (error instanceof ProxyBodyTooLarge) throw new InvalidCredentialProxyRequest(413)
    throw error
  }
  if (length !== null && Number(length) !== bytes.byteLength) throw new InvalidCredentialProxyRequest()
  let payload: unknown
  try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)) }
  catch { throw new InvalidCredentialProxyRequest() }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new InvalidCredentialProxyRequest()
  const body = payload as Record<string, unknown>
  if (
    Object.keys(body).some((key) => !['email', 'password', 'captcha_token', ...(options.requireTerms ? ['accepted', 'terms_version'] : [])].includes(key)) ||
    !validCredential(body.email, 320) || !validCredential(body.password, 1024)
  ) throw new InvalidCredentialProxyRequest()
  const proof = body.captcha_token
  if (options.requireTerms && (body.accepted !== true || body.terms_version !== CURRENT_TERMS_VERSION)) throw new InvalidCredentialProxyRequest()
  if (options.requireCaptcha && (proof === undefined || proof === null)) throw new InvalidCredentialProxyRequest()
  if (proof !== undefined && proof !== null &&
      (typeof proof !== 'string' || proof.length < 1 || proof.length > 2048 || /[^\x21-\x7e]/.test(proof))) {
    throw new InvalidCredentialProxyRequest()
  }
  // Preserve credential case/whitespace/Unicode. Only the backend authenticates.
  return JSON.stringify({ email: body.email, password: body.password,
    ...(proof === undefined ? {} : { captcha_token: proof }),
    ...(options.requireTerms ? { accepted: true, terms_version: CURRENT_TERMS_VERSION } : {}),
  })
}
