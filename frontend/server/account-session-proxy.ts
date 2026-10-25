import { ACCOUNT_COOKIE, readProxyAccountToken, validatedSessionCookie } from './account-session-proxy-cookies.ts'
import { planAccountSessionProxy, type AccountSessionProxyEnvironment } from './account-session-proxy-policy.ts'

const TIMEOUT_MS = 20_000
const MAX_RESPONSE_BYTES = 4096
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/

function reply(detail: string, status: number): Response {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store' } })
}

function utcTime(value: unknown): number {
  if (typeof value !== 'string' || !UTC_TIMESTAMP.test(value)) throw new Error('Invalid expiry')
  const time = Date.parse(value)
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== value.slice(0, 19)) {
    throw new Error('Invalid expiry')
  }
  return time
}

async function confirmEmptyBody(request: Request, signal: AbortSignal): Promise<boolean> {
  if (request.body === null) return true
  const reader = request.body.getReader()
  const cancel = () => { void reader.cancel().catch(() => {}) }
  signal.addEventListener('abort', cancel, { once: true })
  try {
    signal.throwIfAborted()
    const first = await reader.read()
    signal.throwIfAborted()
    // A closed stream is empty. Never drain or ignore a supplied payload,
    // including ambiguous zero-byte chunks that have not reached EOF.
    return first.done === true
  } finally {
    signal.removeEventListener('abort', cancel)
    cancel()
    reader.releaseLock()
  }
}

async function readMetadata(response: Response, signal: AbortSignal) {
  const length = response.headers.get('Content-Length')
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
    throw new Error('Invalid response size')
  }
  if (!response.body) throw new Error('Missing response body')
  const reader = response.body.getReader()
  const cancel = () => { void reader.cancel().catch(() => {}) }
  signal.addEventListener('abort', cancel, { once: true })
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      signal.throwIfAborted()
      const { done, value } = await reader.read()
      signal.throwIfAborted()
      if (done) break
      size += value.byteLength
      if (size > MAX_RESPONSE_BYTES) throw new Error('Oversized response')
      chunks.push(value)
    }
  } finally {
    signal.removeEventListener('abort', cancel)
    cancel()
    reader.releaseLock()
  }
  const bytes = new Uint8Array(size)
  if (length !== null && Number(length) !== size) throw new Error('Response length mismatch')
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  const payload: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('Invalid session response')
  }
  const body = payload as Record<string, unknown>
  if (
    Object.keys(body).sort().join(',') !== 'absolute_expires_at,expires_at,user_id' ||
    typeof body.user_id !== 'string' || !UUID.test(body.user_id)
  ) {
    throw new Error('Invalid session metadata')
  }
  const idle = utcTime(body.expires_at)
  const absolute = utcTime(body.absolute_expires_at)
  if (idle <= Date.now() || idle > absolute) throw new Error('Expired session metadata')
  return { body, idle }
}

export async function forwardAccountSession(
  request: Request,
  env: AccountSessionProxyEnvironment,
): Promise<Response> {
  const decision = planAccountSessionProxy(request, env)
  if (decision instanceof Response) return decision
  const plan = decision
  let token: string | null
  try { token = readProxyAccountToken(request) }
  catch { return reply('Invalid account-session request.', 400) }
  if (request.signal.aborted) return reply('Account session check was cancelled.', 502)

  const controller = new AbortController()
  const abort = () => controller.abort()
  const cancelled = new Promise<never>((_resolve, reject) => {
    controller.signal.addEventListener('abort', () => reject(new Error('Cancelled')), { once: true })
  })
  request.signal.addEventListener('abort', abort, { once: true })
  const timer = setTimeout(abort, TIMEOUT_MS)
  let upstream: Response | undefined
  async function exchange(): Promise<Response> {
    try {
      if (request.body !== null && !await confirmEmptyBody(request, controller.signal)) {
        return reply('Invalid account-session request.', 400)
      }
      controller.signal.throwIfAborted()
      const headers = new Headers({
        Accept: 'application/json', 'Accept-Encoding': 'identity', Origin: plan.publicOrigin,
      })
      if (token) headers.set('Cookie', `${ACCOUNT_COOKIE}=${token}`)
      upstream = await fetch(plan.upstreamUrl, {
        method: 'POST', headers, cache: 'no-store', redirect: 'manual',
        credentials: 'omit', signal: controller.signal,
      })
      controller.signal.throwIfAborted()
      if (upstream.status === 403) return reply('Request origin is not allowed.', 403)
      if (upstream.status === 503) return reply('Account sessions are temporarily unavailable.', 503)
      if (
        (upstream.status !== 200 && upstream.status !== 401) ||
        upstream.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
        !['', 'identity'].includes(upstream.headers.get('Content-Encoding')?.toLowerCase() ?? '')
      ) {
        throw new Error('Unexpected backend response')
      }
      if (upstream.status === 401) {
        const cookie = validatedSessionCookie(upstream.headers, 401, token)
        const response = reply('Invalid or expired account session.', 401)
        response.headers.set('Set-Cookie', cookie)
        return response
      }
      const { body, idle } = await readMetadata(upstream, controller.signal)
      const cookie = validatedSessionCookie(upstream.headers, 200, token, idle)
      controller.signal.throwIfAborted()
      return Response.json(body, {
        headers: { 'Cache-Control': 'no-store', 'Set-Cookie': cookie },
      })
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
    return reply('Account sessions are temporarily unavailable.', 502)
  } finally {
    clearTimeout(timer)
    request.signal.removeEventListener('abort', abort)
  }
}
