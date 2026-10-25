import { proxyUtcTime, readProxyBytes } from './session-proxy-io.ts'

const MAX_RESPONSE_BYTES = 4096
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export async function readAccountProxyMetadata(response: Response, signal: AbortSignal) {
  const length = response.headers.get('Content-Length')
  if (
    response.headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json' ||
    !['', 'identity'].includes(response.headers.get('Content-Encoding')?.toLowerCase() ?? '') ||
    (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES))
  ) throw new Error('Invalid session response framing')
  if (!response.body) throw new Error('Missing response body')
  const bytes = await readProxyBytes(response.body, signal, MAX_RESPONSE_BYTES)
  if (length !== null && Number(length) !== bytes.byteLength) throw new Error('Response length mismatch')
  const payload: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('Invalid session response')
  }
  const body = payload as Record<string, unknown>
  if (
    Object.keys(body).sort().join(',') !== 'absolute_expires_at,expires_at,user_id' ||
    typeof body.user_id !== 'string' || body.user_id.length !== 36 || !UUID.test(body.user_id)
  ) throw new Error('Invalid session metadata')
  const idle = proxyUtcTime(body.expires_at)
  const absolute = proxyUtcTime(body.absolute_expires_at)
  if (idle <= Date.now() || idle > absolute) throw new Error('Expired session metadata')
  return { body, idle }
}
