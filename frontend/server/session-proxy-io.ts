export class ProxyBodyTooLarge extends Error {}

export async function confirmEmptyProxyBody(
  body: ReadableStream<Uint8Array> | null,
  signal: AbortSignal,
): Promise<boolean> {
  signal.throwIfAborted()
  if (body === null) return true
  const reader = body.getReader()
  const cancel = () => { void reader.cancel().catch(() => {}) }
  signal.addEventListener('abort', cancel, { once: true })
  try {
    signal.throwIfAborted()
    const first = await reader.read()
    signal.throwIfAborted()
    // EOF alone proves emptiness; reject even an unfinished zero-byte chunk.
    return first.done === true
  } finally {
    signal.removeEventListener('abort', cancel)
    cancel()
    reader.releaseLock()
  }
}

export function proxyUtcTime(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)) {
    throw new Error('Invalid expiry')
  }
  const time = Date.parse(value)
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== value.slice(0, 19)) {
    throw new Error('Invalid expiry')
  }
  return time
}

export async function readProxyBytes(
  body: ReadableStream<Uint8Array> | null,
  signal: AbortSignal,
  maximum: number,
): Promise<Uint8Array> {
  signal.throwIfAborted()
  if (body === null) return new Uint8Array()
  const reader = body.getReader()
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
      if (size > maximum) throw new ProxyBodyTooLarge('Oversized body')
      if (value.byteLength) chunks.push(value)
    }
  } finally {
    signal.removeEventListener('abort', cancel)
    cancel()
    reader.releaseLock()
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  return bytes
}
