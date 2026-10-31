/**
 * Direct backend health URL used only to wake a sleeping free-tier backend.
 * Requests through the Pages proxy cannot wake it, so the browser asks once
 * directly. Anything other than an exact HTTPS health URL disables the wake.
 */
export function apiWakeUrl(value = import.meta.env.VITE_API_WAKE_URL): string | null {
  const raw = value?.trim()
  if (!raw) return null

  try {
    const url = new URL(raw)

    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      url.pathname !== '/api/v1/health'
    ) {
      return null
    }

    return url.href
  } catch {
    return null
  }
}

/** Fire-and-forget wake request: no cookies or referrer, and the opaque answer is ignored. */
export function sendWakeRequest(url: string, signal: AbortSignal): void {
  void fetch(url, {
    mode: 'no-cors',
    credentials: 'omit',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
    signal,
  }).catch(() => undefined)
}
