import { useEffect, useState } from 'react'
import { apiWakeUrl, sendWakeRequest } from '../lib/apiWake'

export type ApiStatus = 'checking' | 'connected' | 'unavailable'

const DEADLINE_MS = 75_000
const RETRY_DELAY_MS = 5_000
// Statuses the proxy returns while the backend is asleep or starting.
const WAKING_STATUSES = new Set([502, 503, 504])

export function useApiHealth() {
  const [status, setStatus] = useState<ApiStatus>('checking')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    const wakeUrl = apiWakeUrl()
    let active = true
    let retryTimer: number | undefined

    const timeout = window.setTimeout(() => {
      window.clearTimeout(retryTimer)
      controller.abort()
      if (active) setStatus('unavailable')
    }, DEADLINE_MS)

    function finish(next: ApiStatus) {
      window.clearTimeout(timeout)
      window.clearTimeout(retryTimer)
      if (active) setStatus(next)
    }

    // Retrying only helps while a wake request is starting the backend.
    function retryOrFail() {
      if (wakeUrl) {
        retryTimer = window.setTimeout(() => void checkHealth(), RETRY_DELAY_MS)
      } else {
        finish('unavailable')
      }
    }

    async function checkHealth() {
      let response: Response

      try {
        response = await fetch('/api/v1/health', {
          signal: controller.signal,
          cache: 'no-store',
          redirect: 'error',
        })
      } catch {
        if (!controller.signal.aborted) retryOrFail()
        return
      }

      try {
        if (!response.ok) {
          if (WAKING_STATUSES.has(response.status)) {
            await response.body?.cancel()
            if (!controller.signal.aborted) retryOrFail()
            return
          }

          throw new Error('Health request failed')
        }

        const body: unknown = await response.json()

        if (
          typeof body !== 'object' ||
          body === null ||
          !('status' in body) ||
          body.status !== 'ok' ||
          !('service' in body) ||
          body.service !== 'mazda6-assistant-api'
        ) {
          throw new Error('Unexpected health response')
        }

        if (!controller.signal.aborted) finish('connected')
      } catch {
        if (!controller.signal.aborted) finish('unavailable')
      }
    }

    if (wakeUrl) sendWakeRequest(wakeUrl, controller.signal)
    void checkHealth()

    return () => {
      active = false
      window.clearTimeout(timeout)
      window.clearTimeout(retryTimer)
      controller.abort()
    }
  }, [attempt])

  function retry() {
    setStatus('checking')
    setAttempt((value) => value + 1)
  }

  return { status, retry }
}
