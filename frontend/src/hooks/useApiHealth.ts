import { useEffect, useState } from 'react'

export type ApiStatus = 'checking' | 'connected' | 'unavailable'

export function useApiHealth() {
  const [status, setStatus] = useState<ApiStatus>('checking')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    const timeout = window.setTimeout(() => {
      controller.abort()
      if (active) setStatus('unavailable')
    }, 75_000)

    async function checkHealth() {
      try {
        const response = await fetch('/api/v1/health', {
          signal: controller.signal,
          cache: 'no-store',
          redirect: 'error',
        })

        if (!response.ok) {
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

        if (active && !controller.signal.aborted) setStatus('connected')
      } catch {
        if (active) setStatus('unavailable')
      } finally {
        window.clearTimeout(timeout)
      }
    }

    void checkHealth()

    return () => {
      active = false
      window.clearTimeout(timeout)
      controller.abort()
    }
  }, [attempt])

  function retry() {
    setStatus('checking')
    setAttempt((value) => value + 1)
  }

  return { status, retry }
}
