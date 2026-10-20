import { useEffect, useRef, useState } from 'react'
import { ensureGuestSession } from '../api/guest'

type GuestState = {
  status: 'idle' | 'loading' | 'ready' | 'error'
  message: string
}

export function useGuestSession() {
  const enabled = import.meta.env.DEV
  const request = useRef<AbortController | null>(null)

  const [state, setState] = useState<GuestState>({
    status: 'idle',
    message: '',
  })

  useEffect(() => {
    return () => {
      request.current?.abort()
      request.current = null
    }
  }, [])

  async function start() {
    if (!enabled || request.current || state.status === 'ready') {
      return
    }

    const controller = new AbortController()
    request.current = controller
    let timedOut = false

    const timeout = window.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, 15_000)

    setState({
      status: 'loading',
      message: 'Starting guest access…',
    })

    try {
      await ensureGuestSession(controller.signal)

      if (request.current !== controller) return

      if (controller.signal.aborted) {
        throw new Error('Request cancelled')
      }

      setState({
        status: 'ready',
        message: 'Guest session ready. Chat is still in development.',
      })
    } catch {
      if (request.current !== controller) return

      setState({
        status: 'error',
        message: timedOut
          ? 'Guest access took too long. Please try again.'
          : 'Guest access could not be started. Please try again.',
      })
    } finally {
      window.clearTimeout(timeout)

      if (request.current === controller) {
        request.current = null
      }
    }
  }

  return {
    enabled,
    status: state.status,
    message: state.message,
    start,
  }
}