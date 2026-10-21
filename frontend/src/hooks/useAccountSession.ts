import { useEffect, useRef, useState } from 'react'
import {
  checkAccountSession,
  type AccountSessionResponse,
} from '../api/account'

type AccountSessionState = {
  status: 'disabled' | 'checking' | 'signed_in' | 'signed_out' | 'unavailable'
  session: AccountSessionResponse | null
  message: string
}

export function useAccountSession() {
  const enabled = import.meta.env.DEV
  const request = useRef<AbortController | null>(null)
  const [attempt, setAttempt] = useState(0)

  const [state, setState] = useState<AccountSessionState>({
    status: enabled ? 'checking' : 'disabled',
    session: null,
    message: enabled ? 'Checking your account session…' : '',
  })

  useEffect(() => {
    if (!enabled) return

    const controller = new AbortController()
    request.current = controller

    let active = true
    let timedOut = false

    const timeout = window.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, 15_000)

    async function restore() {
      // Let StrictMode discard its first effect before sending a request.
      await Promise.resolve()
      if (!active) return

      try {
        const session = await checkAccountSession(controller.signal)

        if (!active) return

        if (controller.signal.aborted) {
          throw new Error('Session check cancelled')
        }

        if (session === null) {
          setState({
            status: 'signed_out',
            session: null,
            message: '',
          })
        } else {
          setState({
            status: 'signed_in',
            session,
            message: 'Signed in. Chat is still in development.',
          })
        }
      } catch {
        if (!active) return

        setState({
          status: 'unavailable',
          session: null,
          message: timedOut
            ? 'Account session check took too long. Please try again.'
            : 'Account session could not be checked. Please try again.',
        })
      } finally {
        window.clearTimeout(timeout)

        if (request.current === controller) {
          request.current = null
        }
      }
    }

    void restore()

    return () => {
      active = false
      window.clearTimeout(timeout)
      controller.abort()

      if (request.current === controller) {
        request.current = null
      }
    }
  }, [enabled, attempt])

  function refresh() {
    if (!enabled || request.current) return

    setState({
      status: 'checking',
      session: null,
      message: 'Checking your account session…',
    })
    setAttempt((current) => current + 1)
  }

  function acceptSignIn(session: AccountSessionResponse) {
    if (!enabled || request.current) return

    setState({
      status: 'signed_in',
      session,
      message: 'Signed in. Chat is still in development.',
    })
  }

  function acceptSignOut() {
    if (!enabled || request.current) return

    setState({
      status: 'signed_out',
      session: null,
      message: 'Signed out.',
    })
  }

  return {
    enabled,
    status: state.status,
    session: state.session,
    message: state.message,
    refresh,
    acceptSignIn,
    acceptSignOut,
  }
}
