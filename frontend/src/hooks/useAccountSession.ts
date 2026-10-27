import { useEffect, useRef, useState } from 'react'
import { isAccountAuthEnabled } from '../lib/accountFeatures'
import {
  checkAccountSession,
  type AccountSessionResponse,
} from '../api/account'
import {
  consumeGoogleReturn,
  type GoogleReturnOutcome,
} from '../lib/googleReturn'

type AccountSessionState = {
  status: 'disabled' | 'checking' | 'signed_in' | 'signed_out' | 'unavailable'
  session: AccountSessionResponse | null
  message: string
}

const GOOGLE_RETURN_MESSAGES: Record<GoogleReturnOutcome, string> = {
  success: 'Google sign-in could not be confirmed. Please sign in again.',
  rejected: 'Google sign-in was not completed. Please try again.',
  unavailable: 'Google sign-in is temporarily unavailable. Please try again.',
  'sign-out-required':
    'The previous account session is no longer available. Please sign in again.',
}

export function useAccountSession(backendReady = true) {
  const enabled = isAccountAuthEnabled()
  const request = useRef<AbortController | null>(null)
  const googleReturn = useRef<GoogleReturnOutcome | null | undefined>(undefined)
  const [attempt, setAttempt] = useState(0)

  const [state, setState] = useState<AccountSessionState>({
    status: enabled ? 'checking' : 'disabled',
    session: null,
    message: enabled ? 'Checking your account session…' : '',
  })

  useEffect(() => {
    if (!enabled || !backendReady) return

    if (googleReturn.current === undefined) {
      googleReturn.current = consumeGoogleReturn()
    }

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
            message: googleReturn.current
              ? GOOGLE_RETURN_MESSAGES[googleReturn.current]
              : '',
          })
        } else {
          setState({
            status: 'signed_in',
            session,
            message:
              googleReturn.current === 'sign-out-required'
                ? 'You are already signed in. Sign out before choosing another account.'
                : 'Signed in. Chat is still in development.',
          })
        }

        // A completed session check has handled this return hint.
        googleReturn.current = null
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
  }, [enabled, backendReady, attempt])

  function refresh() {
    if (!enabled || !backendReady || request.current) return

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
