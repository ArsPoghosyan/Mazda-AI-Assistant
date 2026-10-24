import { useEffect, useRef, useState } from 'react'
import { GoogleSignInRateLimitedError, startGoogleSignIn } from '../api/google'

type GoogleSignInState = {
  status: 'idle' | 'loading' | 'redirecting' | 'error'
  message: string
}

type PendingRequest = {
  controller: AbortController
  timeout: number
}

const FAILURE = 'Google sign-in could not be started. Please try again.'

const SAFE_MESSAGES = new Set([
  FAILURE,
  'Please start Google sign-in again.',
  'Sign out before starting another account login.',
  'Google sign-in is temporarily unavailable.',
])

function configuredIssuer(): string | null {
  const value = import.meta.env.VITE_SUPABASE_AUTH_ISSUER?.trim()
  if (!value) return null

  try {
    const url = new URL(value)

    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      url.pathname !== '/auth/v1' ||
      url.search ||
      url.hash
    ) {
      return null
    }

    return url.href
  } catch {
    return null
  }
}

function navigateToGoogle(destination: string): void {
  window.location.assign(destination)
}

export function useGoogleSignIn(
  navigate: (destination: string) => void = navigateToGoogle,
) {
  const issuer = configuredIssuer()
  const enabled =
    import.meta.env.DEV &&
    import.meta.env.VITE_GOOGLE_OAUTH_ENABLED === 'true' &&
    issuer !== null

  const request = useRef<PendingRequest | null>(null)
  const navigating = useRef(false)

  const [state, setState] = useState<GoogleSignInState>({
    status: 'idle',
    message: '',
  })

  useEffect(() => {
    function cancelPending() {
      const pending = request.current
      request.current = null

      if (pending) {
        window.clearTimeout(pending.timeout)
        pending.controller.abort()
      }
    }

    function handlePageShow(event: PageTransitionEvent) {
      if (!event.persisted) return

      cancelPending()
      navigating.current = false
      setState({ status: 'idle', message: '' })
    }

    window.addEventListener('pageshow', handlePageShow)

    return () => {
      window.removeEventListener('pageshow', handlePageShow)
      cancelPending()
    }
  }, [])

  async function start(): Promise<void> {
    if (!enabled || issuer === null || request.current || navigating.current) {
      return
    }

    const controller = new AbortController()
    let timedOut = false

    const timeout = window.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, 15_000)

    request.current = { controller, timeout }
    setState({
      status: 'loading',
      message: 'Opening Google sign-in…',
    })

    try {
      const callback = new URL(
        '/api/v1/account/google/callback',
        window.location.origin,
      ).href

      const result = await startGoogleSignIn(
        issuer,
        callback,
        controller.signal,
      )

      if (request.current?.controller !== controller) return

      if (
        controller.signal.aborted ||
        Date.parse(result.expires_at) <= Date.now()
      ) {
        throw new Error(FAILURE)
      }

      navigating.current = true
      setState({
        status: 'redirecting',
        message: 'Redirecting to Google…',
      })

      navigate(result.authorization_url)
    } catch (error) {
      if (request.current?.controller !== controller) return

      navigating.current = false

      let message = FAILURE
      if (timedOut) {
        message = 'Google sign-in took too long. Please try again.'
      } else if (error instanceof GoogleSignInRateLimitedError) {
        const seconds = error.retryAfterSeconds
        message = seconds === null
          ? error.message
          : `Too many Google sign-in attempts. Please wait ${seconds} ${seconds === 1 ? 'second' : 'seconds'} before trying again.`
      } else if (error instanceof Error && SAFE_MESSAGES.has(error.message)) {
        message = error.message
      }
      setState({ status: 'error', message })
    } finally {
      window.clearTimeout(timeout)

      if (request.current?.controller === controller) {
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
