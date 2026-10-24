import { useEffect, useRef, useState } from 'react'
import {
  ensureGuestSession,
  GuestRateLimitedError,
  GuestVerificationRequiredError,
} from '../api/guest'

type GuestState = {
  status: 'idle' | 'loading' | 'verification' | 'ready' | 'error'
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

  async function start(turnstileToken?: string) {
    if (!enabled || request.current || state.status === 'ready') {
      return
    }

    // Accept proofs only while a challenge is expected.
    if (
      turnstileToken !== undefined &&
      state.status !== 'verification'
    ) {
      return
    }

    // Wait for the widget instead of repeating the initial request.
    if (
      turnstileToken === undefined &&
      state.status === 'verification'
    ) {
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
      await ensureGuestSession(controller.signal, turnstileToken)

      if (request.current !== controller) return

      if (controller.signal.aborted) {
        throw new Error('Request cancelled')
      }

      setState({
        status: 'ready',
        message: 'Guest session ready. Chat is still in development.',
      })
    } catch (error) {
      if (request.current !== controller) return

      if (timedOut) {
        setState({
          status: 'error',
          message: 'Guest access took too long. Please try again.',
        })
      } else if (
        !controller.signal.aborted &&
        error instanceof GuestRateLimitedError
      ) {
        const seconds = error.retryAfterSeconds
        setState({
          status: 'error',
          message: seconds === null
            ? error.message
            : `Too many guest-access attempts. Please wait ${seconds} ${seconds === 1 ? 'second' : 'seconds'} before trying again.`,
        })
      } else if (
        !controller.signal.aborted &&
        error instanceof GuestVerificationRequiredError
      ) {
        if (turnstileToken === undefined) {
          setState({
            status: 'verification',
            message: 'Complete human verification to continue.',
          })
        } else {
          setState({
            status: 'error',
            message: 'Verification was not accepted. Please try again.',
          })
        }
      } else {
        setState({
          status: 'error',
          message: 'Guest access could not be started. Please try again.',
        })
      }
    } finally {
      window.clearTimeout(timeout)

      if (request.current === controller) {
        request.current = null
      }
    }
  }

  function invalidateVerification() {
    setState((current) =>
      current.status === 'verification'
        ? {
            status: 'verification',
            message: 'Complete a new verification check to continue.',
          }
        : current,
    )
  }

  return {
    enabled,
    status: state.status,
    message: state.message,
    start,
    invalidateVerification,
  }
}
