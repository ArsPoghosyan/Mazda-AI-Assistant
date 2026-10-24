import { useEffect, useRef, useState } from 'react'
import {
  AccountEmailConfirmationRateLimitedError,
  AccountEmailConfirmationRejectedError,
  confirmAccountEmail,
  type AccountEmailConfirmationCredentials,
} from '../api/account-registration'

type ConfirmationState = {
  status: 'idle' | 'loading' | 'confirmed' | 'error'
  message: string
}

type PendingRequest = {
  controller: AbortController
  timeout: number
}

export function useAccountEmailConfirmation() {
  const enabled = import.meta.env.DEV
  const request = useRef<PendingRequest | null>(null)
  const completed = useRef(false)

  const [state, setState] = useState<ConfirmationState>({
    status: 'idle',
    message: '',
  })

  useEffect(() => {
    return () => {
      const pending = request.current
      request.current = null

      if (pending) {
        window.clearTimeout(pending.timeout)
        pending.controller.abort()
      }
    }
  }, [])

  async function start(
    credentials: AccountEmailConfirmationCredentials,
  ): Promise<boolean> {
    if (!enabled || request.current || completed.current) return false

    const controller = new AbortController()
    let timedOut = false

    const timeout = window.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, 15_000)

    request.current = { controller, timeout }

    setState({
      status: 'loading',
      message: 'Confirming email…',
    })

    try {
      await confirmAccountEmail(credentials, controller.signal)

      if (request.current?.controller !== controller) return false

      if (controller.signal.aborted) {
        throw new Error('Email-confirmation request cancelled')
      }

      completed.current = true

      setState({
        status: 'confirmed',
        message: 'Email confirmed. You can now sign in.',
      })

      return true
    } catch (error) {
      if (request.current?.controller !== controller) return false

      let message =
        'Email confirmation could not be completed. Please try again.'

      if (timedOut) {
        message = 'Email confirmation took too long. Please try again.'
      } else if (error instanceof AccountEmailConfirmationRateLimitedError) {
        const seconds = error.retryAfterSeconds
        message = seconds === null
          ? error.message
          : `Too many email confirmation attempts. Please wait ${seconds} ${seconds === 1 ? 'second' : 'seconds'} before trying again.`
      } else if (error instanceof AccountEmailConfirmationRejectedError) {
        message =
          'Email confirmation was rejected. Check your email and code, then try again.'
      }

      setState({
        status: 'error',
        message,
      })

      return false
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
