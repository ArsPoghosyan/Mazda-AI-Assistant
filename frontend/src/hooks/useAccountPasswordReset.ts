import { useEffect, useRef, useState } from 'react'
import {
  AccountPasswordResetRateLimitedError,
  AccountPasswordResetRejectedError,
  resetAccountPassword,
  type AccountPasswordResetCredentials,
} from '../api/account-password-reset'

type PasswordResetState = {
  status: 'idle' | 'loading' | 'completed' | 'error'
  message: string
}

type PendingRequest = {
  controller: AbortController
  timeout: number
}

export function useAccountPasswordReset() {
  const enabled = import.meta.env.DEV
  const active = useRef(false)
  const request = useRef<PendingRequest | null>(null)
  const completed = useRef(false)

  const [state, setState] = useState<PasswordResetState>({
    status: 'idle',
    message: '',
  })

  useEffect(() => {
    active.current = true

    return () => {
      active.current = false
      const pending = request.current
      request.current = null

      if (pending) {
        window.clearTimeout(pending.timeout)
        pending.controller.abort()
      }
    }
  }, [])

  async function start(credentials: AccountPasswordResetCredentials): Promise<boolean> {
    // Refs also guard clicks through callbacks captured before the latest render.
    if (!enabled || !active.current || request.current || completed.current) return false

    const controller = new AbortController()
    let timedOut = false

    const timeout = window.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, 15_000)

    request.current = { controller, timeout }
    setState({ status: 'loading', message: 'Resetting password…' })

    try {
      await resetAccountPassword(credentials, controller.signal)

      if (!active.current || request.current?.controller !== controller) return false

      if (controller.signal.aborted) {
        throw new Error('Password reset request cancelled')
      }

      completed.current = true
      setState({
        status: 'completed',
        message: 'Password reset completed. Sign in with your new password.',
      })
      return true
    } catch (error) {
      if (!active.current || request.current?.controller !== controller) return false

      let message = 'Password reset could not be confirmed. Try signing in with your new password before starting recovery again.'

      if (timedOut) {
        message = 'Password reset took too long to confirm. Try signing in with your new password before starting recovery again.'
      } else if (error instanceof AccountPasswordResetRejectedError) {
        message = 'Password reset was rejected. Check your email, code and new password, then try again.'
      } else if (error instanceof AccountPasswordResetRateLimitedError) {
        message = 'Too many password-reset attempts. Please try again later.'
      }

      setState({ status: 'error', message })
      return false
    } finally {
      window.clearTimeout(timeout)
      if (request.current?.controller === controller) request.current = null
    }
  }

  return {
    enabled,
    status: state.status,
    message: state.message,
    start,
  }
}
