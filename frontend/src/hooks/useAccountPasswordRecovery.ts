import { useEffect, useRef, useState } from 'react'
import {
  AccountPasswordRecoveryRateLimitedError,
  AccountPasswordRecoveryRejectedError,
  AccountPasswordRecoveryVerificationRequiredError,
  requestAccountPasswordRecovery,
  type AccountPasswordRecoveryCredentials,
} from '../api/account-password-recovery'

type PasswordRecoveryState = {
  status: 'idle' | 'loading' | 'accepted' | 'error'
  message: string
}

type PendingRequest = {
  controller: AbortController
  timeout: number
}

export function useAccountPasswordRecovery() {
  const enabled = import.meta.env.DEV
  const active = useRef(false)
  const request = useRef<PendingRequest | null>(null)
  const completed = useRef(false)

  const [state, setState] = useState<PasswordRecoveryState>({
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

  async function start(
    credentials: AccountPasswordRecoveryCredentials,
  ): Promise<boolean> {
    // Refs guard duplicate calls before React renders the loading/accepted state.
    if (!enabled || !active.current || request.current || completed.current) return false

    const controller = new AbortController()
    let timedOut = false

    const timeout = window.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, 15_000)

    request.current = { controller, timeout }
    setState({ status: 'loading', message: 'Requesting password recovery…' })

    try {
      await requestAccountPasswordRecovery(credentials, controller.signal)

      if (!active.current || request.current?.controller !== controller) return false

      if (controller.signal.aborted) {
        throw new Error('Recovery request cancelled')
      }

      completed.current = true
      setState({
        status: 'accepted',
        message: 'If password recovery can proceed, check your email for the next steps.',
      })
      return true
    } catch (error) {
      if (!active.current || request.current?.controller !== controller) return false

      let message = 'Password recovery could not be requested. Please try again.'

      if (timedOut) {
        message = 'Recovery request took too long. Check your email before trying again.'
      } else if (error instanceof AccountPasswordRecoveryVerificationRequiredError) {
        message = 'Verification was not accepted. Complete a new check.'
      } else if (error instanceof AccountPasswordRecoveryRejectedError) {
        message = 'Password recovery was rejected. Check your details and try again.'
      } else if (error instanceof AccountPasswordRecoveryRateLimitedError) {
        message = 'Too many recovery requests. Please try again later.'
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
