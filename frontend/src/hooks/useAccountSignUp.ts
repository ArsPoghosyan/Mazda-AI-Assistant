import { useEffect, useRef, useState } from 'react'
import {
  AccountSignUpRejectedError,
  AccountSignUpVerificationRequiredError,
  signUpAccount,
  type AccountSignUpCredentials,
} from '../api/account-registration'

type SignUpState = {
  status: 'idle' | 'loading' | 'accepted' | 'error'
  message: string
}

type PendingRequest = {
  controller: AbortController
  timeout: number
}

export function useAccountSignUp() {
  const enabled = import.meta.env.DEV
  const request = useRef<PendingRequest | null>(null)
  const completed = useRef(false)

  const [state, setState] = useState<SignUpState>({
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
    credentials: AccountSignUpCredentials,
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
      message: 'Submitting registration…',
    })

    try {
      await signUpAccount(credentials, controller.signal)

      if (request.current?.controller !== controller) return false

      if (controller.signal.aborted) {
        throw new Error('Registration request cancelled')
      }

      completed.current = true

      setState({
        status: 'accepted',
        message:
          'If registration can proceed, check your email for a verification code.',
      })

      return true
    } catch (error) {
      if (request.current?.controller !== controller) return false

      let message =
        'Registration could not be completed. Please try again.'

      if (timedOut) {
        message = 'Registration took too long. Please try again.'
      } else if (
        error instanceof AccountSignUpVerificationRequiredError
      ) {
        message = 'Verification was not accepted. Complete a new check.'
      } else if (error instanceof AccountSignUpRejectedError) {
        message =
          'Registration was rejected. Check your details and try again.'
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