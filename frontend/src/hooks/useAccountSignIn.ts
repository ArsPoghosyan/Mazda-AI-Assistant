import { useEffect, useRef, useState } from 'react'
import {
  AccountSignInRejectedError,
  AccountVerificationRequiredError,
  signInAccount,
  type AccountSignInCredentials,
} from '../api/account'

type SignInState = {
  status: 'idle' | 'loading' | 'ready' | 'error'
  message: string
}

type PendingRequest = {
  controller: AbortController
  timeout: number
}

export function useAccountSignIn() {
  const enabled = import.meta.env.DEV
  const request = useRef<PendingRequest | null>(null)

  const [state, setState] = useState<SignInState>({
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

  async function start(credentials: AccountSignInCredentials) {
    if (!enabled || request.current || state.status === 'ready') {
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
      message: 'Signing in…',
    })

    try {
      await signInAccount(credentials, controller.signal)

      if (request.current?.controller !== controller) return

      if (controller.signal.aborted) {
        setState({
          status: 'error',
          message: 'Sign-in took too long. Please try again.',
        })
        return
      }

      setState({
        status: 'ready',
        message: 'Signed in. Chat is still in development.',
      })
    } catch (error) {
      if (request.current?.controller !== controller) return

      let message = 'Sign-in could not be completed. Please try again.'

      if (timedOut) {
        message = 'Sign-in took too long. Please try again.'
      } else if (error instanceof AccountVerificationRequiredError) {
        message = 'Verification was not accepted. Complete a new check.'
      } else if (error instanceof AccountSignInRejectedError) {
        message = 'Sign-in was rejected. Check your details and try again.'
      }

      setState({
        status: 'error',
        message,
      })
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