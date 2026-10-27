import { useEffect, useRef, useState } from 'react'
import { signOutAccount } from '../api/account'
import { isAccountAuthEnabled } from '../lib/accountFeatures'

type SignOutState = {
  status: 'idle' | 'loading' | 'ready' | 'error'
  message: string
}

type PendingRequest = {
  controller: AbortController
  timeout: number
}

export function useAccountSignOut() {
  const enabled = isAccountAuthEnabled()
  const request = useRef<PendingRequest | null>(null)

  const [state, setState] = useState<SignOutState>({
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

  async function start(): Promise<boolean> {
    if (!enabled || request.current) return false

    const controller = new AbortController()
    let timedOut = false

    const timeout = window.setTimeout(() => {
      timedOut = true
      controller.abort()
    }, 15_000)

    request.current = { controller, timeout }

    setState({
      status: 'loading',
      message: 'Signing out…',
    })

    try {
      await signOutAccount(controller.signal)

      if (request.current?.controller !== controller) return false

      if (controller.signal.aborted) {
        throw new Error('Sign-out request cancelled')
      }

      setState({
        status: 'ready',
        message: 'Signed out.',
      })

      return true
    } catch {
      if (request.current?.controller !== controller) return false

      setState({
        status: 'error',
        message: timedOut
          ? 'Sign-out took too long. Please try again.'
          : 'Sign-out could not be completed. Please try again.',
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
