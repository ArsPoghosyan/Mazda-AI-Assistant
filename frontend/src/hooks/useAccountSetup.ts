import { useEffect, useRef, useState } from 'react'
import type { AccountSessionResponse } from '../api/account'
import { acceptAccountTerms, checkAccountTerms, SetupSessionExpired } from '../api/accountTerms'

type Status = 'checking' | 'required' | 'submitting' | 'ready' | 'unavailable' | 'expired'
type State = { session: AccountSessionResponse; attempt: number; status: Status; message: string }
const FAILURE = 'Account setup could not be completed. Please try again.'

export function useAccountSetup(session: AccountSessionResponse) {
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<State>({ session, attempt, status: 'checking', message: '' })
  const request = useRef<{ controller: AbortController; timer: number } | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      if (request.current?.controller !== controller) return
      request.current = null
      controller.abort()
      setState({ session, attempt, status: 'unavailable', message: FAILURE })
    }, 15_000)
    request.current = { controller, timer }
    let active = true
    void (async () => {
      await Promise.resolve()
      if (!active) return
      try {
        const result = await checkAccountTerms(controller.signal, session.user_id)
        controller.signal.throwIfAborted()
        if (active && request.current?.controller === controller) setState({ session, attempt,
          status: result.acceptance_required ? 'required' : 'ready', message: '' })
      } catch (error) {
        if (active && request.current?.controller === controller) setState({ session, attempt,
          status: error instanceof SetupSessionExpired ? 'expired' : 'unavailable',
          message: error instanceof SetupSessionExpired ? error.message : FAILURE })
      } finally {
        window.clearTimeout(timer)
        if (request.current?.controller === controller) request.current = null
      }
    })()
    return () => {
      active = false
      controller.abort()
      window.clearTimeout(timer)
      const pending = request.current
      request.current = null
      if (pending) { window.clearTimeout(pending.timer); pending.controller.abort() }
    }
  }, [session, attempt])

  async function accept() {
    if (request.current || state.session !== session || state.attempt !== attempt || state.status !== 'required') return
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      if (request.current?.controller !== controller) return
      request.current = null
      controller.abort()
      setState({ session, attempt, status: 'required', message: FAILURE })
    }, 15_000)
    request.current = { controller, timer }
    setState({ session, attempt, status: 'submitting', message: '' })
    try {
      const result = await acceptAccountTerms(controller.signal, session.user_id)
      controller.signal.throwIfAborted()
      if (request.current?.controller === controller) setState({ session, attempt,
        status: result.acceptance_required ? 'required' : 'ready', message: '' })
    } catch (error) {
      if (request.current?.controller === controller) setState({ session, attempt,
        status: error instanceof SetupSessionExpired ? 'expired' : 'required',
        message: error instanceof SetupSessionExpired ? error.message : FAILURE })
    } finally {
      window.clearTimeout(timer)
      if (request.current?.controller === controller) request.current = null
    }
  }

  const current = state.session === session && state.attempt === attempt
  return { status: current ? state.status : 'checking' as Status,
    message: current ? state.message : '', accept,
    retry: () => { if (!request.current) setAttempt(value => value + 1) } }
}
