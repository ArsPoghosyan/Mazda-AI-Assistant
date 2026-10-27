import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  checkAccountSession,
  type AccountSessionResponse,
} from '../api/account'
import { useAccountSession } from './useAccountSession'

vi.mock('../api/account', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/account')>()
  return { ...actual, checkAccountSession: vi.fn() }
})

const session: AccountSessionResponse = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

const returns = [
  ['success', 'Google sign-in could not be confirmed. Please sign in again.'],
  ['rejected', 'Google sign-in was not completed. Please try again.'],
  ['unavailable', 'Google sign-in is temporarily unavailable. Please try again.'],
  ['sign-out-required', 'The previous account session is no longer available. Please sign in again.'],
] as const

let originalUrl: string
let originalState: unknown

function setReturn(outcome: string) {
  window.history.replaceState(
    { keep: 'synthetic-entry' }, '',
    `/?view=account#google-sign-in=${outcome}`,
  )
}

function deferredSession() {
  let resolve!: (value: AccountSessionResponse | null) => void
  const promise = new Promise<AccountSessionResponse | null>((complete) => {
    resolve = complete
  })
  return { promise, resolve }
}

async function mountSession() {
  const view = renderHook(useAccountSession, { wrapper: StrictMode })
  await act(async () => { await Promise.resolve() })
  return view
}

beforeEach(() => {
  originalUrl = window.location.href
  originalState = window.history.state
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'false')
  vi.mocked(checkAccountSession).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
  window.history.replaceState(originalState, '', originalUrl)
})

test.each(returns)('backend rejection controls status for %s under StrictMode', async (outcome, message) => {
  setReturn(outcome)
  const replace = vi.spyOn(window.history, 'replaceState')
  vi.mocked(checkAccountSession).mockResolvedValue(null)

  const { result, rerender } = await mountSession()

  expect(result.current.status).toBe('signed_out')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe(message)
  expect(window.location.hash).toBe('')
  expect(window.location.search).toBe('?view=account')
  expect(window.history.state).toEqual({ keep: 'synthetic-entry' })
  expect(replace).toHaveBeenCalledTimes(1)
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
  rerender()
  expect(result.current.message).toBe(message)
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})

test.each(returns)('verified backend session takes priority over %s hint', async (outcome) => {
  setReturn(outcome)
  vi.mocked(checkAccountSession).mockResolvedValue(session)

  const { result } = await mountSession()

  expect(result.current.status).toBe('signed_in')
  expect(result.current.session).toEqual(session)
  expect(result.current.message).toBe(outcome === 'sign-out-required'
    ? 'You are already signed in. Sign out before choosing another account.'
    : 'Signed in. Chat is still in development.')
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})

test.each(returns)('production verifies the backend before trusting the %s return hint', async (outcome, message) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  setReturn(outcome)
  const pending = deferredSession()
  vi.mocked(checkAccountSession).mockReturnValueOnce(pending.promise).mockResolvedValueOnce(session)
  const { result } = await mountSession()
  expect(result.current.status).toBe('checking')
  expect(result.current.session).toBeNull()
  expect(window.location.hash).toBe('')
  expect(window.location.search).toBe('?view=account')
  expect(window.history.state).toEqual({ keep: 'synthetic-entry' })
  await act(async () => { pending.resolve(null); await pending.promise })
  expect(result.current.status).toBe('signed_out')
  expect(result.current.message).toBe(message)
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
  await act(async () => { result.current.refresh() })
  expect(result.current.status).toBe('signed_in')
  expect(result.current.session).toEqual(session)
  expect(checkAccountSession).toHaveBeenCalledTimes(2)
})

test('forged success stays checking until the backend rejects the session', async () => {
  setReturn('success')
  const pending = deferredSession()
  vi.mocked(checkAccountSession).mockReturnValue(pending.promise)
  const { result } = await mountSession()

  expect(window.location.hash).toBe('')
  expect(result.current.status).toBe('checking')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe('Checking your account session…')

  await act(async () => {
    pending.resolve(null)
    await pending.promise
  })
  expect(result.current.status).toBe('signed_out')
  expect(result.current.session).toBeNull()
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})

test.each(returns)('backend failure stays unavailable and preserves %s for explicit retry', async (outcome, message) => {
  setReturn(outcome)
  vi.mocked(checkAccountSession)
    .mockResolvedValue(null)
    .mockRejectedValueOnce(new Error('synthetic-private-detail'))
  const { result, rerender } = await mountSession()

  expect(result.current.status).toBe('unavailable')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe('Account session could not be checked. Please try again.')
  rerender()
  expect(checkAccountSession).toHaveBeenCalledTimes(1)

  await act(async () => { result.current.refresh() })
  expect(result.current.status).toBe('signed_out')
  expect(result.current.message).toBe(message)
  expect(checkAccountSession).toHaveBeenCalledTimes(2)

  await act(async () => { result.current.refresh() })
  expect(result.current.status).toBe('signed_out')
  expect(result.current.message).toBe('')
})

test('a Google return timeout remains unavailable until a verified retry', async () => {
  vi.useFakeTimers()
  setReturn('success')
  vi.mocked(checkAccountSession).mockImplementationOnce((signal) =>
    new Promise((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
    }),
  ).mockResolvedValueOnce(session)
  const { result } = await mountSession()
  const signal = vi.mocked(checkAccountSession).mock.calls[0]?.[0]

  await act(async () => { await vi.advanceTimersByTimeAsync(15_000) })
  expect(signal?.aborted).toBe(true)
  expect(result.current.status).toBe('unavailable')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe('Account session check took too long. Please try again.')
  expect(checkAccountSession).toHaveBeenCalledTimes(1)

  await act(async () => { result.current.refresh() })
  expect(result.current.status).toBe('signed_in')
  expect(result.current.session).toEqual(session)
  expect(vi.getTimerCount()).toBe(0)
})

test('unmount after a Google return aborts and ignores a late verified session', async () => {
  setReturn('success')
  const pending = deferredSession()
  vi.mocked(checkAccountSession).mockReturnValue(pending.promise)
  const { result, unmount } = await mountSession()
  const signal = vi.mocked(checkAccountSession).mock.calls[0]?.[0]
  unmount()

  await act(async () => {
    pending.resolve(session)
    await pending.promise
  })
  expect(signal?.aborted).toBe(true)
  expect(result.current.status).toBe('checking')
  expect(result.current.session).toBeNull()
})

test('production leaves the marker untouched and performs no session check', async () => {
  vi.stubEnv('DEV', false)
  setReturn('success')
  const replace = vi.spyOn(window.history, 'replaceState')
  const { result } = await mountSession()

  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('disabled')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe('')
  expect(window.location.hash).toBe('#google-sign-in=success')
  expect(replace).not.toHaveBeenCalled()
  expect(checkAccountSession).not.toHaveBeenCalled()
})

test.each(['unknown', 'success&google-sign-in=rejected', 'success&extra=synthetic'])('ignores malformed %s hint without skipping the session check', async (outcome) => {
  setReturn(outcome)
  const hash = window.location.hash
  vi.mocked(checkAccountSession).mockResolvedValue(null)
  const { result } = await mountSession()

  expect(result.current.status).toBe('signed_out')
  expect(result.current.message).toBe('')
  expect(window.location.hash).toBe(hash)
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})

test('reads the initial hint only once across refreshes and ignores later fragments', async () => {
  setReturn('rejected')
  vi.mocked(checkAccountSession).mockResolvedValue(null)
  const { result } = await mountSession()
  setReturn('success')

  await act(async () => { result.current.refresh() })

  expect(result.current.status).toBe('signed_out')
  expect(result.current.message).toBe('')
  expect(window.location.hash).toBe('#google-sign-in=success')
  expect(checkAccountSession).toHaveBeenCalledTimes(2)
})

test('history cleanup failure does not prevent backend restoration or accept the hint', async () => {
  setReturn('success')
  vi.spyOn(window.history, 'replaceState').mockImplementationOnce(() => {
    throw new DOMException('Synthetic history failure', 'SecurityError')
  })
  vi.mocked(checkAccountSession).mockResolvedValue(null)
  const { result } = await mountSession()

  expect(result.current.status).toBe('signed_out')
  expect(result.current.message).toBe('')
  expect(window.location.hash).toBe('#google-sign-in=success')
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})
