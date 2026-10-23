import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountPasswordResetRateLimitedError,
  AccountPasswordResetRejectedError,
  resetAccountPassword,
  type AccountPasswordResetResponse,
} from '../api/account-password-reset'
import { useAccountPasswordReset } from './useAccountPasswordReset'

vi.mock('../api/account-password-reset', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/account-password-reset')>()
  return { ...actual, resetAccountPassword: vi.fn() }
})

const credentials = {
  email: 'owner@example.test', code: '001234', new_password: '  synthetic-new-password-é  ',
}
const completion: AccountPasswordResetResponse = { status: 'completed' }
const failureMessage = 'Password reset could not be confirmed. Try signing in with your new password before starting recovery again.'
const timeoutMessage = 'Password reset took too long to confirm. Try signing in with your new password before starting recovery again.'

function deferredRequest() {
  let resolve!: (value: AccountPasswordResetResponse) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<AccountPasswordResetResponse>((complete, fail) => {
    resolve = complete
    reject = fail
  })
  return { promise, resolve, reject }
}

function mountHook() {
  return renderHook(useAccountPasswordReset, { wrapper: StrictMode })
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(resetAccountPassword).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test('mounting under StrictMode stays idle without attempting a password change', () => {
  const { result } = mountHook()
  expect(result.current.enabled).toBe(true)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(resetAccountPassword).not.toHaveBeenCalled()
})

test('blocks duplicate resets and stale callbacks after confirmed completion', async () => {
  vi.useFakeTimers()
  const pending = deferredRequest()
  vi.mocked(resetAccountPassword).mockReturnValue(pending.promise)
  const { result } = mountHook()
  const originalStart = result.current.start
  let submission!: Promise<boolean>
  let duplicate!: Promise<boolean>
  act(() => {
    submission = originalStart(credentials)
    duplicate = originalStart(credentials)
  })
  expect(result.current.status).toBe('loading')
  expect(result.current.message).toBe('Resetting password…')
  expect(resetAccountPassword).toHaveBeenCalledExactlyOnceWith(credentials, expect.any(AbortSignal))
  await act(async () => {
    expect(await duplicate).toBe(false)
    pending.resolve(completion)
    expect(await submission).toBe(true)
  })
  expect(result.current.status).toBe('completed')
  expect(result.current.message).toBe('Password reset completed. Sign in with your new password.')
  expect(vi.getTimerCount()).toBe(0)
  const visibleState = JSON.stringify(result.current)
  for (const value of Object.values(credentials)) expect(visibleState).not.toContain(value)
  await act(async () => {
    expect(await originalStart(credentials)).toBe(false)
    expect(await result.current.start(credentials)).toBe(false)
  })
  expect(resetAccountPassword).toHaveBeenCalledTimes(1)
})

test.each([
  {
    name: 'rejected input/code', error: new AccountPasswordResetRejectedError(),
    message: 'Password reset was rejected. Check your email, code and new password, then try again.',
  },
  {
    name: 'rate limit', error: new AccountPasswordResetRateLimitedError(),
    message: 'Too many password-reset attempts. Please try again later.',
  },
  { name: 'private provider error', error: new Error('private-provider-detail'), message: failureMessage },
  { name: 'unexpected non-Error value', error: 'private-provider-detail', message: failureMessage },
  { name: 'unexpected cancellation', error: new DOMException('private-provider-detail', 'AbortError'), message: failureMessage },
])('handles $name without automatic retries or private details', async ({ error, message }) => {
  vi.useFakeTimers()
  vi.mocked(resetAccountPassword).mockRejectedValueOnce(error)
  const { result } = mountHook()
  await act(async () => { expect(await result.current.start(credentials)).toBe(false) })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(message)
  expect(result.current.message).not.toContain('private-provider-detail')
  expect(resetAccountPassword).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)

  const fresh = { ...credentials, code: '000987', new_password: '  fresh-synthetic-password  ' }
  vi.mocked(resetAccountPassword).mockResolvedValueOnce(completion)
  await act(async () => { expect(await result.current.start(fresh)).toBe(true) })
  expect(resetAccountPassword).toHaveBeenCalledTimes(2)
  expect(vi.mocked(resetAccountPassword).mock.calls[1]?.[0]).toEqual(fresh)
  expect(result.current.status).toBe('completed')
  expect(vi.getTimerCount()).toBe(0)
})

test('aborts at exactly 15 seconds and preserves uncertainty without retrying', async () => {
  vi.useFakeTimers()
  vi.mocked(resetAccountPassword).mockImplementationOnce((_credentials, signal) =>
    new Promise<AccountPasswordResetResponse>((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
    }),
  )
  const { result } = mountHook()
  let submission!: Promise<boolean>
  act(() => { submission = result.current.start(credentials) })
  const signal = vi.mocked(resetAccountPassword).mock.calls[0]?.[1]
  await act(async () => { await vi.advanceTimersByTimeAsync(14_999) })
  expect(signal?.aborted).toBe(false)
  expect(result.current.status).toBe('loading')
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1)
    expect(await submission).toBe(false)
  })
  expect(signal?.aborted).toBe(true)
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(timeoutMessage)
  expect(resetAccountPassword).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
})

test.each(['resolve', 'reject'] as const)('a late %s after the deadline cannot confirm completion', async (outcome) => {
  vi.useFakeTimers()
  const pending = deferredRequest()
  vi.mocked(resetAccountPassword).mockReturnValueOnce(pending.promise)
  const { result } = mountHook()
  let submission!: Promise<boolean>
  act(() => { submission = result.current.start(credentials) })
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000) })
  await act(async () => {
    if (outcome === 'resolve') pending.resolve(completion)
    else pending.reject(new AccountPasswordResetRejectedError())
    expect(await submission).toBe(false)
  })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(timeoutMessage)
  expect(resetAccountPassword).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
})

test.each(['resolve', 'reject'] as const)('unmount aborts reset and ignores a late %s', async (outcome) => {
  vi.useFakeTimers()
  const pending = deferredRequest()
  vi.mocked(resetAccountPassword).mockReturnValueOnce(pending.promise)
  const { result, unmount } = mountHook()
  const originalStart = result.current.start
  let submission!: Promise<boolean>
  act(() => { submission = originalStart(credentials) })
  const signal = vi.mocked(resetAccountPassword).mock.calls[0]?.[1]
  unmount()
  expect(signal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
  await act(async () => {
    if (outcome === 'resolve') pending.resolve(completion)
    else pending.reject(new Error('private-late-detail'))
    expect(await submission).toBe(false)
    expect(await originalStart(credentials)).toBe(false)
  })
  expect(result.current.status).toBe('loading')
  expect(resetAccountPassword).toHaveBeenCalledTimes(1)
})

test('completion clears the deadline without aborting its finished signal', async () => {
  vi.useFakeTimers()
  vi.mocked(resetAccountPassword).mockResolvedValueOnce(completion)
  const { result } = mountHook()
  await act(async () => { expect(await result.current.start(credentials)).toBe(true) })
  const signal = vi.mocked(resetAccountPassword).mock.calls[0]?.[1]
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
  expect(signal?.aborted).toBe(false)
  expect(result.current.status).toBe('completed')
  expect(vi.getTimerCount()).toBe(0)
})

test('does not attempt a password reset outside development', async () => {
  vi.stubEnv('DEV', false)
  const { result } = mountHook()
  await act(async () => { expect(await result.current.start(credentials)).toBe(false) })
  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(resetAccountPassword).not.toHaveBeenCalled()
})
