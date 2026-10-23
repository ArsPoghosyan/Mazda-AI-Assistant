import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountPasswordRecoveryRateLimitedError,
  AccountPasswordRecoveryRejectedError,
  AccountPasswordRecoveryVerificationRequiredError,
  requestAccountPasswordRecovery,
  type AccountPasswordRecoveryResponse,
} from '../api/account-password-recovery'
import { useAccountPasswordRecovery } from './useAccountPasswordRecovery'

vi.mock('../api/account-password-recovery', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/account-password-recovery')>()
  return { ...actual, requestAccountPasswordRecovery: vi.fn() }
})

const credentials = { email: 'owner@example.test', captcha_token: 'synthetic-proof' }
const acknowledgement: AccountPasswordRecoveryResponse = { status: 'accepted' }
const acceptedMessage = 'If password recovery can proceed, check your email for the next steps.'
const timeoutMessage = 'Recovery request took too long. Check your email before trying again.'

function deferredRequest() {
  let resolve!: (value: AccountPasswordRecoveryResponse) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<AccountPasswordRecoveryResponse>((complete, fail) => {
    resolve = complete
    reject = fail
  })
  return { promise, resolve, reject }
}

function mountHook() {
  return renderHook(useAccountPasswordRecovery, { wrapper: StrictMode })
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(requestAccountPasswordRecovery).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test('mounting under StrictMode is idle and sends no recovery email', () => {
  const { result } = mountHook()
  expect(result.current.enabled).toBe(true)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
})

test('blocks immediate duplicate starts and old callbacks after acceptance', async () => {
  vi.useFakeTimers()
  const pending = deferredRequest()
  vi.mocked(requestAccountPasswordRecovery).mockReturnValue(pending.promise)
  const { result } = mountHook()
  const originalStart = result.current.start
  let submission!: Promise<boolean>
  let duplicate!: Promise<boolean>
  act(() => {
    submission = originalStart(credentials)
    duplicate = originalStart(credentials)
  })
  expect(result.current.status).toBe('loading')
  expect(result.current.message).toBe('Requesting password recovery…')
  expect(requestAccountPasswordRecovery).toHaveBeenCalledExactlyOnceWith(
    credentials, expect.any(AbortSignal),
  )
  await act(async () => {
    expect(await duplicate).toBe(false)
    pending.resolve(acknowledgement)
    expect(await submission).toBe(true)
  })
  expect(result.current.status).toBe('accepted')
  expect(result.current.message).toBe(acceptedMessage)
  expect(vi.getTimerCount()).toBe(0)
  await act(async () => {
    expect(await originalStart(credentials)).toBe(false)
    expect(await result.current.start(credentials)).toBe(false)
  })
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(1)
})

test.each([
  {
    name: 'rejected request', error: new AccountPasswordRecoveryRejectedError(),
    message: 'Password recovery was rejected. Check your details and try again.',
  },
  {
    name: 'rejected verification', error: new AccountPasswordRecoveryVerificationRequiredError(),
    message: 'Verification was not accepted. Complete a new check.',
  },
  {
    name: 'rate limit', error: new AccountPasswordRecoveryRateLimitedError(),
    message: 'Too many recovery requests. Please try again later.',
  },
  {
    name: 'private provider error', error: new Error('private-provider-detail'),
    message: 'Password recovery could not be requested. Please try again.',
  },
  {
    name: 'unexpected non-Error value', error: 'private-provider-detail',
    message: 'Password recovery could not be requested. Please try again.',
  },
])('handles $name and retries only on an explicit fresh submission', async ({ error, message }) => {
  vi.useFakeTimers()
  vi.mocked(requestAccountPasswordRecovery).mockRejectedValueOnce(error)
  const { result } = mountHook()
  await act(async () => { expect(await result.current.start(credentials)).toBe(false) })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(message)
  expect(result.current.message).not.toContain('private-provider-detail')
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)

  const fresh = { ...credentials, captcha_token: 'fresh-synthetic-proof' }
  vi.mocked(requestAccountPasswordRecovery).mockResolvedValueOnce(acknowledgement)
  await act(async () => { expect(await result.current.start(fresh)).toBe(true) })
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(2)
  expect(vi.mocked(requestAccountPasswordRecovery).mock.calls[1]?.[0]).toEqual(fresh)
  expect(result.current.status).toBe('accepted')
  expect(vi.getTimerCount()).toBe(0)
})

test('aborts at exactly 15 seconds, clears the timer and permits explicit retry', async () => {
  vi.useFakeTimers()
  vi.mocked(requestAccountPasswordRecovery).mockImplementationOnce((_credentials, signal) =>
    new Promise<AccountPasswordRecoveryResponse>((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true })
    }),
  )
  const { result } = mountHook()
  let submission!: Promise<boolean>
  act(() => { submission = result.current.start(credentials) })
  const signal = vi.mocked(requestAccountPasswordRecovery).mock.calls[0]?.[1]
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
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
  vi.mocked(requestAccountPasswordRecovery).mockResolvedValueOnce(acknowledgement)
  await act(async () => { expect(await result.current.start({ ...credentials, captcha_token: 'fresh-proof' })).toBe(true) })
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(2)
})

test('a late result after the deadline cannot become an accepted recovery request', async () => {
  vi.useFakeTimers()
  const pending = deferredRequest()
  vi.mocked(requestAccountPasswordRecovery).mockReturnValueOnce(pending.promise)
  const { result } = mountHook()
  let submission!: Promise<boolean>
  act(() => { submission = result.current.start(credentials) })
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000) })
  await act(async () => {
    pending.resolve(acknowledgement)
    expect(await submission).toBe(false)
  })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(timeoutMessage)
  expect(vi.getTimerCount()).toBe(0)
})

test.each(['resolve', 'reject'] as const)('unmount aborts recovery and ignores a late %s', async (outcome) => {
  vi.useFakeTimers()
  const pending = deferredRequest()
  vi.mocked(requestAccountPasswordRecovery).mockReturnValueOnce(pending.promise)
  const { result, unmount } = mountHook()
  const originalStart = result.current.start
  let submission!: Promise<boolean>
  act(() => { submission = originalStart(credentials) })
  const signal = vi.mocked(requestAccountPasswordRecovery).mock.calls[0]?.[1]
  unmount()
  expect(signal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
  await act(async () => {
    if (outcome === 'resolve') pending.resolve(acknowledgement)
    else pending.reject(new Error('private-late-detail'))
    expect(await submission).toBe(false)
    expect(await originalStart(credentials)).toBe(false)
  })
  expect(result.current.status).toBe('loading')
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(1)
})

test('a finished request leaves no timer that could abort its signal later', async () => {
  vi.useFakeTimers()
  vi.mocked(requestAccountPasswordRecovery).mockResolvedValueOnce(acknowledgement)
  const { result } = mountHook()
  await act(async () => { expect(await result.current.start(credentials)).toBe(true) })
  const signal = vi.mocked(requestAccountPasswordRecovery).mock.calls[0]?.[1]
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
  expect(signal?.aborted).toBe(false)
  expect(result.current.status).toBe('accepted')
  expect(vi.getTimerCount()).toBe(0)
})

test('does not start recovery outside development', async () => {
  vi.stubEnv('DEV', false)
  const { result } = mountHook()
  await act(async () => { expect(await result.current.start(credentials)).toBe(false) })
  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
})
