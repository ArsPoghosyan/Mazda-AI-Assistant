import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountEmailConfirmationRejectedError,
  confirmAccountEmail,
  type AccountEmailConfirmationResponse,
} from '../api/account-registration'
import { useAccountEmailConfirmation } from './useAccountEmailConfirmation'

vi.mock('../api/account-registration', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../api/account-registration')>()

  return {
    ...actual,
    confirmAccountEmail: vi.fn(),
  }
})

const credentials = {
  email: 'owner@example.test',
  code: '00001234',
}

const confirmation: AccountEmailConfirmationResponse = {
  status: 'confirmed',
}

function deferredConfirmation() {
  let resolve!: (value: AccountEmailConfirmationResponse) => void

  const promise = new Promise<AccountEmailConfirmationResponse>((complete) => {
    resolve = complete
  })

  return { promise, resolve }
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(confirmAccountEmail).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test('mounting does not submit a confirmation code', () => {
  const { result } = renderHook(useAccountEmailConfirmation, {
    wrapper: StrictMode,
  })

  expect(result.current.enabled).toBe(true)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(confirmAccountEmail).not.toHaveBeenCalled()
})

test('blocks duplicates while pending and after confirmation', async () => {
  const pending = deferredConfirmation()
  vi.mocked(confirmAccountEmail).mockReturnValue(pending.promise)

  const { result } = renderHook(useAccountEmailConfirmation, {
    wrapper: StrictMode,
  })

  const originalStart = result.current.start
  let submission!: Promise<boolean>
  let duplicate!: Promise<boolean>

  act(() => {
    submission = originalStart(credentials)
    duplicate = originalStart(credentials)
  })

  expect(result.current.status).toBe('loading')
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)

  const call = vi.mocked(confirmAccountEmail).mock.calls[0]

  expect(call?.[0]).toEqual(credentials)
  expect(call?.[0].code).toBe('00001234')
  expect(call?.[1]).toBeInstanceOf(AbortSignal)

  await act(async () => {
    expect(await duplicate).toBe(false)
    pending.resolve(confirmation)
    expect(await submission).toBe(true)
  })

  expect(result.current.status).toBe('confirmed')
  expect(result.current.message).toBe(
    'Email confirmed. You can now sign in.',
  )

  await act(async () => {
    expect(await originalStart(credentials)).toBe(false)
    expect(await result.current.start(credentials)).toBe(false)
  })

  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)
})

test.each([
  {
    name: 'rejected code',
    error: new AccountEmailConfirmationRejectedError(),
    message:
      'Email confirmation was rejected. Check your email and code, then try again.',
  },
  {
    name: 'unexpected failure',
    error: new Error('private-provider-detail'),
    message: 'Email confirmation could not be completed. Please try again.',
  },
])('handles $name without automatically retrying', async ({ error, message }) => {
  vi.mocked(confirmAccountEmail).mockRejectedValueOnce(error)

  const { result } = renderHook(useAccountEmailConfirmation, {
    wrapper: StrictMode,
  })

  await act(async () => {
    expect(await result.current.start(credentials)).toBe(false)
  })

  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(message)
  expect(result.current.message).not.toContain('private-provider-detail')
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)

  vi.mocked(confirmAccountEmail).mockResolvedValueOnce(confirmation)

  const correctedCredentials = {
    ...credentials,
    code: '00005678',
  }

  await act(async () => {
    expect(await result.current.start(correctedCredentials)).toBe(true)
  })

  expect(confirmAccountEmail).toHaveBeenCalledTimes(2)
  expect(vi.mocked(confirmAccountEmail).mock.calls[1]?.[0]).toEqual(
    correctedCredentials,
  )
  expect(result.current.status).toBe('confirmed')
})

test('aborts a stalled confirmation after 15 seconds', async () => {
  vi.useFakeTimers()

  vi.mocked(confirmAccountEmail).mockImplementation(
    (_credentials, signal) =>
      new Promise<AccountEmailConfirmationResponse>((_resolve, reject) => {
        signal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true },
        )
      }),
  )

  const { result } = renderHook(useAccountEmailConfirmation, {
    wrapper: StrictMode,
  })

  let submission!: Promise<boolean>

  act(() => {
    submission = result.current.start(credentials)
  })

  const signal = vi.mocked(confirmAccountEmail).mock.calls[0]?.[1]

  await act(async () => {
    await vi.advanceTimersByTimeAsync(14_999)
  })

  expect(signal?.aborted).toBe(false)
  expect(result.current.status).toBe('loading')

  await act(async () => {
    await vi.advanceTimersByTimeAsync(1)
    expect(await submission).toBe(false)
  })

  expect(signal?.aborted).toBe(true)
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(
    'Email confirmation took too long. Please try again.',
  )
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
})

test('does not accept a late response after timeout', async () => {
  vi.useFakeTimers()

  // Deliberately simulate a transport that resolves despite cancellation.
  const pending = deferredConfirmation()
  vi.mocked(confirmAccountEmail).mockReturnValue(pending.promise)

  const { result } = renderHook(useAccountEmailConfirmation, {
    wrapper: StrictMode,
  })

  let submission!: Promise<boolean>

  act(() => {
    submission = result.current.start(credentials)
  })

  const signal = vi.mocked(confirmAccountEmail).mock.calls[0]?.[1]

  await act(async () => {
    await vi.advanceTimersByTimeAsync(15_000)
  })

  expect(signal?.aborted).toBe(true)

  await act(async () => {
    pending.resolve(confirmation)
    expect(await submission).toBe(false)
  })

  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(
    'Email confirmation took too long. Please try again.',
  )
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
})

test('unmount aborts the request and ignores its late result', async () => {
  vi.useFakeTimers()

  const pending = deferredConfirmation()
  vi.mocked(confirmAccountEmail).mockReturnValue(pending.promise)

  const { result, unmount } = renderHook(useAccountEmailConfirmation, {
    wrapper: StrictMode,
  })

  let submission!: Promise<boolean>

  act(() => {
    submission = result.current.start(credentials)
  })

  const signal = vi.mocked(confirmAccountEmail).mock.calls[0]?.[1]

  unmount()

  expect(signal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)

  await act(async () => {
    pending.resolve(confirmation)
    expect(await submission).toBe(false)
  })

  expect(result.current.status).toBe('loading')
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)
})

test('does not submit outside development', async () => {
  vi.stubEnv('DEV', false)

  const { result } = renderHook(useAccountEmailConfirmation, {
    wrapper: StrictMode,
  })

  await act(async () => {
    expect(await result.current.start(credentials)).toBe(false)
  })

  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('idle')
  expect(confirmAccountEmail).not.toHaveBeenCalled()
})