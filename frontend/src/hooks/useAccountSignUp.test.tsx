import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountSignUpRateLimitedError,
  AccountSignUpRejectedError,
  AccountSignUpVerificationRequiredError,
  signUpAccount,
  type AccountSignUpResponse,
} from '../api/account-registration'
import { useAccountSignUp } from './useAccountSignUp'

vi.mock('../api/account-registration', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../api/account-registration')>()

  return {
    ...actual,
    signUpAccount: vi.fn(),
  }
})

const credentials = {
  email: 'owner@example.test',
  password: 'synthetic-password',
  captcha_token: 'synthetic-proof',
  accepted: true,
  terms_version: '2026-10-26',
}

const acknowledgement: AccountSignUpResponse = {
  status: 'accepted',
}

function deferredRegistration() {
  let resolve!: (value: AccountSignUpResponse) => void

  const promise = new Promise<AccountSignUpResponse>((complete) => {
    resolve = complete
  })

  return { promise, resolve }
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'false')
  vi.stubEnv('VITE_ACCOUNT_REGISTRATION_ENABLED', 'false')
  vi.mocked(signUpAccount).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test('mounting does not submit registration', () => {
  const { result } = renderHook(useAccountSignUp, {
    wrapper: StrictMode,
  })

  expect(result.current.enabled).toBe(true)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(signUpAccount).not.toHaveBeenCalled()
})

test('blocks duplicate submissions while pending and after acceptance', async () => {
  const pending = deferredRegistration()
  vi.mocked(signUpAccount).mockReturnValue(pending.promise)

  const { result } = renderHook(useAccountSignUp, {
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
  expect(signUpAccount).toHaveBeenCalledTimes(1)

  const call = vi.mocked(signUpAccount).mock.calls[0]

  expect(call?.[0]).toEqual(credentials)
  expect(call?.[1]).toBeInstanceOf(AbortSignal)

  await act(async () => {
    expect(await duplicate).toBe(false)
    pending.resolve(acknowledgement)
    expect(await submission).toBe(true)
  })

  expect(result.current.status).toBe('accepted')
  expect(result.current.message).toBe(
    'If registration can proceed, check your email for a verification code.',
  )

  await act(async () => {
    expect(await originalStart(credentials)).toBe(false)
    expect(await result.current.start(credentials)).toBe(false)
  })

  expect(signUpAccount).toHaveBeenCalledTimes(1)
})

test.each([
  {
    name: 'rate limit with a wait time',
    error: new AccountSignUpRateLimitedError('61'),
    message: 'Too many sign-up attempts. Please wait 61 seconds before trying again.',
  },
  {
    name: 'one-second rate limit',
    error: new AccountSignUpRateLimitedError('1'),
    message: 'Too many sign-up attempts. Please wait 1 second before trying again.',
  },
  {
    name: 'rate limit without a wait time',
    error: new AccountSignUpRateLimitedError(),
    message: 'Too many sign-up attempts. Please try again later.',
  },
  {
    name: 'rate limit with private retry details',
    error: new AccountSignUpRateLimitedError('private-provider-detail'),
    message: 'Too many sign-up attempts. Please try again later.',
  },
  {
    name: 'rejected registration',
    error: new AccountSignUpRejectedError(),
    message: 'Registration was rejected. Check your details and try again.',
  },
  {
    name: 'rejected verification',
    error: new AccountSignUpVerificationRequiredError(),
    message: 'Verification was not accepted. Complete a new check.',
  },
  {
    name: 'unexpected failure',
    error: new Error('private-provider-detail'),
    message: 'Registration could not be completed. Please try again.',
  },
])('handles $name without automatically retrying', async ({ error, message }) => {
  vi.mocked(signUpAccount).mockRejectedValueOnce(error)

  const { result } = renderHook(useAccountSignUp, {
    wrapper: StrictMode,
  })

  await act(async () => {
    expect(await result.current.start(credentials)).toBe(false)
  })

  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(message)
  expect(result.current.message).not.toContain('private-provider-detail')
  expect(signUpAccount).toHaveBeenCalledTimes(1)

  vi.mocked(signUpAccount).mockResolvedValueOnce(acknowledgement)

  const freshCredentials = {
    ...credentials,
    captcha_token: 'fresh-synthetic-proof',
  }

  await act(async () => {
    expect(await result.current.start(freshCredentials)).toBe(true)
  })

  expect(signUpAccount).toHaveBeenCalledTimes(2)
  expect(vi.mocked(signUpAccount).mock.calls[1]?.[0]).toEqual(
    freshCredentials,
  )
  expect(result.current.status).toBe('accepted')
})

test('aborts a stalled submission after 15 seconds', async () => {
  vi.useFakeTimers()

  vi.mocked(signUpAccount).mockImplementation(
    (_credentials, signal) =>
      new Promise<AccountSignUpResponse>((_resolve, reject) => {
        signal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true },
        )
      }),
  )

  const { result } = renderHook(useAccountSignUp, {
    wrapper: StrictMode,
  })

  let submission!: Promise<boolean>

  act(() => {
    submission = result.current.start(credentials)
  })

  const signal = vi.mocked(signUpAccount).mock.calls[0]?.[1]

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
    'Registration took too long. Please try again.',
  )
  expect(signUpAccount).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
})

test('a rate-limit response never schedules another registration', async () => {
  vi.useFakeTimers()
  vi.mocked(signUpAccount).mockRejectedValueOnce(new AccountSignUpRateLimitedError('61'))
  const { result } = renderHook(useAccountSignUp, { wrapper: StrictMode })

  await act(async () => {
    expect(await result.current.start(credentials)).toBe(false)
  })
  expect(vi.getTimerCount()).toBe(0)

  await act(async () => {
    await vi.advanceTimersByTimeAsync(120_000)
  })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(
    'Too many sign-up attempts. Please wait 61 seconds before trying again.',
  )
  expect(signUpAccount).toHaveBeenCalledTimes(1)
})

test('unmount aborts the request and ignores its late result', async () => {
  vi.useFakeTimers()

  const pending = deferredRegistration()
  vi.mocked(signUpAccount).mockReturnValue(pending.promise)

  const { result, unmount } = renderHook(useAccountSignUp, {
    wrapper: StrictMode,
  })

  let submission!: Promise<boolean>

  act(() => {
    submission = result.current.start(credentials)
  })

  const signal = vi.mocked(signUpAccount).mock.calls[0]?.[1]

  unmount()

  expect(signal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)

  await act(async () => {
    pending.resolve(acknowledgement)
    expect(await submission).toBe(false)
  })

  expect(result.current.status).toBe('loading')
  expect(signUpAccount).toHaveBeenCalledTimes(1)
})

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production registration flag %s blocks sign-up', async (flag) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  vi.stubEnv('VITE_ACCOUNT_REGISTRATION_ENABLED', flag)

  const { result } = renderHook(useAccountSignUp, {
    wrapper: StrictMode,
  })

  await act(async () => {
    expect(await result.current.start(credentials)).toBe(false)
  })

  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('idle')
  expect(signUpAccount).not.toHaveBeenCalled()
})

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('registration cannot bypass production account flag %s', async (flag) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', flag)
  vi.stubEnv('VITE_ACCOUNT_REGISTRATION_ENABLED', 'true')
  const { result } = renderHook(useAccountSignUp, { wrapper: StrictMode })
  await act(async () => { expect(await result.current.start(credentials)).toBe(false) })
  expect(result.current.enabled).toBe(false)
  expect(signUpAccount).not.toHaveBeenCalled()
})
