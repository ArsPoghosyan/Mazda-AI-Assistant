import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountSignInRateLimitedError,
  AccountSignInRejectedError,
  AccountSignOutRequiredError,
  AccountVerificationRequiredError,
  signInAccount,
  type AccountSessionResponse,
} from '../api/account'
import { useAccountSignIn } from './useAccountSignIn'

vi.mock('../api/account', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/account')>()

  return {
    ...actual,
    signInAccount: vi.fn(),
  }
})

const credentials = {
  email: 'owner@example.test',
  password: 'synthetic-password',
  captcha_token: 'synthetic-proof',
}

const session: AccountSessionResponse = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

function deferredSession() {
  let resolve!: (value: AccountSessionResponse) => void

  const promise = new Promise<AccountSessionResponse>((complete) => {
    resolve = complete
  })

  return { promise, resolve }
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(signInAccount).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test('mounting does not submit credentials', () => {
  const { result } = renderHook(useAccountSignIn, {
    wrapper: StrictMode,
  })

  expect(result.current.enabled).toBe(true)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(signInAccount).not.toHaveBeenCalled()
})

test('blocks duplicate submissions while pending and after success', async () => {
  const pending = deferredSession()
  vi.mocked(signInAccount).mockReturnValue(pending.promise)

  const { result } = renderHook(useAccountSignIn, {
    wrapper: StrictMode,
  })

  let submission!: Promise<AccountSessionResponse | null>
  let duplicate!: Promise<AccountSessionResponse | null>

  act(() => {
    submission = result.current.start(credentials)
    duplicate = result.current.start(credentials)
  })

  expect(result.current.status).toBe('loading')
  expect(signInAccount).toHaveBeenCalledTimes(1)

  const call = vi.mocked(signInAccount).mock.calls[0]

  expect(call?.[0]).toEqual(credentials)
  expect(call?.[1]).toBeInstanceOf(AbortSignal)

  await act(async () => {
    expect(await duplicate).toBeNull()
    pending.resolve(session)
    expect(await submission).toEqual(session)
  })

  expect(result.current.status).toBe('ready')
  expect(result.current.message).toBe(
    'Signed in. Chat is still in development.',
  )

  await act(async () => {
    expect(await result.current.start(credentials)).toBeNull()
  })

  expect(signInAccount).toHaveBeenCalledTimes(1)
})

test.each([
  {
    name: 'rate limit with retry time',
    error: new AccountSignInRateLimitedError('61'),
    message: 'Too many sign-in attempts. Please wait 61 seconds before trying again.',
  },
  {
    name: 'one-second rate limit',
    error: new AccountSignInRateLimitedError('1'),
    message: 'Too many sign-in attempts. Please wait 1 second before trying again.',
  },
  {
    name: 'rate limit without retry time',
    error: new AccountSignInRateLimitedError(),
    message: 'Too many sign-in attempts. Please try again later.',
  },
  {
    name: 'rate limit with untrusted retry time',
    error: new AccountSignInRateLimitedError('private-provider-detail'),
    message: 'Too many sign-in attempts. Please try again later.',
  },
  {
    name: 'rejected credentials',
    error: new AccountSignInRejectedError(),
    message: 'Sign-in was rejected. Check your details and try again.',
  },
  {
    name: 'existing account session',
    error: new AccountSignOutRequiredError(),
    message: 'Sign out before starting another account login.',
  },
  {
    name: 'rejected verification',
    error: new AccountVerificationRequiredError(),
    message: 'Verification was not accepted. Complete a new check.',
  },
  {
    name: 'unexpected failure',
    error: new Error('private-provider-detail'),
    message: 'Sign-in could not be completed. Please try again.',
  },
])('handles $name without automatically retrying', async ({ error, message }) => {
  vi.mocked(signInAccount).mockRejectedValueOnce(error)

  const { result } = renderHook(useAccountSignIn, {
    wrapper: StrictMode,
  })

  await act(async () => {
    expect(await result.current.start(credentials)).toBeNull()
  })

  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(message)
  expect(result.current.message).not.toContain('private-provider-detail')
  expect(signInAccount).toHaveBeenCalledTimes(1)

  vi.mocked(signInAccount).mockResolvedValueOnce(session)

  const freshCredentials = {
    ...credentials,
    captcha_token: 'fresh-synthetic-proof',
  }

  await act(async () => {
    expect(await result.current.start(freshCredentials)).toEqual(session)
  })

  expect(signInAccount).toHaveBeenCalledTimes(2)
  expect(vi.mocked(signInAccount).mock.calls[1]?.[0]).toEqual(
    freshCredentials,
  )
  expect(result.current.status).toBe('ready')
})

test('aborts a stalled submission after 15 seconds', async () => {
  vi.useFakeTimers()

  vi.mocked(signInAccount).mockImplementation(
    (_credentials, signal) =>
      new Promise<AccountSessionResponse>((_resolve, reject) => {
        signal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true },
        )
      }),
  )

  const { result } = renderHook(useAccountSignIn, {
    wrapper: StrictMode,
  })

  let submission!: Promise<AccountSessionResponse | null>

  act(() => {
    submission = result.current.start(credentials)
  })

  const signal = vi.mocked(signInAccount).mock.calls[0]?.[1]

  await act(async () => {
    await vi.advanceTimersByTimeAsync(14_999)
  })

  expect(signal?.aborted).toBe(false)
  expect(result.current.status).toBe('loading')

  await act(async () => {
    await vi.advanceTimersByTimeAsync(1)
    expect(await submission).toBeNull()
  })

  expect(signal?.aborted).toBe(true)
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(
    'Sign-in took too long. Please try again.',
  )
  expect(signInAccount).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
})

test('a rate-limit wait message never schedules another credential submission', async () => {
  vi.useFakeTimers()
  vi.mocked(signInAccount).mockRejectedValueOnce(new AccountSignInRateLimitedError('61'))
  const { result } = renderHook(useAccountSignIn, { wrapper: StrictMode })

  await act(async () => {
    expect(await result.current.start(credentials)).toBeNull()
  })
  expect(vi.getTimerCount()).toBe(0)

  await act(async () => {
    await vi.advanceTimersByTimeAsync(120_000)
  })
  expect(result.current.message).toBe(
    'Too many sign-in attempts. Please wait 61 seconds before trying again.',
  )
  expect(signInAccount).toHaveBeenCalledTimes(1)
})

test('unmount aborts the request and ignores its late result', async () => {
  vi.useFakeTimers()

  const pending = deferredSession()
  vi.mocked(signInAccount).mockReturnValue(pending.promise)

  const { result, unmount } = renderHook(useAccountSignIn, {
    wrapper: StrictMode,
  })

  let submission!: Promise<AccountSessionResponse | null>

  act(() => {
    submission = result.current.start(credentials)
  })

  const signal = vi.mocked(signInAccount).mock.calls[0]?.[1]

  unmount()

  expect(signal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)

  await act(async () => {
    pending.resolve(session)
    expect(await submission).toBeNull()
  })

  expect(result.current.status).toBe('loading')
  expect(signInAccount).toHaveBeenCalledTimes(1)
})

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production flag %s cannot submit credentials', async (flag) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', flag)

  const { result } = renderHook(useAccountSignIn, {
    wrapper: StrictMode,
  })

  await act(async () => {
    expect(await result.current.start(credentials)).toBeNull()
  })

  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('idle')
  expect(signInAccount).not.toHaveBeenCalled()
})
