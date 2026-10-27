import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  GoogleSignInRateLimitedError,
  startGoogleSignIn,
  type GoogleLoginStartResponse,
} from '../api/google'
import { useGoogleSignIn } from './useGoogleSignIn'

vi.mock('../api/google', async (importOriginal) => ({
  ...await importOriginal<typeof import('../api/google')>(), startGoogleSignIn: vi.fn(),
}))

const ISSUER = 'https://auth.example.test/auth/v1'
const DESTINATION = `${ISSUER}/authorize?${new URLSearchParams({
  provider: 'google',
  redirect_to: `${window.location.origin}/api/v1/account/google/callback`,
  code_challenge: 'a'.repeat(43),
  code_challenge_method: 's256',
})}`
const FAILURE = 'Google sign-in could not be started. Please try again.'

function validStart(): GoogleLoginStartResponse {
  return {
    authorization_url: DESTINATION,
    expires_at: new Date(Date.now() + 600_000).toISOString(),
  }
}

function deferredStart() {
  let resolve!: (value: GoogleLoginStartResponse) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<GoogleLoginStartResponse>((complete, fail) => {
    resolve = complete
    reject = fail
  })
  return { promise, resolve, reject }
}

function mountHook() {
  const navigate = vi.fn<(destination: string) => void>()
  const view = renderHook(() => useGoogleSignIn(navigate), {
    wrapper: StrictMode,
  })
  return { ...view, navigate }
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'false')
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'true')
  vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', ISSUER)
  vi.mocked(startGoogleSignIn).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test('mounting in StrictMode does not start login or navigate', () => {
  const { result, navigate } = mountHook()
  expect(result.current.enabled).toBe(true)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  expect(navigate).not.toHaveBeenCalled()
})

test('blocks immediate duplicate clicks, waits for validation and blocks after navigation', async () => {
  vi.useFakeTimers()
  const pending = deferredStart()
  vi.mocked(startGoogleSignIn).mockReturnValue(pending.promise)
  const { result, navigate } = mountHook()
  let submission!: Promise<void>
  let duplicate!: Promise<void>

  act(() => {
    submission = result.current.start()
    duplicate = result.current.start()
  })

  expect(result.current.status).toBe('loading')
  expect(result.current.message).toBe('Opening Google sign-in…')
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(startGoogleSignIn).toHaveBeenCalledWith(
    ISSUER,
    `${window.location.origin}/api/v1/account/google/callback`,
    expect.any(AbortSignal),
  )
  expect(navigate).not.toHaveBeenCalled()

  await act(async () => {
    await duplicate
    pending.resolve(validStart())
    await submission
  })

  expect(result.current.status).toBe('redirecting')
  expect(result.current.message).toBe('Redirecting to Google…')
  expect(navigate).toHaveBeenCalledExactlyOnceWith(DESTINATION)
  expect(vi.getTimerCount()).toBe(0)
  await act(async () => { await result.current.start() })
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
})

test.each([undefined, 'false', 'TRUE', '1'])('does not start with flag %s', async (flag) => {
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', flag)
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('idle')
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  expect(navigate).not.toHaveBeenCalled()
})

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production account flag %s blocks Google even with its flag on', async (flag) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', flag)
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.enabled).toBe(false)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  expect(navigate).not.toHaveBeenCalled()
})

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production Google flag %s stays closed with account controls enabled', async (flag) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', flag)
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.enabled).toBe(false)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  expect(navigate).not.toHaveBeenCalled()
})

test('production opt-in starts once with the same-origin callback and a validated result', async () => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  const pending = deferredStart()
  vi.mocked(startGoogleSignIn).mockReturnValue(pending.promise)
  const { result, navigate } = mountHook()
  expect(result.current.enabled).toBe(true)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  let first!: Promise<void>
  let duplicate!: Promise<void>
  act(() => {
    first = result.current.start()
    duplicate = result.current.start()
  })
  expect(startGoogleSignIn).toHaveBeenCalledExactlyOnceWith(
    ISSUER, `${window.location.origin}/api/v1/account/google/callback`, expect.any(AbortSignal),
  )
  expect(navigate).not.toHaveBeenCalled()
  await act(async () => {
    await duplicate
    pending.resolve(validStart())
    await first
  })
  expect(navigate).toHaveBeenCalledExactlyOnceWith(DESTINATION)
  await act(async () => { await result.current.start() })
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
})

test.each([undefined, '', 'http://auth.example.test/auth/v1', `${ISSUER}?next=untrusted`])('production rejects an absent or invalid issuer %s', async (issuer) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', issuer)
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.enabled).toBe(false)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  expect(navigate).not.toHaveBeenCalled()
})

test.each([
  undefined, '', 'not-a-url', 'http://auth.example.test/auth/v1',
  'https://user:private@auth.example.test/auth/v1',
  'https://auth.example.test/other', `${ISSUER}?next=untrusted`, `${ISSUER}#fragment`,
])('rejects absent or invalid public issuer %s before a request', async (issuer) => {
  vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', issuer)
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.enabled).toBe(false)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  expect(navigate).not.toHaveBeenCalled()
})

test.each([
  'Please start Google sign-in again.',
  'Sign out before starting another account login.',
  'Google sign-in is temporarily unavailable.',
  FAILURE,
])('shows the approved message without retrying: %s', async (message) => {
  vi.mocked(startGoogleSignIn).mockRejectedValueOnce(new Error(message))
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(message)
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(navigate).not.toHaveBeenCalled()

  vi.mocked(startGoogleSignIn).mockResolvedValueOnce(validStart())
  await act(async () => { await result.current.start() })
  expect(startGoogleSignIn).toHaveBeenCalledTimes(2)
  expect(navigate).toHaveBeenCalledExactlyOnceWith(DESTINATION)
})

test.each([new Error('private-provider-detail'), 'private-provider-detail']) (
  'masks unrecognized failure details', async (error) => {
    vi.mocked(startGoogleSignIn).mockRejectedValueOnce(error)
    const { result, navigate } = mountHook()
    await act(async () => { await result.current.start() })
    expect(result.current.status).toBe('error')
    expect(result.current.message).toBe(FAILURE)
    expect(navigate).not.toHaveBeenCalled()
  },
)

test.each([
  ['1', 'Too many Google sign-in attempts. Please wait 1 second before trying again.'],
  ['61', 'Too many Google sign-in attempts. Please wait 61 seconds before trying again.'],
  ['86400', 'Too many Google sign-in attempts. Please wait 86400 seconds before trying again.'],
  [null, 'Too many Google sign-in attempts. Please try again later.'],
  ['0', 'Too many Google sign-in attempts. Please try again later.'],
  ['private-provider-detail', 'Too many Google sign-in attempts. Please try again later.'],
] as const)('rate limit %s stays on the page until an explicit retry', async (header, message) => {
  vi.useFakeTimers()
  vi.mocked(startGoogleSignIn).mockRejectedValueOnce(new GoogleSignInRateLimitedError(header))
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(message)
  expect(navigate).not.toHaveBeenCalled()
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)

  await act(async () => { await vi.advanceTimersByTimeAsync(86_401_000) })
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(navigate).not.toHaveBeenCalled()
  expect(result.current.message).toBe(message)

  vi.mocked(startGoogleSignIn).mockResolvedValueOnce(validStart())
  await act(async () => { await result.current.start() })
  expect(startGoogleSignIn).toHaveBeenCalledTimes(2)
  expect(result.current.status).toBe('redirecting')
  expect(navigate).toHaveBeenCalledExactlyOnceWith(DESTINATION)
  expect(vi.getTimerCount()).toBe(0)
})

test('ordinary errors cannot impersonate typed rate-limit guidance', async () => {
  vi.mocked(startGoogleSignIn).mockRejectedValueOnce(new Error(
    'Too many Google sign-in attempts. Please wait 61 seconds before trying again.',
  ))
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.message).toBe(FAILURE)
  expect(navigate).not.toHaveBeenCalled()
})

test('timeout feedback wins over a late rate-limit rejection', async () => {
  vi.useFakeTimers()
  const pending = deferredStart()
  vi.mocked(startGoogleSignIn).mockReturnValue(pending.promise)
  const { result, navigate } = mountHook()
  let submission!: Promise<void>
  act(() => { submission = result.current.start() })
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000) })
  await act(async () => {
    pending.reject(new GoogleSignInRateLimitedError('61'))
    await submission
  })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe('Google sign-in took too long. Please try again.')
  expect(navigate).not.toHaveBeenCalled()
  expect(vi.getTimerCount()).toBe(0)
})

test('unmount ignores a late rate-limit response', async () => {
  vi.useFakeTimers()
  const pending = deferredStart()
  vi.mocked(startGoogleSignIn).mockReturnValue(pending.promise)
  const { result, unmount, navigate } = mountHook()
  let submission!: Promise<void>
  act(() => { submission = result.current.start() })
  const signal = vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]
  unmount()
  expect(signal?.aborted).toBe(true)
  await act(async () => {
    pending.reject(new GoogleSignInRateLimitedError('61'))
    await submission
  })
  expect(navigate).not.toHaveBeenCalled()
  expect(vi.getTimerCount()).toBe(0)
})

test('aborts a stalled request at 15 seconds and clears its timer', async () => {
  vi.useFakeTimers()
  vi.mocked(startGoogleSignIn).mockImplementation(
    (_issuer, _callback, signal) => new Promise((_resolve, reject) => {
      signal?.addEventListener('abort', () => {
        reject(new DOMException('Aborted', 'AbortError'))
      }, { once: true })
    }),
  )
  const { result, navigate } = mountHook()
  let submission!: Promise<void>
  act(() => { submission = result.current.start() })
  const signal = vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]

  await act(async () => { await vi.advanceTimersByTimeAsync(14_999) })
  expect(signal?.aborted).toBe(false)
  expect(result.current.status).toBe('loading')

  await act(async () => {
    await vi.advanceTimersByTimeAsync(1)
    await submission
  })
  expect(signal?.aborted).toBe(true)
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe('Google sign-in took too long. Please try again.')
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(navigate).not.toHaveBeenCalled()
  expect(vi.getTimerCount()).toBe(0)
})

test('never navigates when an aborted request resolves late', async () => {
  vi.useFakeTimers()
  const pending = deferredStart()
  vi.mocked(startGoogleSignIn).mockReturnValue(pending.promise)
  const { result, navigate } = mountHook()
  let submission!: Promise<void>
  act(() => { submission = result.current.start() })

  await act(async () => { await vi.advanceTimersByTimeAsync(15_000) })
  expect(vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]?.aborted).toBe(true)
  await act(async () => {
    pending.resolve(validStart())
    await submission
  })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe('Google sign-in took too long. Please try again.')
  expect(navigate).not.toHaveBeenCalled()
  expect(vi.getTimerCount()).toBe(0)
})

test.each(['resolve', 'reject'] as const)('unmount cancels and ignores a late %s', async (outcome) => {
  vi.useFakeTimers()
  const pending = deferredStart()
  vi.mocked(startGoogleSignIn).mockReturnValue(pending.promise)
  const { result, unmount, navigate } = mountHook()
  let submission!: Promise<void>
  act(() => { submission = result.current.start() })
  const signal = vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]

  unmount()
  expect(signal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
  await act(async () => {
    if (outcome === 'resolve') pending.resolve(validStart())
    else pending.reject(new Error('private-late-failure'))
    await submission
  })
  expect(navigate).not.toHaveBeenCalled()
})

test('rejects an attempt that expires before navigation', async () => {
  vi.useFakeTimers()
  const pending = deferredStart()
  const response = { ...validStart(), expires_at: new Date(Date.now() + 1_000).toISOString() }
  vi.mocked(startGoogleSignIn).mockReturnValue(pending.promise)
  const { result, navigate } = mountHook()
  let submission!: Promise<void>
  act(() => { submission = result.current.start() })

  await act(async () => {
    await vi.advanceTimersByTimeAsync(1_000)
    pending.resolve(response)
    await submission
  })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(FAILURE)
  expect(navigate).not.toHaveBeenCalled()
  expect(vi.getTimerCount()).toBe(0)
})

test('navigation failure is masked and releases the duplicate-click guard', async () => {
  vi.mocked(startGoogleSignIn).mockResolvedValue(validStart())
  const { result, navigate } = mountHook()
  navigate.mockImplementationOnce(() => { throw new Error('private-navigation-detail') })
  await act(async () => { await result.current.start() })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(FAILURE)

  await act(async () => { await result.current.start() })
  expect(result.current.status).toBe('redirecting')
  expect(startGoogleSignIn).toHaveBeenCalledTimes(2)
  expect(navigate).toHaveBeenCalledTimes(2)
})

test('back-forward cache restoration releases the navigation latch', async () => {
  vi.mocked(startGoogleSignIn).mockResolvedValue(validStart())
  const { result, navigate } = mountHook()
  await act(async () => { await result.current.start() })
  expect(result.current.status).toBe('redirecting')

  act(() => { window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })) })
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  await act(async () => { await result.current.start() })
  expect(startGoogleSignIn).toHaveBeenCalledTimes(2)
  expect(navigate).toHaveBeenCalledTimes(2)
})

test('an ordinary pageshow event does not release an active navigation latch', async () => {
  vi.mocked(startGoogleSignIn).mockResolvedValue(validStart())
  const { result } = mountHook()
  await act(async () => { await result.current.start() })
  act(() => { window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: false })) })
  await act(async () => { await result.current.start() })
  expect(result.current.status).toBe('redirecting')
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
})

test('restoration cancels old work without allowing it to overwrite a new attempt', async () => {
  vi.useFakeTimers()
  const old = deferredStart()
  const fresh = deferredStart()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(old.promise).mockReturnValueOnce(fresh.promise)
  const { result, navigate } = mountHook()
  let first!: Promise<void>
  let second!: Promise<void>
  act(() => { first = result.current.start() })
  const oldSignal = vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]

  act(() => { window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })) })
  expect(oldSignal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
  act(() => { second = result.current.start() })

  await act(async () => {
    old.resolve(validStart())
    await first
  })
  expect(result.current.status).toBe('loading')
  expect(navigate).not.toHaveBeenCalled()
  expect(vi.getTimerCount()).toBe(1)

  await act(async () => {
    fresh.resolve(validStart())
    await second
  })
  expect(navigate).toHaveBeenCalledExactlyOnceWith(DESTINATION)
  expect(vi.getTimerCount()).toBe(0)
})
