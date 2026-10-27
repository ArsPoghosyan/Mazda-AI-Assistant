import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { signOutAccount } from '../api/account'
import { useAccountSignOut } from './useAccountSignOut'

vi.mock('../api/account', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/account')>()

  return {
    ...actual,
    signOutAccount: vi.fn(),
  }
})

function deferredSignOut() {
  let resolve!: () => void

  const promise = new Promise<void>((complete) => {
    resolve = () => complete()
  })

  return { promise, resolve }
}

function mountSignOut() {
  return renderHook(useAccountSignOut, {
    wrapper: StrictMode,
  })
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(signOutAccount).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test('mounting does not automatically sign out', () => {
  const { result } = mountSignOut()

  expect(result.current.enabled).toBe(true)
  expect(result.current.status).toBe('idle')
  expect(result.current.message).toBe('')
  expect(signOutAccount).not.toHaveBeenCalled()
})

test('blocks overlapping requests and remains reusable after success', async () => {
  const pending = deferredSignOut()
  vi.mocked(signOutAccount).mockReturnValueOnce(pending.promise)

  const { result } = mountSignOut()

  let submission!: Promise<boolean>
  let duplicate!: Promise<boolean>

  act(() => {
    submission = result.current.start()
    duplicate = result.current.start()
  })

  expect(result.current.status).toBe('loading')
  expect(signOutAccount).toHaveBeenCalledTimes(1)
  expect(
    vi.mocked(signOutAccount).mock.calls[0]?.[0],
  ).toBeInstanceOf(AbortSignal)

  await act(async () => {
    expect(await duplicate).toBe(false)
    pending.resolve()
    expect(await submission).toBe(true)
  })

  expect(result.current.status).toBe('ready')
  expect(result.current.message).toBe('Signed out.')

  // A later sign-in/sign-out cycle can reuse this controller.
  vi.mocked(signOutAccount).mockResolvedValueOnce(undefined)

  await act(async () => {
    expect(await result.current.start()).toBe(true)
  })

  expect(signOutAccount).toHaveBeenCalledTimes(2)
})

test('failure uses a safe message and retries only when requested', async () => {
  vi.mocked(signOutAccount).mockRejectedValueOnce(
    new Error('private-provider-detail'),
  )

  const { result, rerender } = mountSignOut()

  await act(async () => {
    expect(await result.current.start()).toBe(false)
  })

  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(
    'Sign-out could not be completed. Please try again.',
  )
  expect(result.current.message).not.toContain('private-provider-detail')

  rerender()
  expect(signOutAccount).toHaveBeenCalledTimes(1)

  vi.mocked(signOutAccount).mockResolvedValueOnce(undefined)

  await act(async () => {
    expect(await result.current.start()).toBe(true)
  })

  expect(result.current.status).toBe('ready')
  expect(signOutAccount).toHaveBeenCalledTimes(2)
})

test('aborts a stalled request after 15 seconds', async () => {
  vi.useFakeTimers()

  vi.mocked(signOutAccount).mockImplementation(
    (signal) =>
      new Promise<void>((_resolve, reject) => {
        signal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true },
        )
      }),
  )

  const { result } = mountSignOut()
  let submission!: Promise<boolean>

  act(() => {
    submission = result.current.start()
  })

  const signal = vi.mocked(signOutAccount).mock.calls[0]?.[0]

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
    'Sign-out took too long. Please try again.',
  )
  expect(signOutAccount).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
})

test('a late successful response after the deadline cannot confirm sign-out', async () => {
  vi.useFakeTimers()

  const pending = deferredSignOut()
  vi.mocked(signOutAccount).mockReturnValueOnce(pending.promise)

  const { result } = mountSignOut()
  let submission!: Promise<boolean>

  act(() => {
    submission = result.current.start()
  })

  await act(async () => {
    await vi.advanceTimersByTimeAsync(15_000)
    pending.resolve()
    expect(await submission).toBe(false)
  })

  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(
    'Sign-out took too long. Please try again.',
  )
  expect(vi.getTimerCount()).toBe(0)
})

test('unmount aborts the request and ignores its late result', async () => {
  vi.useFakeTimers()

  const pending = deferredSignOut()
  vi.mocked(signOutAccount).mockReturnValueOnce(pending.promise)

  const { result, unmount } = mountSignOut()
  let submission!: Promise<boolean>

  act(() => {
    submission = result.current.start()
  })

  const signal = vi.mocked(signOutAccount).mock.calls[0]?.[0]

  unmount()

  expect(signal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)

  await act(async () => {
    pending.resolve()
    expect(await submission).toBe(false)
  })

  expect(result.current.status).toBe('loading')
  expect(signOutAccount).toHaveBeenCalledTimes(1)
})

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production flag %s cannot sign out', async (flag) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', flag)

  const { result } = mountSignOut()

  await act(async () => {
    expect(await result.current.start()).toBe(false)
  })

  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('idle')
  expect(signOutAccount).not.toHaveBeenCalled()
})
