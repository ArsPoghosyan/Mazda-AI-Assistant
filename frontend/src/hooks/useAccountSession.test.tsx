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

  return {
    ...actual,
    checkAccountSession: vi.fn(),
  }
})

const session: AccountSessionResponse = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

function deferredSession() {
  let resolve!: (value: AccountSessionResponse | null) => void

  const promise = new Promise<AccountSessionResponse | null>((complete) => {
    resolve = complete
  })

  return { promise, resolve }
}

async function mountSession() {
  const view = renderHook(useAccountSession, {
    wrapper: StrictMode,
  })

  await act(async () => {
    await Promise.resolve()
  })

  return view
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(checkAccountSession).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test('restores once under StrictMode and blocks overlapping refreshes', async () => {
  const pending = deferredSession()
  vi.mocked(checkAccountSession).mockReturnValue(pending.promise)

  const { result, rerender } = await mountSession()

  expect(result.current.status).toBe('checking')
  expect(result.current.session).toBeNull()
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
  expect(
    vi.mocked(checkAccountSession).mock.calls[0]?.[0],
  ).toBeInstanceOf(AbortSignal)

  act(() => {
    result.current.refresh()
    result.current.acceptSignIn(session)
    result.current.acceptSignOut()
  })

  expect(result.current.status).toBe('checking')
  expect(checkAccountSession).toHaveBeenCalledTimes(1)

  await act(async () => {
    pending.resolve(session)
    await pending.promise
  })

  expect(result.current.status).toBe('signed_in')
  expect(result.current.session).toEqual(session)
  expect(result.current.message).toBe(
    'Signed in. Chat is still in development.',
  )

  rerender()
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})

test('a missing or rejected session produces signed_out', async () => {
  vi.mocked(checkAccountSession).mockResolvedValue(null)

  const { result } = await mountSession()

  expect(result.current.status).toBe('signed_out')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe('')
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})

test('failure remains unavailable until an explicit successful retry', async () => {
  const pending = deferredSession()

  vi.mocked(checkAccountSession)
    .mockRejectedValueOnce(new Error('private-provider-detail'))
    .mockReturnValueOnce(pending.promise)

  const { result, rerender } = await mountSession()

  expect(result.current.status).toBe('unavailable')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe(
    'Account session could not be checked. Please try again.',
  )
  expect(result.current.message).not.toContain('private-provider-detail')

  rerender()
  expect(checkAccountSession).toHaveBeenCalledTimes(1)

  await act(async () => {
    result.current.refresh()
  })

  expect(result.current.status).toBe('checking')
  expect(checkAccountSession).toHaveBeenCalledTimes(2)

  act(() => {
    result.current.refresh()
  })

  expect(checkAccountSession).toHaveBeenCalledTimes(2)

  await act(async () => {
    pending.resolve(session)
    await pending.promise
  })

  expect(result.current.status).toBe('signed_in')
  expect(result.current.session).toEqual(session)
})

test('a stalled check times out after 15 seconds without retrying', async () => {
  vi.useFakeTimers()

  vi.mocked(checkAccountSession).mockImplementation(
    (signal) =>
      new Promise<AccountSessionResponse | null>((_resolve, reject) => {
        signal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true },
        )
      }),
  )

  const { result } = await mountSession()
  const signal = vi.mocked(checkAccountSession).mock.calls[0]?.[0]

  await act(async () => {
    await vi.advanceTimersByTimeAsync(14_999)
  })

  expect(result.current.status).toBe('checking')
  expect(signal?.aborted).toBe(false)

  await act(async () => {
    await vi.advanceTimersByTimeAsync(1)
  })

  expect(signal?.aborted).toBe(true)
  expect(result.current.status).toBe('unavailable')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe(
    'Account session check took too long. Please try again.',
  )
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
})

test('unmount aborts the check and ignores a late successful response', async () => {
  vi.useFakeTimers()

  const pending = deferredSession()
  vi.mocked(checkAccountSession).mockReturnValue(pending.promise)

  const { result, unmount } = await mountSession()
  const signal = vi.mocked(checkAccountSession).mock.calls[0]?.[0]

  unmount()

  expect(signal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)

  await act(async () => {
    pending.resolve(session)
    await pending.promise
  })

  expect(result.current.status).toBe('checking')
  expect(result.current.session).toBeNull()
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})

test('unmount before the initial microtask prevents any request', async () => {
  vi.mocked(checkAccountSession).mockResolvedValue(session)

  const { unmount } = renderHook(useAccountSession, {
    wrapper: StrictMode,
  })

  unmount()

  await act(async () => {
    await Promise.resolve()
  })

  expect(checkAccountSession).not.toHaveBeenCalled()
})

test('a new mount checks again rather than reusing an old identity', async () => {
  vi.mocked(checkAccountSession)
    .mockResolvedValueOnce(session)
    .mockResolvedValueOnce(null)

  const first = await mountSession()

  expect(first.result.current.status).toBe('signed_in')
  first.unmount()

  const second = await mountSession()

  expect(second.result.current.status).toBe('signed_out')
  expect(second.result.current.session).toBeNull()
  expect(checkAccountSession).toHaveBeenCalledTimes(2)
})

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production flag %s cannot restore or refresh a session', async (flag) => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', flag)

  const { result } = await mountSession()

  act(() => {
    result.current.refresh()
    result.current.acceptSignIn(session)
  })

  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('disabled')
  expect(result.current.session).toBeNull()
  expect(checkAccountSession).not.toHaveBeenCalled()
})

test('accepts successful sign-in metadata without another session request', async () => {
  vi.mocked(checkAccountSession).mockResolvedValue(null)
  const { result } = await mountSession()

  act(() => {
    result.current.acceptSignIn(session)
  })

  expect(result.current.status).toBe('signed_in')
  expect(result.current.session).toEqual(session)
  expect(result.current.message).toBe('Signed in. Chat is still in development.')
  expect(checkAccountSession).toHaveBeenCalledTimes(1)
})

test('confirmed sign-out clears account metadata without another request', async () => {
  vi.mocked(checkAccountSession).mockResolvedValue(session)
  const { result } = await mountSession()

  act(() => {
    result.current.acceptSignOut()
  })

  expect(result.current.status).toBe('signed_out')
  expect(result.current.session).toBeNull()
  expect(result.current.message).toBe('Signed out.')
  expect(checkAccountSession).toHaveBeenCalledTimes(1)

  act(() => {
    result.current.acceptSignIn(session)
  })

  expect(result.current.status).toBe('signed_in')
  expect(result.current.session).toEqual(session)
})
