import { StrictMode } from 'react'
import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { ensureGuestSession, GuestRateLimitedError } from '../api/guest'
import { useGuestSession } from './useGuestSession'

vi.mock('../api/guest', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/guest')>()
  return { ...actual, ensureGuestSession: vi.fn() }
})

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_GUEST_ACCESS_ENABLED', 'false')
  vi.mocked(ensureGuestSession).mockReset()
})

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production flag %s blocks guest requests and unsolicited proofs', async flag => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_GUEST_ACCESS_ENABLED', flag)
  const { result } = renderHook(useGuestSession, { wrapper: StrictMode })
  await act(async () => { await result.current.start() })
  await act(async () => { await result.current.start('unsolicited-proof') })
  expect(result.current.enabled).toBe(false)
  expect(result.current.status).toBe('idle')
  expect(ensureGuestSession).not.toHaveBeenCalled()
})

test('production guest access works independently of the account switch and only after a click', async () => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_GUEST_ACCESS_ENABLED', 'true')
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'false')
  vi.mocked(ensureGuestSession).mockResolvedValue({ status: 'ok', expires_at: '2030-01-01T12:00:00Z' })
  const { result } = renderHook(useGuestSession, { wrapper: StrictMode })
  expect(result.current.enabled).toBe(true)
  expect(ensureGuestSession).not.toHaveBeenCalled()
  await act(async () => { await result.current.start('unsolicited-proof') })
  expect(ensureGuestSession).not.toHaveBeenCalled()
  await act(async () => { await result.current.start() })
  await act(async () => { await result.current.start() })
  expect(ensureGuestSession).toHaveBeenCalledExactlyOnceWith(expect.any(AbortSignal), undefined)
  expect(result.current.status).toBe('ready')
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllEnvs()
})

test.each([
  ['1', 'Too many guest-access attempts. Please wait 1 second before trying again.'],
  ['61', 'Too many guest-access attempts. Please wait 61 seconds before trying again.'],
  ['86400', 'Too many guest-access attempts. Please wait 86400 seconds before trying again.'],
  [null, 'Too many guest-access attempts. Please try again later.'],
  ['0', 'Too many guest-access attempts. Please try again later.'],
  ['private-provider-detail', 'Too many guest-access attempts. Please try again later.'],
] as const)('shows safe guest retry guidance for %s', async (header, message) => {
  vi.useFakeTimers()
  vi.mocked(ensureGuestSession).mockRejectedValueOnce(new GuestRateLimitedError(header))
  const { result } = renderHook(useGuestSession, { wrapper: StrictMode })
  expect(ensureGuestSession).not.toHaveBeenCalled()
  await act(async () => { await result.current.start() })
  expect(result.current.status).toBe('error')
  expect(result.current.message).toBe(message)
  expect(ensureGuestSession).toHaveBeenCalledExactlyOnceWith(expect.any(AbortSignal), undefined)
  expect(vi.getTimerCount()).toBe(0)
  await act(async () => { await vi.advanceTimersByTimeAsync(86_401_000) })
  expect(ensureGuestSession).toHaveBeenCalledTimes(1)
  expect(result.current.message).toBe(message)
})

test('retries only on a new action and never accepts a proof while rate limited', async () => {
  vi.mocked(ensureGuestSession)
    .mockRejectedValueOnce(new GuestRateLimitedError('61'))
    .mockResolvedValueOnce({ status: 'ok', expires_at: '2030-01-01T12:00:00Z' })
  const { result } = renderHook(useGuestSession, { wrapper: StrictMode })
  await act(async () => { await result.current.start() })
  expect(result.current.status).toBe('error')
  await act(async () => { await result.current.start('stale-proof') })
  expect(ensureGuestSession).toHaveBeenCalledTimes(1)
  await act(async () => { await result.current.start() })
  expect(ensureGuestSession).toHaveBeenCalledTimes(2)
  expect(vi.mocked(ensureGuestSession).mock.calls[1]?.[1]).toBeUndefined()
  expect(result.current.status).toBe('ready')
  expect(result.current.message).toBe('Guest session ready. Chat is still in development.')
})
