import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { useApiHealth } from './useApiHealth'

const WAKE = 'https://backend.example.test/api/v1/health'
const healthy = () => Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
const asleep = () => new Response('error code: 502', { status: 502 })

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

function stubFetch(health: () => Response | Promise<Response>) {
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url) => {
    if (url === WAKE) return new Response(null)
    if (url === '/api/v1/health') return health()
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

const callsTo = (fetchMock: ReturnType<typeof stubFetch>, url: string) =>
  fetchMock.mock.calls.filter(([requested]) => requested === url)

test('a configured wake request is sent once, without cookies or referrer', async () => {
  vi.stubEnv('VITE_API_WAKE_URL', WAKE)
  const fetchMock = stubFetch(healthy)
  const { result } = renderHook(() => useApiHealth())
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })

  expect(result.current.status).toBe('connected')
  const wakes = callsTo(fetchMock, WAKE)
  expect(wakes).toHaveLength(1)
  expect(wakes[0]?.[1]).toMatchObject({
    mode: 'no-cors',
    credentials: 'omit',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  })
  expect(vi.getTimerCount()).toBe(0)
})

test('a sleeping backend is retried every five seconds until it answers', async () => {
  vi.stubEnv('VITE_API_WAKE_URL', WAKE)
  const answers = [asleep, asleep, healthy]
  const fetchMock = stubFetch(() => (answers.shift() ?? healthy)())
  const { result } = renderHook(() => useApiHealth())

  await act(async () => { await vi.advanceTimersByTimeAsync(4_999) })
  expect(result.current.status).toBe('checking')
  expect(callsTo(fetchMock, '/api/v1/health')).toHaveLength(1)

  await act(async () => { await vi.advanceTimersByTimeAsync(5_001) })
  expect(result.current.status).toBe('connected')
  expect(callsTo(fetchMock, '/api/v1/health')).toHaveLength(3)
  expect(callsTo(fetchMock, WAKE)).toHaveLength(1)
  expect(vi.getTimerCount()).toBe(0)
})

test('network failures are retried while the backend wakes', async () => {
  vi.stubEnv('VITE_API_WAKE_URL', WAKE)
  let failed = false
  stubFetch(() => {
    if (failed) return healthy()
    failed = true
    return Promise.reject(new TypeError('Failed to fetch'))
  })
  const { result } = renderHook(() => useApiHealth())
  await act(async () => { await vi.advanceTimersByTimeAsync(5_000) })
  expect(result.current.status).toBe('connected')
})

test('the existing 75-second deadline still ends the wait', async () => {
  vi.stubEnv('VITE_API_WAKE_URL', WAKE)
  const fetchMock = stubFetch(asleep)
  const { result } = renderHook(() => useApiHealth())

  await act(async () => { await vi.advanceTimersByTimeAsync(74_999) })
  expect(result.current.status).toBe('checking')
  await act(async () => { await vi.advanceTimersByTimeAsync(1) })

  expect(result.current.status).toBe('unavailable')
  // One request at 0 s, then one every 5 s up to 70 s.
  expect(callsTo(fetchMock, '/api/v1/health')).toHaveLength(15)
  expect(fetchMock.mock.calls.every(([, options]) => options?.signal?.aborted)).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
})

test.each([
  ['unexpected body', () => Response.json({ status: 'ok', service: 'wrong-service' })],
  ['missing route', () => new Response(null, { status: 404 })],
  ['server error', () => new Response(null, { status: 500 })],
] as const)('%s fails immediately without retrying', async (_name, health) => {
  vi.stubEnv('VITE_API_WAKE_URL', WAKE)
  const fetchMock = stubFetch(health)
  const { result } = renderHook(() => useApiHealth())
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })

  expect(result.current.status).toBe('unavailable')
  expect(callsTo(fetchMock, '/api/v1/health')).toHaveLength(1)
  expect(vi.getTimerCount()).toBe(0)
})

test.each([
  ['unset', undefined],
  ['invalid', 'http://backend.example.test/api/v1/health'],
] as const)('%s wake URL keeps the previous fail-fast behaviour', async (_name, value) => {
  if (value !== undefined) vi.stubEnv('VITE_API_WAKE_URL', value)
  const fetchMock = stubFetch(asleep)
  const { result } = renderHook(() => useApiHealth())
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })

  expect(result.current.status).toBe('unavailable')
  expect(fetchMock.mock.calls.map(([url]) => url)).toEqual(['/api/v1/health'])
  expect(vi.getTimerCount()).toBe(0)
})

test('try again sends a fresh wake request', async () => {
  vi.stubEnv('VITE_API_WAKE_URL', WAKE)
  let ready = false
  const fetchMock = stubFetch(() => (ready ? healthy() : asleep()))
  const { result } = renderHook(() => useApiHealth())
  await act(async () => { await vi.advanceTimersByTimeAsync(75_000) })
  expect(result.current.status).toBe('unavailable')

  ready = true
  await act(async () => {
    result.current.retry()
    await vi.advanceTimersByTimeAsync(0)
  })
  expect(result.current.status).toBe('connected')
  expect(callsTo(fetchMock, WAKE)).toHaveLength(2)
  expect(vi.getTimerCount()).toBe(0)
})

test('unmounting cancels the wake request and pending retries', async () => {
  vi.stubEnv('VITE_API_WAKE_URL', WAKE)
  const fetchMock = stubFetch(asleep)
  const view = renderHook(() => useApiHealth())
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })
  expect(vi.getTimerCount()).toBeGreaterThan(0)

  view.unmount()
  expect(vi.getTimerCount()).toBe(0)
  expect(fetchMock.mock.calls.every(([, options]) => options?.signal?.aborted)).toBe(true)
})
