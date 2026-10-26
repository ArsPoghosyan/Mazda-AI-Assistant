import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import App from './App'

const health = () => Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
const session = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

function deferredResponse() {
  let resolve!: (value: Response) => void
  const promise = new Promise<Response>((complete) => { resolve = complete })
  return { promise, resolve }
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.stubEnv('DEV', true)
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  window.history.replaceState(null, '', '/')
})

function renderApp() {
  return render(<StrictMode><App /></StrictMode>)
}

test('a minute-long cold start precedes the full session deadline and preserves Google return handling', async () => {
  const waking = deferredResponse()
  const restoring = deferredResponse()
  window.history.replaceState(null, '', '/#google-sign-in=success')
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url) => {
    if (url === '/api/v1/health') return (await waking.promise).clone()
    if (url === '/api/v1/account/session') return restoring.promise
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  renderApp()

  expect(screen.getByText('Starting the service… This may take about a minute.')).toBeTruthy()
  const guest = screen.getByRole('button', { name: 'Try as Guest' })
  const account = screen.getByRole('button', { name: 'Waiting for service…' })
  expect(guest.hasAttribute('disabled')).toBe(true)
  expect(account.hasAttribute('disabled')).toBe(true)
  fireEvent.click(guest)
  fireEvent.click(account)
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
  expect(screen.queryByRole('dialog')).toBeNull()

  await act(async () => { waking.resolve(health()) })
  expect(screen.getByText('API connected')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Checking account…' }).hasAttribute('disabled')).toBe(true)
  const checks = fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/session')
  expect(checks).toHaveLength(1)
  expect(window.location.hash).toBe('')
  await act(async () => { await vi.advanceTimersByTimeAsync(14_999) })
  expect(checks[0]?.[1]?.signal?.aborted).toBe(false)
  expect(screen.queryByText(/session check took too long/)).toBeNull()

  await act(async () => { restoring.resolve(Response.json(session)) })
  expect(screen.getByRole('button', { name: 'Signed in' })).toBeTruthy()
  expect(screen.queryByText(/Google sign-in could not be confirmed/)).toBeNull()
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/session')).toHaveLength(1)
  expect(fetchMock.mock.calls.every(([url]) => [
    '/api/v1/health', '/api/v1/account/session',
  ].includes(String(url)))).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
})

test('startup timeout ignores late success and waits for a manual retry before restoring', async () => {
  const waking = deferredResponse()
  let ready = false
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url) => {
    if (url === '/api/v1/health') return ready ? health() : (await waking.promise).clone()
    if (url === '/api/v1/account/session') return new Response(null, { status: 401 })
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  renderApp()
  await act(async () => { await vi.advanceTimersByTimeAsync(75_000) })
  expect(screen.getByText('API unavailable')).toBeTruthy()
  expect(screen.queryByText(/Account session could not be checked/)).toBeNull()
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  expect(screen.getByRole('button', { name: 'Service unavailable' }).hasAttribute('disabled')).toBe(true)
  expect(screen.getByRole('button', { name: 'Service unavailable' }).getAttribute('aria-busy')).toBe('false')
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
  expect(fetchMock.mock.calls.every(([, options]) => options?.signal?.aborted)).toBe(true)
  const count = fetchMock.mock.calls.length
  await act(async () => {
    waking.resolve(health())
    await vi.advanceTimersByTimeAsync(120_000)
  })
  expect(screen.getByText('API unavailable')).toBeTruthy()
  expect(fetchMock).toHaveBeenCalledTimes(count)

  ready = true
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Try again' })) })
  expect(screen.getByText('API connected')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(false)
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(false)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/session')).toHaveLength(1)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/health')).toHaveLength(count + 1)
  expect(vi.getTimerCount()).toBe(0)
})

test.each([
  ['HTTP error', () => new Response('private-hosting-details', { status: 503 })],
  ['invalid health metadata', () => Response.json({ status: 'ok', service: 'wrong-service' })],
  ['network failure', () => Promise.reject(new Error('private-hosting-details'))],
] as const)('%s keeps account and guest actions closed without session requests', async (_name, response) => {
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url) => {
    if (url === '/api/v1/health') return response()
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  await act(async () => { renderApp() })
  expect(screen.getByText('API unavailable')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Try again' }).hasAttribute('disabled')).toBe(false)
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  expect(screen.getByRole('button', { name: 'Service unavailable' }).hasAttribute('disabled')).toBe(true)
  expect(document.body.textContent).not.toContain('private-hosting-details')
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
})

test('unmount during startup aborts health and prevents session checks after a late response', async () => {
  const waking = deferredResponse()
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async () => waking.promise)
  vi.stubGlobal('fetch', fetchMock)
  const view = renderApp()
  view.unmount()
  expect(fetchMock.mock.calls.every(([, options]) => options?.signal?.aborted)).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
  await act(async () => { waking.resolve(health()) })
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
})

test('successful health does not activate production account or guest access', async () => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('PROD', true)
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url) => {
    if (url === '/api/v1/health') return health()
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  await act(async () => { renderApp() })
  expect(screen.getByText('API connected')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(true)
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
})
