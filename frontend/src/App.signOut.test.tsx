import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import App from './App'
import { loadTurnstile } from './lib/turnstile'

vi.mock('./lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

const session = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

function deferredResponse() {
  let resolve!: (response: Response) => void
  const promise = new Promise<Response>((complete) => { resolve = complete })
  return { promise, resolve }
}

function mockNetwork(
  signOut: (options?: RequestInit) => Response | Promise<Response>,
  signedIn = true,
) {
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url, options) => {
    if (url === '/api/v1/health') {
      return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
    }
    if (url === '/api/v1/account/terms/status') return Response.json({ terms_version: '2026-10-28', accepted_at: new Date(Date.now() - 1000).toISOString(), acceptance_required: false })
    if (url === '/api/v1/account/session') {
      return signedIn ? Response.json(session) : new Response(null, { status: 401 })
    }
    if (url === '/api/v1/account/sign-out') return signOut(options)
    if (url === '/api/v1/guest/session') {
      return Response.json({ status: 'ok', expires_at: session.expires_at })
    }
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function signOutCalls(fetchMock: ReturnType<typeof mockNetwork>) {
  return fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-out')
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(loadTurnstile).mockReset()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

async function mountApp() {
  const view = render(<StrictMode><App /></StrictMode>)
  await act(async () => { await Promise.resolve() })
  return view
}

test('keeps account access until confirmation, blocks duplicates, and enables guest afterward', async () => {
  const pending = deferredResponse()
  const fetchMock = mockNetwork(() => pending.promise)
  await mountApp()

  const signOut = screen.getByRole('button', { name: 'Sign out' })
  expect(signOutCalls(fetchMock)).toHaveLength(0)
  fireEvent.click(signOut)

  const loading = screen.getByRole('button', { name: 'Signing out…' })
  expect(loading.hasAttribute('disabled')).toBe(true)
  expect(screen.getByRole('button', { name: 'Signed in' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  fireEvent.click(loading)
  expect(signOutCalls(fetchMock)).toHaveLength(1)

  await act(async () => {
    pending.resolve(new Response(null, { status: 204 }))
    await pending.promise
  })

  const signIn = screen.getByRole('button', { name: 'Sign In' })
  expect(signIn.hasAttribute('disabled')).toBe(false)
  expect(document.activeElement).toBe(signIn)
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull()
  expect(screen.getByText('Signed out.')).toBeTruthy()
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/session')).toHaveLength(1)

  fireEvent.click(screen.getByRole('button', { name: 'Try as Guest' }))
  await screen.findByText('Guest session ready. Chat is still in development.')
  expect(loadTurnstile).not.toHaveBeenCalled()
})

test.each([200, 403, 503])('HTTP %s keeps the account and allows an explicit retry', async (status) => {
  let attempts = 0
  const fetchMock = mockNetwork(() => {
    attempts += 1
    return attempts === 1
      ? new Response('private-detail', { status })
      : new Response(null, { status: 204 })
  })
  const { rerender } = await mountApp()
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))

  await screen.findByText('Sign-out could not be completed. Please try again.')
  expect(screen.getByRole('button', { name: 'Signed in' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  expect(document.body.textContent).not.toContain('private-detail')
  rerender(<StrictMode><App /></StrictMode>)
  expect(signOutCalls(fetchMock)).toHaveLength(1)

  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
  await screen.findByRole('button', { name: 'Sign In' })
  expect(signOutCalls(fetchMock)).toHaveLength(2)
})

test('a timed-out sign-out keeps account state and offers a retry', async () => {
  vi.useFakeTimers()
  const fetchMock = mockNetwork((options) => new Promise<Response>((_resolve, reject) => {
    options?.signal?.addEventListener('abort', () => {
      reject(new DOMException('Aborted', 'AbortError'))
    }, { once: true })
  }))
  await mountApp()
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))

  await act(async () => {
    await vi.advanceTimersByTimeAsync(15_000)
  })

  expect(screen.getByText('Sign-out took too long. Please try again.')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Signed in' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Sign out' }).hasAttribute('disabled')).toBe(false)
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  expect(signOutCalls(fetchMock)).toHaveLength(1)
})

test('unmount cancels sign-out and ignores late success', async () => {
  const pending = deferredResponse()
  const fetchMock = mockNetwork(() => pending.promise)
  const { unmount } = await mountApp()
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
  const signal = signOutCalls(fetchMock)[0]?.[1]?.signal
  unmount()
  expect(signal?.aborted).toBe(true)

  await act(async () => {
    pending.resolve(new Response(null, { status: 204 }))
    await pending.promise
  })
  expect(screen.queryByText('Signed out.')).toBeNull()
})

test('a signed-out visitor has no sign-out button', async () => {
  const fetchMock = mockNetwork(() => new Response(null, { status: 204 }), false)
  await mountApp()
  expect(screen.getByRole('button', { name: 'Sign In' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull()
  expect(signOutCalls(fetchMock)).toHaveLength(0)
})

test('production does not expose sign-out or send account requests', async () => {
  vi.stubEnv('DEV', false)
  const fetchMock = mockNetwork(() => new Response(null, { status: 204 }))
  await mountApp()
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull()
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
})
