import { StrictMode } from 'react'
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import App from './App'
import { loadTurnstile } from './lib/turnstile'

vi.mock('./lib/turnstile', () => ({
  loadTurnstile: vi.fn(),
}))

const session = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

function deferredResponse() {
  let resolve!: (response: Response) => void

  const promise = new Promise<Response>((complete) => {
    resolve = complete
  })

  return { promise, resolve }
}

function mockNetwork(
  respond: () => Response | Promise<Response>,
) {
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(
    async (input) => {
      if (input === '/api/v1/health') {
        return Response.json({
          status: 'ok',
          service: 'mazda6-assistant-api',
        })
      }

      if (input === '/api/v1/account/session') {
        return respond()
      }

      throw new Error('Unexpected request')
    },
  )

  vi.stubGlobal('fetch', fetchMock)

  return fetchMock
}

function accountRequests(
  fetchMock: ReturnType<typeof mockNetwork>,
) {
  return fetchMock.mock.calls.filter(
    ([input]) => input === '/api/v1/account/session',
  )
}

function expectOnlySessionAndHealthRequests(
  fetchMock: ReturnType<typeof mockNetwork>,
) {
  expect(
    fetchMock.mock.calls.every(
      ([input]) =>
        input === '/api/v1/health' ||
        input === '/api/v1/account/session',
    ),
  ).toBe(true)

  expect(loadTurnstile).not.toHaveBeenCalled()
}

function mountApp() {
  return render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}

let originalUrl: string
let originalHistoryState: unknown

beforeEach(() => {
  originalUrl = window.location.href
  originalHistoryState = window.history.state
  vi.stubEnv('DEV', true)
  vi.mocked(loadTurnstile).mockReset()
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  window.history.replaceState(originalHistoryState, '', originalUrl)
})

test.each([
  ['success', 'Google sign-in could not be confirmed. Please sign in again.'],
  ['rejected', 'Google sign-in was not completed. Please try again.'],
  ['unavailable', 'Google sign-in is temporarily unavailable. Please try again.'],
  [
    'sign-out-required',
    'The previous account session is no longer available. Please sign in again.',
  ],
])('shows the %s return message only after session rejection', async (outcome, message) => {
  window.history.replaceState(null, '', `/#google-sign-in=${outcome}`)

  const fetchMock = mockNetwork(
    () => new Response(null, { status: 401 }),
  )

  mountApp()

  await screen.findByText(message)

  expect(window.location.hash).toBe('')
  expect(
    screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled'),
  ).toBe(false)
  expect(
    screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled'),
  ).toBe(false)
  expect(
    screen.queryByRole('button', { name: 'Signed in' }),
  ).toBeNull()

  expect(accountRequests(fetchMock)).toHaveLength(1)
  expectOnlySessionAndHealthRequests(fetchMock)
})

test('Google success waits for backend verification before showing Signed in', async () => {
  window.history.replaceState(null, '', '/#google-sign-in=success')

  const pending = deferredResponse()
  const fetchMock = mockNetwork(() => pending.promise)

  mountApp()

  await screen.findByText('API connected')

  expect(
    screen.getByRole('button', {
      name: 'Checking account…',
    }).hasAttribute('disabled'),
  ).toBe(true)
  expect(
    screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled'),
  ).toBe(true)
  expect(
    screen.queryByRole('button', { name: 'Signed in' }),
  ).toBeNull()

  await act(async () => {
    pending.resolve(Response.json(session))
    await pending.promise
  })

  await screen.findByRole('button', { name: 'Signed in' })
  expect(
    screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled'),
  ).toBe(true)

  expect(accountRequests(fetchMock)).toHaveLength(1)
  expectOnlySessionAndHealthRequests(fetchMock)
})

test('Google return stays unavailable until an explicit session retry', async () => {
  window.history.replaceState(null, '', '/#google-sign-in=success')

  let attempts = 0
  const fetchMock = mockNetwork(() => {
    attempts += 1
    return attempts === 1
      ? new Response('synthetic-private-detail', { status: 503 })
      : new Response(null, { status: 401 })
  })

  mountApp()

  const retry = await screen.findByRole('button', {
    name: 'Retry session check',
  })

  expect(
    screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled'),
  ).toBe(true)
  expect(document.body.textContent).not.toContain('synthetic-private-detail')
  expect(accountRequests(fetchMock)).toHaveLength(1)

  fireEvent.click(retry)

  await screen.findByText(
    'Google sign-in could not be confirmed. Please sign in again.',
  )
  expect(
    screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled'),
  ).toBe(false)

  expect(accountRequests(fetchMock)).toHaveLength(2)
  expectOnlySessionAndHealthRequests(fetchMock)
})

test('blocks access while checking and restores the account once', async () => {
  const pending = deferredResponse()
  const fetchMock = mockNetwork(() => pending.promise)

  const { rerender } = mountApp()

  expect(
    screen
      .getByRole('button', { name: 'Checking account…' })
      .hasAttribute('disabled'),
  ).toBe(true)

  expect(
    screen
      .getByRole('button', { name: 'Try as Guest' })
      .hasAttribute('disabled'),
  ).toBe(true)

  await screen.findByText('API connected')

  expect(accountRequests(fetchMock)).toHaveLength(1)

  const options = accountRequests(fetchMock)[0]?.[1]

  expect(options?.method).toBe('POST')
  expect(options?.credentials).toBe('same-origin')
  expect(options?.cache).toBe('no-store')
  expect(options?.redirect).toBe('error')
  expect(options?.body).toBeUndefined()

  await act(async () => {
    pending.resolve(Response.json(session))
    await pending.promise
  })

  const accountButton = await screen.findByRole('button', {
    name: 'Signed in',
  })

  expect(accountButton.hasAttribute('disabled')).toBe(true)

  expect(
    screen
      .getByRole('button', { name: 'Try as Guest' })
      .hasAttribute('disabled'),
  ).toBe(true)

  expect(
    screen.getByText('Signed in. Chat is still in development.'),
  ).toBeTruthy()

  rerender(
    <StrictMode>
      <App />
    </StrictMode>,
  )

  expect(accountRequests(fetchMock)).toHaveLength(1)
  expectOnlySessionAndHealthRequests(fetchMock)
})

test('a rejected session enables sign-in and guest access', async () => {
  const fetchMock = mockNetwork(
    () => new Response('private-response-detail', { status: 401 }),
  )

  mountApp()

  const signInButton = await screen.findByRole('button', {
    name: 'Sign In',
  })

  expect(signInButton.hasAttribute('disabled')).toBe(false)

  expect(
    screen
      .getByRole('button', { name: 'Try as Guest' })
      .hasAttribute('disabled'),
  ).toBe(false)

  expect(document.body.textContent).not.toContain(
    'private-response-detail',
  )

  expect(accountRequests(fetchMock)).toHaveLength(1)
  expectOnlySessionAndHealthRequests(fetchMock)
})

test.each([403, 500, 503])(
  'HTTP %s keeps guest access blocked until a manual retry succeeds',
  async (status) => {
    const pending = deferredResponse()
    let attempts = 0

    const fetchMock = mockNetwork(() => {
      attempts += 1

      if (attempts === 1) {
        return new Response('private-provider-detail', { status })
      }

      return pending.promise
    })

    const { rerender } = mountApp()

    const retryButton = await screen.findByRole('button', {
      name: 'Retry session check',
    })

    expect(retryButton.hasAttribute('disabled')).toBe(false)

    expect(
      screen.getByText(
        'Account session could not be checked. Please try again.',
      ),
    ).toBeTruthy()

    expect(
      screen
        .getByRole('button', { name: 'Try as Guest' })
        .hasAttribute('disabled'),
    ).toBe(true)

    expect(document.body.textContent).not.toContain(
      'private-provider-detail',
    )

    rerender(
      <StrictMode>
        <App />
      </StrictMode>,
    )

    expect(accountRequests(fetchMock)).toHaveLength(1)

    fireEvent.click(retryButton)

    const checkingButton = screen.getByRole('button', {
      name: 'Checking account…',
    })

    expect(checkingButton.hasAttribute('disabled')).toBe(true)

    fireEvent.click(checkingButton)
    fireEvent.click(checkingButton)

    await act(async () => {
      await Promise.resolve()
    })

    expect(accountRequests(fetchMock)).toHaveLength(2)

    await act(async () => {
      pending.resolve(Response.json(session))
      await pending.promise
    })

    await screen.findByRole('button', { name: 'Signed in' })

    expect(accountRequests(fetchMock)).toHaveLength(2)
    expectOnlySessionAndHealthRequests(fetchMock)
  },
)

test('invalid successful metadata leaves the session unavailable', async () => {
  const fetchMock = mockNetwork(() => Response.json(null))

  mountApp()

  await screen.findByRole('button', {
    name: 'Retry session check',
  })

  expect(
    screen
      .getByRole('button', { name: 'Try as Guest' })
      .hasAttribute('disabled'),
  ).toBe(true)

  expect(
    screen.queryByRole('button', { name: 'Signed in' }),
  ).toBeNull()

  expect(
    screen.queryByRole('button', { name: 'Sign In' }),
  ).toBeNull()

  expect(accountRequests(fetchMock)).toHaveLength(1)
  expectOnlySessionAndHealthRequests(fetchMock)
})

test('unmount aborts the pending check and ignores a late response', async () => {
  const pending = deferredResponse()
  const fetchMock = mockNetwork(() => pending.promise)

  const { unmount } = mountApp()

  await screen.findByText('API connected')

  const signal = accountRequests(fetchMock)[0]?.[1]?.signal

  expect(signal).toBeInstanceOf(AbortSignal)
  expect(signal?.aborted).toBe(false)

  unmount()

  expect(signal?.aborted).toBe(true)

  await act(async () => {
    pending.resolve(Response.json(session))
    await pending.promise
  })

  expect(
    screen.queryByRole('button', { name: 'Signed in' }),
  ).toBeNull()

  expect(accountRequests(fetchMock)).toHaveLength(1)
  expectOnlySessionAndHealthRequests(fetchMock)
})

test('does not restore accounts outside development', async () => {
  vi.stubEnv('DEV', false)

  const fetchMock = mockNetwork(() => Response.json(session))

  mountApp()

  await screen.findByText('API connected')

  expect(
    screen
      .getByRole('button', { name: 'Sign In' })
      .hasAttribute('disabled'),
  ).toBe(true)

  expect(
    screen
      .getByRole('button', { name: 'Try as Guest' })
      .hasAttribute('disabled'),
  ).toBe(true)

  expect(accountRequests(fetchMock)).toHaveLength(0)
  expectOnlySessionAndHealthRequests(fetchMock)
})
