import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, test, vi } from 'vitest'
import App from './App'
import { loadTurnstile, type TurnstileApi } from './lib/turnstile'

vi.mock('./lib/turnstile', () => ({
  loadTurnstile: vi.fn(),
}))

afterEach(async () => {
  cleanup()

  if (vi.isFakeTimers()) {
    await vi.runOnlyPendingTimersAsync()
    vi.useRealTimers()
  }

  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

test('loading the page does not create a guest session', async () => {
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input) => {
    if (input !== '/api/v1/health') {
      throw new Error('Unexpected request')
    }

    return Response.json({
      status: 'ok',
      service: 'mazda6-assistant-api',
    })
  })

  vi.stubGlobal('fetch', fetchMock)

  render(
    <StrictMode>
      <App />
    </StrictMode>,
  )

  await screen.findByText('API connected')

  expect(fetchMock).toHaveBeenCalled()

  expect(
    fetchMock.mock.calls.every(([input]) => input === '/api/v1/health'),
  ).toBe(true)

  const guestButton = screen.getByRole('button', {
    name: 'Try as Guest',
  })

  expect(guestButton.hasAttribute('disabled')).toBe(false)
})

test('starts one guest request and shows loading then success', async () => {
  const user = userEvent.setup()

  let completeRequest!: (response: Response) => void

  const pendingSession = new Promise<Response>((resolve) => {
    completeRequest = resolve
  })

  const fetchMock = vi.fn<typeof fetch>().mockImplementation(
    async (input, options) => {
      if (input === '/api/v1/health') {
        return Response.json({
          status: 'ok',
          service: 'mazda6-assistant-api',
        })
      }

      if (input === '/api/v1/guest/session') {
        expect(options?.method).toBe('POST')
        expect(options?.credentials).toBe('same-origin')
        return pendingSession
      }

      throw new Error('Unexpected request')
    },
  )

  vi.stubGlobal('fetch', fetchMock)

  render(
    <StrictMode>
      <App />
    </StrictMode>,
  )

  await screen.findByText('API connected')

  const guestRequests = () =>
    fetchMock.mock.calls.filter(
      ([input]) => input === '/api/v1/guest/session',
    )

  await user.click(
    screen.getByRole('button', { name: 'Try as Guest' }),
  )

  const loadingButton = screen.getByRole('button', {
    name: 'Starting…',
  })

  expect(loadingButton.hasAttribute('disabled')).toBe(true)
  expect(loadingButton.getAttribute('aria-busy')).toBe('true')
  expect(guestRequests()).toHaveLength(1)

  await user.click(loadingButton)

  expect(guestRequests()).toHaveLength(1)

  await act(async () => {
    completeRequest(
      Response.json({
        status: 'ok',
        expires_at: '2030-01-01T12:00:00Z',
      }),
    )
  })

  await screen.findByText(
    'Guest session ready. Chat is still in development.',
  )

  const successButton = screen.getByRole('button', {
    name: 'Guest session ready',
  })

  expect(successButton.hasAttribute('disabled')).toBe(true)
  expect(successButton.getAttribute('aria-busy')).toBe('false')
  expect(guestRequests()).toHaveLength(1)
})

test('allows retry after a failed guest request', async () => {
  const user = userEvent.setup()
  let guestRequests = 0

  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input) => {
    if (input === '/api/v1/health') {
      return Response.json({
        status: 'ok',
        service: 'mazda6-assistant-api',
      })
    }

    if (input === '/api/v1/guest/session') {
      guestRequests += 1

      if (guestRequests === 1) {
        return Response.json(
          { detail: 'Private database connection details' },
          { status: 503 },
        )
      }

      return Response.json({
        status: 'ok',
        expires_at: '2030-01-01T12:00:00Z',
      })
    }

    throw new Error('Unexpected request')
  })

  vi.stubGlobal('fetch', fetchMock)

  render(
    <StrictMode>
      <App />
    </StrictMode>,
  )

  await screen.findByText('API connected')

  await user.click(
    screen.getByRole('button', { name: 'Try as Guest' }),
  )

  await screen.findByText(
    'Guest access could not be started. Please try again.',
  )

  const retryButton = screen.getByRole('button', {
    name: 'Try again',
  })

  expect(retryButton.hasAttribute('disabled')).toBe(false)
  expect(retryButton.getAttribute('aria-busy')).toBe('false')
  expect(guestRequests).toBe(1)
  expect(
    screen.queryByText(/private database connection details/i),
  ).toBeNull()

  await user.click(retryButton)

  await screen.findByText(
    'Guest session ready. Chat is still in development.',
  )

  expect(guestRequests).toBe(2)

  const successButton = screen.getByRole('button', {
    name: 'Guest session ready',
  })

  expect(successButton.hasAttribute('disabled')).toBe(true)
})

test('aborts a stalled guest request after 15 seconds', async () => {
  vi.useFakeTimers()

  let guestSignal: AbortSignal | undefined

  const fetchMock = vi.fn<typeof fetch>().mockImplementation(
    async (input, options) => {
      if (input === '/api/v1/health') {
        return Response.json({
          status: 'ok',
          service: 'mazda6-assistant-api',
        })
      }

      if (input === '/api/v1/guest/session') {
        const signal = options?.signal

        if (!signal) {
          throw new Error('Guest request must have an abort signal')
        }

        guestSignal = signal

        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            { once: true },
          )
        })
      }

      throw new Error('Unexpected request')
    },
  )

  vi.stubGlobal('fetch', fetchMock)

  await act(async () => {
    render(
      <StrictMode>
        <App />
      </StrictMode>,
    )
  })

  expect(screen.getByText('API connected')).toBeDefined()

  fireEvent.click(
    screen.getByRole('button', { name: 'Try as Guest' }),
  )

  expect(guestSignal?.aborted).toBe(false)

  await act(async () => {
    await vi.advanceTimersByTimeAsync(14_999)
  })

  expect(guestSignal?.aborted).toBe(false)

  expect(
    screen
      .getByRole('button', { name: 'Starting…' })
      .hasAttribute('disabled'),
  ).toBe(true)

  await act(async () => {
    await vi.advanceTimersByTimeAsync(1)
  })

  expect(guestSignal?.aborted).toBe(true)

  expect(
    screen.getByText('Guest access took too long. Please try again.'),
  ).toBeDefined()

  const retryButton = screen.getByRole('button', {
    name: 'Try again',
  })

  expect(retryButton.hasAttribute('disabled')).toBe(false)
  expect(retryButton.getAttribute('aria-busy')).toBe('false')

  expect(
    fetchMock.mock.calls.filter(
      ([input]) => input === '/api/v1/guest/session',
    ),
  ).toHaveLength(1)
})

test('aborts a pending guest request when the app unmounts', async () => {
  let guestSignal: AbortSignal | undefined

  const fetchMock = vi.fn<typeof fetch>().mockImplementation(
    async (input, options) => {
      if (input === '/api/v1/health') {
        return Response.json({
          status: 'ok',
          service: 'mazda6-assistant-api',
        })
      }

      if (input === '/api/v1/guest/session') {
        const signal = options?.signal

        if (!signal) {
          throw new Error('Guest request must have an abort signal')
        }

        guestSignal = signal

        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            { once: true },
          )
        })
      }

      throw new Error('Unexpected request')
    },
  )

  vi.stubGlobal('fetch', fetchMock)

  const view = render(
    <StrictMode>
      <App />
    </StrictMode>,
  )

  await screen.findByText('API connected')

  vi.useFakeTimers()

  fireEvent.click(
    screen.getByRole('button', { name: 'Try as Guest' }),
  )

  expect(guestSignal?.aborted).toBe(false)
  expect(vi.getTimerCount()).toBeGreaterThan(0)

  await act(async () => {
    view.unmount()
  })

  expect(guestSignal?.aborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
  expect(view.container.childElementCount).toBe(0)

  expect(
    fetchMock.mock.calls.filter(
      ([input]) => input === '/api/v1/guest/session',
    ),
  ).toHaveLength(1)
})

test('keeps guest access disabled outside development', async () => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('PROD', true)

  const user = userEvent.setup()

  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input) => {
    if (input !== '/api/v1/health') {
      throw new Error('Unexpected request')
    }

    return Response.json({
      status: 'ok',
      service: 'mazda6-assistant-api',
    })
  })

  vi.stubGlobal('fetch', fetchMock)

  render(
    <StrictMode>
      <App />
    </StrictMode>,
  )

  await screen.findByText('API connected')

  const guestButton = screen.getByRole('button', {
    name: 'Try as Guest',
  })

  expect(guestButton.hasAttribute('disabled')).toBe(true)

  await user.click(guestButton)

  expect(guestButton.hasAttribute('disabled')).toBe(true)

  expect(
    fetchMock.mock.calls.every(([input]) => input === '/api/v1/health'),
  ).toBe(true)

  expect(
    screen.queryByText(
      'Guest session ready. Chat is still in development.',
    ),
  ).toBeNull()
})

test('requests verification and submits one proof before starting guest access', async () => {
  vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'public-test-site-key')

  const renderWidget = vi.fn<TurnstileApi['render']>(
    () => 'app-test-widget',
  )
  const removeWidget = vi.fn<TurnstileApi['remove']>()

  const api: TurnstileApi = {
    ready: vi.fn<TurnstileApi['ready']>((callback) => callback()),
    render: renderWidget,
    reset: vi.fn<TurnstileApi['reset']>(),
    remove: removeWidget,
  }

  vi.mocked(loadTurnstile).mockReset()
  vi.mocked(loadTurnstile).mockResolvedValue(api)

  let guestRequests = 0

  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input) => {
    if (input === '/api/v1/health') {
      return Response.json({
        status: 'ok',
        service: 'mazda6-assistant-api',
      })
    }

    if (input === '/api/v1/guest/session') {
      guestRequests += 1

      if (guestRequests === 1) {
        return Response.json(
          { detail: 'Human verification is required or was rejected.' },
          {
            status: 403,
            headers: { 'X-Guest-Verification': 'required' },
          },
        )
      }

      return Response.json({
        status: 'ok',
        expires_at: '2030-01-01T12:00:00Z',
      })
    }

    throw new Error('Unexpected request')
  })

  vi.stubGlobal('fetch', fetchMock)

  const user = userEvent.setup()

  render(
    <StrictMode>
      <App />
    </StrictMode>,
  )

  await screen.findByText('API connected')

  expect(loadTurnstile).not.toHaveBeenCalled()
  expect(guestRequests).toBe(0)

  await user.click(
    screen.getByRole('button', { name: 'Try as Guest' }),
  )

  await screen.findByText('Complete the check to continue.')

  expect(guestRequests).toBe(1)
  expect(renderWidget).toHaveBeenCalledTimes(1)

  const verificationButton = screen.getByRole('button', {
    name: 'Complete verification',
  })

  expect(verificationButton.hasAttribute('disabled')).toBe(true)

  const options = renderWidget.mock.calls[0]?.[1]

  if (!options) {
    throw new Error('Expected the verification widget to render')
  }

  expect(options.sitekey).toBe('public-test-site-key')
  expect(options.action).toBe('guest_start')

  await act(async () => {
    options.callback('synthetic-proof')
    options.callback('duplicate-proof')
  })

  await screen.findByText(
    'Guest session ready. Chat is still in development.',
  )

  const requests = fetchMock.mock.calls.filter(
    ([input]) => input === '/api/v1/guest/session',
  )

  expect(requests).toHaveLength(2)
  expect(requests[0]?.[1]?.body).toBeUndefined()
  expect(requests[1]?.[1]?.body).toBe(
    JSON.stringify({ turnstile_token: 'synthetic-proof' }),
  )
  expect(requests[1]?.[1]?.credentials).toBe('same-origin')

  expect(removeWidget).toHaveBeenCalledExactlyOnceWith('app-test-widget')
  expect(screen.queryByText('Human verification')).toBeNull()

  expect(
    screen
      .getByRole('button', { name: 'Guest session ready' })
      .hasAttribute('disabled'),
  ).toBe(true)
})
test.each([
  [403, 'Verification was not accepted. Please try again.'],
  [503, 'Guest access could not be started. Please try again.'],
] as const)(
  'requires a fresh proof after a token submission returns HTTP %s',
  async (failureStatus, expectedMessage) => {
    vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'public-test-site-key')

    const user = userEvent.setup()
    const renderWidget = vi.fn<TurnstileApi['render']>(
      () => 'retry-widget',
    )
    const removeWidget = vi.fn<TurnstileApi['remove']>()

    const api: TurnstileApi = {
      ready: (callback) => callback(),
      render: renderWidget,
      reset: vi.fn<TurnstileApi['reset']>(),
      remove: removeWidget,
    }

    vi.mocked(loadTurnstile).mockReset()
    vi.mocked(loadTurnstile).mockResolvedValue(api)

    let guestRequests = 0

    const fetchMock = vi.fn<typeof fetch>().mockImplementation(
      async (input) => {
        if (input === '/api/v1/health') {
          return Response.json({
            status: 'ok',
            service: 'mazda6-assistant-api',
          })
        }

        if (input !== '/api/v1/guest/session') {
          throw new Error('Unexpected request')
        }

        guestRequests += 1

        if (guestRequests === 1 || guestRequests === 3) {
          return Response.json(
            { detail: 'Verification required.' },
            {
              status: 403,
              headers: { 'X-Guest-Verification': 'required' },
            },
          )
        }

        if (guestRequests === 2) {
          return Response.json(
            { detail: 'Private provider failure details' },
            {
              status: failureStatus,
              headers:
                failureStatus === 403
                  ? { 'X-Guest-Verification': 'required' }
                  : {},
            },
          )
        }

        return Response.json({
          status: 'ok',
          expires_at: '2030-01-01T12:00:00Z',
        })
      },
    )

    vi.stubGlobal('fetch', fetchMock)

    render(
      <StrictMode>
        <App />
      </StrictMode>,
    )

    await screen.findByText('API connected')

    await user.click(
      screen.getByRole('button', { name: 'Try as Guest' }),
    )

    await screen.findByText('Complete the check to continue.')

    const firstOptions = renderWidget.mock.calls[0]?.[1]

    if (!firstOptions) {
      throw new Error('Expected the first challenge')
    }

    await act(async () => {
      firstOptions.callback('first-proof')
    })

    await screen.findByText(expectedMessage)

    expect(guestRequests).toBe(2)
    expect(screen.queryByText('Human verification')).toBeNull()
    expect(
      screen.queryByText(/private provider failure details/i),
    ).toBeNull()

    await user.click(
      screen.getByRole('button', { name: 'Try again' }),
    )

    await screen.findByText('Complete the check to continue.')

    expect(guestRequests).toBe(3)
    expect(renderWidget).toHaveBeenCalledTimes(2)

    const freshOptions = renderWidget.mock.calls[1]?.[1]

    if (!freshOptions) {
      throw new Error('Expected a fresh challenge')
    }

    act(() => {
      firstOptions.callback('stale-proof')
    })

    expect(guestRequests).toBe(3)

    await act(async () => {
      freshOptions.callback('fresh-proof')
    })

    await screen.findByText(
      'Guest session ready. Chat is still in development.',
    )

    const requests = fetchMock.mock.calls.filter(
      ([input]) => input === '/api/v1/guest/session',
    )

    expect(requests.map(([, options]) => options?.body)).toEqual([
      undefined,
      JSON.stringify({ turnstile_token: 'first-proof' }),
      undefined,
      JSON.stringify({ turnstile_token: 'fresh-proof' }),
    ])

    expect(removeWidget).toHaveBeenCalledTimes(2)
  },
)