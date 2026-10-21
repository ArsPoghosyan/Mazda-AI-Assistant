import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import App from './App'
import { loadTurnstile, type TurnstileApi } from './lib/turnstile'

vi.mock('./lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

const session = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

const prototype = HTMLDialogElement.prototype
const originalShow = Object.getOwnPropertyDescriptor(prototype, 'showModal')
const originalClose = Object.getOwnPropertyDescriptor(prototype, 'close')
let api: TurnstileApi

beforeEach(() => {
  // jsdom does not implement the browser's native modal/top layer.
  Object.defineProperty(prototype, 'showModal', {
    configurable: true,
    value: function (this: HTMLDialogElement) { this.open = true },
  })
  Object.defineProperty(prototype, 'close', {
    configurable: true,
    value: function (this: HTMLDialogElement) { this.open = false },
  })
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'public-test-site-key')
  api = {
    ready: (callback) => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'sign-in-session-widget'),
    reset: vi.fn(),
    remove: vi.fn(),
  }
  vi.mocked(loadTurnstile).mockReset()
  vi.mocked(loadTurnstile).mockResolvedValue(api)
})

afterEach(() => {
  cleanup()
  for (const [name, descriptor] of [
    ['showModal', originalShow], ['close', originalClose],
  ] as const) {
    if (descriptor) Object.defineProperty(prototype, name, descriptor)
    else Reflect.deleteProperty(prototype, name)
  }
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

function mockNetwork(signInResponse: () => Response | Promise<Response>) {
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url) => {
    if (url === '/api/v1/health') {
      return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
    }
    if (url === '/api/v1/account/session') {
      return new Response(null, { status: 401 })
    }
    if (url === '/api/v1/account/sign-in') return signInResponse()
    if (url === '/api/v1/account/sign-out') return new Response(null, { status: 204 })
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

async function submitSignIn() {
  const user = userEvent.setup()
  const view = render(<StrictMode><App /></StrictMode>)
  const trigger = await screen.findByRole('button', { name: 'Sign In' })
  await user.click(trigger)
  await screen.findByText('Complete the check to continue.')
  const dialog = screen.getByRole('dialog', { name: 'Sign in' })
  await user.type(within(dialog).getByLabelText('Email'), 'owner@example.test')
  await user.type(
    within(dialog).getByLabelText('Password', { exact: true }),
    'synthetic-password',
  )
  const options = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!options) throw new Error('Expected a verification widget')
  act(() => options.callback('synthetic-proof'))
  await user.click(within(dialog).getByRole('button', { name: 'Sign in' }))
  return { user, view, trigger, dialog }
}

test('successful sign-in updates the App, closes the dialog, and focuses status', async () => {
  const fetchMock = mockNetwork(() => Response.json(session))
  const { user } = await submitSignIn()

  const accountButton = await screen.findByRole('button', { name: 'Signed in' })
  expect(accountButton.hasAttribute('disabled')).toBe(true)
  expect(screen.queryByRole('dialog')).toBeNull()
  const status = screen.getByText('Signed in. Chat is still in development.')
  expect(document.activeElement).toBe(status)
  expect(document.body.style.overflow).toBe('')
  expect(
    screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled'),
  ).toBe(true)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/session')).toHaveLength(1)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(1)
  expect(fetchMock.mock.calls.every(([url]) => [
    '/api/v1/health', '/api/v1/account/session', '/api/v1/account/sign-in',
  ].includes(String(url)))).toBe(true)

  await user.click(screen.getByRole('button', { name: 'Sign out' }))
  const trigger = await screen.findByRole('button', { name: 'Sign In' })
  expect(document.activeElement).toBe(trigger)

  await user.click(trigger)
  await screen.findByText('Complete the check to continue.')
  const dialog = screen.getByRole('dialog', { name: 'Sign in' })
  await user.type(within(dialog).getByLabelText('Email'), 'owner@example.test')
  await user.type(within(dialog).getByLabelText('Password', { exact: true }), 'synthetic-password')
  const options = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!options) throw new Error('Expected a new verification widget')
  act(() => options.callback('fresh-synthetic-proof'))
  await user.click(within(dialog).getByRole('button', { name: 'Sign in' }))
  await screen.findByRole('button', { name: 'Signed in' })
  expect(screen.getByText('Signed in. Chat is still in development.')).toBeTruthy()
  await user.click(screen.getByRole('button', { name: 'Sign out' }))
  await screen.findByRole('button', { name: 'Sign In' })
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-out')).toHaveLength(2)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(2)
})

test.each([
  { name: 'rejected credentials', response: () => new Response('private-detail', { status: 401 }) },
  { name: 'unavailable service', response: () => new Response('private-detail', { status: 503 }) },
  { name: 'invalid success metadata', response: () => Response.json(null) },
])('$name keeps the dialog open without marking the App signed in', async ({ response }) => {
  const fetchMock = mockNetwork(response)
  const { dialog, user, trigger } = await submitSignIn()

  await screen.findByText(/Sign-in (was rejected|could not be completed)/)
  expect(screen.getByRole('dialog')).toBe(dialog)
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  expect(document.body.textContent).not.toContain('private-detail')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(1)
  await user.click(within(dialog).getByRole('button', { name: 'Close sign-in' }))
  expect(document.activeElement).toBe(trigger)
  expect(
    screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled'),
  ).toBe(false)
})

test('closing a pending sign-in ignores its late success in the App', async () => {
  let complete!: (response: Response) => void
  const pending = new Promise<Response>((resolve) => { complete = resolve })
  const fetchMock = mockNetwork(() => pending)
  const { dialog, trigger } = await submitSignIn()
  const signal = fetchMock.mock.calls.find(
    ([url]) => url === '/api/v1/account/sign-in',
  )?.[1]?.signal

  fireEvent(dialog, new Event('cancel', { cancelable: true }))
  expect(signal?.aborted).toBe(true)
  expect(document.activeElement).toBe(trigger)
  await act(async () => {
    complete(Response.json(session))
    await pending
  })
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  expect(screen.queryByText('Signed in. Chat is still in development.')).toBeNull()
  expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(false)
})
