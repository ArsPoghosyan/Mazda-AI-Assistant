import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { CURRENT_TERMS_VERSION } from '../shared/account-terms'
import App from './App'
import { loadTurnstile, type TurnstileApi } from './lib/turnstile'

vi.mock('./lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

const session = { user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z', absolute_expires_at: '2030-01-30T12:00:00Z' }
const prototype = HTMLDialogElement.prototype
const originalShow = Object.getOwnPropertyDescriptor(prototype, 'showModal')
const originalClose = Object.getOwnPropertyDescriptor(prototype, 'close')
let api: TurnstileApi

beforeEach(() => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_GUEST_ACCESS_ENABLED', 'true')
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  vi.stubEnv('VITE_ACCOUNT_REGISTRATION_ENABLED', 'false')
  vi.stubEnv('VITE_ACCOUNT_RECOVERY_ENABLED', 'false')
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'false')
  vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'public-test-site-key')
  Object.defineProperty(prototype, 'showModal', { configurable: true,
    value: function (this: HTMLDialogElement) { this.open = true } })
  Object.defineProperty(prototype, 'close', { configurable: true,
    value: function (this: HTMLDialogElement) { this.open = false } })
  api = { ready: callback => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'guest-widget'), reset: vi.fn(), remove: vi.fn() }
  vi.mocked(loadTurnstile).mockReset()
  vi.mocked(loadTurnstile).mockResolvedValue(api)
})

afterEach(() => {
  cleanup()
  for (const [name, descriptor] of [['showModal', originalShow], ['close', originalClose]] as const) {
    if (descriptor) Object.defineProperty(prototype, name, descriptor)
    else Reflect.deleteProperty(prototype, name)
  }
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

function mockNetwork(options: { cookiePresent?: boolean; proofStatus?: number; signedIn?: boolean;
  sessionResponse?: Promise<Response>; sessionUnavailable?: boolean } = {}) {
  let cookiePresent = options.cookiePresent ?? false
  let proofRejected = false
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
    if (url === '/api/v1/health') return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
    if (url === '/api/v1/account/session') {
      if (options.sessionResponse) return (await options.sessionResponse).clone()
      if (options.sessionUnavailable) return new Response(null, { status: 503 })
      return options.signedIn ? Response.json(session) : new Response(null, { status: 401 })
    }
    if (url === '/api/v1/account/terms/status') return Response.json({ terms_version: CURRENT_TERMS_VERSION,
      accepted_at: new Date(Date.now() - 1000).toISOString(), acceptance_required: false })
    if (url === '/api/v1/guest/session') {
      expect(init?.credentials).toBe('same-origin')
      expect(init?.method).toBe('POST')
      expect(init?.cache).toBe('no-store')
      if (init?.body !== undefined) {
        expect(JSON.parse(String(init.body))).toEqual({ turnstile_token: 'guest-proof' })
        if (options.proofStatus && !proofRejected) {
          proofRejected = true
          return Response.json({ detail: 'private-provider-detail' }, { status: options.proofStatus,
            headers: { 'Retry-After': '61', 'X-Guest-Verification': 'required' } })
        }
        cookiePresent = true
      }
      return cookiePresent
        ? Response.json({ status: 'ok', expires_at: '2030-01-01T12:00:00Z' })
        : Response.json({ detail: 'Verification required' }, { status: 403, headers: { 'X-Guest-Verification': 'required' } })
    }
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function guestRequests(fetchMock: ReturnType<typeof mockNetwork>) {
  return fetchMock.mock.calls.filter(([url]) => url === '/api/v1/guest/session')
}

async function readyForAccess() {
  await screen.findByText('API connected')
  await screen.findByRole('button', { name: 'Sign In' })
}

async function startGuest(user: ReturnType<typeof userEvent.setup>) {
  await readyForAccess()
  await user.click(screen.getByRole('button', { name: 'Try as Guest' }))
}

function challenge() {
  const options = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!options) throw new Error('Expected a verification widget')
  expect(options.action).toBe('guest_start')
  return options
}

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production guest flag %s keeps the button closed without guest requests', async flag => {
  vi.stubEnv('VITE_GUEST_ACCESS_ENABLED', flag)
  const fetchMock = mockNetwork()
  render(<StrictMode><App /></StrictMode>)
  await readyForAccess()
  const button = screen.getByRole('button', { name: 'Try as Guest' })
  expect(button.hasAttribute('disabled')).toBe(true)
  fireEvent.click(button)
  expect(guestRequests(fetchMock)).toHaveLength(0)
  expect(loadTurnstile).not.toHaveBeenCalled()
})

test.each(['false', 'true'])('guest opt-in needs no automatic request and can reuse the browser session; account flag %s', async accountFlag => {
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', accountFlag)
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ cookiePresent: true })
  render(<StrictMode><App /></StrictMode>)
  await readyForAccess()
  expect(guestRequests(fetchMock)).toHaveLength(0)
  await user.click(screen.getByRole('button', { name: 'Try as Guest' }))
  await screen.findByText('Guest session ready. Chat is still in development.')
  expect(guestRequests(fetchMock)).toHaveLength(1)
  expect(guestRequests(fetchMock)[0]?.[1]?.body).toBeUndefined()
  expect(loadTurnstile).not.toHaveBeenCalled()
  if (accountFlag === 'false') expect(fetchMock.mock.calls.some(([url]) => url === '/api/v1/account/session')).toBe(false)
})

test('production first-use proof is submitted once and the returning browser does not need a new proof', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork()
  const first = render(<StrictMode><App /></StrictMode>)
  await startGuest(user)
  await screen.findByText('Complete the check to continue.')
  expect(guestRequests(fetchMock)).toHaveLength(1)
  expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(true)
  const options = challenge()
  act(() => { options.callback('guest-proof'); options.callback('guest-proof') })
  await screen.findByText('Guest session ready. Chat is still in development.')
  expect(guestRequests(fetchMock)).toHaveLength(2)
  expect(screen.getByRole('button', { name: 'Guest session ready' }).hasAttribute('disabled')).toBe(true)
  expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(false)
  first.unmount()
  render(<StrictMode><App /></StrictMode>)
  await readyForAccess()
  expect(guestRequests(fetchMock)).toHaveLength(2)
  await user.click(screen.getByRole('button', { name: 'Try as Guest' }))
  await screen.findByText('Guest session ready. Chat is still in development.')
  expect(guestRequests(fetchMock)).toHaveLength(3)
  expect(guestRequests(fetchMock)[2]?.[1]?.body).toBeUndefined()
})

test.each([
  [503, 'Guest access could not be started. Please try again.'],
  [429, 'Too many guest-access attempts. Please wait 61 seconds before trying again.'],
  [403, 'Verification was not accepted. Please try again.'],
] as const)('production proof failure %s stays private and needs manual retry and a fresh check', async (proofStatus, message) => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ proofStatus })
  render(<StrictMode><App /></StrictMode>)
  await startGuest(user)
  await screen.findByText('Complete the check to continue.')
  act(() => challenge().callback('guest-proof'))
  await screen.findByText(message)
  expect(guestRequests(fetchMock)).toHaveLength(2)
  expect(document.body.textContent).not.toContain('private-provider-detail')
  await user.click(screen.getByRole('button', { name: 'Try again' }))
  await screen.findByText('Complete the check to continue.')
  expect(guestRequests(fetchMock)).toHaveLength(3)
  expect(guestRequests(fetchMock)[2]?.[1]?.body).toBeUndefined()
  act(() => challenge().callback('guest-proof'))
  await screen.findByText('Guest session ready. Chat is still in development.')
  expect(guestRequests(fetchMock)).toHaveLength(4)
})

test('production guest access waits for the account session check', async () => {
  let complete!: (response: Response) => void
  const sessionResponse = new Promise<Response>(resolve => { complete = resolve })
  const fetchMock = mockNetwork({ sessionResponse })
  render(<StrictMode><App /></StrictMode>)
  await screen.findByText('API connected')
  const button = screen.getByRole('button', { name: 'Try as Guest' })
  expect(button.hasAttribute('disabled')).toBe(true)
  fireEvent.click(button)
  expect(guestRequests(fetchMock)).toHaveLength(0)
  await act(async () => { complete(new Response(null, { status: 401 })) })
  await screen.findByRole('button', { name: 'Sign In' })
  expect(button.hasAttribute('disabled')).toBe(false)
})

test.each(['signed-in', 'unavailable'] as const)('production guest access stays blocked when account status is %s', async status => {
  const fetchMock = mockNetwork({ signedIn: status === 'signed-in', sessionUnavailable: status === 'unavailable' })
  render(<StrictMode><App /></StrictMode>)
  await screen.findByRole('button', { name: status === 'signed-in' ? 'Signed in' : 'Retry session check' })
  const button = screen.getByRole('button', { name: 'Try as Guest' })
  expect(button.hasAttribute('disabled')).toBe(true)
  fireEvent.click(button)
  expect(guestRequests(fetchMock)).toHaveLength(0)
})

test('production account dialog blocks guest creation until it closes', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork()
  render(<StrictMode><App /></StrictMode>)
  await readyForAccess()
  await user.click(screen.getByRole('button', { name: 'Sign In' }))
  const dialog = screen.getByRole('dialog', { name: 'Sign in' })
  expect(within(dialog).getByLabelText('Email')).toBeDefined()
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  expect(guestRequests(fetchMock)).toHaveLength(0)
  fireEvent(dialog, new Event('cancel', { cancelable: true }))
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(false)
})
