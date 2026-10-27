import { StrictMode } from 'react'
import { act, cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { CURRENT_TERMS_VERSION } from '../shared/account-terms'
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
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'public-test-site-key')
  // This separate flag must not open Google during the email-only rollout.
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'true')
  vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', 'https://example.supabase.co/auth/v1')
  Object.defineProperty(prototype, 'showModal', {
    configurable: true,
    value: function (this: HTMLDialogElement) { this.open = true },
  })
  Object.defineProperty(prototype, 'close', {
    configurable: true,
    value: function (this: HTMLDialogElement) { this.open = false },
  })
  api = {
    ready: (callback) => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'production-sign-in-widget'),
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

function mockNetwork(options: { signedIn?: boolean; accepted?: boolean; rejectSignIn?: boolean; failSignOut?: boolean } = {}) {
  let signedIn = options.signedIn ?? false
  let acceptedAt = options.accepted ? new Date(Date.now() - 1000).toISOString() : null
  let signOutFailed = false
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
    if (url === '/api/v1/health') {
      return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
    }
    if (url === '/api/v1/account/session') {
      return signedIn ? Response.json(session) : new Response(null, { status: 401 })
    }
    if (url === '/api/v1/account/sign-in') {
      if (options.rejectSignIn) return Response.json({ detail: 'private-provider-detail' }, { status: 401 })
      signedIn = true
      return Response.json(session)
    }
    if (url === '/api/v1/account/terms/status' || url === '/api/v1/account/terms/accept') {
      expect(signedIn).toBe(true)
      expect(new Headers(init?.headers).get('X-Account-Subject')).toBe(session.user_id)
      if (url.endsWith('/accept')) {
        expect(JSON.parse(String(init?.body))).toEqual({ accepted: true, terms_version: CURRENT_TERMS_VERSION })
        acceptedAt = new Date(Date.now() - 1000).toISOString()
        return Response.json({ terms_version: CURRENT_TERMS_VERSION, accepted_at: acceptedAt })
      }
      return Response.json({ terms_version: CURRENT_TERMS_VERSION, accepted_at: acceptedAt, acceptance_required: acceptedAt === null })
    }
    if (url === '/api/v1/account/sign-out') {
      if (options.failSignOut && !signOutFailed) {
        signOutFailed = true
        return new Response(null, { status: 503 })
      }
      signedIn = false
      return new Response(null, { status: 204 })
    }
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

async function enterCredentials(user: ReturnType<typeof userEvent.setup>) {
  const trigger = await screen.findByRole('button', { name: 'Sign In' })
  expect(trigger.hasAttribute('disabled')).toBe(false)
  await user.click(trigger)
  await screen.findByText('Complete the check to continue.')
  const dialog = screen.getByRole('dialog', { name: 'Sign in' })
  expect(within(dialog).queryByRole('button', { name: 'Create account' })).toBeNull()
  expect(within(dialog).queryByRole('button', { name: 'Forgot password?' })).toBeNull()
  expect(within(dialog).queryByRole('button', { name: /Google/ })).toBeNull()
  await user.type(within(dialog).getByLabelText('Email'), 'owner@example.test')
  await user.type(within(dialog).getByLabelText('Password', { exact: true }), 'synthetic-password')
  const widget = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!widget) throw new Error('Expected a verification widget')
  expect(widget.action).toBe('account_sign_in')
  act(() => widget.callback('synthetic-proof'))
  await user.click(within(dialog).getByRole('button', { name: 'Sign in' }))
  return dialog
}

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production flag %s leaves the App closed without account or widget requests', async (flag) => {
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', flag)
  const fetchMock = mockNetwork()
  render(<StrictMode><App /></StrictMode>)
  await screen.findByText('API connected')
  const trigger = screen.getByRole('button', { name: 'Sign In' })
  expect(trigger.hasAttribute('disabled')).toBe(true)
  await userEvent.setup().click(trigger)
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
  expect(loadTurnstile).not.toHaveBeenCalled()
})

test('production opt-in signs in, completes explicit Terms, restores after remount, and signs out', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork()
  let view = render(<StrictMode><App /></StrictMode>)
  const dialog = await enterCredentials(user)
  expect(dialog.hasAttribute('open')).toBe(false)
  const setup = await screen.findByRole('dialog', { name: 'Finish account setup' })
  const checkbox = within(setup).getByRole('checkbox') as HTMLInputElement
  expect(checkbox.checked).toBe(false)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/terms/accept')).toHaveLength(0)
  await user.click(checkbox)
  await user.click(within(setup).getByRole('button', { name: 'Finish setup' }))
  await screen.findByText('Account setup complete.')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(1)
  const request = fetchMock.mock.calls.find(([url]) => url === '/api/v1/account/sign-in')?.[1]
  expect(JSON.parse(String(request?.body))).toEqual({
    email: 'owner@example.test', password: 'synthetic-password', captcha_token: 'synthetic-proof',
  })
  expect(request?.credentials).toBe('same-origin')

  view.unmount()
  view = render(<StrictMode><App /></StrictMode>)
  await screen.findByText('Account setup complete.')
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/session')).toHaveLength(2)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/terms/accept')).toHaveLength(1)
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  await user.click(screen.getByRole('button', { name: 'Sign out' }))
  const trigger = await screen.findByRole('button', { name: 'Sign In' })
  expect(document.activeElement).toBe(trigger)
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull()

  view.unmount()
  render(<StrictMode><App /></StrictMode>)
  expect((await screen.findByRole('button', { name: 'Sign In' })).hasAttribute('disabled')).toBe(false)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/session')).toHaveLength(3)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-out')).toHaveLength(1)
  const allowed = ['/api/v1/health', '/api/v1/account/session', '/api/v1/account/sign-in',
    '/api/v1/account/sign-out', '/api/v1/account/terms/status', '/api/v1/account/terms/accept']
  expect(fetchMock.mock.calls.every(([url]) => allowed.includes(String(url)))).toBe(true)
})

test('production sign-out failure keeps the restored identity until manual retry succeeds', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ signedIn: true, accepted: true, failSignOut: true })
  render(<StrictMode><App /></StrictMode>)
  await screen.findByText('Account setup complete.')
  await user.click(screen.getByRole('button', { name: 'Sign out' }))
  await screen.findByText('Sign-out could not be completed. Please try again.')
  expect(screen.getByRole('button', { name: 'Signed in' }).hasAttribute('disabled')).toBe(true)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-out')).toHaveLength(1)
  await user.click(screen.getByRole('button', { name: 'Sign out' }))
  await screen.findByRole('button', { name: 'Sign In' })
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-out')).toHaveLength(2)
})

test('production rejected sign-in stays signed out and consumes the proof without retrying', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ rejectSignIn: true })
  render(<StrictMode><App /></StrictMode>)
  const dialog = await enterCredentials(user)
  await within(dialog).findByText('Sign-in was rejected. Check your details and try again.')
  expect((within(dialog).getByLabelText('Password', { exact: true }) as HTMLInputElement).value).toBe('')
  expect(within(dialog).getByRole('button', { name: 'Sign in' }).hasAttribute('disabled')).toBe(true)
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  expect(document.body.textContent).not.toContain('private-provider-detail')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(1)
  expect(fetchMock.mock.calls.filter(([url]) => String(url).startsWith('/api/v1/account/terms/'))).toHaveLength(0)
})
