import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { CURRENT_TERMS_VERSION } from '../shared/account-terms'
import App from './App'
import { loadTurnstile, type TurnstileApi } from './lib/turnstile'

vi.mock('./lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

const email = 'new-owner@example.test'
const password = 'synthetic-password'
const session = { user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z', absolute_expires_at: '2030-01-30T12:00:00Z' }
const prototype = HTMLDialogElement.prototype
const originalShow = Object.getOwnPropertyDescriptor(prototype, 'showModal')
const originalClose = Object.getOwnPropertyDescriptor(prototype, 'close')
let api: TurnstileApi

beforeEach(() => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_GUEST_ACCESS_ENABLED', 'false')
  vi.stubEnv('VITE_ACCOUNT_RECOVERY_ENABLED', 'false')
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  vi.stubEnv('VITE_ACCOUNT_REGISTRATION_ENABLED', 'true')
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'true')
  vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', 'https://example.supabase.co/auth/v1')
  vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'public-test-site-key')
  Object.defineProperty(prototype, 'showModal', { configurable: true,
    value: function (this: HTMLDialogElement) { this.open = true } })
  Object.defineProperty(prototype, 'close', { configurable: true,
    value: function (this: HTMLDialogElement) { this.open = false } })
  api = { ready: callback => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'registration-widget'), reset: vi.fn(), remove: vi.fn() }
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

function mockNetwork(options: { missingAgreement?: boolean; rejectCodeOnce?: boolean; signUpStatus?: number; signUpPending?: Promise<Response> } = {}) {
  let signedIn = false
  let confirmed = false
  let codeRejected = false
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
    if (url === '/api/v1/health') return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
    if (url === '/api/v1/account/session') return signedIn ? Response.json(session) : new Response(null, { status: 401 })
    if (url === '/api/v1/account/sign-up') {
      expect(JSON.parse(String(init?.body))).toEqual({ email, password, captcha_token: 'signup-proof',
        accepted: true, terms_version: CURRENT_TERMS_VERSION })
      if (options.signUpPending) return options.signUpPending
      if (options.signUpStatus) return Response.json({ detail: 'private-provider-detail' }, {
        status: options.signUpStatus, headers: { 'Retry-After': '31' },
      })
      return Response.json({ status: 'accepted' }, { status: 202 })
    }
    if (url === '/api/v1/account/confirm-email') {
      expect(JSON.parse(String(init?.body))).toEqual({ email, code: '00001234' })
      if (options.rejectCodeOnce && !codeRejected) {
        codeRejected = true
        return Response.json({ detail: 'private-provider-detail' }, { status: 400 })
      }
      confirmed = true
      return Response.json({ status: 'confirmed' })
    }
    if (url === '/api/v1/account/sign-in') {
      expect(confirmed).toBe(true)
      expect(JSON.parse(String(init?.body))).toEqual({ email, password, captcha_token: 'signin-proof' })
      signedIn = true
      return Response.json(session)
    }
    if (url === '/api/v1/account/terms/status') {
      expect(signedIn).toBe(true)
      return Response.json({ terms_version: CURRENT_TERMS_VERSION,
        accepted_at: options.missingAgreement ? null : new Date(Date.now() - 1000).toISOString(),
        acceptance_required: Boolean(options.missingAgreement) })
    }
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

async function openSignUp(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Sign In' }))
  await user.click(screen.getByRole('button', { name: 'Create account' }))
  const dialog = screen.getByRole('dialog', { name: 'Create account' })
  await within(dialog).findByText('Complete the check to continue.')
  await user.type(within(dialog).getByLabelText('Email'), email)
  await user.type(within(dialog).getByLabelText('Password', { exact: true }), password)
  const widget = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!widget) throw new Error('Expected the sign-up verification widget')
  expect(widget.action).toBe('account_sign_up')
  act(() => widget.callback('signup-proof'))
  return dialog
}

async function submitSignUp(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement) {
  await user.click(within(dialog).getByRole('checkbox'))
  await user.click(within(dialog).getByRole('button', { name: 'Create account' }))
}

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production registration flag %s hides navigation while preserving email and Google sign-in', async (flag) => {
  vi.stubEnv('VITE_ACCOUNT_REGISTRATION_ENABLED', flag)
  const fetchMock = mockNetwork()
  render(<StrictMode><App /></StrictMode>)
  await userEvent.setup().click(await screen.findByRole('button', { name: 'Sign In' }))
  const dialog = screen.getByRole('dialog', { name: 'Sign in' })
  expect(within(dialog).queryByRole('button', { name: 'Create account' })).toBeNull()
  expect(within(dialog).queryByRole('button', { name: 'Forgot password?' })).toBeNull()
  expect(within(dialog).getByRole('button', { name: 'Continue with Google' }).hasAttribute('disabled')).toBe(false)
  expect((within(dialog).getByLabelText('Email') as HTMLInputElement).closest('fieldset')?.disabled).toBe(false)
  expect(fetchMock.mock.calls.every(([url]) => ['/api/v1/health', '/api/v1/account/session'].includes(String(url)))).toBe(true)
})

test('registration opt-in cannot open the production account dialog when the account flag is off', async () => {
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'false')
  const fetchMock = mockNetwork()
  render(<StrictMode><App /></StrictMode>)
  await waitFor(() => expect(screen.queryByText('Starting the service… This may take about a minute.')).toBeNull())
  expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(true)
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
  expect(loadTurnstile).not.toHaveBeenCalled()
})

test.each([false, true])('production sign-up requires Terms, preserves leading code zeros and waits for separate sign-in; agreement missing: %s', async (missingAgreement) => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ missingAgreement })
  render(<StrictMode><App /></StrictMode>)
  const dialog = await openSignUp(user)
  const checkbox = within(dialog).getByRole('checkbox') as HTMLInputElement
  expect(checkbox.checked).toBe(false)
  expect(within(dialog).getByRole('button', { name: 'Create account' }).hasAttribute('disabled')).toBe(true)
  fireEvent.submit(within(dialog).getByRole('form', { name: 'Create account' }))
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-up')).toHaveLength(0)
  await submitSignUp(user, dialog)
  const confirmation = await screen.findByRole('dialog', { name: 'Confirm your email' })
  expect(within(confirmation).getByText(email)).toBeDefined()
  expect(within(confirmation).queryByLabelText('Password', { exact: true })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  await user.type(within(confirmation).getByLabelText('Verification code'), '00001234')
  await user.click(within(confirmation).getByRole('button', { name: 'Confirm email' }))
  await within(confirmation).findByText('Email confirmed. You can now sign in.')
  expect((within(confirmation).getByLabelText('Verification code') as HTMLInputElement).value).toBe('')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(0)
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  await user.click(within(confirmation).getByRole('button', { name: 'Continue to sign in' }))
  const signIn = screen.getByRole('dialog', { name: 'Sign in' })
  expect((within(signIn).getByLabelText('Email') as HTMLInputElement).value).toBe(email)
  expect((within(signIn).getByLabelText('Password', { exact: true }) as HTMLInputElement).value).toBe('')
  expect(within(signIn).queryByRole('button', { name: 'Forgot password?' })).toBeNull()
  await within(signIn).findByText('Complete the check to continue.')
  await user.type(within(signIn).getByLabelText('Password', { exact: true }), password)
  const widget = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!widget) throw new Error('Expected a fresh sign-in widget')
  expect(widget.action).toBe('account_sign_in')
  act(() => widget.callback('signin-proof'))
  await user.click(within(signIn).getByRole('button', { name: 'Sign in' }))
  await screen.findByRole('button', { name: 'Signed in' })
  if (missingAgreement) {
    const setup = await screen.findByRole('dialog', { name: 'Finish account setup' })
    expect((within(setup).getByRole('checkbox') as HTMLInputElement).checked).toBe(false)
  } else {
    await screen.findByText('Account setup complete.')
    expect(screen.queryByRole('dialog')).toBeNull()
  }
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-up')).toHaveLength(1)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/confirm-email')).toHaveLength(1)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(1)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/terms/accept')).toHaveLength(0)
})

test('a rejected code is cleared, leaves the account signed out and retries only on request', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ rejectCodeOnce: true })
  render(<StrictMode><App /></StrictMode>)
  await submitSignUp(user, await openSignUp(user))
  const confirmation = await screen.findByRole('dialog', { name: 'Confirm your email' })
  await user.type(within(confirmation).getByLabelText('Verification code'), '00001234')
  await user.click(within(confirmation).getByRole('button', { name: 'Confirm email' }))
  await within(confirmation).findByText('Email confirmation was rejected. Check your email and code, then try again.')
  expect((within(confirmation).getByLabelText('Verification code') as HTMLInputElement).value).toBe('')
  expect(document.body.textContent).not.toContain('private-provider-detail')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/confirm-email')).toHaveLength(1)
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  await user.type(within(confirmation).getByLabelText('Verification code'), '00001234')
  await user.click(within(confirmation).getByRole('button', { name: 'Confirm email' }))
  await within(confirmation).findByText('Email confirmed. You can now sign in.')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/confirm-email')).toHaveLength(2)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(0)
})

test('registration rate limiting keeps the dialog open without leaking details or retrying', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ signUpStatus: 429 })
  render(<StrictMode><App /></StrictMode>)
  const dialog = await openSignUp(user)
  await submitSignUp(user, dialog)
  await within(dialog).findByText('Too many sign-up attempts. Please wait 31 seconds before trying again.')
  expect((within(dialog).getByLabelText('Password', { exact: true }) as HTMLInputElement).value).toBe('')
  expect(within(dialog).getByRole('button', { name: 'Create account' }).hasAttribute('disabled')).toBe(true)
  expect(document.body.textContent).not.toContain('private-provider-detail')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-up')).toHaveLength(1)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/confirm-email')).toHaveLength(0)
})

test('closing pending registration aborts and ignores late acceptance', async () => {
  let complete!: (response: Response) => void
  const pending = new Promise<Response>(resolve => { complete = resolve })
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ signUpPending: pending })
  render(<StrictMode><App /></StrictMode>)
  const dialog = await openSignUp(user)
  await submitSignUp(user, dialog)
  const signal = fetchMock.mock.calls.find(([url]) => url === '/api/v1/account/sign-up')?.[1]?.signal
  fireEvent(dialog, new Event('cancel', { cancelable: true }))
  expect(signal?.aborted).toBe(true)
  await act(async () => { complete(Response.json({ status: 'accepted' }, { status: 202 })); await pending })
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/confirm-email')).toHaveLength(0)
})
