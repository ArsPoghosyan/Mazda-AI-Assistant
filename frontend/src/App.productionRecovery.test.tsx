import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { CURRENT_TERMS_VERSION } from '../shared/account-terms'
import App from './App'
import { loadTurnstile, type TurnstileApi } from './lib/turnstile'

vi.mock('./lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

const email = 'owner@example.test'
const newPassword = '  synthetic-new-password  '
const session = { user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z', absolute_expires_at: '2030-01-30T12:00:00Z' }
const prototype = HTMLDialogElement.prototype
const originalShow = Object.getOwnPropertyDescriptor(prototype, 'showModal')
const originalClose = Object.getOwnPropertyDescriptor(prototype, 'close')
let api: TurnstileApi

beforeEach(() => {
  vi.stubEnv('DEV', false)
  vi.stubEnv('VITE_GUEST_ACCESS_ENABLED', 'false')
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'true')
  vi.stubEnv('VITE_ACCOUNT_RECOVERY_ENABLED', 'true')
  vi.stubEnv('VITE_ACCOUNT_REGISTRATION_ENABLED', 'false')
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'false')
  vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'public-test-site-key')
  Object.defineProperty(prototype, 'showModal', { configurable: true,
    value: function (this: HTMLDialogElement) { this.open = true } })
  Object.defineProperty(prototype, 'close', { configurable: true,
    value: function (this: HTMLDialogElement) { this.open = false } })
  api = { ready: callback => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'recovery-widget'), reset: vi.fn(), remove: vi.fn() }
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

function mockNetwork(options: { rejectResetOnce?: boolean; recoveryStatus?: number } = {}) {
  let recovered = false
  let rejected = false
  let signedIn = false
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
    if (url === '/api/v1/health') return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
    if (url === '/api/v1/account/session') return signedIn ? Response.json(session) : new Response(null, { status: 401 })
    if (url === '/api/v1/account/password-recovery') {
      expect(JSON.parse(String(init?.body))).toEqual({ email, captcha_token: 'recovery-proof' })
      if (options.recoveryStatus) return Response.json({ detail: 'private-provider-detail' }, { status: options.recoveryStatus })
      return Response.json({ status: 'accepted' }, { status: 202 })
    }
    if (url === '/api/v1/account/password-reset') {
      expect(JSON.parse(String(init?.body))).toEqual({ email, code: '00001234', new_password: newPassword })
      if (options.rejectResetOnce && !rejected) {
        rejected = true
        return Response.json({ detail: 'private-provider-detail' }, { status: 400 })
      }
      recovered = true
      return Response.json({ status: 'completed' })
    }
    if (url === '/api/v1/account/sign-in') {
      expect(recovered).toBe(true)
      expect(JSON.parse(String(init?.body))).toEqual({ email, password: newPassword, captcha_token: 'signin-proof' })
      signedIn = true
      return Response.json(session)
    }
    if (url === '/api/v1/account/terms/status') {
      expect(signedIn).toBe(true)
      return Response.json({ terms_version: CURRENT_TERMS_VERSION,
        accepted_at: new Date(Date.now() - 1000).toISOString(), acceptance_required: false })
    }
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

async function openSignIn(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Sign In' }))
  return screen.getByRole('dialog', { name: 'Sign in' })
}

async function openRecovery(user: ReturnType<typeof userEvent.setup>) {
  const dialog = await openSignIn(user)
  await user.type(within(dialog).getByLabelText('Email'), email)
  await user.type(within(dialog).getByLabelText('Password', { exact: true }), 'synthetic-old-password')
  await user.click(within(dialog).getByRole('button', { name: 'Forgot password?' }))
  const recovery = await screen.findByRole('dialog', { name: 'Recover your password' })
  await within(recovery).findByText('Complete the check to continue.')
  expect(within(recovery).getByLabelText<HTMLInputElement>('Email').value).toBe(email)
  expect(within(recovery).queryByLabelText('Password', { exact: true })).toBeNull()
  return recovery
}

function completeCheck(action: 'account_password_recovery' | 'account_sign_in', proof: string) {
  const widget = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!widget) throw new Error('Expected a verification widget')
  expect(widget.action).toBe(action)
  act(() => widget.callback(proof))
}

test.each([undefined, '', 'false', 'TRUE', '1', 'true '])('production recovery flag %s hides recovery without making requests', async flag => {
  vi.stubEnv('VITE_ACCOUNT_RECOVERY_ENABLED', flag)
  const fetchMock = mockNetwork()
  render(<StrictMode><App /></StrictMode>)
  const dialog = await openSignIn(userEvent.setup())
  expect(within(dialog).queryByRole('button', { name: 'Forgot password?' })).toBeNull()
  expect(fetchMock.mock.calls.every(([url]) => ['/api/v1/health', '/api/v1/account/session'].includes(String(url)))).toBe(true)
})

test('recovery opt-in alone cannot open disabled production account controls', async () => {
  vi.stubEnv('VITE_ACCOUNT_AUTH_ENABLED', 'false')
  const fetchMock = mockNetwork()
  render(<StrictMode><App /></StrictMode>)
  await waitFor(() => expect(screen.queryByText('Starting the service… This may take about a minute.')).toBeNull())
  expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(true)
  expect(fetchMock.mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
  expect(loadTurnstile).not.toHaveBeenCalled()
})

test.each([false, true])('production recovery and reset require separate sign-in, preserving code zeros; rejected code first: %s', async rejectResetOnce => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ rejectResetOnce })
  render(<StrictMode><App /></StrictMode>)
  const recovery = await openRecovery(user)
  fireEvent.submit(within(recovery).getByRole('form', { name: 'Recover your password' }))
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/password-recovery')).toHaveLength(0)
  completeCheck('account_password_recovery', 'recovery-proof')
  await user.click(within(recovery).getByRole('button', { name: 'Send recovery code' }))
  const reset = await screen.findByRole('dialog', { name: 'Reset your password' })
  expect(reset).toBe(recovery)
  expect(within(reset).queryByText('Human verification')).toBeNull()
  const code = within(reset).getByLabelText<HTMLInputElement>('Recovery code')
  const password = within(reset).getByLabelText<HTMLInputElement>('New password')
  async function submitReset() {
    await user.type(code, '00001234')
    await user.type(password, newPassword)
    await user.click(within(reset).getByRole('button', { name: 'Reset password' }))
  }
  await submitReset()
  if (rejectResetOnce) {
    await within(reset).findByText('Password reset was rejected. Check your email, code and new password, then try again.')
    expect(code.value).toBe('')
    expect(password.value).toBe('')
    expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/password-reset')).toHaveLength(1)
    expect(document.body.textContent).not.toContain('private-provider-detail')
    await submitReset()
  }
  await within(reset).findByText('Password reset completed. Sign in with your new password.')
  expect(code.value).toBe('')
  expect(password.value).toBe('')
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')).toHaveLength(0)
  expect(screen.queryByRole('button', { name: 'Signed in' })).toBeNull()
  await user.click(within(reset).getByRole('button', { name: 'Continue to sign in' }))
  const signIn = screen.getByRole('dialog', { name: 'Sign in' })
  await within(signIn).findByText('Complete the check to continue.')
  expect(within(signIn).getByLabelText<HTMLInputElement>('Email').value).toBe(email)
  expect(within(signIn).getByLabelText<HTMLInputElement>('Password', { exact: true }).value).toBe('')
  await user.type(within(signIn).getByLabelText('Password', { exact: true }), newPassword)
  completeCheck('account_sign_in', 'signin-proof')
  await user.click(within(signIn).getByRole('button', { name: 'Sign in' }))
  await screen.findByRole('button', { name: 'Signed in' })
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/password-recovery')).toHaveLength(1)
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/password-reset')).toHaveLength(rejectResetOnce ? 2 : 1)
})

test('production existing-code navigation sends no email and Escape restores focus', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork()
  render(<StrictMode><App /></StrictMode>)
  const recovery = await openRecovery(user)
  await user.click(within(recovery).getByRole('button', { name: 'I already have a recovery code' }))
  const reset = await screen.findByRole('dialog', { name: 'Reset your password' })
  await user.click(within(reset).getByRole('button', { name: 'Request another code' }))
  await screen.findByRole('dialog', { name: 'Recover your password' })
  expect(fetchMock.mock.calls.every(([url]) => ['/api/v1/health', '/api/v1/account/session'].includes(String(url)))).toBe(true)
  fireEvent(recovery, new Event('cancel', { cancelable: true }))
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Sign In' }))
})

test('production recovery failure stays private and never retries or opens reset automatically', async () => {
  const user = userEvent.setup()
  const fetchMock = mockNetwork({ recoveryStatus: 503 })
  render(<StrictMode><App /></StrictMode>)
  const recovery = await openRecovery(user)
  completeCheck('account_password_recovery', 'recovery-proof')
  await user.click(within(recovery).getByRole('button', { name: 'Send recovery code' }))
  await within(recovery).findByText('Password recovery could not be requested. Please try again.')
  expect(document.body.textContent).not.toContain('private-provider-detail')
  expect(screen.queryByRole('dialog', { name: 'Reset your password' })).toBeNull()
  expect(fetchMock.mock.calls.filter(([url]) => url === '/api/v1/account/password-recovery')).toHaveLength(1)
  expect(within(recovery).getByRole('button', { name: 'Send recovery code' }).hasAttribute('disabled')).toBe(true)
})
