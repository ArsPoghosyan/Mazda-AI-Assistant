import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountSignUpRejectedError,
  signUpAccount,
  type AccountSignUpResponse,
} from '../api/account-registration'
import { GoogleSignInRateLimitedError, startGoogleSignIn, type GoogleLoginStartResponse } from '../api/google'
import { loadTurnstile, type TurnstileApi } from '../lib/turnstile'
import AccountSignUpForm from './AccountSignUpForm'

const { navigate } = vi.hoisted(() => ({ navigate: vi.fn<(url: string) => void>() }))

vi.mock('../hooks/useGoogleSignIn', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../hooks/useGoogleSignIn')>()
  return {
    useGoogleSignIn: function useTestGoogleSignIn() {
      return actual.useGoogleSignIn(navigate)
    },
  }
})
vi.mock('../api/google', async (importOriginal) => ({
  ...await importOriginal<typeof import('../api/google')>(), startGoogleSignIn: vi.fn(),
}))
vi.mock('../api/account-registration', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/account-registration')>()
  return { ...actual, signUpAccount: vi.fn() }
})
vi.mock('../lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

const destination = 'https://auth.example.test/auth/v1/authorize?provider=google'
const acknowledgement: AccountSignUpResponse = { status: 'accepted' }
let api: TurnstileApi

function googleResult(): GoogleLoginStartResponse {
  return { authorization_url: destination, expires_at: new Date(Date.now() + 600_000).toISOString() }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((complete) => { resolve = complete })
  return { promise, resolve }
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'true')
  vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', 'https://auth.example.test/auth/v1')
  vi.mocked(startGoogleSignIn).mockReset()
  vi.mocked(signUpAccount).mockReset()
  navigate.mockReset()
  api = {
    ready: (callback) => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'registration-google-widget'),
    reset: vi.fn(), remove: vi.fn(),
  }
  vi.mocked(loadTurnstile).mockReset()
  vi.mocked(loadTurnstile).mockResolvedValue(api)
})

afterEach(() => {
  cleanup()
  vi.unstubAllEnvs()
})

function widgetOptions(index = 0) {
  const options = vi.mocked(api.render).mock.calls[index]?.[1]
  if (!options) throw new Error('Expected the email registration widget')
  return options
}

async function mountForm() {
  const onClose = vi.fn()
  const onSignIn = vi.fn()
  const onAccepted = vi.fn()
  const user = userEvent.setup()
  const view = render(
    <StrictMode>
      <AccountSignUpForm siteKey="public-test-site-key" onClose={onClose}
        onSignIn={onSignIn} onAccepted={onAccepted} />
    </StrictMode>,
  )
  await screen.findByText('Complete the check to continue.')
  return {
    user, view, onClose, onSignIn, onAccepted,
    form: screen.getByRole('form', { name: 'Create account' }),
    email: screen.getByLabelText<HTMLInputElement>('Email'),
    password: screen.getByLabelText<HTMLInputElement>('Password', { exact: true }),
  }
}

test.each(['disabled', 'production', 'missing-issuer'])(
  'preserves email-only registration when Google is %s', (reason) => {
    if (reason === 'disabled') vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'false')
    if (reason === 'production') vi.stubEnv('DEV', false)
    if (reason === 'missing-issuer') vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', '')
    render(<AccountSignUpForm siteKey="public-test-key" onClose={vi.fn()} onAccepted={vi.fn()} />)
    expect(screen.queryByRole('button', { name: 'Continue with Google' })).toBeNull()
    expect(screen.getByText('Enter your email and choose a password. Confirm your email before signing in.')).toBeDefined()
    expect(startGoogleSignIn).not.toHaveBeenCalled()
    expect(signUpAccount).not.toHaveBeenCalled()
  },
)

test('Google account creation starts without credentials or a local CAPTCHA proof', async () => {
  const pending = deferred<GoogleLoginStartResponse>()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(pending.promise)
  const { user, email, password, onAccepted, onSignIn } = await mountForm()
  const google = screen.getByRole('button', { name: 'Continue with Google' })
  expect(google.getAttribute('type')).toBe('button')
  expect(email.value).toBe('')
  expect(password.value).toBe('')
  await user.click(google)
  expect(startGoogleSignIn).toHaveBeenCalledExactlyOnceWith(
    'https://auth.example.test/auth/v1',
    `${window.location.origin}/api/v1/account/google/callback`,
    expect.any(AbortSignal),
  )
  expect(signUpAccount).not.toHaveBeenCalled()
  expect(google.getAttribute('aria-busy')).toBe('true')
  expect(google.hasAttribute('disabled')).toBe(true)
  const status = document.getElementById(google.getAttribute('aria-describedby') ?? '')
  expect(status?.getAttribute('role')).toBe('status')
  expect(status?.textContent).toBe('Opening Google sign-in…')
  expect(email.closest('fieldset')?.disabled).toBe(true)
  expect(screen.queryByText('Human verification')).toBeNull()
  expect(screen.getByRole('button', { name: 'Back to sign in' }).hasAttribute('disabled')).toBe(true)
  expect(screen.getByRole('button', { name: 'Close registration' }).hasAttribute('disabled')).toBe(false)

  await act(async () => { pending.resolve(googleResult()); await pending.promise })
  expect(navigate).toHaveBeenCalledExactlyOnceWith(destination)
  expect(status?.textContent).toBe('Redirecting to Google…')
  expect(onAccepted).not.toHaveBeenCalled()
  expect(onSignIn).not.toHaveBeenCalled()
})

test('Google wins a same-render race, clears the password and invalidates the old proof', async () => {
  const pending = deferred<GoogleLoginStartResponse>()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(pending.promise)
  const { user, form, email, password, onSignIn, view } = await mountForm()
  await user.type(email, 'owner@example.test')
  await user.type(password, 'synthetic-private-password')
  await user.click(screen.getByRole('button', { name: 'Show password' }))
  const old = widgetOptions()
  act(() => old.callback('old-proof'))
  const google = screen.getByRole('button', { name: 'Continue with Google' })
  const back = screen.getByRole('button', { name: 'Back to sign in' })
  act(() => {
    fireEvent.click(google)
    fireEvent.submit(form)
    fireEvent.click(google)
    fireEvent.click(back)
    old.callback('late-proof')
  })
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(signUpAccount).not.toHaveBeenCalled()
  expect(onSignIn).not.toHaveBeenCalled()
  expect(password.value).toBe('')
  expect(password.type).toBe('password')
  expect(email.value).toBe('owner@example.test')
  view.unmount()
  expect(vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]?.aborted).toBe(true)
  await act(async () => { pending.resolve(googleResult()); await pending.promise })
  expect(navigate).not.toHaveBeenCalled()
})

test('email registration wins a same-render race and blocks Google after acknowledgement', async () => {
  const pending = deferred<AccountSignUpResponse>()
  vi.mocked(signUpAccount).mockReturnValueOnce(pending.promise)
  const { user, form, email, password, onSignIn, onAccepted } = await mountForm()
  await user.type(email, 'owner@example.test')
  await user.type(password, 'synthetic-private-password')
  fireEvent.click(screen.getByRole('checkbox'))
  act(() => widgetOptions().callback('email-proof'))
  const google = screen.getByRole('button', { name: 'Continue with Google' })
  const back = screen.getByRole('button', { name: 'Back to sign in' })
  act(() => {
    fireEvent.submit(form)
    fireEvent.click(google)
    fireEvent.click(back)
  })
  expect(signUpAccount).toHaveBeenCalledTimes(1)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  expect(onSignIn).not.toHaveBeenCalled()
  expect(google.hasAttribute('disabled')).toBe(true)
  await act(async () => { pending.resolve(acknowledgement); await pending.promise })
  expect(onAccepted).toHaveBeenCalledExactlyOnceWith('owner@example.test')
  fireEvent.click(google)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
})

test.each([
  [new Error('Google sign-in is temporarily unavailable.'), 'Google sign-in is temporarily unavailable.'],
  [new GoogleSignInRateLimitedError('61'), 'Too many Google sign-in attempts. Please wait 61 seconds before trying again.'],
] as const)('a failed Google start %s allows email registration only with a fresh password and proof', async (error, message) => {
  vi.mocked(startGoogleSignIn).mockRejectedValueOnce(error)
  vi.mocked(signUpAccount).mockResolvedValueOnce(acknowledgement)
  const { user, form, email, password, onAccepted } = await mountForm()
  await user.type(email, 'owner@example.test')
  await user.type(password, 'synthetic-private-password')
  const old = widgetOptions()
  act(() => old.callback('old-proof'))
  await user.click(screen.getByRole('button', { name: 'Continue with Google' }))
  await screen.findByText(message)
  await screen.findByText('Complete the check to continue.')
  expect(email.closest('fieldset')?.disabled).toBe(false)
  expect(password.value).toBe('')
  act(() => { old.callback('late-proof'); fireEvent.submit(form) })
  expect(signUpAccount).not.toHaveBeenCalled()
  expect(screen.getByRole('button', { name: 'Create account' }).hasAttribute('disabled')).toBe(true)
  fireEvent.click(screen.getByRole('checkbox'))
  await user.type(password, 'fresh-password')
  act(() => widgetOptions(1).callback('fresh-proof'))
  await user.click(screen.getByRole('button', { name: 'Create account' }))
  expect(vi.mocked(signUpAccount).mock.calls[0]?.[0]).toEqual({
    email: 'owner@example.test', password: 'fresh-password', captcha_token: 'fresh-proof', accepted: true, terms_version: '2026-10-28',
  })
  expect(onAccepted).toHaveBeenCalledExactlyOnceWith('owner@example.test')
  expect(navigate).not.toHaveBeenCalled()
})

test('a rejected email registration releases the Google option for an explicit start', async () => {
  vi.mocked(signUpAccount).mockRejectedValueOnce(new AccountSignUpRejectedError())
  vi.mocked(startGoogleSignIn).mockResolvedValueOnce(googleResult())
  const { user, form, email, password, onAccepted } = await mountForm()
  await user.type(email, 'owner@example.test')
  await user.type(password, 'synthetic-private-password')
  fireEvent.click(screen.getByRole('checkbox'))
  act(() => widgetOptions().callback('email-proof'))
  fireEvent.submit(form)
  await screen.findByText('Registration was rejected. Check your details and try again.')
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  await user.click(screen.getByRole('button', { name: 'Continue with Google' }))
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(navigate).toHaveBeenCalledExactlyOnceWith(destination)
  expect(onAccepted).not.toHaveBeenCalled()
})

test.each([
  ['1', 'Too many Google sign-in attempts. Please wait 1 second before trying again.'],
  ['61', 'Too many Google sign-in attempts. Please wait 61 seconds before trying again.'],
  [null, 'Too many Google sign-in attempts. Please try again later.'],
  ['private-provider-detail', 'Too many Google sign-in attempts. Please try again later.'],
] as const)('registration announces a Google limit %s and permits manual retry', async (header, message) => {
  vi.mocked(startGoogleSignIn).mockRejectedValueOnce(new GoogleSignInRateLimitedError(header))
    .mockResolvedValueOnce(googleResult())
  const { user, password, onAccepted, onSignIn } = await mountForm()
  await user.type(password, 'synthetic-private-password')
  await user.click(screen.getByRole('button', { name: 'Show password' }))
  const google = screen.getByRole('button', { name: 'Continue with Google' })
  await user.click(google)
  const feedback = await screen.findByText(message)
  expect(feedback.getAttribute('role')).toBe('status')
  expect(feedback.getAttribute('aria-atomic')).toBe('true')
  expect(google.getAttribute('aria-describedby')).toBe(feedback.id)
  expect(google.hasAttribute('disabled')).toBe(false)
  expect(google.getAttribute('aria-busy')).toBe('false')
  expect(password.value).toBe('')
  expect(password.type).toBe('password')
  expect(screen.queryByText('private-provider-detail')).toBeNull()
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(signUpAccount).not.toHaveBeenCalled()
  expect(navigate).not.toHaveBeenCalled()
  expect(onAccepted).not.toHaveBeenCalled()
  expect(onSignIn).not.toHaveBeenCalled()
  await user.click(google)
  expect(startGoogleSignIn).toHaveBeenCalledTimes(2)
  expect(navigate).toHaveBeenCalledExactlyOnceWith(destination)
  expect(screen.queryByText(message)).toBeNull()
})

test('Google errors hide provider details and retry only on another explicit click', async () => {
  vi.mocked(startGoogleSignIn).mockRejectedValueOnce(new Error('private-provider-detail'))
    .mockResolvedValueOnce(googleResult())
  const { user } = await mountForm()
  const google = screen.getByRole('button', { name: 'Continue with Google' })
  await user.click(google)
  await screen.findByText('Google sign-in could not be started. Please try again.')
  expect(screen.queryByText('private-provider-detail')).toBeNull()
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  await user.click(google)
  expect(startGoogleSignIn).toHaveBeenCalledTimes(2)
  expect(navigate).toHaveBeenCalledExactlyOnceWith(destination)
})

test('Close cancels a pending Google start and ignores a late response', async () => {
  const pending = deferred<GoogleLoginStartResponse>()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(pending.promise)
  const { user, view, onClose, onAccepted } = await mountForm()
  await user.click(screen.getByRole('button', { name: 'Continue with Google' }))
  await user.click(screen.getByRole('button', { name: 'Close registration' }))
  expect(onClose).toHaveBeenCalledOnce()
  view.unmount()
  expect(vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]?.aborted).toBe(true)
  await act(async () => { pending.resolve(googleResult()); await pending.promise })
  expect(navigate).not.toHaveBeenCalled()
  expect(onAccepted).not.toHaveBeenCalled()
})
