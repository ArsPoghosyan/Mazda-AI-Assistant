import { StrictMode, useRef, useState } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { signInAccount, type AccountSessionResponse } from '../api/account'
import { startGoogleSignIn, type GoogleLoginStartResponse } from '../api/google'
import { loadTurnstile, type TurnstileApi } from '../lib/turnstile'
import AccountSignInDialog from './AccountSignInDialog'
import AccountSignInForm from './AccountSignInForm'

const { navigate } = vi.hoisted(() => ({ navigate: vi.fn<(url: string) => void>() }))

vi.mock('../hooks/useGoogleSignIn', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../hooks/useGoogleSignIn')>()
  return {
    useGoogleSignIn: function useTestGoogleSignIn() {
      return actual.useGoogleSignIn(navigate)
    },
  }
})
vi.mock('../api/google', () => ({ startGoogleSignIn: vi.fn() }))
vi.mock('../api/account', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/account')>()
  return { ...actual, signInAccount: vi.fn() }
})
vi.mock('../lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

const session: AccountSessionResponse = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}
const destination = 'https://auth.example.test/auth/v1/authorize?provider=google'
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
  vi.mocked(signInAccount).mockReset()
  navigate.mockReset()
  api = {
    ready: (callback) => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'google-form-widget'),
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
  if (!options) throw new Error('Expected the email verification widget')
  return options
}

async function mountForm() {
  const onClose = vi.fn()
  const onCreateAccount = vi.fn()
  const onSignedIn = vi.fn()
  const user = userEvent.setup()
  const view = render(
    <StrictMode>
      <AccountSignInForm siteKey="public-test-site-key" onClose={onClose}
        onCreateAccount={onCreateAccount} onSignedIn={onSignedIn} />
    </StrictMode>,
  )
  await screen.findByText('Complete the check to continue.')
  return { user, view, onClose, onCreateAccount, onSignedIn,
    form: screen.getByRole('form', { name: 'Sign in' }),
    email: screen.getByLabelText<HTMLInputElement>('Email'),
    password: screen.getByLabelText<HTMLInputElement>('Password', { exact: true }),
  }
}

test.each(['disabled', 'production', 'missing-issuer'])(
  'does not show Google or change the email flow when %s', async (reason) => {
    if (reason === 'disabled') vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'false')
    if (reason === 'production') vi.stubEnv('DEV', false)
    if (reason === 'missing-issuer') vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', '')
    render(<AccountSignInForm siteKey="public-test-key" onClose={vi.fn()} />)
    expect(screen.queryByRole('button', { name: 'Continue with Google' })).toBeNull()
    expect(screen.getByText('Use your email and password to sign in.')).toBeDefined()
    expect(startGoogleSignIn).not.toHaveBeenCalled()
  },
)

test('Google starts without email fields or CAPTCHA and reports progress accessibly', async () => {
  const pending = deferred<GoogleLoginStartResponse>()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(pending.promise)
  const { user, email, password, onSignedIn, onCreateAccount } = await mountForm()
  const google = screen.getByRole('button', { name: 'Continue with Google' })
  expect(google.getAttribute('type')).toBe('button')
  expect(email.value).toBe('')
  expect(password.value).toBe('')
  await user.click(google)
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(signInAccount).not.toHaveBeenCalled()
  expect(google.getAttribute('aria-busy')).toBe('true')
  expect(google.hasAttribute('disabled')).toBe(true)
  const status = document.getElementById(google.getAttribute('aria-describedby') ?? '')
  expect(status?.getAttribute('role')).toBe('status')
  expect(status?.textContent).toBe('Opening Google sign-in…')
  expect(email.closest('fieldset')?.disabled).toBe(true)
  expect(screen.getByRole('button', { name: 'Create account' }).hasAttribute('disabled')).toBe(true)
  expect(screen.getByRole('button', { name: 'Close sign-in' }).hasAttribute('disabled')).toBe(false)

  await act(async () => {
    pending.resolve(googleResult())
    await pending.promise
  })
  expect(navigate).toHaveBeenCalledExactlyOnceWith(destination)
  expect(status?.textContent).toBe('Redirecting to Google…')
  expect(onSignedIn).not.toHaveBeenCalled()
  expect(onCreateAccount).not.toHaveBeenCalled()
})

test('Google wins an immediate cross-mode race and clears password and stale proof', async () => {
  const pending = deferred<GoogleLoginStartResponse>()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(pending.promise)
  const { user, form, email, password, onCreateAccount, view } = await mountForm()
  await user.type(email, 'owner@example.test')
  await user.type(password, 'synthetic-private-password')
  await user.click(screen.getByRole('button', { name: 'Show password' }))
  const old = widgetOptions()
  act(() => old.callback('old-proof'))
  const google = screen.getByRole('button', { name: 'Continue with Google' })
  const create = screen.getByRole('button', { name: 'Create account' })

  act(() => {
    fireEvent.click(google)
    fireEvent.submit(form)
    fireEvent.click(google)
    fireEvent.click(create)
    old.callback('late-proof')
  })
  expect(startGoogleSignIn).toHaveBeenCalledTimes(1)
  expect(signInAccount).not.toHaveBeenCalled()
  expect(onCreateAccount).not.toHaveBeenCalled()
  expect(password.value).toBe('')
  expect(password.type).toBe('password')
  expect(email.value).toBe('owner@example.test')
  view.unmount()
  expect(vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]?.aborted).toBe(true)
  await act(async () => { pending.resolve(googleResult()); await pending.promise })
  expect(navigate).not.toHaveBeenCalled()
})

test('email wins an immediate cross-mode race and blocks Google after success', async () => {
  const pending = deferred<AccountSessionResponse>()
  vi.mocked(signInAccount).mockReturnValueOnce(pending.promise)
  const { user, form, email, password, onCreateAccount, onSignedIn } = await mountForm()
  await user.type(email, 'owner@example.test')
  await user.type(password, 'synthetic-private-password')
  act(() => widgetOptions().callback('email-proof'))
  const google = screen.getByRole('button', { name: 'Continue with Google' })
  const create = screen.getByRole('button', { name: 'Create account' })
  act(() => {
    fireEvent.submit(form)
    fireEvent.click(google)
    fireEvent.click(create)
  })
  expect(signInAccount).toHaveBeenCalledTimes(1)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
  expect(onCreateAccount).not.toHaveBeenCalled()
  expect(google.hasAttribute('disabled')).toBe(true)
  await act(async () => { pending.resolve(session); await pending.promise })
  expect(onSignedIn).toHaveBeenCalledExactlyOnceWith(session)
  fireEvent.click(google)
  expect(startGoogleSignIn).not.toHaveBeenCalled()
})

test('Google failure restores email only with a fresh proof and password', async () => {
  vi.mocked(startGoogleSignIn).mockRejectedValueOnce(new Error('Google sign-in is temporarily unavailable.'))
  vi.mocked(signInAccount).mockResolvedValueOnce(session)
  const { user, form, email, password, onSignedIn } = await mountForm()
  await user.type(email, 'owner@example.test')
  await user.type(password, 'synthetic-private-password')
  const old = widgetOptions()
  act(() => old.callback('old-proof'))
  await user.click(screen.getByRole('button', { name: 'Continue with Google' }))
  await screen.findByText('Google sign-in is temporarily unavailable.')
  await screen.findByText('Complete the check to continue.')
  expect(email.closest('fieldset')?.disabled).toBe(false)
  expect(password.value).toBe('')

  act(() => { old.callback('late-proof'); fireEvent.submit(form) })
  expect(signInAccount).not.toHaveBeenCalled()
  expect(screen.getByRole('button', { name: 'Sign in' }).hasAttribute('disabled')).toBe(true)
  await user.type(password, 'fresh-password')
  act(() => widgetOptions(1).callback('fresh-proof'))
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  expect(signInAccount).toHaveBeenCalledTimes(1)
  expect(vi.mocked(signInAccount).mock.calls[0]?.[0]).toEqual({
    email: 'owner@example.test', password: 'fresh-password', captcha_token: 'fresh-proof',
  })
  expect(onSignedIn).toHaveBeenCalledExactlyOnceWith(session)
  expect(navigate).not.toHaveBeenCalled()
})

test('Google can retry explicitly after an error without an automatic second request', async () => {
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

test('Close remains available and unmount cancels Google without navigation', async () => {
  const pending = deferred<GoogleLoginStartResponse>()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(pending.promise)
  const { user, view, onClose } = await mountForm()
  await user.click(screen.getByRole('button', { name: 'Continue with Google' }))
  await user.click(screen.getByRole('button', { name: 'Close sign-in' }))
  expect(onClose).toHaveBeenCalledOnce()
  view.unmount()
  expect(vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]?.aborted).toBe(true)
  await act(async () => { pending.resolve(googleResult()); await pending.promise })
  expect(navigate).not.toHaveBeenCalled()
})

test.each(['sign_in', 'sign_up'])('native dialog cancellation closes and aborts Google from %s while returning focus', async (mode) => {
  const prototype = HTMLDialogElement.prototype
  const show = Object.getOwnPropertyDescriptor(prototype, 'showModal')
  const close = Object.getOwnPropertyDescriptor(prototype, 'close')
  Object.defineProperty(prototype, 'showModal', {
    configurable: true, value: function (this: HTMLDialogElement) { this.open = true },
  })
  Object.defineProperty(prototype, 'close', {
    configurable: true, value: function (this: HTMLDialogElement) { this.open = false },
  })
  const pending = deferred<GoogleLoginStartResponse>()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(pending.promise)

  function Harness() {
    const [open, setOpen] = useState(true)
    const trigger = useRef<HTMLButtonElement>(null)
    return <>
      <button ref={trigger} type="button" onClick={() => setOpen(true)}>Open sign-in</button>
      <AccountSignInDialog open={open} siteKey="public-test-key" returnFocusRef={trigger}
        onClose={() => setOpen(false)} />
    </>
  }

  try {
    const user = userEvent.setup()
    render(<Harness />)
    if (mode === 'sign_up') {
      await user.click(screen.getByRole('button', { name: 'Create account' }))
      expect(screen.getByRole('form', { name: 'Create account' })).toBeDefined()
    }
    await user.click(screen.getByRole('button', { name: 'Continue with Google' }))
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Open sign-in' }))
    expect(vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]?.aborted).toBe(true)
    await act(async () => { pending.resolve(googleResult()); await pending.promise })
    expect(navigate).not.toHaveBeenCalled()
  } finally {
    cleanup()
    if (show) Object.defineProperty(prototype, 'showModal', show)
    else Reflect.deleteProperty(prototype, 'showModal')
    if (close) Object.defineProperty(prototype, 'close', close)
    else Reflect.deleteProperty(prototype, 'close')
  }
})
