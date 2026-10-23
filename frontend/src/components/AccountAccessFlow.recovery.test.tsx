import { StrictMode, useRef, useState } from 'react'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { signInAccount, type AccountSessionResponse } from '../api/account'
import { requestAccountPasswordRecovery, type AccountPasswordRecoveryResponse } from '../api/account-password-recovery'
import { resetAccountPassword, type AccountPasswordResetResponse } from '../api/account-password-reset'
import { startGoogleSignIn, type GoogleLoginStartResponse } from '../api/google'
import { loadTurnstile, type TurnstileApi } from '../lib/turnstile'
import AccountSignInDialog from './AccountSignInDialog'

vi.mock('../api/account', async (original) => ({ ...await original<typeof import('../api/account')>(), signInAccount: vi.fn() }))
vi.mock('../api/account-password-recovery', async (original) => ({ ...await original<typeof import('../api/account-password-recovery')>(), requestAccountPasswordRecovery: vi.fn() }))
vi.mock('../api/account-password-reset', async (original) => ({ ...await original<typeof import('../api/account-password-reset')>(), resetAccountPassword: vi.fn() }))
vi.mock('../api/google', () => ({ startGoogleSignIn: vi.fn() }))
vi.mock('../lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

const prototype = HTMLDialogElement.prototype
const originalShow = Object.getOwnPropertyDescriptor(prototype, 'showModal')
const originalClose = Object.getOwnPropertyDescriptor(prototype, 'close')
const emailValue = 'owner@example.test'
let api: TurnstileApi

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((complete) => { resolve = complete })
  return { promise, resolve }
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'false')
  vi.mocked(signInAccount).mockReset()
  vi.mocked(requestAccountPasswordRecovery).mockReset()
  vi.mocked(resetAccountPassword).mockReset()
  vi.mocked(startGoogleSignIn).mockReset()
  api = {
    ready: (callback) => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'account-dialog-widget'),
    reset: vi.fn(), remove: vi.fn(),
  }
  vi.mocked(loadTurnstile).mockReset()
  vi.mocked(loadTurnstile).mockResolvedValue(api)
  Object.defineProperty(prototype, 'showModal', { configurable: true, value: vi.fn(function (this: HTMLDialogElement) { this.open = true }) })
  Object.defineProperty(prototype, 'close', { configurable: true, value: vi.fn(function (this: HTMLDialogElement) { this.open = false }) })
})

afterEach(() => {
  cleanup()
  vi.unstubAllEnvs()
  if (originalShow) Object.defineProperty(prototype, 'showModal', originalShow)
  else Reflect.deleteProperty(prototype, 'showModal')
  if (originalClose) Object.defineProperty(prototype, 'close', originalClose)
  else Reflect.deleteProperty(prototype, 'close')
})

function widget() {
  const options = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!options) throw new Error('Expected the current verification widget')
  return options
}

async function mountDialog() {
  const user = userEvent.setup()
  const onSignedIn = vi.fn()
  function Harness() {
    const [open, setOpen] = useState(false)
    const trigger = useRef<HTMLButtonElement>(null)
    return <>
      <button ref={trigger} type="button" onClick={() => setOpen(true)}>Open account</button>
      <AccountSignInDialog open={open} siteKey="public-test-key" returnFocusRef={trigger}
        onClose={() => setOpen(false)} onSignedIn={onSignedIn} />
    </>
  }
  render(<StrictMode><Harness /></StrictMode>)
  const trigger = screen.getByRole('button', { name: 'Open account' })
  await user.click(trigger)
  const dialog = screen.getByRole('dialog', { name: 'Sign in' })
  await screen.findByText('Complete the check to continue.')
  return { user, trigger, dialog, onSignedIn }
}

async function goToRecovery(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Email'), emailValue)
  await user.click(screen.getByRole('button', { name: 'Forgot password?' }))
  await screen.findByRole('dialog', { name: 'Recover your password' })
  await screen.findByText('Complete the check to continue.')
}

test('recovery and reset stay in one dialog and return to a separate, empty-password sign-in', async () => {
  vi.mocked(requestAccountPasswordRecovery).mockResolvedValueOnce({ status: 'accepted' })
  vi.mocked(resetAccountPassword).mockResolvedValueOnce({ status: 'completed' })
  const { user, dialog, onSignedIn } = await mountDialog()
  const opens = vi.mocked(prototype.showModal).mock.calls.length
  const oldPassword = screen.getByLabelText<HTMLInputElement>('Password', { exact: true })
  await user.type(oldPassword, 'synthetic-old-password')
  await goToRecovery(user)
  expect(oldPassword.value).toBe('')
  expect(screen.getByRole('dialog', { name: 'Recover your password' })).toBe(dialog)
  const email = screen.getByLabelText<HTMLInputElement>('Email')
  expect(email.value).toBe(emailValue)
  expect(document.activeElement).toBe(email)
  act(() => widget().callback('recovery-proof'))
  await user.click(screen.getByRole('button', { name: 'Send recovery code' }))
  await screen.findByRole('dialog', { name: 'Reset your password' })
  const code = screen.getByLabelText<HTMLInputElement>('Recovery code')
  const password = screen.getByLabelText<HTMLInputElement>('New password')
  expect(document.activeElement).toBe(code)
  await user.type(code, '001234')
  await user.type(password, '  synthetic-new-password  ')
  await user.click(screen.getByRole('button', { name: 'Reset password' }))
  await screen.findByRole('button', { name: 'Continue to sign in' })
  expect(onSignedIn).not.toHaveBeenCalled()
  expect(signInAccount).not.toHaveBeenCalled()
  expect(code.value).toBe('')
  expect(password.value).toBe('')
  expect(vi.mocked(prototype.showModal).mock.calls.length).toBe(opens)
  await user.click(screen.getByRole('button', { name: 'Continue to sign in' }))
  expect(screen.getByRole('dialog', { name: 'Sign in' })).toBe(dialog)
  expect(screen.getByLabelText<HTMLInputElement>('Email').value).toBe(emailValue)
  expect(screen.getByLabelText<HTMLInputElement>('Password', { exact: true }).value).toBe('')
  expect(document.activeElement).toBe(screen.getByLabelText('Email'))
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(1)
  expect(resetAccountPassword).toHaveBeenCalledTimes(1)
})

test('an existing code skips email delivery and requesting another code never sends automatically', async () => {
  const { user } = await mountDialog()
  await goToRecovery(user)
  await user.click(screen.getByRole('button', { name: 'I already have a recovery code' }))
  await screen.findByRole('dialog', { name: 'Reset your password' })
  await user.click(screen.getByRole('button', { name: 'Request another code' }))
  await screen.findByRole('dialog', { name: 'Recover your password' })
  expect(screen.getByLabelText<HTMLInputElement>('Email').value).toBe(emailValue)
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
  expect(resetAccountPassword).not.toHaveBeenCalled()
})

test('Forgot password wins an immediate submit race and discards the old sign-in proof', async () => {
  const { user } = await mountDialog()
  await user.type(screen.getByLabelText('Email'), emailValue)
  await user.type(screen.getByLabelText('Password', { exact: true }), 'synthetic-password')
  const old = widget()
  act(() => old.callback('sign-in-proof'))
  const form = screen.getByRole('form', { name: 'Sign in' })
  const forgot = screen.getByRole('button', { name: 'Forgot password?' })
  act(() => { fireEvent.click(forgot); fireEvent.submit(form); old.callback('stale-proof') })
  await screen.findByRole('dialog', { name: 'Recover your password' })
  await screen.findByText('Complete the check to continue.')
  expect(signInAccount).not.toHaveBeenCalled()
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
  expect(screen.getByRole('button', { name: 'Send recovery code' }).hasAttribute('disabled')).toBe(true)
})

test('pending email sign-in blocks Forgot password navigation', async () => {
  const pending = deferred<AccountSessionResponse>()
  vi.mocked(signInAccount).mockReturnValueOnce(pending.promise)
  const { user, dialog, onSignedIn } = await mountDialog()
  await user.type(screen.getByLabelText('Email'), emailValue)
  await user.type(screen.getByLabelText('Password', { exact: true }), 'synthetic-password')
  act(() => widget().callback('sign-in-proof'))
  const forgot = screen.getByRole('button', { name: 'Forgot password?' })
  act(() => { fireEvent.submit(screen.getByRole('form', { name: 'Sign in' })); fireEvent.click(forgot) })
  expect(screen.getByRole('dialog', { name: 'Sign in' })).toBe(dialog)
  expect(forgot.hasAttribute('disabled')).toBe(true)
  await user.click(screen.getByRole('button', { name: 'Close sign-in' }))
  await act(async () => {
    pending.resolve({ user_id: '11111111-1111-4111-8111-111111111111', expires_at: '2030-01-01T12:00:00Z', absolute_expires_at: '2030-01-30T12:00:00Z' })
    await pending.promise
  })
  expect(onSignedIn).not.toHaveBeenCalled()
})

test('pending Google sign-in blocks Forgot password navigation', async () => {
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'true')
  vi.stubEnv('VITE_SUPABASE_AUTH_ISSUER', 'https://auth.example.test/auth/v1')
  const pending = deferred<GoogleLoginStartResponse>()
  vi.mocked(startGoogleSignIn).mockReturnValueOnce(pending.promise)
  const { user } = await mountDialog()
  await user.click(screen.getByRole('button', { name: 'Continue with Google' }))
  const forgot = screen.getByRole('button', { name: 'Forgot password?' })
  expect(forgot.hasAttribute('disabled')).toBe(true)
  fireEvent.click(forgot)
  expect(screen.queryByRole('dialog', { name: 'Recover your password' })).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Close sign-in' }))
  expect(vi.mocked(startGoogleSignIn).mock.calls[0]?.[2]?.aborted).toBe(true)
  await act(async () => {
    pending.resolve({ authorization_url: 'https://auth.example.test/auth/v1/authorize?provider=google', expires_at: new Date(Date.now() + 600_000).toISOString() })
    await pending.promise
  })
})

test.each([
  ['recovery', 'close'], ['recovery', 'cancel'], ['reset', 'close'], ['reset', 'cancel'],
])('%s %s cancels pending work, returns focus and reopens cleanly', async (mode, mechanism) => {
  const recovery = deferred<AccountPasswordRecoveryResponse>()
  const reset = deferred<AccountPasswordResetResponse>()
  vi.mocked(requestAccountPasswordRecovery).mockReturnValueOnce(recovery.promise)
  vi.mocked(resetAccountPassword).mockReturnValueOnce(reset.promise)
  const { user, dialog, trigger, onSignedIn } = await mountDialog()
  await goToRecovery(user)
  if (mode === 'recovery') {
    act(() => widget().callback('proof'))
    await user.click(screen.getByRole('button', { name: 'Send recovery code' }))
  } else {
    await user.click(screen.getByRole('button', { name: 'I already have a recovery code' }))
    await user.type(screen.getByLabelText('Recovery code'), '001234')
    await user.type(screen.getByLabelText('New password'), 'synthetic-new-password')
    await user.click(screen.getByRole('button', { name: 'Reset password' }))
  }
  const signal = mode === 'recovery'
    ? vi.mocked(requestAccountPasswordRecovery).mock.calls[0]?.[1]
    : vi.mocked(resetAccountPassword).mock.calls[0]?.[1]
  if (mechanism === 'cancel') fireEvent(dialog, new Event('cancel', { cancelable: true }))
  else await user.click(screen.getByRole('button', { name: mode === 'recovery' ? 'Close password recovery' : 'Close password reset' }))
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(document.activeElement).toBe(trigger)
  expect(signal?.aborted).toBe(true)
  await act(async () => {
    if (mode === 'recovery') { recovery.resolve({ status: 'accepted' }); await recovery.promise }
    else { reset.resolve({ status: 'completed' }); await reset.promise }
  })
  expect(onSignedIn).not.toHaveBeenCalled()
  await user.click(trigger)
  expect(screen.getByRole('dialog', { name: 'Sign in' })).toBeDefined()
  expect(within(dialog).getByLabelText<HTMLInputElement>('Email').value).toBe('')
  expect(within(dialog).getByLabelText<HTMLInputElement>('Password', { exact: true }).value).toBe('')
})

test('an uncertain reset leaves credentials empty and offers a deliberate return to sign-in', async () => {
  vi.mocked(resetAccountPassword).mockRejectedValueOnce(new Error('private-provider-detail'))
  const { user, onSignedIn } = await mountDialog()
  await goToRecovery(user)
  await user.click(screen.getByRole('button', { name: 'I already have a recovery code' }))
  await user.type(screen.getByLabelText('Recovery code'), '001234')
  await user.type(screen.getByLabelText('New password'), 'synthetic-new-password')
  await user.click(screen.getByRole('button', { name: 'Reset password' }))
  await screen.findByText('Password reset could not be confirmed. Try signing in with your new password before starting recovery again.')
  expect(screen.getByLabelText<HTMLInputElement>('Recovery code').value).toBe('')
  expect(screen.getByLabelText<HTMLInputElement>('New password').value).toBe('')
  expect(onSignedIn).not.toHaveBeenCalled()
  expect(signInAccount).not.toHaveBeenCalled()
  await user.click(screen.getByRole('button', { name: 'Back to sign in' }))
  expect(screen.getByRole('dialog', { name: 'Sign in' })).toBeDefined()
  expect(screen.getByLabelText<HTMLInputElement>('Email').value).toBe(emailValue)
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
})
