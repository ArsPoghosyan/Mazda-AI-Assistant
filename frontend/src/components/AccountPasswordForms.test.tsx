import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountPasswordRecoveryVerificationRequiredError,
  requestAccountPasswordRecovery,
  type AccountPasswordRecoveryResponse,
} from '../api/account-password-recovery'
import {
  AccountPasswordResetRejectedError,
  AccountPasswordResetRateLimitedError,
  resetAccountPassword,
  type AccountPasswordResetResponse,
} from '../api/account-password-reset'
import { loadTurnstile, type TurnstileApi } from '../lib/turnstile'
import AccountPasswordRecoveryForm from './AccountPasswordRecoveryForm'
import AccountPasswordResetForm from './AccountPasswordResetForm'

vi.mock('../api/account-password-recovery', async (original) => ({
  ...await original<typeof import('../api/account-password-recovery')>(),
  requestAccountPasswordRecovery: vi.fn(),
}))
vi.mock('../api/account-password-reset', async (original) => ({
  ...await original<typeof import('../api/account-password-reset')>(), resetAccountPassword: vi.fn(),
}))
vi.mock('../lib/turnstile', () => ({ loadTurnstile: vi.fn() }))

let api: TurnstileApi
const emailValue = 'owner@example.test'
const passwordValue = '  synthetic-new-password-é  '

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((complete) => { resolve = complete })
  return { promise, resolve }
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(requestAccountPasswordRecovery).mockReset()
  vi.mocked(resetAccountPassword).mockReset()
  api = {
    ready: (callback) => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'recovery-widget'),
    reset: vi.fn(), remove: vi.fn(),
  }
  vi.mocked(loadTurnstile).mockReset()
  vi.mocked(loadTurnstile).mockResolvedValue(api)
})
afterEach(() => { cleanup(); vi.unstubAllEnvs() })

function widget(index = 0) {
  const options = vi.mocked(api.render).mock.calls[index]?.[1]
  if (!options) throw new Error('Expected a verification widget')
  return options
}

async function mountRecovery() {
  const user = userEvent.setup()
  const onClose = vi.fn()
  const onSignIn = vi.fn()
  const onAccepted = vi.fn()
  const onEnterCode = vi.fn()
  const view = render(<StrictMode><AccountPasswordRecoveryForm siteKey="test-public-key"
    onClose={onClose} onSignIn={onSignIn} onAccepted={onAccepted} onEnterCode={onEnterCode} /></StrictMode>)
  await screen.findByText('Complete the check to continue.')
  return { user, view, onClose, onSignIn, onAccepted, onEnterCode,
    email: screen.getByLabelText<HTMLInputElement>('Email'),
    form: screen.getByRole('form', { name: 'Recover your password' }),
  }
}

function mountReset() {
  const user = userEvent.setup()
  const onClose = vi.fn()
  const onSignIn = vi.fn()
  const onRecover = vi.fn()
  const view = render(<StrictMode><AccountPasswordResetForm email={emailValue}
    onClose={onClose} onSignIn={onSignIn} onRecover={onRecover} /></StrictMode>)
  return { user, view, onClose, onSignIn, onRecover,
    code: screen.getByLabelText<HTMLInputElement>('Recovery code'),
    password: screen.getByLabelText<HTMLInputElement>('New password'),
    form: screen.getByRole('form', { name: 'Reset your password' }),
  }
}

test('recovery focuses email and refuses submission without human verification', async () => {
  const { email, form } = await mountRecovery()
  expect(document.activeElement).toBe(email)
  expect(email.autocomplete).toBe('username')
  expect(widget().action).toBe('account_password_recovery')
  fireEvent.submit(form)
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
  expect(screen.getByRole('button', { name: 'Send recovery code' }).hasAttribute('disabled')).toBe(true)
})

test('an existing code needs a valid email but no new CAPTCHA or email request', async () => {
  const { user, email, onEnterCode, onSignIn } = await mountRecovery()
  const enter = screen.getByRole('button', { name: 'I already have a recovery code' })
  await user.click(enter)
  expect(onEnterCode).not.toHaveBeenCalled()
  await user.type(email, emailValue)
  await user.click(enter)
  expect(onEnterCode).toHaveBeenCalledExactlyOnceWith(emailValue)
  expect(onSignIn).not.toHaveBeenCalled()
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
})

test.each(['Back to sign in', 'I already have a recovery code'])('recovery navigation via %s blocks stale submit events', async (label) => {
  const { user, email, form, onSignIn, onEnterCode } = await mountRecovery()
  await user.type(email, emailValue)
  act(() => widget().callback('proof'))
  const button = screen.getByRole('button', { name: label })
  act(() => { fireEvent.click(button); fireEvent.submit(form); fireEvent.click(button) })
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
  expect(label === 'Back to sign in' ? onSignIn : onEnterCode).toHaveBeenCalledExactlyOnceWith(emailValue)
})

test('recovery consumes proof once, blocks competing navigation and waits for acceptance', async () => {
  const pending = deferred<AccountPasswordRecoveryResponse>()
  vi.mocked(requestAccountPasswordRecovery).mockReturnValue(pending.promise)
  const { user, email, form, onAccepted, onSignIn, onEnterCode } = await mountRecovery()
  await user.type(email, emailValue)
  const old = widget()
  act(() => old.callback('recovery-proof'))
  const back = screen.getByRole('button', { name: 'Back to sign in' })
  const enter = screen.getByRole('button', { name: 'I already have a recovery code' })
  act(() => { fireEvent.submit(form); fireEvent.submit(form); fireEvent.click(back); fireEvent.click(enter); old.callback('stale-proof') })
  expect(requestAccountPasswordRecovery).toHaveBeenCalledExactlyOnceWith(
    { email: emailValue, captcha_token: 'recovery-proof' }, expect.any(AbortSignal),
  )
  expect(onAccepted).not.toHaveBeenCalled()
  expect(onSignIn).not.toHaveBeenCalled()
  expect(onEnterCode).not.toHaveBeenCalled()
  expect(email.closest('fieldset')?.disabled).toBe(true)
  expect(screen.getByRole('button', { name: 'Close password recovery' }).hasAttribute('disabled')).toBe(false)
  await act(async () => { pending.resolve({ status: 'accepted' }); await pending.promise })
  expect(onAccepted).toHaveBeenCalledExactlyOnceWith(emailValue)
  expect(screen.getByText('If password recovery can proceed, check your email for the next steps.')).toBeDefined()
  fireEvent.submit(form)
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(1)
})

test('rejected recovery proof requires fresh verification and ignores stale callbacks', async () => {
  vi.mocked(requestAccountPasswordRecovery).mockRejectedValueOnce(new AccountPasswordRecoveryVerificationRequiredError())
    .mockResolvedValueOnce({ status: 'accepted' })
  const { user, email, form, onAccepted } = await mountRecovery()
  await user.type(email, emailValue)
  const old = widget()
  act(() => old.callback('old-proof'))
  fireEvent.submit(form)
  await screen.findByText('Verification was not accepted. Complete a new check.')
  await screen.findByText('Complete the check to continue.')
  act(() => { old.callback('stale-proof'); fireEvent.submit(form) })
  expect(requestAccountPasswordRecovery).toHaveBeenCalledTimes(1)
  act(() => { widget(1).callback('fresh-proof'); old['expired-callback']() })
  await user.click(screen.getByRole('button', { name: 'Send recovery code' }))
  expect(vi.mocked(requestAccountPasswordRecovery).mock.calls[1]?.[0].captcha_token).toBe('fresh-proof')
  expect(onAccepted).toHaveBeenCalledExactlyOnceWith(emailValue)
})

test('an expired recovery proof disables submission again', async () => {
  const { user, email, form } = await mountRecovery()
  await user.type(email, emailValue)
  act(() => { widget().callback('proof'); widget()['expired-callback']() })
  fireEvent.submit(form)
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
  expect(screen.getByRole('button', { name: 'Send recovery code' }).hasAttribute('disabled')).toBe(true)
})

test('closing recovery aborts on unmount and ignores a late acknowledgement', async () => {
  const pending = deferred<AccountPasswordRecoveryResponse>()
  vi.mocked(requestAccountPasswordRecovery).mockReturnValue(pending.promise)
  const { user, view, email, onClose, onAccepted } = await mountRecovery()
  await user.type(email, emailValue)
  act(() => widget().callback('proof'))
  await user.click(screen.getByRole('button', { name: 'Send recovery code' }))
  await user.click(screen.getByRole('button', { name: 'Close password recovery' }))
  expect(onClose).toHaveBeenCalledOnce()
  const signal = vi.mocked(requestAccountPasswordRecovery).mock.calls[0]?.[1]
  view.unmount()
  expect(signal?.aborted).toBe(true)
  await act(async () => { pending.resolve({ status: 'accepted' }); await pending.promise })
  expect(onAccepted).not.toHaveBeenCalled()
})

test('reset focuses the code field and permits password visibility without changing its value', async () => {
  const { user, code, password } = mountReset()
  expect(document.activeElement).toBe(code)
  expect(code.autocomplete).toBe('one-time-code')
  expect(code.inputMode).toBe('numeric')
  expect(password.autocomplete).toBe('new-password')
  await user.type(password, passwordValue)
  await user.click(screen.getByRole('button', { name: 'Show password' }))
  expect(password.type).toBe('text')
  expect(password.value).toBe(passwordValue)
  await user.click(screen.getByRole('button', { name: 'Show password' }))
  expect(password.type).toBe('password')
  expect(resetAccountPassword).not.toHaveBeenCalled()
  expect(loadTurnstile).not.toHaveBeenCalled()
})

test.each(['', '12345', '12345678901', '1234a6', '１２３４５６'])('reset rejects invalid code %j', (value) => {
  const { code, password, form } = mountReset()
  fireEvent.change(code, { target: { value } })
  fireEvent.change(password, { target: { value: passwordValue } })
  fireEvent.submit(form)
  expect(resetAccountPassword).not.toHaveBeenCalled()
})

test('reset preserves leading zeros/password bytes, clears secrets and waits for explicit sign-in', async () => {
  const pending = deferred<AccountPasswordResetResponse>()
  vi.mocked(resetAccountPassword).mockReturnValue(pending.promise)
  const { user, code, password, form, onSignIn, onRecover } = mountReset()
  await user.type(code, '00001234')
  await user.type(password, passwordValue)
  await user.click(screen.getByRole('button', { name: 'Show password' }))
  const back = screen.getByRole('button', { name: 'Back to sign in' })
  const recover = screen.getByRole('button', { name: 'Request another code' })
  act(() => { fireEvent.submit(form); fireEvent.submit(form); fireEvent.click(back); fireEvent.click(recover) })
  expect(resetAccountPassword).toHaveBeenCalledExactlyOnceWith(
    { email: emailValue, code: '00001234', new_password: passwordValue }, expect.any(AbortSignal),
  )
  expect(code.value).toBe('')
  expect(password.value).toBe('')
  expect(password.type).toBe('password')
  expect(onSignIn).not.toHaveBeenCalled()
  expect(onRecover).not.toHaveBeenCalled()
  await act(async () => { pending.resolve({ status: 'completed' }); await pending.promise })
  const proceed = screen.getByRole('button', { name: 'Continue to sign in' })
  expect(document.activeElement).toBe(proceed)
  expect(onSignIn).not.toHaveBeenCalled()
  fireEvent.submit(form)
  expect(resetAccountPassword).toHaveBeenCalledTimes(1)
  await user.click(proceed)
  expect(onSignIn).toHaveBeenCalledOnce()
})

test.each([
  [new AccountPasswordResetRejectedError(), 'Password reset was rejected. Check your email, code and new password, then try again.'],
  [new AccountPasswordResetRateLimitedError(), 'Too many password-reset attempts. Please try again later.'],
  [new Error('private-provider-detail'), 'Password reset could not be confirmed. Try signing in with your new password before starting recovery again.'],
])('reset failure clears sensitive fields and offers deliberate recovery choices', async (error, message) => {
  vi.mocked(resetAccountPassword).mockRejectedValueOnce(error)
  const { user, code, password, onSignIn, onRecover } = mountReset()
  await user.type(code, '001234')
  await user.type(password, passwordValue)
  await user.click(screen.getByRole('button', { name: 'Reset password' }))
  await screen.findByText(message)
  expect(code.value).toBe('')
  expect(password.value).toBe('')
  expect(document.activeElement).toBe(code)
  expect(screen.queryByRole('button', { name: 'Continue to sign in' })).toBeNull()
  expect(onSignIn).not.toHaveBeenCalled()
  await user.click(screen.getByRole('button', { name: 'Request another code' }))
  expect(onRecover).toHaveBeenCalledOnce()
  expect(resetAccountPassword).toHaveBeenCalledTimes(1)
})

test('reset refuses an empty new password', () => {
  const { code, form } = mountReset()
  fireEvent.change(code, { target: { value: '001234' } })
  fireEvent.submit(form)
  expect(resetAccountPassword).not.toHaveBeenCalled()
})

test.each(['Back to sign in', 'Request another code'])('reset navigation via %s blocks stale submits and clears fields on unmount', async (label) => {
  const { user, view, code, password, form, onSignIn, onRecover } = mountReset()
  await user.type(code, '001234')
  await user.type(password, passwordValue)
  const button = screen.getByRole('button', { name: label })
  act(() => { fireEvent.click(button); fireEvent.submit(form); fireEvent.click(button) })
  expect(resetAccountPassword).not.toHaveBeenCalled()
  expect(label === 'Back to sign in' ? onSignIn : onRecover).toHaveBeenCalledOnce()
  view.unmount()
  expect(code.value).toBe('')
  expect(password.value).toBe('')
})

test.each(['recovery', 'reset'])('does not submit %s outside development', (mode) => {
  vi.stubEnv('DEV', false)
  if (mode === 'recovery') {
    render(<AccountPasswordRecoveryForm siteKey="test-key" onClose={vi.fn()} onSignIn={vi.fn()} onAccepted={vi.fn()} onEnterCode={vi.fn()} />)
  } else {
    mountReset()
  }
  const form = screen.getByRole('form', { name: mode === 'recovery' ? 'Recover your password' : 'Reset your password' })
  fireEvent.submit(form)
  expect(requestAccountPasswordRecovery).not.toHaveBeenCalled()
  expect(resetAccountPassword).not.toHaveBeenCalled()
  expect(loadTurnstile).not.toHaveBeenCalled()
})
