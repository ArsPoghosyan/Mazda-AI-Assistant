import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountSignUpRejectedError,
  AccountSignUpVerificationRequiredError,
  signUpAccount,
  type AccountSignUpResponse,
} from '../api/account-registration'
import { loadTurnstile, type TurnstileApi } from '../lib/turnstile'
import AccountSignUpForm from './AccountSignUpForm'

vi.mock('../api/account-registration', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../api/account-registration')>()

  return {
    ...actual,
    signUpAccount: vi.fn(),
  }
})

vi.mock('../lib/turnstile', () => ({
  loadTurnstile: vi.fn(),
}))

const acknowledgement: AccountSignUpResponse = {
  status: 'accepted',
}

const passwordValue = '  synthetic-password-é  '

let api: TurnstileApi

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'false')
  vi.mocked(signUpAccount).mockReset()

  api = {
    ready: vi.fn<TurnstileApi['ready']>((callback) => callback()),
    render: vi.fn<TurnstileApi['render']>(() => 'test-widget'),
    reset: vi.fn<TurnstileApi['reset']>(),
    remove: vi.fn<TurnstileApi['remove']>(),
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

  if (!options) {
    throw new Error('Expected a verification widget')
  }

  return options
}

function deferredRegistration() {
  let resolve!: (value: AccountSignUpResponse) => void

  const promise = new Promise<AccountSignUpResponse>((complete) => {
    resolve = complete
  })

  return { promise, resolve }
}

async function mountForm() {
  const user = userEvent.setup()
  const onClose = vi.fn()
  const onAccepted = vi.fn()

  const view = render(
    <StrictMode>
      <AccountSignUpForm
        siteKey="public-test-site-key"
        onClose={onClose}
        onAccepted={onAccepted}
      />
    </StrictMode>,
  )

  await screen.findByText('Complete the check to continue.')

  const email = screen.getByRole<HTMLInputElement>('textbox', {
    name: 'Email',
  })
  const password = screen.getByLabelText<HTMLInputElement>('Password', {
    exact: true,
  })
  const form = screen.getByRole('form', { name: 'Create account' })

  return { user, onClose, onAccepted, view, email, password, form }
}

test('focuses email and requires verification before submission', async () => {
  const { email, password, form } = await mountForm()

  expect(document.activeElement).toBe(email)
  expect(email.autocomplete).toBe('username')
  expect(password.autocomplete).toBe('new-password')
  expect(password.type).toBe('password')
  expect(widgetOptions().action).toBe('account_sign_up')
  expect(screen.getAllByLabelText('Password', { exact: true })).toHaveLength(1)

  expect(
    screen.getByRole('button', { name: 'Create account' }).hasAttribute('disabled'),
  ).toBe(true)

  // Exercise the handler guard without using the disabled button.
  fireEvent.submit(form)

  expect(signUpAccount).not.toHaveBeenCalled()
})

test('shows and hides the password without changing its value', async () => {
  const { user, password } = await mountForm()

  await user.type(password, passwordValue)

  const toggle = screen.getByRole('button', { name: 'Show password' })

  await user.click(toggle)

  expect(password.type).toBe('text')
  expect(password.value).toBe(passwordValue)
  expect(toggle.getAttribute('aria-pressed')).toBe('true')

  await user.click(toggle)

  expect(password.type).toBe('password')
  expect(password.value).toBe(passwordValue)
  expect(toggle.getAttribute('aria-pressed')).toBe('false')
  expect(signUpAccount).not.toHaveBeenCalled()
})

test('submits once, clears the password, and passes only email to confirmation', async () => {
  const pending = deferredRegistration()
  vi.mocked(signUpAccount).mockReturnValue(pending.promise)

  const { user, email, password, form, onAccepted } = await mountForm()

  await user.type(email, 'owner@example.test')
  await user.type(password, passwordValue)
  await user.click(screen.getByRole('button', { name: 'Show password' }))

  act(() => {
    widgetOptions().callback('synthetic-registration-proof')
  })

  await user.click(screen.getByRole('button', { name: 'Create account' }))

  expect(signUpAccount).toHaveBeenCalledTimes(1)
  expect(vi.mocked(signUpAccount).mock.calls[0]?.[0]).toEqual({
    email: 'owner@example.test',
    password: passwordValue,
    captcha_token: 'synthetic-registration-proof',
  })
  expect(vi.mocked(signUpAccount).mock.calls[0]?.[1]).toBeInstanceOf(
    AbortSignal,
  )

  expect(password.value).toBe('')
  expect(password.type).toBe('password')
  expect(email.value).toBe('owner@example.test')
  expect(email.closest('fieldset')?.disabled).toBe(true)
  expect(onAccepted).not.toHaveBeenCalled()

  const loadingButton = screen.getByRole('button', { name: 'Submitting…' })

  expect(loadingButton.hasAttribute('disabled')).toBe(true)
  expect(loadingButton.getAttribute('aria-busy')).toBe('true')

  fireEvent.submit(form)
  expect(signUpAccount).toHaveBeenCalledTimes(1)

  await act(async () => {
    pending.resolve(acknowledgement)
    await pending.promise
  })

  await screen.findByText(
    'If registration can proceed, check your email for a verification code.',
  )

  expect(onAccepted).toHaveBeenCalledExactlyOnceWith('owner@example.test')
  expect(
    screen.getByRole('button', { name: 'Check your email' }).hasAttribute('disabled'),
  ).toBe(true)
  expect(screen.queryByText('Human verification')).toBeNull()

  fireEvent.submit(form)

  expect(signUpAccount).toHaveBeenCalledTimes(1)
  expect(onAccepted).toHaveBeenCalledTimes(1)
})

test('an expired proof disables submission again', async () => {
  const { form } = await mountForm()
  const options = widgetOptions()

  act(() => {
    options.callback('synthetic-registration-proof')
  })

  expect(
    screen.getByRole('button', { name: 'Create account' }).hasAttribute('disabled'),
  ).toBe(false)

  act(() => {
    options['expired-callback']()
  })

  expect(
    screen.getByRole('button', { name: 'Create account' }).hasAttribute('disabled'),
  ).toBe(true)

  fireEvent.submit(form)

  expect(signUpAccount).not.toHaveBeenCalled()
})

test.each([
  {
    name: 'registration rejection',
    error: new AccountSignUpRejectedError(),
    message: 'Registration was rejected. Check your details and try again.',
  },
  {
    name: 'verification rejection',
    error: new AccountSignUpVerificationRequiredError(),
    message: 'Verification was not accepted. Complete a new check.',
  },
])('requires a fresh proof after $name', async ({ error, message }) => {
  vi.mocked(signUpAccount)
    .mockRejectedValueOnce(error)
    .mockResolvedValueOnce(acknowledgement)

  const { user, email, password, onAccepted } = await mountForm()
  const oldOptions = widgetOptions()

  await user.type(email, 'owner@example.test')
  await user.type(password, passwordValue)

  act(() => {
    oldOptions.callback('first-proof')
  })

  await user.click(screen.getByRole('button', { name: 'Create account' }))

  await screen.findByText(message)
  await screen.findByText('Complete the check to continue.')

  expect(api.render).toHaveBeenCalledTimes(2)
  expect(password.value).toBe('')
  expect(email.value).toBe('owner@example.test')
  expect(signUpAccount).toHaveBeenCalledTimes(1)
  expect(onAccepted).not.toHaveBeenCalled()

  act(() => {
    oldOptions.callback('stale-proof')
  })

  expect(
    screen.getByRole('button', { name: 'Create account' }).hasAttribute('disabled'),
  ).toBe(true)

  await user.type(password, passwordValue)

  act(() => {
    widgetOptions(1).callback('fresh-proof')
    oldOptions['expired-callback']()
  })

  await user.click(screen.getByRole('button', { name: 'Create account' }))
  await screen.findByText(
    'If registration can proceed, check your email for a verification code.',
  )

  expect(signUpAccount).toHaveBeenCalledTimes(2)
  expect(
    vi.mocked(signUpAccount).mock.calls[1]?.[0].captcha_token,
  ).toBe('fresh-proof')
  expect(onAccepted).toHaveBeenCalledExactlyOnceWith('owner@example.test')
})

test('closing allows cancellation and ignores a late accepted response', async () => {
  const pending = deferredRegistration()
  vi.mocked(signUpAccount).mockReturnValue(pending.promise)

  const { user, onClose, onAccepted, view, email, password } = await mountForm()

  await user.type(email, 'owner@example.test')
  await user.type(password, passwordValue)

  act(() => {
    widgetOptions().callback('synthetic-registration-proof')
  })

  await user.click(screen.getByRole('button', { name: 'Create account' }))

  const signal = vi.mocked(signUpAccount).mock.calls[0]?.[1]

  await user.click(screen.getByRole('button', { name: 'Close registration' }))

  expect(onClose).toHaveBeenCalledTimes(1)

  // Simulate the parent removing the form after closing the dialog.
  view.unmount()

  expect(signal?.aborted).toBe(true)

  await act(async () => {
    pending.resolve(acknowledgement)
    await pending.promise
  })

  expect(onAccepted).not.toHaveBeenCalled()
  expect(signUpAccount).toHaveBeenCalledTimes(1)
  expect(view.container.childElementCount).toBe(0)
})

test('does not load verification or submit outside development', () => {
  vi.stubEnv('DEV', false)
  const onAccepted = vi.fn()

  render(
    <AccountSignUpForm
      siteKey="public-test-site-key"
      onClose={vi.fn()}
      onAccepted={onAccepted}
    />,
  )

  expect(
    screen.getByText('Account registration is not available here yet.'),
  ).toBeDefined()
  expect(loadTurnstile).not.toHaveBeenCalled()

  fireEvent.submit(screen.getByRole('form', { name: 'Create account' }))

  expect(signUpAccount).not.toHaveBeenCalled()
  expect(onAccepted).not.toHaveBeenCalled()
})
