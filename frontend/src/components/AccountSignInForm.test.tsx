import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountSignInRejectedError,
  AccountVerificationRequiredError,
  signInAccount,
  type AccountSessionResponse,
} from '../api/account'
import { loadTurnstile, type TurnstileApi } from '../lib/turnstile'
import AccountSignInForm from './AccountSignInForm'

vi.mock('../api/account', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/account')>()

  return {
    ...actual,
    signInAccount: vi.fn(),
  }
})

vi.mock('../lib/turnstile', () => ({
  loadTurnstile: vi.fn(),
}))

const session: AccountSessionResponse = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

const passwordValue = '  synthetic-password-é  '

let api: TurnstileApi

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(signInAccount).mockReset()

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

async function mountForm() {
  const user = userEvent.setup()
  const onClose = vi.fn()

  const view = render(
    <StrictMode>
      <AccountSignInForm
        siteKey="public-test-site-key"
        onClose={onClose}
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
  const form = screen.getByRole('form', { name: 'Sign in' })

  return { user, onClose, view, email, password, form }
}

function deferredSession() {
  let resolve!: (value: AccountSessionResponse) => void

  const promise = new Promise<AccountSessionResponse>((complete) => {
    resolve = complete
  })

  return { promise, resolve }
}

test('focuses email and requires verification before submission', async () => {
  const { email, password, form } = await mountForm()

  expect(document.activeElement).toBe(email)
  expect(email.autocomplete).toBe('username')
  expect(password.autocomplete).toBe('current-password')
  expect(password.type).toBe('password')
  expect(widgetOptions().action).toBe('account_sign_in')

  expect(
    screen.getByRole('button', { name: 'Sign in' }).hasAttribute('disabled'),
  ).toBe(true)

  // Bypass the disabled button to exercise the submit-handler guard.
  fireEvent.submit(form)

  expect(signInAccount).not.toHaveBeenCalled()
})

test('allows showing and hiding the password without changing it', async () => {
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
  expect(signInAccount).not.toHaveBeenCalled()
})

test('submits once, clears the password, and shows success', async () => {
  const pending = deferredSession()
  vi.mocked(signInAccount).mockReturnValue(pending.promise)

  const { user, email, password, form } = await mountForm()

  await user.type(email, 'owner@example.test')
  await user.type(password, passwordValue)
  await user.click(screen.getByRole('button', { name: 'Show password' }))

  act(() => {
    widgetOptions().callback('synthetic-account-proof')
  })

  await user.click(screen.getByRole('button', { name: 'Sign in' }))

  expect(signInAccount).toHaveBeenCalledTimes(1)
  expect(vi.mocked(signInAccount).mock.calls[0]?.[0]).toEqual({
    email: 'owner@example.test',
    password: passwordValue,
    captcha_token: 'synthetic-account-proof',
  })
  expect(password.value).toBe('')
  expect(password.type).toBe('password')
  expect(email.value).toBe('owner@example.test')
  expect(email.closest('fieldset')?.disabled).toBe(true)

  const loadingButton = screen.getByRole('button', { name: 'Signing in…' })
  expect(loadingButton.hasAttribute('disabled')).toBe(true)
  expect(loadingButton.getAttribute('aria-busy')).toBe('true')

  fireEvent.submit(form)
  expect(signInAccount).toHaveBeenCalledTimes(1)

  await act(async () => {
    pending.resolve(session)
    await pending.promise
  })

  await screen.findByText('Signed in. Chat is still in development.')

  expect(
    screen.getByRole('button', { name: 'Signed in' }).hasAttribute('disabled'),
  ).toBe(true)
  expect(screen.queryByText('Human verification')).toBeNull()
})

test('an expired proof disables submission again', async () => {
  const { form } = await mountForm()
  const options = widgetOptions()

  act(() => {
    options.callback('synthetic-account-proof')
  })

  expect(
    screen.getByRole('button', { name: 'Sign in' }).hasAttribute('disabled'),
  ).toBe(false)

  act(() => {
    options['expired-callback']()
  })

  expect(
    screen.getByRole('button', { name: 'Sign in' }).hasAttribute('disabled'),
  ).toBe(true)

  fireEvent.submit(form)
  expect(signInAccount).not.toHaveBeenCalled()
})

test.each([
  {
    name: 'credential rejection',
    error: new AccountSignInRejectedError(),
    message: 'Sign-in was rejected. Check your details and try again.',
  },
  {
    name: 'verification rejection',
    error: new AccountVerificationRequiredError(),
    message: 'Verification was not accepted. Complete a new check.',
  },
])('requires a fresh proof after $name', async ({ error, message }) => {
  vi.mocked(signInAccount)
    .mockRejectedValueOnce(error)
    .mockResolvedValueOnce(session)

  const { user, email, password } = await mountForm()
  const oldOptions = widgetOptions()

  await user.type(email, 'owner@example.test')
  await user.type(password, passwordValue)

  act(() => {
    oldOptions.callback('first-proof')
  })

  await user.click(screen.getByRole('button', { name: 'Sign in' }))

  await screen.findByText(message)
  await screen.findByText('Complete the check to continue.')

  expect(api.render).toHaveBeenCalledTimes(2)
  expect(password.value).toBe('')
  expect(email.value).toBe('owner@example.test')
  expect(signInAccount).toHaveBeenCalledTimes(1)

  act(() => {
    oldOptions.callback('stale-proof')
  })

  expect(
    screen.getByRole('button', { name: 'Sign in' }).hasAttribute('disabled'),
  ).toBe(true)

  await user.type(password, passwordValue)

  act(() => {
    widgetOptions(1).callback('fresh-proof')
    oldOptions['expired-callback']()
  })

  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  await screen.findByText('Signed in. Chat is still in development.')

  expect(signInAccount).toHaveBeenCalledTimes(2)
  expect(
    vi.mocked(signInAccount).mock.calls[1]?.[0].captcha_token,
  ).toBe('fresh-proof')
})

test('closing invokes the parent and unmount cancels a pending request', async () => {
  const pending = deferredSession()
  vi.mocked(signInAccount).mockReturnValue(pending.promise)

  const { user, onClose, view, email, password } = await mountForm()

  await user.type(email, 'owner@example.test')
  await user.type(password, passwordValue)

  act(() => {
    widgetOptions().callback('synthetic-account-proof')
  })

  await user.click(screen.getByRole('button', { name: 'Sign in' }))

  const signal = vi.mocked(signInAccount).mock.calls[0]?.[1]

  await user.click(screen.getByRole('button', { name: 'Close sign-in' }))

  expect(onClose).toHaveBeenCalledTimes(1)

  // The parent will remove the form when onClose is called.
  view.unmount()
  expect(signal?.aborted).toBe(true)

  await act(async () => {
    pending.resolve(session)
    await pending.promise
  })

  expect(signInAccount).toHaveBeenCalledTimes(1)
  expect(view.container.childElementCount).toBe(0)
})

test('does not load verification or submit outside development', () => {
  vi.stubEnv('DEV', false)

  render(
    <AccountSignInForm
      siteKey="public-test-site-key"
      onClose={vi.fn()}
    />,
  )

  expect(
    screen.getByText('Account sign-in is not available here yet.'),
  ).toBeDefined()
  expect(loadTurnstile).not.toHaveBeenCalled()

  fireEvent.submit(screen.getByRole('form', { name: 'Sign in' }))

  expect(signInAccount).not.toHaveBeenCalled()
})