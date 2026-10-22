import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import {
  AccountEmailConfirmationRejectedError,
  confirmAccountEmail,
  type AccountEmailConfirmationResponse,
} from '../api/account-registration'
import AccountEmailConfirmationForm from './AccountEmailConfirmationForm'

vi.mock('../api/account-registration', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../api/account-registration')>()

  return {
    ...actual,
    confirmAccountEmail: vi.fn(),
  }
})

const confirmation: AccountEmailConfirmationResponse = {
  status: 'confirmed',
}

beforeEach(() => {
  vi.stubEnv('DEV', true)
  vi.mocked(confirmAccountEmail).mockReset()
})

afterEach(() => {
  cleanup()
  vi.unstubAllEnvs()
})

function deferredConfirmation() {
  let resolve!: (value: AccountEmailConfirmationResponse) => void

  const promise = new Promise<AccountEmailConfirmationResponse>((complete) => {
    resolve = complete
  })

  return { promise, resolve }
}

function mountForm() {
  const user = userEvent.setup()
  const onClose = vi.fn()
  const onSignIn = vi.fn()

  const view = render(
    <StrictMode>
      <AccountEmailConfirmationForm
        email="owner@example.test"
        onClose={onClose}
        onSignIn={onSignIn}
      />
    </StrictMode>,
  )

  const code = screen.getByRole<HTMLInputElement>('textbox', {
    name: 'Verification code',
  })
  const form = screen.getByRole('form', {
    name: 'Confirm your email',
  })

  return { user, onClose, onSignIn, view, code, form }
}

test('focuses the code field and supports code autofill', () => {
  const { code } = mountForm()

  expect(document.activeElement).toBe(code)
  expect(code.type).toBe('text')
  expect(code.inputMode).toBe('numeric')
  expect(code.autocomplete).toBe('one-time-code')
  expect(code.required).toBe(true)
  expect(screen.getByText('owner@example.test')).toBeDefined()
  expect(confirmAccountEmail).not.toHaveBeenCalled()
  expect(
    screen.queryByRole('button', { name: 'Continue to sign in' }),
  ).toBeNull()
})

test.each([
  '',
  '12345',
  '12345678901',
  '12345a',
  '123 456',
  '１２３４５６',
])('does not submit invalid code %j', (value) => {
  const { code, form, onSignIn } = mountForm()

  // Bypass typing limits to exercise the form's validation guard.
  fireEvent.change(code, { target: { value } })
  fireEvent.submit(form)

  expect(confirmAccountEmail).not.toHaveBeenCalled()
  expect(onSignIn).not.toHaveBeenCalled()
})

test('pastes a code, preserves leading zeros, and waits for explicit sign-in navigation', async () => {
  const pending = deferredConfirmation()
  vi.mocked(confirmAccountEmail).mockReturnValue(pending.promise)

  const { user, code, form, onSignIn } = mountForm()

  await user.click(code)
  await user.paste('00001234')
  await user.click(screen.getByRole('button', { name: 'Confirm email' }))

  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)
  expect(vi.mocked(confirmAccountEmail).mock.calls[0]?.[0]).toEqual({
    email: 'owner@example.test',
    code: '00001234',
  })
  expect(vi.mocked(confirmAccountEmail).mock.calls[0]?.[1]).toBeInstanceOf(
    AbortSignal,
  )
  expect(code.value).toBe('')
  expect(code.closest('fieldset')?.disabled).toBe(true)
  expect(onSignIn).not.toHaveBeenCalled()

  const loadingButton = screen.getByRole('button', { name: 'Confirming…' })

  expect(loadingButton.hasAttribute('disabled')).toBe(true)
  expect(loadingButton.getAttribute('aria-busy')).toBe('true')

  fireEvent.submit(form)
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)

  await act(async () => {
    pending.resolve(confirmation)
    await pending.promise
  })

  await screen.findByText('Email confirmed. You can now sign in.')

  expect(onSignIn).not.toHaveBeenCalled()

  fireEvent.submit(form)
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)

  await user.click(
    screen.getByRole('button', { name: 'Continue to sign in' }),
  )

  expect(onSignIn).toHaveBeenCalledTimes(1)
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)
})

test.each([
  {
    name: 'rejected code',
    error: new AccountEmailConfirmationRejectedError(),
    message:
      'Email confirmation was rejected. Check your email and code, then try again.',
  },
  {
    name: 'unexpected failure',
    error: new Error('private-provider-detail'),
    message: 'Email confirmation could not be completed. Please try again.',
  },
])('allows an explicit retry after $name', async ({ error, message }) => {
  vi.mocked(confirmAccountEmail)
    .mockRejectedValueOnce(error)
    .mockResolvedValueOnce(confirmation)

  const { user, code, onSignIn } = mountForm()

  await user.type(code, '00001234')
  await user.click(screen.getByRole('button', { name: 'Confirm email' }))

  await screen.findByText(message)

  expect(code.value).toBe('')
  expect(code.closest('fieldset')?.disabled).toBe(false)
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)
  expect(onSignIn).not.toHaveBeenCalled()
  expect(screen.queryByText('private-provider-detail')).toBeNull()

  await user.type(code, '00005678')
  await user.click(screen.getByRole('button', { name: 'Confirm email' }))

  await screen.findByText('Email confirmed. You can now sign in.')

  expect(confirmAccountEmail).toHaveBeenCalledTimes(2)
  expect(vi.mocked(confirmAccountEmail).mock.calls[1]?.[0]).toEqual({
    email: 'owner@example.test',
    code: '00005678',
  })
  expect(onSignIn).not.toHaveBeenCalled()
})

test('closing allows cancellation and ignores a late confirmation', async () => {
  const pending = deferredConfirmation()
  vi.mocked(confirmAccountEmail).mockReturnValue(pending.promise)

  const { user, code, onClose, onSignIn, view } = mountForm()

  await user.type(code, '00001234')
  await user.click(screen.getByRole('button', { name: 'Confirm email' }))

  const signal = vi.mocked(confirmAccountEmail).mock.calls[0]?.[1]

  await user.click(
    screen.getByRole('button', { name: 'Close email confirmation' }),
  )

  expect(onClose).toHaveBeenCalledTimes(1)

  // Simulate the parent removing the form when the dialog closes.
  view.unmount()

  expect(signal?.aborted).toBe(true)

  await act(async () => {
    pending.resolve(confirmation)
    await pending.promise
  })

  expect(onSignIn).not.toHaveBeenCalled()
  expect(confirmAccountEmail).toHaveBeenCalledTimes(1)
  expect(view.container.childElementCount).toBe(0)
})

test('does not submit outside development', () => {
  vi.stubEnv('DEV', false)

  const { code, form, onSignIn } = mountForm()

  expect(
    screen.getByText('Email confirmation is not available here yet.'),
  ).toBeDefined()
  expect(code.closest('fieldset')?.disabled).toBe(true)
  expect(
    screen.getByRole('button', { name: 'Confirm email' }).hasAttribute('disabled'),
  ).toBe(true)

  fireEvent.change(code, { target: { value: '00001234' } })
  fireEvent.submit(form)

  expect(confirmAccountEmail).not.toHaveBeenCalled()
  expect(onSignIn).not.toHaveBeenCalled()
})