import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import App from './App'
import { loadTurnstile, type TurnstileApi } from './lib/turnstile'

vi.mock('./lib/turnstile', () => ({ loadTurnstile: vi.fn() }))
vi.mock('./hooks/useAccountSession', () => ({
  useAccountSession: () => ({
    enabled: import.meta.env.DEV,
    status: import.meta.env.DEV ? 'signed_out' : 'disabled',
    session: null,
    message: '',
    refresh: vi.fn(),
    acceptSignIn: vi.fn(),
    acceptSignOut: vi.fn(),
  }),
}))

const prototype = HTMLDialogElement.prototype
const originalShow = Object.getOwnPropertyDescriptor(prototype, 'showModal')
const originalClose = Object.getOwnPropertyDescriptor(prototype, 'close')
let api: TurnstileApi

function healthResponse() {
  return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
}

beforeEach(() => {
  // jsdom has no native modal/top-layer implementation. Browser checks cover that.
  Object.defineProperty(prototype, 'showModal', {
    configurable: true,
    value: vi.fn(function (this: HTMLDialogElement) { this.open = true }),
  })
  Object.defineProperty(prototype, 'close', {
    configurable: true,
    value: vi.fn(function (this: HTMLDialogElement) { this.open = false }),
  })
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_TURNSTILE_SITE_KEY', 'public-test-site-key')
  api = {
    ready: (callback) => callback(),
    render: vi.fn<TurnstileApi['render']>(() => 'sign-in-test-widget'),
    reset: vi.fn(),
    remove: vi.fn(),
  }
  vi.mocked(loadTurnstile).mockReset()
  vi.mocked(loadTurnstile).mockResolvedValue(api)
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockImplementation(async (input) => {
    if (input === '/api/v1/health') return healthResponse()
    throw new Error('Unexpected request')
  }))
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

async function mountApp() {
  const user = userEvent.setup()
  const view = render(<StrictMode><App /></StrictMode>)
  await waitFor(() => expect(screen.queryByText('Starting the service… This may take about a minute.')).toBeNull())
  const trigger = screen.getByRole('button', { name: 'Sign In' })
  return { user, view, trigger }
}

async function openDialog() {
  const app = await mountApp()
  await app.user.click(app.trigger)
  await screen.findByText('Complete the check to continue.')
  const dialog = screen.getByRole('dialog', { name: 'Sign in' })
  return { ...app, dialog }
}

function options() {
  const value = vi.mocked(api.render).mock.calls.at(-1)?.[1]
  if (!value) throw new Error('Expected the sign-in widget')
  return value
}

test('page load keeps sign-in closed and does not load verification', async () => {
  const { trigger } = await mountApp()
  expect(trigger.getAttribute('aria-haspopup')).toBe('dialog')
  expect(trigger.getAttribute('aria-expanded')).toBe('false')
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(loadTurnstile).not.toHaveBeenCalled()
  expect(vi.mocked(fetch).mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
})

test('opens outside the hero, focuses email, and restores focus on Close', async () => {
  const { user, trigger, dialog } = await openDialog()
  expect(dialog.closest('main')).toBeNull()
  expect(dialog.getAttribute('aria-modal')).toBe('true')
  expect(trigger.getAttribute('aria-expanded')).toBe('true')
  expect(document.activeElement).toBe(within(dialog).getByLabelText('Email'))
  expect(document.body.style.overflow).toBe('hidden')
  expect(options().size).toBe('flexible')
  expect(options().action).toBe('account_sign_in')
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)

  await user.click(within(dialog).getByRole('button', { name: 'Close sign-in' }))
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(document.activeElement).toBe(trigger)
  expect(document.body.style.overflow).toBe('')
  expect(trigger.getAttribute('aria-expanded')).toBe('false')
})

test('a native cancel event closes the dialog and restores focus', async () => {
  const { trigger, dialog } = await openDialog()
  fireEvent(dialog, new Event('cancel', { cancelable: true }))
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(document.activeElement).toBe(trigger)
  expect(document.body.style.overflow).toBe('')
})

test('focus guards wrap between the first and last available controls', async () => {
  const { dialog } = await openDialog()
  act(() => options().callback('synthetic-proof'))
  const first = within(dialog).getByRole('button', { name: 'Close sign-in' })
  const last = within(dialog).getByRole('button', { name: 'Create account' })
  // jsdom has no layout. Mark the boundary controls as visible for this check.
  const rectangles = [new DOMRect(0, 0, 100, 44)] as unknown as DOMRectList
  vi.spyOn(first, 'getClientRects').mockReturnValue(rectangles)
  vi.spyOn(last, 'getClientRects').mockReturnValue(rectangles)
  const guards = dialog.querySelectorAll<HTMLElement>('[data-dialog-focus-guard]')
  act(() => guards[0]?.focus())
  expect(document.activeElement).toBe(last)
  act(() => guards[1]?.focus())
  expect(document.activeElement).toBe(first)
})

test('reopening clears credentials and ignores the old verification proof', async () => {
  const { user, trigger, dialog } = await openDialog()
  const staleOptions = options()
  await user.type(within(dialog).getByLabelText('Email'), 'owner@example.test')
  await user.type(within(dialog).getByLabelText('Password', { exact: true }), 'synthetic-password')
  await user.click(within(dialog).getByRole('button', { name: 'Close sign-in' }))
  await user.click(trigger)
  await screen.findByText('Complete the check to continue.')

  expect(screen.getByLabelText<HTMLInputElement>('Email').value).toBe('')
  expect(screen.getByLabelText<HTMLInputElement>('Password', { exact: true }).value).toBe('')
  act(() => staleOptions.callback('stale-proof'))
  expect(screen.getByRole('button', { name: 'Sign in' }).hasAttribute('disabled')).toBe(true)
  expect(vi.mocked(fetch).mock.calls.every(([url]) => url === '/api/v1/health')).toBe(true)
})

test('submits the sign-in request once and cancels it when the dialog closes', async () => {
  let complete!: (response: Response) => void
  const pending = new Promise<Response>((resolve) => { complete = resolve })
  vi.mocked(fetch).mockImplementation(async (url) => {
    if (url === '/api/v1/health') return healthResponse()
    if (url === '/api/v1/account/sign-in') return pending
    throw new Error('Unexpected request')
  })
  const { user, trigger, dialog } = await openDialog()
  await user.type(within(dialog).getByLabelText('Email'), 'owner@example.test')
  await user.type(within(dialog).getByLabelText('Password', { exact: true }), 'synthetic-password')
  act(() => options().callback('synthetic-proof'))
  await user.click(within(dialog).getByRole('button', { name: 'Sign in' }))
  const calls = vi.mocked(fetch).mock.calls.filter(([url]) => url === '/api/v1/account/sign-in')
  expect(calls).toHaveLength(1)
  expect(JSON.parse(String(calls[0]?.[1]?.body))).toEqual({
    email: 'owner@example.test', password: 'synthetic-password', captcha_token: 'synthetic-proof',
  })
  const signal = calls[0]?.[1]?.signal
  expect(signal?.aborted).toBe(false)
  await user.click(within(dialog).getByRole('button', { name: 'Close sign-in' }))
  expect(signal?.aborted).toBe(true)
  expect(document.activeElement).toBe(trigger)
  await act(async () => {
    complete(Response.json({
      user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
      expires_at: '2030-01-01T12:00:00Z', absolute_expires_at: '2030-01-30T12:00:00Z',
    }))
    await pending
  })
  expect(screen.queryByText('Signed in. Chat is still in development.')).toBeNull()
})

test('registration and confirmation return to a separate sign-in inside the same dialog', async () => {
  vi.mocked(fetch).mockImplementation(async (url) => {
    if (url === '/api/v1/health') return healthResponse()
    if (url === '/api/v1/account/sign-up') {
      return Response.json({ status: 'accepted' }, { status: 202 })
    }
    if (url === '/api/v1/account/confirm-email') {
      return Response.json({ status: 'confirmed' })
    }
    throw new Error('Unexpected request')
  })

  const { user, dialog } = await openDialog()
  const modalOpens = vi.mocked(prototype.showModal).mock.calls.length

  await user.click(within(dialog).getByRole('button', { name: 'Create account' }))
  await screen.findByText('Complete the check to continue.')

  expect(screen.getByRole('dialog', { name: 'Create account' })).toBe(dialog)
  expect(options().action).toBe('account_sign_up')
  expect(document.activeElement).toBe(within(dialog).getByLabelText('Email'))

  await user.type(within(dialog).getByLabelText('Email'), 'owner@example.test')
  await user.type(within(dialog).getByLabelText('Password', { exact: true }), 'synthetic-password')
  fireEvent.click(within(dialog).getByRole('checkbox'))
      act(() => options().callback('synthetic-registration-proof'))
  await user.click(within(dialog).getByRole('button', { name: 'Create account' }))

  await screen.findByRole('dialog', { name: 'Confirm your email' })
  const code = within(dialog).getByLabelText('Verification code')
  expect(document.activeElement).toBe(code)
  expect(within(dialog).queryByLabelText('Password', { exact: true })).toBeNull()

  await user.paste('00001234')
  await user.click(within(dialog).getByRole('button', { name: 'Confirm email' }))
  await screen.findByText('Email confirmed. You can now sign in.')

  const confirmationCalls = vi.mocked(fetch).mock.calls.filter(
    ([url]) => url === '/api/v1/account/confirm-email',
  )
  expect(confirmationCalls).toHaveLength(1)
  expect(JSON.parse(String(confirmationCalls[0]?.[1]?.body))).toEqual({
    email: 'owner@example.test', code: '00001234',
  })
  expect(vi.mocked(fetch).mock.calls.some(
    ([url]) => url === '/api/v1/account/sign-in',
  )).toBe(false)

  await user.click(within(dialog).getByRole('button', { name: 'Continue to sign in' }))
  await screen.findByText('Complete the check to continue.')

  expect(screen.getByRole('dialog', { name: 'Sign in' })).toBe(dialog)
  expect(within(dialog).getByLabelText<HTMLInputElement>('Email').value).toBe('owner@example.test')
  expect(within(dialog).getByLabelText<HTMLInputElement>('Password', { exact: true }).value).toBe('')
  expect(options().action).toBe('account_sign_in')
  expect(vi.mocked(prototype.showModal)).toHaveBeenCalledTimes(modalOpens)
  expect(document.body.style.overflow).toBe('hidden')
  expect(vi.mocked(fetch).mock.calls.some(
    ([url]) => url === '/api/v1/account/sign-in',
  )).toBe(false)
})

test.each(['registration', 'confirmation'] as const)(
  'closing from %s resets the flow and restores focus', async (stage) => {
    vi.mocked(fetch).mockImplementation(async (url) => {
      if (url === '/api/v1/health') return healthResponse()
      if (url === '/api/v1/account/sign-up') {
        return Response.json({ status: 'accepted' }, { status: 202 })
      }
      throw new Error('Unexpected request')
    })

    const { user, trigger, dialog } = await openDialog()
    await user.click(within(dialog).getByRole('button', { name: 'Create account' }))
    await screen.findByText('Complete the check to continue.')
    await user.type(within(dialog).getByLabelText('Email'), 'owner@example.test')
    await user.type(within(dialog).getByLabelText('Password', { exact: true }), 'synthetic-password')

    if (stage === 'confirmation') {
      fireEvent.click(within(dialog).getByRole('checkbox'))
      act(() => options().callback('synthetic-registration-proof'))
      await user.click(within(dialog).getByRole('button', { name: 'Create account' }))
      await screen.findByRole('dialog', { name: 'Confirm your email' })
      await user.type(within(dialog).getByLabelText('Verification code'), '00001234')
    }

    fireEvent(dialog, new Event('cancel', { cancelable: true }))

    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(trigger)
    expect(document.body.style.overflow).toBe('')

    await user.click(trigger)
    await screen.findByText('Complete the check to continue.')

    const reopened = screen.getByRole('dialog', { name: 'Sign in' })
    expect(within(reopened).getByLabelText<HTMLInputElement>('Email').value).toBe('')
    expect(within(reopened).getByLabelText<HTMLInputElement>('Password', { exact: true }).value).toBe('')
    expect(within(reopened).queryByLabelText('Verification code')).toBeNull()
    expect(options().action).toBe('account_sign_in')
  },
)

test('unmount restores the previous body scroll setting', async () => {
  document.body.style.overflow = 'auto'
  const { view } = await openDialog()
  view.unmount()
  expect(document.body.style.overflow).toBe('auto')
  document.body.style.overflow = ''
})

test('sign-in remains unavailable outside development', async () => {
  vi.stubEnv('DEV', false)
  const { user, trigger } = await mountApp()
  expect(trigger.hasAttribute('disabled')).toBe(true)
  await user.click(trigger)
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(loadTurnstile).not.toHaveBeenCalled()
})
