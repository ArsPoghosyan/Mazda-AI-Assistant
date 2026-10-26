import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import Page from './Page'
import AccountSignInForm from './components/AccountSignInForm'
import AccountSignUpForm from './components/AccountSignUpForm'

vi.mock('./components/TurnstileChallenge', () => ({ default: () => null }))

let originalUrl: string
let originalTitle: string

beforeEach(() => {
  originalUrl = window.location.href
  originalTitle = document.title
  vi.stubEnv('DEV', true)
  vi.stubEnv('VITE_GOOGLE_OAUTH_ENABLED', 'false')
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  window.history.replaceState(null, '', originalUrl)
  document.title = originalTitle
})

test.each(['/privacy', '/privacy/', '/privacy?source=footer', '/privacy/#privacy-retention'])(
  '%s opens the notice directly without starting health, auth or verification requests',
  async (url) => {
    window.history.replaceState(null, '', url)
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    render(<StrictMode><Page /></StrictMode>)
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getByRole('heading', { name: 'Privacy Notice', level: 1 })).toBeTruthy()
    expect(document.title).toBe('Privacy Notice | Mazda AI Assistant')
    expect(screen.getByRole('link', { name: 'Back to Mazda AI Assistant' }).getAttribute('href')).toBe('/')
    expect(screen.getByRole('link', { name: 'arsenpoghosyan29@gmail.com' }).getAttribute('href')).toBe('mailto:arsenpoghosyan29@gmail.com')
    expect(screen.queryByRole('button', { name: 'Sign In' })).toBeNull()
    expect(screen.queryByRole('checkbox')).toBeNull()
    await act(async () => { await Promise.resolve() })
    expect(fetchMock).not.toHaveBeenCalled()
  },
)

test('the notice has keyboard navigation, confirmed expiry and approved retention without implying active AI chat', async () => {
  const user = userEvent.setup()
  window.history.replaceState(null, '', '/privacy')
  render(<Page />)
  await user.tab()
  const skip = screen.getByRole('link', { name: 'Skip to privacy notice' })
  expect(document.activeElement).toBe(skip)
  expect(skip.getAttribute('href')).toBe('#privacy-content')
  expect(screen.getByRole('main').id).toBe('privacy-content')
  expect(screen.getByRole('main').getAttribute('tabindex')).toBe('-1')
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('link', { name: 'Back to Mazda AI Assistant' }))
  expect(screen.getByText(/Guest sessions: expire after 30 inactive days/)).toBeTruthy()
  expect(screen.getByText(/Account sessions: expire after 7 inactive days/)).toBeTruthy()
  expect(screen.getByText(/Pending Google sign-in attempts: expire after 10 minutes/)).toBeTruthy()
  expect(screen.getByText(/emails and attachments: kept for up to 90 days after resolution/)).toBeTruthy()
  expect(screen.getByText(/completion records: kept for up to 12 months after resolution/)).toBeTruthy()
  expect(screen.getByText(/Public account and guest access are not enabled/)).toBeTruthy()
  expect(screen.getByText(/Session expiry does not delete an account/)).toBeTruthy()
  expect(screen.getByText(/no self-service account-deletion control/)).toBeTruthy()
})

test.each(['/', '/privacy-other'])(
  '%s preserves the landing page and footer notice link without activating production authentication',
  async (url) => {
    vi.stubEnv('DEV', false)
    vi.stubEnv('PROD', true)
    window.history.replaceState(null, '', url)
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input) => {
      if (input !== '/api/v1/health') throw new Error('Unexpected request')
      return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<StrictMode><Page /></StrictMode>)
    await screen.findByText('API connected')
    const link = screen.getByRole('link', { name: 'Privacy Notice' })
    expect(link.getAttribute('href')).toBe('/privacy')
    expect(link.hasAttribute('target')).toBe(false)
    expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
    expect(fetchMock.mock.calls.every(([input]) => input === '/api/v1/health')).toBe(true)
  },
)

test.each(['sign-in', 'registration'] as const)(
  '%s opens a labelled safe new-tab notice link without submitting or clearing credentials',
  async (mode) => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    const close = vi.fn()
    const accepted = vi.fn()
    render(mode === 'sign-in'
      ? <AccountSignInForm siteKey="" onClose={close} />
      : <AccountSignUpForm siteKey="" onClose={close} onAccepted={accepted} />)
    const email = screen.getByLabelText('Email') as HTMLInputElement
    const password = screen.getByLabelText('Password', { exact: true }) as HTMLInputElement
    fireEvent.change(email, { target: { value: 'owner@example.test' } })
    fireEvent.change(password, { target: { value: 'synthetic-password' } })
    const link = screen.getByRole('link', { name: 'Privacy Notice (opens in a new tab)' })
    expect(link.getAttribute('href')).toBe('/privacy')
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toBe('noopener noreferrer')
    // jsdom does not navigate tabs; check app state around the native link.
    link.addEventListener('click', (event) => event.preventDefault())
    await user.click(link)
    expect(email.value).toBe('owner@example.test')
    expect(password.value).toBe('synthetic-password')
    expect(close).not.toHaveBeenCalled()
    expect(accepted).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.queryByRole('checkbox')).toBeNull()
  },
)
