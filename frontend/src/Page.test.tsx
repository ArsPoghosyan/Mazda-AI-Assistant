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
    expect(screen.getByRole('link', { name: 'Terms of Service' }).getAttribute('href')).toBe('/terms')
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

test.each(['/', '/privacy-other', '/terms-other'])(
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
    expect(screen.getByRole('link', { name: 'Terms of Service' }).getAttribute('href')).toBe('/terms')
    expect(screen.getByRole('button', { name: 'Sign In' }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
    expect(fetchMock.mock.calls.every(([input]) => input === '/api/v1/health')).toBe(true)
  },
)

test(
  'registration opens safe new-tab policy links near submission without clearing credentials',
  async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    const close = vi.fn()
    const accepted = vi.fn()
    render(<AccountSignUpForm siteKey="" onClose={close} onAccepted={accepted} />)
    const email = screen.getByLabelText('Email') as HTMLInputElement
    const password = screen.getByLabelText('Password', { exact: true }) as HTMLInputElement
    fireEvent.change(email, { target: { value: 'owner@example.test' } })
    fireEvent.change(password, { target: { value: 'synthetic-password' } })
    for (const [name, path] of [['Privacy Notice', '/privacy'], ['Terms of Service', '/terms']]) {
      const link = screen.getByRole('link', { name })
      expect(link.getAttribute('href')).toBe(path)
      expect(link.getAttribute('target')).toBe('_blank')
      expect(link.getAttribute('rel')).toBe('noopener noreferrer')
      expect(link.className).toContain('underline')
      // jsdom does not navigate tabs; check app state around the native link.
      link.addEventListener('click', (event) => event.preventDefault())
      await user.click(link)
      expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false)
    }
    await user.click(screen.getByText(/I agree to the/))
    expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false)
    expect(screen.queryByText(/opens in a new tab/)).toBeNull()
    expect(email.value).toBe('owner@example.test')
    expect(password.value).toBe('synthetic-password')
    expect(close).not.toHaveBeenCalled()
    expect(accepted).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
    expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false)
  },
)

test('sign-in leaves policy links to registration and the site footer', () => {
  render(<AccountSignInForm siteKey="" onClose={vi.fn()} />)
  expect(screen.queryByRole('link', { name: /Privacy Notice/ })).toBeNull()
  expect(screen.queryByRole('link', { name: /Terms of Service/ })).toBeNull()
  expect(screen.queryByRole('checkbox')).toBeNull()
})

test.each(['/terms', '/terms/', '/terms?source=google', '/terms/#terms-privacy'])(
  '%s opens development-stage Terms without starting backend or authentication requests',
  async (url) => {
    window.history.replaceState(null, '', url)
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    render(<StrictMode><Page /></StrictMode>)
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getByRole('heading', { name: 'Terms of Service', level: 1 })).toBeTruthy()
    expect(document.title).toBe('Terms of Service | Mazda AI Assistant')
    expect(screen.getByRole('link', { name: 'Back to Mazda AI Assistant' }).getAttribute('href')).toBe('/')
    const privacyLinks = screen.getAllByRole('link', { name: 'Privacy Notice' })
    expect(privacyLinks.every((link) => link.getAttribute('href') === '/privacy')).toBe(true)
    expect(screen.getByRole('link', { name: 'arsenpoghosyan29@gmail.com' }).getAttribute('href')).toBe('mailto:arsenpoghosyan29@gmail.com')
    expect(screen.queryByRole('button', { name: 'Sign In' })).toBeNull()
    expect(screen.queryByRole('checkbox')).toBeNull()
    await act(async () => { await Promise.resolve() })
    expect(fetchMock).not.toHaveBeenCalled()
  },
)

test('Terms have keyboard access and describe current availability without claiming active automotive guidance', async () => {
  const user = userEvent.setup()
  window.history.replaceState(null, '', '/terms')
  render(<Page />)
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('link', { name: 'Skip to terms of service' }))
  expect(screen.getByRole('link', { name: 'Skip to terms of service' }).getAttribute('href')).toBe('#terms-content')
  expect(screen.getByRole('main').id).toBe('terms-content')
  expect(screen.getByRole('main').getAttribute('tabindex')).toBe('-1')
  await user.tab()
  expect(document.activeElement).toBe(screen.getByRole('link', { name: 'Back to Mazda AI Assistant' }))
  expect(screen.getByText(/Public account and guest access are not enabled/)).toBeTruthy()
  expect(screen.getByText(/current website does not generate automotive advice/)).toBeTruthy()
  expect(screen.getByText(/independent, unofficial and unaffiliated with Mazda/)).toBeTruthy()
  expect(screen.getByText(/Signing out ends the local session; it does not delete the account/)).toBeTruthy()
  expect(screen.getByText(/rights or protections that apply under applicable law/)).toBeTruthy()
})
