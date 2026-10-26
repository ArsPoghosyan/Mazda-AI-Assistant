import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import AccountSetupFlow from './AccountSetupFlow'
import { CURRENT_TERMS_VERSION as version } from '../../shared/account-terms'

const session = { user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c', expires_at: '2030-01-01T12:00:00Z', absolute_expires_at: '2030-01-30T12:00:00Z' }
const missing = { terms_version: version, accepted_at: null, acceptance_required: true }
const time = new Date(Date.now() - 1000).toISOString()
const done = { terms_version: version, accepted_at: time }
const prototype = HTMLDialogElement.prototype
const show = Object.getOwnPropertyDescriptor(prototype, 'showModal')
const close = Object.getOwnPropertyDescriptor(prototype, 'close')

beforeEach(() => {
  Object.defineProperty(prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', '') } })
  Object.defineProperty(prototype, 'close', { configurable: true, value() { this.removeAttribute('open') } })
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  if (show) Object.defineProperty(prototype, 'showModal', show); else Reflect.deleteProperty(prototype, 'showModal')
  if (close) Object.defineProperty(prototype, 'close', close); else Reflect.deleteProperty(prototype, 'close')
})

function mount() { return render(<StrictMode><AccountSetupFlow session={session} onSessionExpired={vi.fn()} /></StrictMode>) }

test('first use opens the modal with unchecked Terms and separate safe policy links; one explicit acceptance completes setup', async () => {
  const user = userEvent.setup()
  const fetch = vi.fn<typeof globalThis.fetch>().mockImplementation(async (url, options) => {
    if (url === '/api/v1/account/terms/status') return Response.json(missing)
    expect(url).toBe('/api/v1/account/terms/accept')
    expect(JSON.parse(String(options?.body))).toEqual({ accepted: true, terms_version: version })
    return Response.json(done)
  })
  vi.stubGlobal('fetch', fetch)
  mount()
  const dialog = await screen.findByRole('dialog', { name: 'Finish account setup' })
  const checkbox = within(dialog).getByRole('checkbox', { name: 'I agree to the Terms of Service.' }) as HTMLInputElement
  expect(checkbox.checked).toBe(false)
  const submit = within(dialog).getByRole('button', { name: 'Finish setup' })
  expect(submit.hasAttribute('disabled')).toBe(true)
  fireEvent.submit(submit.closest('form')!)
  expect(fetch.mock.calls.filter(([url]) => String(url).endsWith('/accept'))).toHaveLength(0)
  for (const name of ['Privacy Notice', 'Terms of Service']) {
    const link = within(dialog).getByRole('link', { name })
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toBe('noopener noreferrer')
    expect(link.className).toContain('underline')
    link.addEventListener('click', event => event.preventDefault())
    await user.click(link)
    expect(checkbox.checked).toBe(false)
  }
  await user.click(within(dialog).getByText(/I agree to the/))
  expect(checkbox.checked).toBe(false)
  await user.click(checkbox)
  await user.click(submit)
  await screen.findByText('Account setup complete.')
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(fetch.mock.calls.filter(([url]) => String(url).endsWith('/accept'))).toHaveLength(1)
  expect(fetch.mock.calls.filter(([url]) => String(url).endsWith('/status'))).toHaveLength(1)
  expect(document.body.style.overflow).not.toBe('hidden')
})

test('returning accepted accounts skip the dialog and never resubmit agreement', async () => {
  const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(Response.json({ ...done, acceptance_required: false }))
  vi.stubGlobal('fetch', fetch)
  mount()
  await screen.findByText('Account setup complete.')
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(fetch).toHaveBeenCalledTimes(1)
})

test('Escape dismisses without accepting; setup can be reopened and the page stays locked until acceptance', async () => {
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(Response.json(missing)))
  mount()
  const dialog = await screen.findByRole('dialog')
  expect(document.body.style.overflow).toBe('hidden')
  fireEvent(dialog, new Event('cancel', { cancelable: true }))
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(screen.queryByText('Account setup complete.')).toBeNull()
  const reopen = screen.getByRole('button', { name: 'Finish account setup' })
  expect(document.activeElement).toBe(reopen)
  fireEvent.click(reopen)
  expect(screen.getByRole('dialog')).toBeTruthy()
  expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false)
})

test.each([503, 404, 500])('unavailable setup status %s blocks completion and offers manual retry', async status => {
  const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(new Response('private-detail', { status }))
    .mockImplementation(async () => Response.json(missing))
  vi.stubGlobal('fetch', fetch)
  mount()
  await screen.findByText('Account setup could not be completed. Please try again.')
  expect(screen.queryByText('Account setup complete.')).toBeNull()
  expect(screen.queryByRole('checkbox')).toBeNull()
  expect(document.body.textContent).not.toContain('private-detail')
  expect(fetch).toHaveBeenCalledTimes(1)
  fireEvent.click(screen.getByRole('button', { name: 'Retry account setup' }))
  await screen.findByRole('dialog')
  expect(fetch).toHaveBeenCalledTimes(2)
})

test('double submission sends one request, keeps the dialog on failure and permits explicit idempotent retry', async () => {
  let resolve!: (value: Response) => void
  const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(Response.json(missing))
    .mockImplementationOnce(() => new Promise<Response>(complete => { resolve = complete }))
    .mockImplementation(async () => Response.json(done))
  vi.stubGlobal('fetch', fetch)
  mount()
  const dialog = await screen.findByRole('dialog')
  fireEvent.click(within(dialog).getByRole('checkbox'))
  const form = within(dialog).getByRole('button', { name: 'Finish setup' }).closest('form')!
  fireEvent.submit(form)
  fireEvent.submit(form)
  expect(fetch).toHaveBeenCalledTimes(2)
  await act(async () => { resolve(new Response('private-detail', { status: 503 })) })
  await within(dialog).findByText('Account setup could not be completed. Please try again.')
  expect((within(dialog).getByRole('checkbox') as HTMLInputElement).checked).toBe(true)
  fireEvent.submit(form)
  await screen.findByText('Account setup complete.')
  expect(fetch).toHaveBeenCalledTimes(3)
})

test('leaving during acceptance aborts it and ignores a late success', async () => {
  let resolve!: (value: Response) => void
  let signal: AbortSignal | undefined
  const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(Response.json(missing))
    .mockImplementationOnce((_url, options) => { signal = options?.signal ?? undefined; return new Promise<Response>(complete => { resolve = complete }) })
  vi.stubGlobal('fetch', fetch)
  const { unmount } = mount()
  const dialog = await screen.findByRole('dialog')
  fireEvent.click(within(dialog).getByRole('checkbox'))
  fireEvent.submit(within(dialog).getByRole('button', { name: 'Finish setup' }).closest('form')!)
  unmount()
  expect(signal?.aborted).toBe(true)
  await act(async () => { resolve(Response.json(done)) })
  expect(screen.queryByText('Account setup complete.')).toBeNull()
})

test('a new verified account cannot inherit a previous account status response', async () => {
  let resolve!: (value: Response) => void
  const fetch = vi.fn<typeof globalThis.fetch>().mockImplementationOnce(() => new Promise<Response>(complete => { resolve = complete }))
    .mockImplementation(async () => Response.json(missing))
  vi.stubGlobal('fetch', fetch)
  const { rerender } = mount()
  await act(async () => { await Promise.resolve() })
  rerender(<StrictMode><AccountSetupFlow session={{ ...session, user_id: '663128d6-22fd-464f-a3bd-31018fdf1b3c' }} onSessionExpired={vi.fn()} /></StrictMode>)
  await screen.findByRole('dialog')
  await act(async () => { resolve(Response.json({ ...done, acceptance_required: false })) })
  expect(screen.queryByText('Account setup complete.')).toBeNull()
})

test('a status request that ignores abort still times out without granting access', async () => {
  vi.useFakeTimers()
  vi.stubGlobal('fetch', vi.fn<typeof fetch>(() => new Promise<Response>(() => {})))
  mount()
  await act(async () => { await vi.advanceTimersByTimeAsync(15_000) })
  expect(screen.getByRole('button', { name: 'Retry account setup' })).toBeTruthy()
  expect(screen.queryByText('Account setup complete.')).toBeNull()
})

test('expired session provides a return path without accepting', async () => {
  vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(Response.json({}, { status: 401 })))
  const expired = vi.fn()
  render(<AccountSetupFlow session={session} onSessionExpired={expired} />)
  await screen.findByText('Your session expired. Please sign in again.')
  fireEvent.click(screen.getByRole('button', { name: 'Check account session' }))
  expect(expired).toHaveBeenCalledOnce()
})
