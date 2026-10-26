import { StrictMode } from 'react'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import App from './App'
import { CURRENT_TERMS_VERSION as version } from '../shared/account-terms'

const session = { user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c', expires_at: '2030-01-01T12:00:00Z', absolute_expires_at: '2030-01-30T12:00:00Z' }
const prototype = HTMLDialogElement.prototype
const show = Object.getOwnPropertyDescriptor(prototype, 'showModal')
const close = Object.getOwnPropertyDescriptor(prototype, 'close')

beforeEach(() => {
  vi.stubEnv('DEV', true)
  Object.defineProperty(prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', '') } })
  Object.defineProperty(prototype, 'close', { configurable: true, value() { this.removeAttribute('open') } })
})
afterEach(() => {
  cleanup()
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
  window.history.replaceState(null, '', '/')
  if (show) Object.defineProperty(prototype, 'showModal', show); else Reflect.deleteProperty(prototype, 'showModal')
  if (close) Object.defineProperty(prototype, 'close', close); else Reflect.deleteProperty(prototype, 'close')
})

test.each(['', '#google-sign-in=success'])('verified restore %s requires explicit setup while keeping sign-out available', async hash => {
  window.history.replaceState(null, '', '/' + hash)
  const fetch = vi.fn<typeof globalThis.fetch>().mockImplementation(async url => {
    if (url === '/api/v1/health') return Response.json({ status: 'ok', service: 'mazda6-assistant-api' })
    if (url === '/api/v1/account/session') return Response.json(session)
    if (url === '/api/v1/account/terms/status') return Response.json({ terms_version: version, accepted_at: null, acceptance_required: true })
    if (url === '/api/v1/account/sign-out') return new Response(null, { status: 204 })
    throw new Error('Unexpected request')
  })
  vi.stubGlobal('fetch', fetch)
  render(<StrictMode><App /></StrictMode>)
  const dialog = await screen.findByRole('dialog', { name: 'Finish account setup' })
  expect((within(dialog).getByRole('checkbox') as HTMLInputElement).checked).toBe(false)
  expect(screen.getByRole('button', { name: 'Try as Guest' }).hasAttribute('disabled')).toBe(true)
  fireEvent(dialog, new Event('cancel', { cancelable: true }))
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
  await screen.findByRole('button', { name: 'Sign In' })
  expect(screen.queryByText('Account setup complete.')).toBeNull()
  expect(fetch.mock.calls.filter(([url]) => String(url).endsWith('/accept'))).toHaveLength(0)
  expect(fetch.mock.calls.filter(([url]) => url === '/api/v1/guest/session')).toHaveLength(0)
})
