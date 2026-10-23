import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { consumeGoogleReturn, parseGoogleReturn } from './googleReturn'

const outcomes = [
  'success',
  'rejected',
  'unavailable',
  'sign-out-required',
] as const

const invalidMarkers = [
  '',
  '#section',
  'google-sign-in=success',
  '#google-sign-in=',
  '#google-sign-in=unknown',
  '#Google-sign-in=success',
  '#google-sign-in=SUCCESS',
  '#google%2Dsign-in=success',
  '#google-sign-in=%73uccess',
  '#google-sign-in=success ',
  '#google-sign-in=success&',
  '#google-sign-in=success&google-sign-in=success',
  '#google-sign-in=success&google-sign-in=rejected',
  '#google-sign-in=success&next=https://example.test',
  '#?google-sign-in=success',
  '#access_token=synthetic-token',
] as const

let originalUrl: string
let originalState: unknown

beforeEach(() => {
  originalUrl = window.location.href
  originalState = window.history.state
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  window.history.replaceState(originalState, '', originalUrl)
})

test.each(outcomes)('consumes exact %s hint once without changing navigation state', (outcome) => {
  const hash = `#google-sign-in=${outcome}`
  const path = '/?view=account&label=hello%20world'
  const state = { syntheticEntry: 7, nested: { keep: true } }
  window.history.replaceState(state, '', path + hash)
  const length = window.history.length
  const replace = vi.spyOn(window.history, 'replaceState')
  const push = vi.spyOn(window.history, 'pushState')
  const fetch = vi.fn()
  vi.stubGlobal('fetch', fetch)

  expect(parseGoogleReturn(hash)).toBe(outcome)
  expect(consumeGoogleReturn()).toBe(outcome)
  expect(window.location.pathname + window.location.search).toBe(path)
  expect(window.location.hash).toBe('')
  expect(window.history.state).toEqual(state)
  expect(window.history.length).toBe(length)
  expect(replace).toHaveBeenCalledExactlyOnceWith(state, '', path)
  expect(push).not.toHaveBeenCalled()
  expect(fetch).not.toHaveBeenCalled()

  expect(consumeGoogleReturn()).toBeNull()
  expect(replace).toHaveBeenCalledTimes(1)
})

test.each(invalidMarkers)('leaves unsupported or ambiguous fragment %j untouched', (hash) => {
  // A missing # is parser input only: assigning it to a URL would add the #.
  const browserHash = hash.startsWith('#') || hash === '' ? hash : '#section'
  const url = new URL('/?keep=yes', window.location.origin)
  // Setting hash encodes whitespace instead of trimming it from the whole URL.
  url.hash = browserHash
  window.history.replaceState({ keep: true }, '', url.href)
  const before = window.location.href
  const replace = vi.spyOn(window.history, 'replaceState')

  expect(parseGoogleReturn(hash)).toBeNull()
  expect(consumeGoogleReturn()).toBeNull()
  expect(window.location.href).toBe(before)
  expect(window.history.state).toEqual({ keep: true })
  expect(replace).not.toHaveBeenCalled()
})

test('returns no hint if history cleanup fails and permits an explicit retry', () => {
  window.history.replaceState({ keep: true }, '', '/#google-sign-in=success')
  const replace = vi.spyOn(window.history, 'replaceState')
    .mockImplementationOnce(() => {
      throw new DOMException('Synthetic history failure', 'SecurityError')
    })

  expect(() => expect(consumeGoogleReturn()).toBeNull()).not.toThrow()
  expect(window.location.hash).toBe('#google-sign-in=success')
  expect(window.history.state).toEqual({ keep: true })
  expect(consumeGoogleReturn()).toBe('success')
  expect(window.location.hash).toBe('')
  expect(replace).toHaveBeenCalledTimes(2)
})

test('importing the helper leaves the marker and history untouched', async () => {
  window.history.replaceState(null, '', '/#google-sign-in=rejected')
  const replace = vi.spyOn(window.history, 'replaceState')
  vi.resetModules()

  await import('./googleReturn')

  expect(window.location.hash).toBe('#google-sign-in=rejected')
  expect(replace).not.toHaveBeenCalled()
})
