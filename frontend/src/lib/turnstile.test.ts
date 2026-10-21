import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { TurnstileApi } from './turnstile'

const SCRIPT_URL =
  'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

const SCRIPT_SELECTOR = `script[src="${SCRIPT_URL}"]`
const LOAD_ERROR = 'Human verification could not be loaded.'

function makeApi(): TurnstileApi {
  return {
    ready: vi.fn<TurnstileApi['ready']>((callback) => callback()),
    render: vi.fn<TurnstileApi['render']>(() => 'synthetic-widget'),
    reset: vi.fn<TurnstileApi['reset']>(),
    remove: vi.fn<TurnstileApi['remove']>(),
  }
}

function pendingScript(): HTMLScriptElement {
  const script =
    document.querySelector<HTMLScriptElement>(SCRIPT_SELECTOR)

  if (!script) {
    throw new Error('Expected a Turnstile script element.')
  }

  return script
}

beforeEach(() => {
  vi.resetModules()
  vi.useFakeTimers()
  delete window.turnstile
})

afterEach(() => {
  vi.clearAllTimers()
  vi.useRealTimers()
  delete window.turnstile

  document.querySelectorAll(SCRIPT_SELECTOR).forEach((script) => {
    script.remove()
  })

  vi.restoreAllMocks()
})

test('importing the loader does not load the script', async () => {
  await import('./turnstile')

  expect(document.querySelectorAll(SCRIPT_SELECTOR)).toHaveLength(0)
  expect(vi.getTimerCount()).toBe(0)
})

test('concurrent callers share one loading attempt', async () => {
  const { loadTurnstile } = await import('./turnstile')

  const first = loadTurnstile()
  const second = loadTurnstile()

  expect(second).toBe(first)
  expect(document.querySelectorAll(SCRIPT_SELECTOR)).toHaveLength(1)

  const script = pendingScript()
  expect(script.async).toBe(false)

  const api = makeApi()

  api.ready = vi.fn<TurnstileApi['ready']>((callback) => {
    if (script.async || script.defer) {
      throw new Error('SDK readiness requires a non-async script')
    }

    callback()
  })
  window.turnstile = api
  script.dispatchEvent(new Event('load'))

  await expect(first).resolves.toBe(api)
  await expect(second).resolves.toBe(api)

  expect(loadTurnstile()).toBe(first)
  expect(api.ready).toHaveBeenCalledTimes(1)
  expect(script.onload).toBeNull()
  expect(script.onerror).toBeNull()
  expect(vi.getTimerCount()).toBe(0)
})

test('reuses an existing SDK without appending a script', async () => {
  const { loadTurnstile } = await import('./turnstile')
  const api = makeApi()
  window.turnstile = api

  await expect(loadTurnstile()).resolves.toBe(api)

  expect(api.ready).toHaveBeenCalledTimes(1)
  expect(document.querySelectorAll(SCRIPT_SELECTOR)).toHaveLength(0)
  expect(vi.getTimerCount()).toBe(0)
})

test('waits for SDK readiness after the script loads', async () => {
  const { loadTurnstile } = await import('./turnstile')
  const callbacks: Array<() => void> = []
  const api = makeApi()

  api.ready = vi.fn<TurnstileApi['ready']>((callback) => {
    callbacks.push(callback)
  })

  const pending = loadTurnstile()
  const resolved = vi.fn()
  void pending.then(resolved)

  window.turnstile = api
  pendingScript().dispatchEvent(new Event('load'))
  await Promise.resolve()

  expect(callbacks).toHaveLength(1)
  expect(resolved).not.toHaveBeenCalled()

  callbacks[0]?.()

  await expect(pending).resolves.toBe(api)
  expect(vi.getTimerCount()).toBe(0)
})

test('script failure cleans up and permits a fresh attempt', async () => {
  const { loadTurnstile } = await import('./turnstile')
  const first = loadTurnstile()
  const failedScript = pendingScript()
  const failure = expect(first).rejects.toThrow(LOAD_ERROR)

  failedScript.dispatchEvent(new Event('error'))
  await failure

  expect(failedScript.isConnected).toBe(false)
  expect(failedScript.onload).toBeNull()
  expect(failedScript.onerror).toBeNull()
  expect(vi.getTimerCount()).toBe(0)

  const retry = loadTurnstile()
  expect(retry).not.toBe(first)
  expect(document.querySelectorAll(SCRIPT_SELECTOR)).toHaveLength(1)

  const api = makeApi()
  window.turnstile = api
  pendingScript().dispatchEvent(new Event('load'))

  await expect(retry).resolves.toBe(api)
})

test('a loaded script without a usable SDK fails safely', async () => {
  const { loadTurnstile } = await import('./turnstile')
  const pending = loadTurnstile()
  const script = pendingScript()
  const failure = expect(pending).rejects.toThrow(LOAD_ERROR)

  script.dispatchEvent(new Event('load'))
  await failure

  expect(script.isConnected).toBe(false)
  expect(script.onload).toBeNull()
  expect(script.onerror).toBeNull()
  expect(vi.getTimerCount()).toBe(0)
})

test.each(['script', 'ready'])(
  'times out during %s loading and permits retry',
  async (phase) => {
    const { loadTurnstile } = await import('./turnstile')
    const callbacks: Array<() => void> = []
    const first = loadTurnstile()
    const script = pendingScript()

    if (phase === 'ready') {
      const api = makeApi()
      api.ready = vi.fn<TurnstileApi['ready']>((callback) => {
        callbacks.push(callback)
      })

      window.turnstile = api
      script.dispatchEvent(new Event('load'))
      expect(callbacks).toHaveLength(1)
    }

    const failure = expect(first).rejects.toThrow(LOAD_ERROR)
    await vi.advanceTimersByTimeAsync(10_000)
    await failure

    expect(script.isConnected).toBe(false)
    expect(script.onload).toBeNull()
    expect(script.onerror).toBeNull()
    expect(vi.getTimerCount()).toBe(0)

    // A readiness callback arriving after timeout cannot revive the attempt.
    callbacks[0]?.()

    delete window.turnstile
    const retry = loadTurnstile()
    expect(retry).not.toBe(first)

    const api = makeApi()
    window.turnstile = api
    pendingScript().dispatchEvent(new Event('load'))

    await expect(retry).resolves.toBe(api)
    expect(vi.getTimerCount()).toBe(0)
  },
)

test('an SDK readiness exception becomes a generic failure', async () => {
  const { loadTurnstile } = await import('./turnstile')
  const api = makeApi()

  api.ready = vi.fn<TurnstileApi['ready']>(() => {
    throw new Error('Private SDK failure details')
  })
  window.turnstile = api

  await expect(loadTurnstile()).rejects.toThrow(LOAD_ERROR)

  expect(document.querySelectorAll(SCRIPT_SELECTOR)).toHaveLength(0)
  expect(vi.getTimerCount()).toBe(0)
})

test('a script insertion exception becomes a generic failure', async () => {
  const { loadTurnstile } = await import('./turnstile')

  vi.spyOn(document.head, 'append').mockImplementationOnce(() => {
    throw new Error('Private insertion failure details')
  })

  await expect(loadTurnstile()).rejects.toThrow(LOAD_ERROR)

  expect(document.querySelectorAll(SCRIPT_SELECTOR)).toHaveLength(0)
  expect(vi.getTimerCount()).toBe(0)
})