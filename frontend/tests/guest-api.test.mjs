import assert from 'node:assert/strict'
import { test } from 'node:test'

import { ensureGuestSession } from '../src/api/guest.ts'

const session = {
  status: 'ok',
  expires_at: '2030-01-01T12:00:00Z',
}

test('requests a guest session with cookies and cancellation support', async (t) => {
  const controller = new AbortController()

  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/guest/session')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.signal, controller.signal)

    return Response.json(session)
  })

  assert.deepEqual(
    await ensureGuestSession(controller.signal),
    session,
  )
  assert.equal(request.mock.callCount(), 1)
})

for (const [status, message] of [
  [403, 'Guest access could not be verified.'],
  [503, 'Guest access is temporarily unavailable.'],
  [500, 'Guest access could not be started.'],
]) {
  test(`handles HTTP ${status} without exposing server details`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => {
      return Response.json(
        { detail: 'Internal server details' },
        { status },
      )
    })

    await assert.rejects(ensureGuestSession(), {
      name: 'Error',
      message,
    })
  })
}

for (const [label, body] of [
  ['null', null],
  ['incorrect status', { ...session, status: 'unavailable' }],
  ['missing expiry', { status: 'ok' }],
  ['invalid expiry', { ...session, expires_at: 'invalid' }],
  ['non-string expiry', { ...session, expires_at: 123 }],
]) {
  test(`rejects a response with ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json(body))

    await assert.rejects(ensureGuestSession(), {
      name: 'Error',
      message: 'Unexpected guest session response.',
    })
  })
}

test('rejects malformed JSON', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => {
    return new Response('not JSON', {
      headers: { 'Content-Type': 'application/json' },
    })
  })

  await assert.rejects(ensureGuestSession(), {
    name: 'Error',
    message: 'Unexpected guest session response.',
  })
})

test('preserves cancellation errors for the calling component', async (t) => {
  const controller = new AbortController()
  const error = new DOMException('Aborted', 'AbortError')
  controller.abort(error)

  t.mock.method(globalThis, 'fetch', async () => {
    throw error
  })

  await assert.rejects(ensureGuestSession(controller.signal), {
    name: 'AbortError',
  })
})