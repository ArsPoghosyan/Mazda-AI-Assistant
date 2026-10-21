import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  ensureGuestSession,
  GuestVerificationRequiredError,
} from '../src/api/guest.ts'

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
    assert.equal(options.body, undefined)
    assert.equal(options.headers, undefined)

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

test('sends a challenge token as JSON with cookies and cancellation', async (t) => {
  const controller = new AbortController()
  const token = 'synthetic-widget-token'

  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/guest/session')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.signal, controller.signal)
    assert.deepEqual(options.headers, {
      'Content-Type': 'application/json',
    })
    assert.deepEqual(JSON.parse(options.body), {
      turnstile_token: token,
    })

    return Response.json(session)
  })

  assert.deepEqual(
    await ensureGuestSession(controller.signal, token),
    session,
  )
  assert.equal(request.mock.callCount(), 1)
})

test('recognizes an explicit human-verification response', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => {
    return Response.json(
      { detail: 'Private provider details' },
      {
        status: 403,
        headers: { 'X-Guest-Verification': 'required' },
      },
    )
  })

  await assert.rejects(ensureGuestSession(), (error) => {
    assert.ok(error instanceof GuestVerificationRequiredError)
    assert.equal(error.message, 'Please complete human verification.')
    return true
  })
})

for (const [status, message] of [
  [400, 'Guest access could not be started.'],
  [503, 'Guest access is temporarily unavailable.'],
]) {
  test(`ignores the verification header on HTTP ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => {
      return Response.json(
        { detail: 'Private server details' },
        {
          status,
          headers: { 'X-Guest-Verification': 'required' },
        },
      )
    })

    await assert.rejects(ensureGuestSession(), {
      name: 'Error',
      message,
    })
  })
}