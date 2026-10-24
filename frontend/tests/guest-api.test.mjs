import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  ensureGuestSession,
  GuestRateLimitedError,
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

for (const [header, seconds] of [
  ['1', 1], ['61', 61], ['86400', 86400], ['00001', 1],
  [null, null], ['', null], ['0', null], ['-1', null], ['+1', null],
  ['1.5', null], ['1e2', null], ['86401', null], ['100000', null],
  ['1, 2', null], ['Wed, 21 Oct 2030 07:28:00 GMT', null],
  ['private-provider-detail', null], ['9'.repeat(1000), null],
]) {
  test(`guest 429 safely parses Retry-After ${JSON.stringify(header)}`, async (t) => {
    const response = new Response('private-provider-detail', {
      status: 429,
      headers: {
        ...(header === null ? {} : { 'Retry-After': header }),
        'X-Guest-Verification': 'required',
      },
    })
    const readBody = t.mock.method(response, 'json', async () => {
      throw new Error('Error bodies must not be read')
    })
    const request = t.mock.method(globalThis, 'fetch', async () => response)

    await assert.rejects(ensureGuestSession(), (error) => {
      assert.ok(error instanceof GuestRateLimitedError)
      assert.equal(error.retryAfterSeconds, seconds)
      assert.equal(error.message, 'Too many guest-access attempts. Please try again later.')
      assert.equal(error.cause, undefined)
      assert.equal(error instanceof GuestVerificationRequiredError, false)
      return true
    })
    assert.equal(request.mock.callCount(), 1)
    assert.equal(readBody.mock.callCount(), 0)
  })
}

for (const [status, message] of [
  [400, 'Guest access could not be started.'],
  [403, 'Guest access could not be verified.'],
  [503, 'Guest access is temporarily unavailable.'],
  [500, 'Guest access could not be started.'],
]) {
  test(`ignores Retry-After on guest HTTP ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response(null, {
      status, headers: { 'Retry-After': '61' },
    }))
    await assert.rejects(ensureGuestSession(), { name: 'Error', message })
  })
}

test('ignores Retry-After on a successful guest session response', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => Response.json(session, {
    headers: { 'Retry-After': '61' },
  }))
  assert.deepEqual(await ensureGuestSession(), session)
})

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
