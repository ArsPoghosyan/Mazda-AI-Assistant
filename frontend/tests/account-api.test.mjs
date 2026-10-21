import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AccountVerificationRequiredError,
  signInAccount,
} from '../src/api/account.ts'

const credentials = {
  email: 'owner@example.test',
  password: '  synthetic-password-é  ',
  captcha_token: 'synthetic-captcha-proof',
}

const session = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}

test('submits only credentials and proof once, returning only metadata', async (t) => {
  const controller = new AbortController()

  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/account/sign-in')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.deepEqual(options.headers, {
      'Content-Type': 'application/json',
    })
    assert.deepEqual(JSON.parse(options.body), credentials)

    return Response.json({
      ...session,
      access_token: 'unexpected-synthetic-provider-token',
    })
  })

  const result = await signInAccount(
    { ...credentials, user_id: 'untrusted-owner' },
    controller.signal,
  )

  assert.deepEqual(result, session)
  assert.equal(request.mock.callCount(), 1)
})

for (const [status, name, message] of [
  [
    401,
    'AccountSignInRejectedError',
    'Sign-in was rejected. Please try again.',
  ],
  [
    403,
    'Error',
    'Sign-in could not be verified. Please try again.',
  ],
  [
    503,
    'Error',
    'Sign-in is temporarily unavailable. Please try again.',
  ],
  [
    500,
    'Error',
    'Sign-in could not be completed. Please try again.',
  ],
]) {
  test(`handles HTTP ${status} without exposing server details`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () =>
      Response.json(
        { detail: 'Private server and provider details' },
        { status },
      ),
    )

    await assert.rejects(signInAccount(credentials), { name, message })
  })
}

test('recognizes an explicit verification rejection', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    Response.json(
      { detail: 'Private verification details' },
      {
        status: 403,
        headers: { 'X-Account-Verification': 'required' },
      },
    ),
  )

  await assert.rejects(signInAccount(credentials), (error) => {
    assert.ok(error instanceof AccountVerificationRequiredError)
    assert.equal(error.message, 'Please complete human verification.')
    return true
  })
})

test('ignores the verification header on an unavailable response', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    Response.json(
      { detail: 'Private service details' },
      {
        status: 503,
        headers: { 'X-Account-Verification': 'required' },
      },
    ),
  )

  await assert.rejects(signInAccount(credentials), {
    name: 'Error',
    message: 'Sign-in is temporarily unavailable. Please try again.',
  })
})

for (const [label, body] of [
  ['null', null],
  ['invalid user ID', { ...session, user_id: 'not-a-uuid' }],
  [
    'missing expiry',
    {
      user_id: session.user_id,
      absolute_expires_at: session.absolute_expires_at,
    },
  ],
  ['invalid expiry', { ...session, expires_at: 'invalid' }],
  ['non-string expiry', { ...session, expires_at: 123 }],
  [
    'invalid absolute expiry',
    { ...session, absolute_expires_at: 'invalid' },
  ],
  [
    'idle expiry beyond absolute expiry',
    { ...session, expires_at: '2031-01-01T12:00:00Z' },
  ],
]) {
  test(`rejects a response with ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json(body))

    await assert.rejects(signInAccount(credentials), {
      name: 'Error',
      message: 'Unexpected sign-in response.',
    })
  })
}

test('rejects malformed response JSON', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('not JSON', {
      headers: { 'Content-Type': 'application/json' },
    }),
  )

  await assert.rejects(signInAccount(credentials), {
    name: 'Error',
    message: 'Unexpected sign-in response.',
  })
})

test('masks network errors without retrying', async (t) => {
  const request = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('Private transport details')
  })

  await assert.rejects(signInAccount(credentials), {
    name: 'Error',
    message: 'Sign-in could not be completed. Please try again.',
  })

  assert.equal(request.mock.callCount(), 1)
})

test('preserves request cancellation', async (t) => {
  const controller = new AbortController()
  const reason = new DOMException('Cancelled', 'AbortError')
  controller.abort(reason)

  t.mock.method(globalThis, 'fetch', async () => {
    throw reason
  })

  await assert.rejects(
    signInAccount(credentials, controller.signal),
    (error) => {
      assert.equal(error, reason)
      return true
    },
  )
})

test('preserves cancellation while reading the response body', async (t) => {
  const controller = new AbortController()
  const reason = new DOMException('Cancelled', 'AbortError')
  const response = Response.json(session)

  t.mock.method(response, 'json', async () => {
    controller.abort(reason)
    throw reason
  })
  t.mock.method(globalThis, 'fetch', async () => response)

  await assert.rejects(
    signInAccount(credentials, controller.signal),
    (error) => {
      assert.equal(error, reason)
      return true
    },
  )
})