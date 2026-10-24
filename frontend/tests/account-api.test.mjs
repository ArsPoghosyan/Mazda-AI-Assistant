import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AccountSignInRateLimitedError,
  AccountSignOutRequiredError,
  AccountVerificationRequiredError,
  checkAccountSession,
  signInAccount,
  signOutAccount,
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
    409,
    'AccountSignOutRequiredError',
    'Sign out before starting another account login.',
  ],
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

test('requires sign-out on conflict without reading private content or retrying', async (t) => {
  const response = new Response('private conflict details', {
    status: 409,
    headers: { 'Retry-After': '61', 'X-Account-Verification': 'required' },
  })
  const read = t.mock.method(response, 'json', async () => {
    throw new Error('Error response body must not be read')
  })
  const request = t.mock.method(globalThis, 'fetch', async () => response)

  await assert.rejects(signInAccount(credentials), (error) => {
    assert.ok(error instanceof AccountSignOutRequiredError)
    assert.equal(error.message, 'Sign out before starting another account login.')
    assert.equal(error.cause, undefined)
    return true
  })
  assert.equal(read.mock.callCount(), 0)
  assert.equal(request.mock.callCount(), 1)
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

for (const seconds of [1, 61, 600, 86_400]) {
  test(`reads a ${seconds}-second sign-in limit without reading private content or retrying`, async (t) => {
    const response = new Response('private non-JSON provider response', {
      status: 429,
      headers: {
        'Retry-After': String(seconds),
        'X-Account-Verification': 'required',
      },
    })
    const read = t.mock.method(response, 'json', async () => {
      throw new Error('Error response body must not be read')
    })
    const request = t.mock.method(globalThis, 'fetch', async () => response)

    await assert.rejects(signInAccount(credentials), (error) => {
      assert.ok(error instanceof AccountSignInRateLimitedError)
      assert.equal(error.name, 'AccountSignInRateLimitedError')
      assert.equal(error.retryAfterSeconds, seconds)
      assert.equal(error.message, 'Too many sign-in attempts. Please try again later.')
      assert.equal(error.cause, undefined)
      return true
    })
    assert.equal(request.mock.callCount(), 1)
    assert.equal(read.mock.callCount(), 0)
  })
}

for (const [label, header] of [
  ['missing', null],
  ['empty', ''],
  ['zero', '0'],
  ['negative', '-1'],
  ['fraction', '1.5'],
  ['exponent', '1e3'],
  ['too large', '86401'],
  ['oversized', '9'.repeat(1000)],
  ['date', 'Wed, 21 Oct 2030 07:28:00 GMT'],
  ['private details', 'private-retry-detail'],
  ['nonfinite', 'Infinity'],
  ['not a number', 'NaN'],
  ['multiple values', '10, 20'],
]) {
  test(`uses safe fallback for ${label} sign-in retry information`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response('private-body', {
      status: 429,
      headers: header === null ? {} : { 'Retry-After': header },
    }))

    await assert.rejects(signInAccount(credentials), (error) => {
      assert.ok(error instanceof AccountSignInRateLimitedError)
      assert.equal(error.retryAfterSeconds, null)
      assert.equal(error.message, 'Too many sign-in attempts. Please try again later.')
      assert.equal(error.cause, undefined)
      return true
    })
  })
}

for (const status of [401, 403, 503, 500]) {
  test(`ignores Retry-After on HTTP ${status} sign-in responses`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response('private-body', {
      status,
      headers: { 'Retry-After': '61' },
    }))

    await assert.rejects(signInAccount(credentials), (error) => {
      assert.equal(error instanceof AccountSignInRateLimitedError, false)
      assert.equal(error.retryAfterSeconds, undefined)
      assert.equal(error.message.includes('private-body'), false)
      return true
    })
  })
}

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

test('checks the cookie session once and returns only metadata', async (t) => {
  const controller = new AbortController()

  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/account/session')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.equal(options.body, undefined)
    assert.equal(options.headers, undefined)

    return Response.json({
      ...session,
      access_token: 'unexpected-synthetic-provider-token',
    })
  })

  assert.deepEqual(
    await checkAccountSession(controller.signal),
    session,
  )
  assert.equal(request.mock.callCount(), 1)
})

test('treats HTTP 401 as signed out without parsing its body', async (t) => {
  const request = t.mock.method(globalThis, 'fetch', async () =>
    new Response('Private rejection details', { status: 401 }),
  )

  assert.equal(await checkAccountSession(), null)
  assert.equal(request.mock.callCount(), 1)
})

for (const status of [403, 429, 500, 503]) {
  test(`session HTTP ${status} remains an error rather than signed out`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () =>
      Response.json(
        { detail: 'Private server details' },
        {
          status,
          headers: { 'X-Account-Verification': 'required' },
        },
      ),
    )

    await assert.rejects(checkAccountSession(), {
      name: 'Error',
      message: 'Account session is temporarily unavailable. Please try again.',
    })
    assert.equal(request.mock.callCount(), 1)
  })
}

for (const [label, body] of [
  ['null', null],
  ['invalid identity', { ...session, user_id: 'not-a-uuid' }],
  [
    'inconsistent expiry',
    { ...session, expires_at: '2031-01-01T12:00:00Z' },
  ],
]) {
  test(`rejects session metadata with ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json(body))

    await assert.rejects(checkAccountSession(), {
      name: 'Error',
      message: 'Unexpected account-session response.',
    })
  })
}

test('rejects malformed session JSON without exposing it', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('Private malformed response', {
      headers: { 'Content-Type': 'application/json' },
    }),
  )

  await assert.rejects(checkAccountSession(), {
    name: 'Error',
    message: 'Unexpected account-session response.',
  })
})

test('masks session network failures without retrying', async (t) => {
  const request = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('Private transport details')
  })

  await assert.rejects(checkAccountSession(), {
    name: 'Error',
    message: 'Account session could not be checked. Please try again.',
  })
  assert.equal(request.mock.callCount(), 1)
})

test('preserves session request cancellation', async (t) => {
  const controller = new AbortController()
  const reason = new DOMException('Cancelled', 'AbortError')
  controller.abort(reason)

  t.mock.method(globalThis, 'fetch', async () => {
    throw reason
  })

  await assert.rejects(
    checkAccountSession(controller.signal),
    (error) => {
      assert.equal(error, reason)
      return true
    },
  )
})

test('preserves cancellation while reading session metadata', async (t) => {
  const controller = new AbortController()
  const reason = new DOMException('Cancelled', 'AbortError')
  const response = Response.json(session)

  t.mock.method(response, 'json', async () => {
    controller.abort(reason)
    throw reason
  })
  t.mock.method(globalThis, 'fetch', async () => response)

  await assert.rejects(
    checkAccountSession(controller.signal),
    (error) => {
      assert.equal(error, reason)
      return true
    },
  )
})

test('signs out once using the cookie without sending a body', async (t) => {
  const controller = new AbortController()

  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/account/sign-out')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.equal(options.body, undefined)
    assert.equal(options.headers, undefined)

    return new Response(null, { status: 204 })
  })

  assert.equal(await signOutAccount(controller.signal), undefined)
  assert.equal(request.mock.callCount(), 1)
})

for (const status of [200, 401, 403, 500, 503]) {
  test(`sign-out HTTP ${status} does not count as confirmed success`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () =>
      Response.json(
        { detail: 'private-provider-detail' },
        { status },
      ),
    )

    await assert.rejects(signOutAccount(), (error) => {
      assert.equal(
        error.message,
        'Sign-out could not be completed. Please try again.',
      )
      assert.equal(error.cause, undefined)
      assert.equal(error.message.includes('private-provider-detail'), false)
      return true
    })

    assert.equal(request.mock.callCount(), 1)
  })
}

test('masks sign-out network failures without retrying', async (t) => {
  const request = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('private-network-detail')
  })

  await assert.rejects(signOutAccount(), (error) => {
    assert.equal(
      error.message,
      'Sign-out could not be completed. Please try again.',
    )
    assert.equal(error.cause, undefined)
    return true
  })

  assert.equal(request.mock.callCount(), 1)
})

test('preserves sign-out cancellation', async (t) => {
  const controller = new AbortController()
  const cancellation = new DOMException('Aborted', 'AbortError')
  controller.abort(cancellation)

  t.mock.method(globalThis, 'fetch', async () => {
    throw cancellation
  })

  await assert.rejects(
    signOutAccount(controller.signal),
    (error) => error === cancellation,
  )
})
