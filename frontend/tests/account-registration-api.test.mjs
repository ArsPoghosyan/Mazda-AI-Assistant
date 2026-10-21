import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AccountEmailConfirmationRejectedError,
  AccountSignUpVerificationRequiredError,
  confirmAccountEmail,
  signUpAccount,
} from '../src/api/account-registration.ts'

const credentials = {
  email: 'owner@example.test',
  password: '  synthetic-password-é  ',
  captcha_token: 'synthetic-captcha-proof',
}

const acknowledgement = { status: 'accepted' }

test('submits only registration credentials once and returns acknowledgement', async (t) => {
  const controller = new AbortController()

  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/account/sign-up')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.deepEqual(options.headers, {
      'Content-Type': 'application/json',
    })
    assert.deepEqual(JSON.parse(options.body), credentials)

    return Response.json(
      {
        ...acknowledgement,
        message: 'Untrusted server message',
        access_token: 'unexpected-synthetic-provider-token',
      },
      { status: 202 },
    )
  })

  const result = await signUpAccount(
    { ...credentials, user_id: 'untrusted-owner', role: 'admin' },
    controller.signal,
  )

  assert.deepEqual(result, acknowledgement)
  assert.equal(request.mock.callCount(), 1)
})

for (const [status, name, message] of [
  [
    400,
    'AccountSignUpRejectedError',
    'Registration was rejected. Check your details and try again.',
  ],
  [
    403,
    'Error',
    'Registration could not be completed. Please try again.',
  ],
  [
    503,
    'Error',
    'Registration is temporarily unavailable. Please try again.',
  ],
  [
    500,
    'Error',
    'Registration could not be completed. Please try again.',
  ],
]) {
  test(`registration HTTP ${status} hides server details`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () =>
      Response.json(
        { detail: 'Private server and provider details' },
        { status },
      ),
    )

    await assert.rejects(signUpAccount(credentials), { name, message })
    assert.equal(request.mock.callCount(), 1)
  })
}

test('recognizes explicit registration CAPTCHA rejection', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    Response.json(
      { detail: 'Private verification details' },
      {
        status: 403,
        headers: { 'X-Account-Verification': 'required' },
      },
    ),
  )

  await assert.rejects(signUpAccount(credentials), (error) => {
    assert.ok(error instanceof AccountSignUpVerificationRequiredError)
    assert.equal(error.message, 'Please complete human verification.')
    return true
  })
})

for (const [status, name, message] of [
  [
    400,
    'AccountSignUpRejectedError',
    'Registration was rejected. Check your details and try again.',
  ],
  [
    503,
    'Error',
    'Registration is temporarily unavailable. Please try again.',
  ],
]) {
  test(`ignores registration verification header on HTTP ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () =>
      Response.json(
        { detail: 'Private provider details' },
        {
          status,
          headers: { 'X-Account-Verification': 'required' },
        },
      ),
    )

    await assert.rejects(signUpAccount(credentials), { name, message })
  })
}

for (const status of [200, 201, 204]) {
  test(`rejects unexpected registration success status ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () =>
      new Response(
        status === 204 ? null : JSON.stringify(acknowledgement),
        {
          status,
          headers: { 'Content-Type': 'application/json' },
        },
      ),
    )

    await assert.rejects(signUpAccount(credentials), {
      name: 'Error',
      message: 'Registration could not be completed. Please try again.',
    })
  })
}

for (const [label, body] of [
  ['null', null],
  ['array', []],
  ['number', 123],
  ['missing status', {}],
  ['incorrect status', { status: 'confirmed' }],
  ['non-string status', { status: true }],
]) {
  test(`rejects registration response with ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () =>
      Response.json(body, { status: 202 }),
    )

    await assert.rejects(signUpAccount(credentials), {
      name: 'Error',
      message: 'Unexpected registration response.',
    })
  })
}

test('masks malformed registration response JSON', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('Private non-JSON response', {
      status: 202,
      headers: { 'Content-Type': 'application/json' },
    }),
  )

  await assert.rejects(signUpAccount(credentials), {
    name: 'Error',
    message: 'Unexpected registration response.',
  })
})

test('masks registration network errors without retrying', async (t) => {
  const request = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('Private transport details')
  })

  await assert.rejects(signUpAccount(credentials), (error) => {
    assert.equal(
      error.message,
      'Registration could not be completed. Please try again.',
    )
    assert.equal(error.cause, undefined)
    return true
  })

  assert.equal(request.mock.callCount(), 1)
})

for (const withSignal of [true, false]) {
  test(`preserves registration cancellation with signal=${withSignal}`, async (t) => {
    const controller = new AbortController()
    const reason = new DOMException('Cancelled', 'AbortError')

    if (withSignal) {
      controller.abort(reason)
    }

    const request = t.mock.method(globalThis, 'fetch', async () => {
      throw reason
    })

    await assert.rejects(
      signUpAccount(credentials, withSignal ? controller.signal : undefined),
      (error) => {
        assert.equal(error, reason)
        return true
      },
    )

    assert.equal(request.mock.callCount(), 1)
  })
}

test('preserves cancellation while reading registration response', async (t) => {
  const controller = new AbortController()
  const reason = new DOMException('Cancelled', 'AbortError')
  const response = Response.json(acknowledgement, { status: 202 })

  t.mock.method(response, 'json', async () => {
    controller.abort(reason)
    throw reason
  })
  t.mock.method(globalThis, 'fetch', async () => response)

  await assert.rejects(
    signUpAccount(credentials, controller.signal),
    (error) => {
      assert.equal(error, reason)
      return true
    },
  )
})

const confirmationCredentials = {
  email: 'owner@example.test',
  code: '001234',
}

const confirmation = { status: 'confirmed' }

test('submits only email and code once, returning confirmation metadata', async (t) => {
  const controller = new AbortController()

  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/account/confirm-email')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.deepEqual(options.headers, {
      'Content-Type': 'application/json',
    })
    assert.deepEqual(JSON.parse(options.body), confirmationCredentials)

    return Response.json({
      ...confirmation,
      message: 'Untrusted server message',
      user_id: 'untrusted-owner',
      access_token: 'unexpected-synthetic-provider-token',
      refresh_token: 'unexpected-synthetic-refresh-token',
    })
  })

  const result = await confirmAccountEmail(
    {
      ...confirmationCredentials,
      type: 'recovery',
      password: 'must-not-forward',
    },
    controller.signal,
  )

  assert.deepEqual(result, confirmation)
  assert.equal(request.mock.callCount(), 1)
})

for (const [status, name, message] of [
  [
    400,
    'AccountEmailConfirmationRejectedError',
    'Email confirmation was rejected. Check your email and code, then try again.',
  ],
  [
    403,
    'Error',
    'Email confirmation could not be completed. Please try again.',
  ],
  [
    503,
    'Error',
    'Email confirmation is temporarily unavailable. Please try again.',
  ],
  [
    500,
    'Error',
    'Email confirmation could not be completed. Please try again.',
  ],
]) {
  test(`confirmation HTTP ${status} hides server details`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () =>
      Response.json(
        { detail: 'Private server and provider details' },
        { status },
      ),
    )

    await assert.rejects(
      confirmAccountEmail(confirmationCredentials),
      (error) => {
        assert.equal(error.name, name)
        assert.equal(error.message, message)

        if (status === 400) {
          assert.ok(error instanceof AccountEmailConfirmationRejectedError)
        }

        return true
      },
    )

    assert.equal(request.mock.callCount(), 1)
  })
}

for (const [status, message] of [
  [
    403,
    'Email confirmation could not be completed. Please try again.',
  ],
  [
    503,
    'Email confirmation is temporarily unavailable. Please try again.',
  ],
]) {
  test(`confirmation ignores verification header on HTTP ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () =>
      Response.json(
        { detail: 'Private provider details' },
        {
          status,
          headers: { 'X-Account-Verification': 'required' },
        },
      ),
    )

    await assert.rejects(confirmAccountEmail(confirmationCredentials), {
      name: 'Error',
      message,
    })
  })
}

for (const status of [201, 202, 204]) {
  test(`rejects unexpected confirmation success status ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () =>
      new Response(
        status === 204 ? null : JSON.stringify(confirmation),
        {
          status,
          headers: { 'Content-Type': 'application/json' },
        },
      ),
    )

    await assert.rejects(confirmAccountEmail(confirmationCredentials), {
      name: 'Error',
      message: 'Email confirmation could not be completed. Please try again.',
    })
  })
}

for (const [label, body] of [
  ['null', null],
  ['array', []],
  ['number', 123],
  ['missing status', {}],
  ['incorrect status', { status: 'accepted' }],
  ['non-string status', { status: true }],
]) {
  test(`rejects confirmation response with ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json(body))

    await assert.rejects(confirmAccountEmail(confirmationCredentials), {
      name: 'Error',
      message: 'Unexpected email-confirmation response.',
    })
  })
}

test('masks malformed confirmation response JSON', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('Private non-JSON response', {
      headers: { 'Content-Type': 'application/json' },
    }),
  )

  await assert.rejects(confirmAccountEmail(confirmationCredentials), {
    name: 'Error',
    message: 'Unexpected email-confirmation response.',
  })
})

test('masks confirmation network errors without retrying', async (t) => {
  const request = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('Private transport details')
  })

  await assert.rejects(
    confirmAccountEmail(confirmationCredentials),
    (error) => {
      assert.equal(
        error.message,
        'Email confirmation could not be completed. Please try again.',
      )
      assert.equal(error.cause, undefined)
      return true
    },
  )

  assert.equal(request.mock.callCount(), 1)
})

for (const withSignal of [true, false]) {
  test(`preserves confirmation cancellation with signal=${withSignal}`, async (t) => {
    const controller = new AbortController()
    const reason = new DOMException('Cancelled', 'AbortError')

    if (withSignal) {
      controller.abort(reason)
    }

    const request = t.mock.method(globalThis, 'fetch', async () => {
      throw reason
    })

    await assert.rejects(
      confirmAccountEmail(
        confirmationCredentials,
        withSignal ? controller.signal : undefined,
      ),
      (error) => {
        assert.equal(error, reason)
        return true
      },
    )

    assert.equal(request.mock.callCount(), 1)
  })
}

test('preserves cancellation while reading confirmation response', async (t) => {
  const controller = new AbortController()
  const reason = new DOMException('Cancelled', 'AbortError')
  const response = Response.json(confirmation)

  t.mock.method(response, 'json', async () => {
    controller.abort(reason)
    throw reason
  })
  t.mock.method(globalThis, 'fetch', async () => response)

  await assert.rejects(
    confirmAccountEmail(confirmationCredentials, controller.signal),
    (error) => {
      assert.equal(error, reason)
      return true
    },
  )
})