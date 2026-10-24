import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AccountPasswordResetRateLimitedError,
  AccountPasswordResetRejectedError,
  resetAccountPassword,
} from '../src/api/account-password-reset.ts'

const credentials = {
  email: 'owner@example.test',
  code: '001234',
  new_password: '  synthetic-new-password-é  ',
}
const completion = { status: 'completed' }
const failureMessage = 'Password reset could not be confirmed. Try signing in with your new password before starting recovery again.'
const unexpectedMessage = 'Unexpected password-reset response. Try signing in with your new password before starting recovery again.'

for (const seconds of [1, 61, 600, 86_400]) {
  test(`reset reads a ${seconds}-second limit without reading the body or retrying`, async (t) => {
    const response = new Response('private non-JSON password detail', {
      status: 429,
      headers: {
        'Retry-After': String(seconds),
        'X-Account-Verification': 'required',
      },
    })
    const read = t.mock.method(response, 'json', async () => {
      throw new Error('Error body must not be read')
    })
    const request = t.mock.method(globalThis, 'fetch', async () => response)
    await assert.rejects(resetAccountPassword(credentials), (error) => {
      assert.ok(error instanceof AccountPasswordResetRateLimitedError)
      assert.equal(error.name, 'AccountPasswordResetRateLimitedError')
      assert.equal(error.retryAfterSeconds, seconds)
      assert.equal(error.message, 'Too many password-reset attempts. Please try again later.')
      assert.equal(error.cause, undefined)
      return true
    })
    assert.equal(request.mock.callCount(), 1)
    assert.equal(read.mock.callCount(), 0)
    assert.equal(response.bodyUsed, false)
  })
}

for (const [label, header] of [
  ['missing', null], ['empty', ''], ['zero', '0'], ['negative', '-1'],
  ['fraction', '1.5'], ['exponent', '1e3'], ['too large', '86401'],
  ['oversized', '9'.repeat(1000)], ['date', 'Wed, 21 Oct 2030 07:28:00 GMT'],
  ['private details', 'private-retry-detail'], ['nonfinite', 'Infinity'],
  ['not a number', 'NaN'], ['multiple values', '10, 20'],
]) {
  test(`reset uses safe fallback for ${label} retry information`, async (t) => {
    const response = new Response('private-password-detail', {
      status: 429,
      headers: header === null ? {} : { 'Retry-After': header },
    })
    const request = t.mock.method(globalThis, 'fetch', async () => response)
    await assert.rejects(resetAccountPassword(credentials), (error) => {
      assert.ok(error instanceof AccountPasswordResetRateLimitedError)
      assert.equal(error.retryAfterSeconds, null)
      assert.equal(error.message, 'Too many password-reset attempts. Please try again later.')
      assert.equal(error.cause, undefined)
      return true
    })
    assert.equal(request.mock.callCount(), 1)
    assert.equal(response.bodyUsed, false)
  })
}

for (const status of [400, 401, 403, 413, 415, 500, 503]) {
  test(`reset ignores Retry-After on HTTP ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response('private-password-detail', {
      status, headers: { 'Retry-After': '61' },
    }))
    await assert.rejects(resetAccountPassword(credentials), (error) => {
      assert.equal(error instanceof AccountPasswordResetRateLimitedError, false)
      assert.equal(error.retryAfterSeconds, undefined)
      assert.equal(error.message.includes('private-password-detail'), false)
      return true
    })
  })
}

test('submits reset once, preserves credentials and returns only completion metadata', async (t) => {
  const controller = new AbortController()
  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/account/password-reset')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.deepEqual(options.headers, { 'Content-Type': 'application/json' })
    assert.deepEqual(JSON.parse(options.body), credentials)
    return Response.json({
      ...completion,
      message: 'Untrusted response message',
      user_id: 'untrusted-owner',
      access_token: 'synthetic-private-token',
      refresh_token: 'synthetic-private-refresh-token',
    })
  })

  const result = await resetAccountPassword({
    ...credentials,
    user_id: 'untrusted-owner',
    type: 'signup',
    captcha_token: 'must-not-forward',
    access_token: 'must-not-forward',
    redirect_to: 'https://untrusted.example.test',
  }, controller.signal)

  assert.deepEqual(result, completion)
  assert.equal(request.mock.callCount(), 1)
})

for (const code of ['000001', '0000000001']) {
  test(`preserves a ${code.length}-digit recovery code including leading zeros`, async (t) => {
    const password = '\tCafe\u0301-new-password\n '
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
      const sent = JSON.parse(options.body)
      assert.equal(sent.code, code)
      assert.equal(typeof sent.code, 'string')
      assert.equal(sent.new_password, password)
      return Response.json(completion)
    })
    assert.deepEqual(await resetAccountPassword({
      ...credentials, code, new_password: password,
    }), completion)
  })
}

for (const [status, errorType, message] of [
  [400, AccountPasswordResetRejectedError,
    'Password reset was rejected. Check your email, code and new password, then try again.'],
  [403, Error, failureMessage],
  [429, AccountPasswordResetRateLimitedError,
    'Too many password-reset attempts. Please try again later.'],
  [503, Error,
    'Password reset is temporarily unavailable. Try signing in with your new password before starting recovery again.'],
  [500, Error, failureMessage],
  [401, Error, failureMessage],
  [413, Error, failureMessage],
  [415, Error, failureMessage],
]) {
  test(`reset HTTP ${status} hides error bodies and never repeats the password change`, async (t) => {
    const response = Response.json({ detail: 'Private provider/password detail' }, {
      status, headers: { 'Retry-After': 'untrusted-value' },
    })
    const read = t.mock.method(response, 'json', async () => {
      throw new Error('Error bodies must not be parsed')
    })
    const request = t.mock.method(globalThis, 'fetch', async () => response)
    await assert.rejects(resetAccountPassword(credentials), (error) => {
      assert.equal(error.constructor, errorType)
      assert.equal(error.message, message)
      assert.equal(error.cause, undefined)
      assert.equal(error.retryAfter, undefined)
      return true
    })
    assert.equal(read.mock.callCount(), 0)
    assert.equal(request.mock.callCount(), 1)
  })
}

for (const [status, errorType] of [[403, Error], [429, AccountPasswordResetRateLimitedError]]) {
  test(`reset ignores a CAPTCHA marker on HTTP ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json({}, {
      status, headers: { 'X-Account-Verification': 'required' },
    }))
    await assert.rejects(resetAccountPassword(credentials), (error) => {
      assert.equal(error.constructor, errorType)
      assert.ok(!error.message.includes('verification'))
      return true
    })
  })
}

for (const status of [201, 202, 204]) {
  test(`does not claim reset completion on HTTP ${status}`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () => new Response(
      status === 204 ? null : JSON.stringify(completion), { status },
    ))
    await assert.rejects(resetAccountPassword(credentials), {
      name: 'Error', message: failureMessage,
    })
    assert.equal(request.mock.callCount(), 1)
  })
}

for (const [label, body] of [
  ['null', null],
  ['array', []],
  ['string', 'completed'],
  ['number', 123],
  ['missing status', {}],
  ['accepted instead of completed', { status: 'accepted' }],
  ['wrong case', { status: 'Completed' }],
  ['non-string status', { status: true }],
]) {
  test(`rejects reset completion with ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json(body))
    await assert.rejects(resetAccountPassword(credentials), {
      name: 'Error', message: unexpectedMessage,
    })
  })
}

test('masks malformed reset response JSON without retaining private parser details', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new Response('Private provider/password detail', {
    status: 200, headers: { 'Content-Type': 'application/json' },
  }))
  await assert.rejects(resetAccountPassword(credentials), (error) => {
    assert.equal(error.message, unexpectedMessage)
    assert.equal(error.cause, undefined)
    return true
  })
})

for (const detail of [new Error('Private transport/password detail'), 'Private non-Error detail']) {
  test(`masks a ${typeof detail} reset network error without retrying`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () => { throw detail })
    await assert.rejects(resetAccountPassword(credentials), (error) => {
      assert.equal(error.message, failureMessage)
      assert.equal(error.cause, undefined)
      return true
    })
    assert.equal(request.mock.callCount(), 1)
  })
}

for (const withSignal of [true, false]) {
  test(`preserves reset AbortError identity with signal=${withSignal}`, async (t) => {
    const controller = new AbortController()
    const reason = new DOMException('Cancelled', 'AbortError')
    if (withSignal) controller.abort(reason)
    t.mock.method(globalThis, 'fetch', async () => { throw reason })
    await assert.rejects(resetAccountPassword(
      credentials, withSignal ? controller.signal : undefined,
    ), (error) => {
      assert.equal(error, reason)
      return true
    })
  })
}

test('preserves the custom cancellation reason from an aborted reset signal', async (t) => {
  const controller = new AbortController()
  const reason = new Error('Synthetic cancellation reason')
  const request = t.mock.method(globalThis, 'fetch', async () => {
    controller.abort(reason)
    throw reason
  })
  await assert.rejects(resetAccountPassword(credentials, controller.signal), (error) => {
    assert.equal(error, reason)
    return true
  })
  assert.equal(request.mock.callCount(), 1)
})

test('preserves cancellation while reading reset completion', async (t) => {
  const controller = new AbortController()
  const reason = new DOMException('Cancelled', 'AbortError')
  const response = Response.json(completion)
  t.mock.method(response, 'json', async () => {
    controller.abort(reason)
    throw reason
  })
  t.mock.method(globalThis, 'fetch', async () => response)
  await assert.rejects(resetAccountPassword(credentials, controller.signal), (error) => {
    assert.equal(error, reason)
    return true
  })
})
