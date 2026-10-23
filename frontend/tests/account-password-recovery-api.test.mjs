import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  AccountPasswordRecoveryRateLimitedError,
  AccountPasswordRecoveryRejectedError,
  AccountPasswordRecoveryVerificationRequiredError,
  requestAccountPasswordRecovery,
} from '../src/api/account-password-recovery.ts'

const credentials = {
  email: 'owner@example.test',
  captcha_token: 'synthetic-recovery-proof',
}
const acknowledgement = { status: 'accepted' }
const failureMessage = 'Password recovery could not be requested. Please try again.'

test('requests recovery once, whitelists fields and returns only neutral metadata', async (t) => {
  const controller = new AbortController()
  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/account/password-recovery')
    assert.equal(options.method, 'POST')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.equal(options.signal, controller.signal)
    assert.deepEqual(options.headers, { 'Content-Type': 'application/json' })
    assert.deepEqual(JSON.parse(options.body), credentials)
    return Response.json({
      ...acknowledgement,
      message: 'Untrusted server message',
      user_id: 'untrusted-owner',
      access_token: 'synthetic-private-token',
    }, { status: 202 })
  })

  const result = await requestAccountPasswordRecovery({
    ...credentials,
    password: 'must-not-forward',
    user_id: 'untrusted-owner',
    redirect_to: 'https://untrusted.example.test',
  }, controller.signal)

  assert.deepEqual(result, acknowledgement)
  assert.equal(request.mock.callCount(), 1)
})

for (const [status, errorType, message] of [
  [400, AccountPasswordRecoveryRejectedError,
    'Password recovery was rejected. Check your details and try again.'],
  [403, Error, failureMessage],
  [429, AccountPasswordRecoveryRateLimitedError,
    'Too many recovery requests. Please try again later.'],
  [503, Error, 'Password recovery is temporarily unavailable.'],
  [500, Error, failureMessage],
  [401, Error, failureMessage],
]) {
  test(`recovery HTTP ${status} is controlled, ignores the body and never retries`, async (t) => {
    const response = Response.json({ detail: 'Private provider details' }, {
      status,
      headers: { 'Retry-After': 'untrusted-value' },
    })
    const read = t.mock.method(response, 'json', async () => {
      throw new Error('Error bodies must not be parsed')
    })
    const request = t.mock.method(globalThis, 'fetch', async () => response)

    await assert.rejects(requestAccountPasswordRecovery(credentials), (error) => {
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

test('recognizes the explicit CAPTCHA rejection marker on HTTP 403', async (t) => {
  const request = t.mock.method(globalThis, 'fetch', async () => Response.json(
    { detail: 'Private verification detail' },
    { status: 403, headers: { 'X-Account-Verification': 'required' } },
  ))

  await assert.rejects(requestAccountPasswordRecovery(credentials), (error) => {
    assert.ok(error instanceof AccountPasswordRecoveryVerificationRequiredError)
    assert.equal(error.message, 'Please complete human verification.')
    return true
  })
  assert.equal(request.mock.callCount(), 1)
})

for (const [status, errorType] of [
  [400, AccountPasswordRecoveryRejectedError],
  [429, AccountPasswordRecoveryRateLimitedError],
  [503, Error],
]) {
  test(`ignores a verification marker on HTTP ${status}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json({}, {
      status, headers: { 'X-Account-Verification': 'required' },
    }))
    await assert.rejects(requestAccountPasswordRecovery(credentials), (error) => {
      assert.equal(error.constructor, errorType)
      assert.ok(!(error instanceof AccountPasswordRecoveryVerificationRequiredError))
      return true
    })
  })
}

for (const marker of ['', 'Required', 'true']) {
  test(`does not treat verification marker ${JSON.stringify(marker)} as a challenge`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json({}, {
      status: 403, headers: { 'X-Account-Verification': marker },
    }))
    await assert.rejects(requestAccountPasswordRecovery(credentials), {
      name: 'Error', message: failureMessage,
    })
  })
}

for (const status of [200, 201, 204]) {
  test(`rejects unexpected recovery success status ${status}`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () => new Response(
      status === 204 ? null : JSON.stringify(acknowledgement), { status },
    ))
    await assert.rejects(requestAccountPasswordRecovery(credentials), {
      name: 'Error', message: failureMessage,
    })
    assert.equal(request.mock.callCount(), 1)
  })
}

for (const [label, body] of [
  ['null', null],
  ['array', []],
  ['string', 'accepted'],
  ['number', 123],
  ['missing status', {}],
  ['incorrect status', { status: 'completed' }],
  ['wrong case', { status: 'Accepted' }],
  ['non-string status', { status: true }],
]) {
  test(`rejects recovery acknowledgement with ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json(body, { status: 202 }))
    await assert.rejects(requestAccountPasswordRecovery(credentials), {
      name: 'Error', message: 'Unexpected password-recovery response.',
    })
  })
}

test('masks malformed JSON and omits the parser error cause', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new Response('Private response content', {
    status: 202, headers: { 'Content-Type': 'application/json' },
  }))
  await assert.rejects(requestAccountPasswordRecovery(credentials), (error) => {
    assert.equal(error.message, 'Unexpected password-recovery response.')
    assert.equal(error.cause, undefined)
    return true
  })
})

for (const detail of [new Error('Private transport detail'), 'Private non-Error detail']) {
  test(`masks a ${typeof detail} network failure without retrying`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () => { throw detail })
    await assert.rejects(requestAccountPasswordRecovery(credentials), (error) => {
      assert.equal(error.message, failureMessage)
      assert.equal(error.cause, undefined)
      return true
    })
    assert.equal(request.mock.callCount(), 1)
  })
}

for (const withSignal of [true, false]) {
  test(`preserves AbortError identity with signal=${withSignal}`, async (t) => {
    const controller = new AbortController()
    const reason = new DOMException('Cancelled', 'AbortError')
    if (withSignal) controller.abort(reason)
    t.mock.method(globalThis, 'fetch', async () => { throw reason })
    await assert.rejects(requestAccountPasswordRecovery(
      credentials, withSignal ? controller.signal : undefined,
    ), (error) => {
      assert.equal(error, reason)
      return true
    })
  })
}

test('preserves a custom cancellation reason from an aborted request signal', async (t) => {
  const controller = new AbortController()
  const reason = new Error('Synthetic cancellation reason')
  const request = t.mock.method(globalThis, 'fetch', async () => {
    controller.abort(reason)
    throw reason
  })
  await assert.rejects(requestAccountPasswordRecovery(credentials, controller.signal), (error) => {
    assert.equal(error, reason)
    return true
  })
  assert.equal(request.mock.callCount(), 1)
})

test('preserves cancellation while reading the acknowledgement body', async (t) => {
  const controller = new AbortController()
  const reason = new DOMException('Cancelled', 'AbortError')
  const response = Response.json(acknowledgement, { status: 202 })
  t.mock.method(response, 'json', async () => {
    controller.abort(reason)
    throw reason
  })
  t.mock.method(globalThis, 'fetch', async () => response)
  await assert.rejects(requestAccountPasswordRecovery(credentials, controller.signal), (error) => {
    assert.equal(error, reason)
    return true
  })
})
