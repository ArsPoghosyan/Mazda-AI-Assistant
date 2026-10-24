import assert from 'node:assert/strict'
import { test } from 'node:test'

import { GoogleSignInRateLimitedError, startGoogleSignIn } from '../src/api/google.ts'

const ISSUER = 'https://auth.example.test/auth/v1'
const CALLBACK = 'http://127.0.0.1:5173/api/v1/account/google/callback'
const INVALID = 'Unexpected Google sign-in response.'

function authorizationUrl(overrides = {}) {
  const url = new URL(`${ISSUER}/authorize`)
  url.search = new URLSearchParams({
    provider: 'google',
    redirect_to: CALLBACK,
    code_challenge: 'a'.repeat(43),
    code_challenge_method: 's256',
    ...overrides,
  }).toString()
  return url.href
}

function responseBody(overrides = {}) {
  return {
    authorization_url: authorizationUrl(),
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    ...overrides,
  }
}

function start(signal) {
  return startGoogleSignIn(ISSUER, CALLBACK, signal)
}

test('sends one empty POST with cookies and returns only validated metadata', async (t) => {
  const controller = new AbortController()
  const body = responseBody()

  const request = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url, '/api/v1/account/google/start')
    assert.deepEqual(options, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
    })

    return Response.json({
      ...body,
      access_token: 'unexpected-private-token',
    })
  })

  assert.deepEqual(await start(controller.signal), body)
  assert.equal(request.mock.callCount(), 1)
})

const validUrl = authorizationUrl()

for (const [label, url] of [
  ['another issuer', validUrl.replace('auth.example.test', 'untrusted.example')],
  ['HTTP', validUrl.replace('https:', 'http:')],
  ['credentials', validUrl.replace('://', '://user:private@')],
  ['wrong path', validUrl.replace('/authorize?', '/user?')],
  ['fragment', `${validUrl}#unexpected`],
  ['duplicate parameter', `${validUrl}&provider=google`],
  ['extra parameter', `${validUrl}&next=https://untrusted.example`],
  ['wrong provider', authorizationUrl({ provider: 'github' })],
  ['wrong callback', authorizationUrl({ redirect_to: 'https://untrusted.example' })],
  ['wrong PKCE method', authorizationUrl({ code_challenge_method: 'plain' })],
  ['invalid challenge', authorizationUrl({ code_challenge: 'invalid' })],
]) {
  test(`rejects a destination containing ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () =>
      Response.json(responseBody({ authorization_url: url })),
    )

    await assert.rejects(start(), { message: INVALID })
  })
}

for (const [label, body] of [
  ['null', null],
  ['missing URL', { expires_at: '2099-01-01T00:00:00Z' }],
  ['non-string URL', responseBody({ authorization_url: 123 })],
  ['oversized URL', responseBody({ authorization_url: 'x'.repeat(8193) })],
  ['missing expiry', { authorization_url: validUrl }],
  ['invalid expiry', responseBody({ expires_at: 'invalid' })],
  ['expired attempt', responseBody({ expires_at: '2000-01-01T00:00:00Z' })],
  ['non-string expiry', responseBody({ expires_at: 123 })],
]) {
  test(`rejects response metadata with ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json(body))

    await assert.rejects(start(), { message: INVALID })
  })
}

for (const [status, message] of [
  [400, 'Please start Google sign-in again.'],
  [409, 'Sign out before starting another account login.'],
  [503, 'Google sign-in is temporarily unavailable.'],
  [403, 'Google sign-in could not be started. Please try again.'],
  [500, 'Google sign-in could not be started. Please try again.'],
]) {
  test(`handles HTTP ${status} without exposing details or retrying`, async (t) => {
    const request = t.mock.method(globalThis, 'fetch', async () =>
      Response.json({ detail: 'Private provider details' }, { status }),
    )

    await assert.rejects(start(), { message })
    assert.equal(request.mock.callCount(), 1)
  })
}

test('rejects malformed JSON with a generic error', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('{"private-details":', { status: 200 }),
  )

  await assert.rejects(start(), { message: INVALID })
})

for (const [label, header, seconds] of [
  ['one second', '1', 1], ['61 seconds', '61', 61], ['maximum', '86400', 86400],
  ['leading zeros', '00001', 1], ['missing', null, null], ['empty', '', null],
  ['zero', '0', null], ['negative', '-1', null], ['positive sign', '+1', null],
  ['fraction', '1.5', null], ['exponent', '1e2', null], ['too large', '86401', null],
  ['six digits', '100000', null], ['oversized', '9'.repeat(1000), null],
  ['multiple values', '1, 2', null], ['date', 'Wed, 21 Oct 2030 07:28:00 GMT', null],
  ['private details', 'private-provider-detail', null], ['nonfinite', 'Infinity', null],
]) {
  test(`Google 429 uses safe retry guidance for ${label}`, async (t) => {
    const response = new Response('private-provider-detail', {
      status: 429, headers: header === null ? {} : { 'Retry-After': header },
    })
    const json = t.mock.method(response, 'json', async () => {
      throw new Error('Error bodies must not be read')
    })
    const request = t.mock.method(globalThis, 'fetch', async () => response)
    await assert.rejects(start(), (error) => {
      assert.ok(error instanceof GoogleSignInRateLimitedError)
      assert.equal(error.retryAfterSeconds, seconds)
      assert.equal(error.message, 'Too many Google sign-in attempts. Please try again later.')
      assert.equal(error.cause, undefined)
      return true
    })
    assert.equal(json.mock.callCount(), 0)
    assert.equal(request.mock.callCount(), 1)
  })
}

for (const [status, message] of [
  [400, 'Please start Google sign-in again.'],
  [409, 'Sign out before starting another account login.'],
  [503, 'Google sign-in is temporarily unavailable.'],
  [403, 'Google sign-in could not be started. Please try again.'],
  [500, 'Google sign-in could not be started. Please try again.'],
]) {
  test(`Google HTTP ${status} ignores Retry-After`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response(null, {
      status, headers: { 'Retry-After': '61' },
    }))
    await assert.rejects(start(), { name: 'Error', message })
  })
}

test('Google success ignores Retry-After and retains destination validation', async (t) => {
  const body = responseBody()
  t.mock.method(globalThis, 'fetch', async () => Response.json(body, {
    headers: { 'Retry-After': '61' },
  }))
  assert.deepEqual(await start(), body)
})

test('masks network errors without retrying', async (t) => {
  const request = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('Private transport details')
  })

  await assert.rejects(start(), {
    message: 'Google sign-in could not be started. Please try again.',
  })
  assert.equal(request.mock.callCount(), 1)
})

for (const stage of ['request', 'body']) {
  test(`preserves cancellation during the ${stage}`, async (t) => {
    const controller = new AbortController()
    const reason = new DOMException('Cancelled', 'AbortError')

    if (stage === 'request') {
      t.mock.method(globalThis, 'fetch', async () => {
        controller.abort(reason)
        throw reason
      })
    } else {
      const response = Response.json(responseBody())
      t.mock.method(response, 'json', async () => {
        controller.abort(reason)
        throw reason
      })
      t.mock.method(globalThis, 'fetch', async () => response)
    }

    await assert.rejects(start(controller.signal), (error) => {
      assert.equal(error, reason)
      return true
    })
  })
}
