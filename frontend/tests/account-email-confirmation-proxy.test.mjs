import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'

const site = 'https://site.example'
const path = '/api/v1/account/confirm-email'
const secret = 'ab'.repeat(32) // Public synthetic fixture.
const credentials = { email: ' Owner@Example.test ', code: '001234' }
const accepted = { status: 'confirmed', message: 'Email confirmed. You can now sign in.' }
const env = { API_ORIGIN: 'https://backend.example', AUTH_PUBLIC_ORIGIN: site,
  ACCOUNT_EMAIL_CONFIRMATION_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: secret }

function incoming(options = {}, url = site + path) {
  return new Request(url, { method: 'POST', body: JSON.stringify(credentials), ...options, headers: {
    Origin: site, 'CF-Connecting-IP': '198.51.100.20', 'Content-Type': 'application/json', ...options.headers,
  } })
}

function dispatch(options = {}, configuration = env, url) {
  return onRequest({ request: incoming(options, url), env: configuration })
}

function upstream(body = accepted, options = {}) { return Response.json(body, { status: 200, ...options }) }

async function failure(response, status = 502) {
  assert.equal(response.status, status)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  for (const header of ['Set-Cookie', 'Authorization', 'Location', 'Access-Control-Allow-Origin', 'X-Private', 'X-AskM6-Proxy-Secret']) {
    assert.equal(response.headers.get(header), null)
  }
  const text = await response.text()
  for (const value of [secret, credentials.email, credentials.code, 'private']) assert.equal(text.includes(value), false)
}

for (const [label, input] of [['exact credentials', credentials],
  ['Unicode and maximum lengths', { email: '\ufeff' + 'é'.repeat(319), code: '0123456789' }]]) {
  test(`forwards ${label} once without browser credentials, returns only the generic confirmation`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
      assert.equal(url.href, env.API_ORIGIN + path)
      assert.equal(options.body, JSON.stringify(input))
      assert.equal(options.method, 'POST')
      assert.equal(options.redirect, 'manual')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.credentials, 'omit')
      assert.deepEqual(Object.fromEntries(options.headers), {
        accept: 'application/json', 'accept-encoding': 'identity', 'content-type': 'application/json', origin: site,
        'x-askm6-client-ip': '198.51.100.20', 'x-askm6-proxy-secret': secret,
      })
      return upstream(accepted, { headers: { 'X-Private': 'private', 'X-AskM6-Proxy-Secret': secret, 'Access-Control-Allow-Origin': '*' } })
    })
    const response = await dispatch({ body: JSON.stringify(input), headers: {
      Cookie: '__Host-askm6_account=private; __Host-askm6_guest=private; __Host-askm6_google=private',
      Authorization: 'Bearer private', 'X-AskM6-Proxy-Secret': 'forged', 'X-AskM6-Client-IP': '203.0.113.99',
    } })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), accepted)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    for (const header of ['Set-Cookie', 'X-Private', 'X-AskM6-Proxy-Secret', 'Access-Control-Allow-Origin']) assert.equal(response.headers.get(header), null)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const flag of [undefined, 'false', 'TRUE', ' true ', '1']) {
  test(`email confirmation is independently gated for ${JSON.stringify(flag)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({}, { ...env, ACCOUNT_EMAIL_CONFIRMATION_PROXY_ENABLED: flag }), 404)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const [label, configuration, options, url, status] of [
  ['missing backend', { API_ORIGIN: undefined }, {}, undefined, 503],
  ['HTTP backend', { API_ORIGIN: 'http://backend.example' }, {}, undefined, 503],
  ['backend path', { API_ORIGIN: 'https://backend.example/private' }, {}, undefined, 503],
  ['same origin', { API_ORIGIN: site }, {}, undefined, 503],
  ['missing public origin', { AUTH_PUBLIC_ORIGIN: undefined }, {}, undefined, 503],
  ['wrong method', {}, { method: 'GET', body: undefined }, undefined, 405],
  ['wrong Origin', {}, { headers: { Origin: 'https://other.example' } }, undefined, 403],
  ['empty Origin', {}, { headers: { Origin: '' } }, undefined, 403],
  ['combined Origin', {}, { headers: { Origin: `${site}, ${site}` } }, undefined, 403],
  ['cross-site metadata', {}, { headers: { 'Sec-Fetch-Site': 'cross-site' } }, undefined, 403],
  ['preview URL', {}, {}, 'https://preview.example' + path, 403],
  ['query', {}, {}, site + path + '?redirect=private', 400],
  ['fragment', {}, {}, site + path + '#private', 400],
  ['disabled IP trust', { AUTH_PROXY_TRUST_ENABLED: 'false' }, {}, undefined, 503],
  ['missing shared key', { AUTH_PROXY_SHARED_SECRET: undefined }, {}, undefined, 503],
  ['invalid shared key', { AUTH_PROXY_SHARED_SECRET: 'private' }, {}, undefined, 503],
  ['missing edge IP', {}, { headers: { 'CF-Connecting-IP': '' } }, undefined, 503],
  ['combined edge IP', {}, { headers: { 'CF-Connecting-IP': '198.51.100.20, 203.0.113.30' } }, undefined, 503],
  ['non-JSON', {}, { headers: { 'Content-Type': 'text/plain' } }, undefined, 415],
  ['declared oversize', {}, { headers: { 'Content-Length': '4097' } }, undefined, 413],
  ['wrong declared length', {}, { headers: { 'Content-Length': '0' } }, undefined, 400],
  ['ambiguous length', {}, { headers: { 'Content-Length': '1, 1' } }, undefined, 400],
  ['compressed input', {}, { headers: { 'Content-Encoding': 'gzip' } }, undefined, 400],
  ['combined framing', {}, { headers: { 'Transfer-Encoding': 'chunked', 'Content-Length': '1' } }, undefined, 400],
]) {
  test(`rejects ${label} before backend accounting/provider work`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const response = await dispatch(options, { ...env, ...configuration }, url)
    if (status === 405) assert.equal(response.headers.get('Allow'), 'POST')
    await failure(response, status)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const [label, value] of [['null', null], ['array', []], ['scalar', 'x'], ['missing fields', {}],
  ['missing code', { email: 'x' }], ['null code', { ...credentials, code: null }],
  ['empty code', { ...credentials, code: '' }], ['short code', { ...credentials, code: '12345' }],
  ['long code', { ...credentials, code: '12345678901' }], ['non-string code', { ...credentials, code: 123456 }],
  ['Unicode digits', { ...credentials, code: '１２３４５６' }], ['trailing code newline', { ...credentials, code: '123456\n' }],
  ['code with whitespace', { ...credentials, code: ' 123456' }], ['password field', { ...credentials, password: 'private' }],
  ['CAPTCHA field', { ...credentials, captcha_token: 'private' }],
  ['unknown owner', { ...credentials, user_id: 'private' }], ['provider redirect', { ...credentials, redirect_to: 'https://private.example' }],
  ['nonstring email', { ...credentials, email: 1 }], ['oversized email', { ...credentials, email: 'x'.repeat(321) }],
  ['invalid UTF-8 email', { ...credentials, email: '\ud800' }], ['empty email', { ...credentials, email: '' }]]) {
  test(`rejects ${label} credential schema`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({ body: JSON.stringify(value) }), 400)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const body of [undefined, '{', new Uint8Array([0xff])]) {
  test(`rejects empty/malformed/invalid UTF-8 request ${String(body)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({ body }), 400)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('bounds actual UTF-8 bytes, accepts exact-limit chunked input and rebuilds only credentials', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.body, JSON.stringify(credentials))
    assert.equal(options.headers.get('Content-Length'), null)
    assert.equal(options.headers.get('Transfer-Encoding'), null)
    return upstream()
  })
  const json = JSON.stringify(credentials)
  const body = json + ' '.repeat(4096 - new TextEncoder().encode(json).byteLength)
  const response = await dispatch({ body, headers: { 'Transfer-Encoding': 'chunked' } })
  assert.equal(response.status, 200)
  await response.arrayBuffer()
  await failure(await dispatch({ body: body + ' ' }), 413)
  assert.equal(fetch.mock.callCount(), 1)
})

for (const [status, headers, verification, retry] of [[400, {}, null, null], [413, {}, null, null], [415, {}, null, null],
  [403, {}, null, null], [403, { 'X-Account-Verification': 'required' }, null, null],
  [403, { 'X-Account-Verification': 'required, required' }, null, null],
  [503, { 'X-Account-Verification': 'required', 'Retry-After': '5' }, null, null],
  ...['1', '86400', '0030', '0', '86401', '-1', '1.5', 'Wed, 21 Oct 2030 07:28:00 GMT', undefined]
    .map((raw) => [429, raw === undefined ? {} : { 'Retry-After': raw }, null, ['1', '86400', '0030'].includes(raw) ? String(Number(raw)) : null]),
]) {
  test(`retains only safe errors (${status}, ${JSON.stringify(headers)}) without cookies or provider details`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('private provider rejection', {
      status, headers: { ...headers, 'Set-Cookie': '__Host-askm6_account=private', Location: 'https://private.example' },
    }))
    const response = await dispatch()
    assert.equal(response.headers.get('X-Account-Verification'), verification)
    assert.equal(response.headers.get('Retry-After'), retry)
    await failure(response, status)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const status of [201, 202, 204, 301, 302, 303, 307, 308, 401, 409, 500]) {
  test(`rejects unexpected success/redirect/error HTTP ${status} without retry`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(status === 204 ? null : 'private', { status }))
    await failure(await dispatch())
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const [label, body] of [['null', null], ['array', []], ['missing fields', {}],
  ['wrong status', { ...accepted, status: 'accepted' }], ['missing message', { status: 'confirmed' }],
  ['private message', { ...accepted, message: 'private account already exists' }],
  ['provider credential', { ...accepted, access_token: 'private' }]]) {
  test(`rejects ${label} confirmation instead of revealing account details`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(body))
    await failure(await dispatch())
  })
}

for (const headers of [{ 'Content-Type': 'text/plain' }, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' },
  { 'Content-Type': 'application/json', 'Content-Length': '4097' }, { 'Content-Type': 'application/json', 'Content-Length': '0' },
  { 'Content-Type': 'application/json', 'Set-Cookie': '__Host-askm6_account=private' },
  { 'Content-Type': 'application/json', 'Set-Cookie': '' }]) {
  test(`rejects unexpected confirmation framing/cookie ${JSON.stringify(headers)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(accepted, { headers }))
    await failure(await dispatch())
  })
}

test('rejects malformed, invalid UTF-8 and actual oversized success bodies', async (t) => {
  let content
  t.mock.method(globalThis, 'fetch', async () => new Response(content, { status: 200, headers: { 'Content-Type': 'application/json' } }))
  for (const body of ['{', new Uint8Array([0xff]), ' '.repeat(4097)]) { content = body; await failure(await dispatch()) }
})

test('network failures stay private and never retry email confirmation', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('private transport failure') })
  await failure(await dispatch())
  assert.equal(fetch.mock.callCount(), 1)
})

test('already-cancelled email confirmation never reaches backend', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await dispatch({ signal: AbortSignal.abort() }))
  assert.equal(fetch.mock.callCount(), 0)
})

for (const kind of ['deadline', 'client']) {
  test(`${kind} cancels stalled input before email confirmation`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let cancelled = false
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const pending = dispatch({ body, duplex: 'half', signal: controller.signal })
    if (kind === 'deadline') t.mock.timers.tick(20_000)
    else controller.abort()
    await failure(await pending)
    assert.equal(cancelled, true)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const kind of ['deadline', 'client']) {
  test(`${kind} rejects late confirmation success without retry or cookie changes`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let signal, release, began
    const started = new Promise((resolve) => { began = resolve })
    const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
      signal = options.signal
      began()
      return new Promise((resolve) => { release = resolve })
    })
    const pending = dispatch({ signal: controller.signal })
    await started
    if (kind === 'deadline') t.mock.timers.tick(20_000)
    else controller.abort()
    await failure(await pending)
    assert.equal(signal.aborted, true)
    assert.equal(fetch.mock.callCount(), 1)
    release(upstream())
    await new Promise((resolve) => setImmediate(resolve))
  })
}

test('the deadline covers response consumption and cancels its stream', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let began, cancelled = false
  const reading = new Promise((resolve) => { began = resolve })
  t.mock.method(globalThis, 'fetch', async () => {
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const original = body.getReader.bind(body)
    t.mock.method(body, 'getReader', () => { began(); return original() })
    return new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } })
  })
  const pending = dispatch()
  await reading
  t.mock.timers.tick(20_000)
  await failure(await pending)
  assert.equal(cancelled, true)
})
