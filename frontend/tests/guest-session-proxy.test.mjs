import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'

const site = 'https://site.example'
const endpoint = '/api/v1/guest/session'
const name = '__Host-askm6_guest'
const token = 'A'.repeat(43)
const secret = 'ab'.repeat(32) // Public synthetic fixture.
const metadata = { status: 'ok', expires_at: '2030-01-01T12:00:00.123456Z' }
const expiry = 'Tue, 01 Jan 2030 12:00:00 GMT'
const cookie = `${name}=${token}; expires=${expiry}; HttpOnly; Path=/; SameSite=lax; Secure`
const env = {
  API_ORIGIN: 'https://backend.example', AUTH_PUBLIC_ORIGIN: site,
  GUEST_SESSION_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: secret,
}

function incoming(options = {}, url = site + endpoint) {
  return new Request(url, { method: 'POST', headers: { Origin: site, 'CF-Connecting-IP': '198.51.100.20' }, ...options })
}

function jsonBody(value, headers = {}) {
  return { body: JSON.stringify(value), headers: {
    Origin: site, 'CF-Connecting-IP': '198.51.100.20', 'Content-Type': 'application/json', ...headers,
  } }
}

function upstream(body = metadata, options = {}) {
  return Response.json(body, { headers: { 'Set-Cookie': cookie }, ...options })
}

async function dispatch(options = {}, config = env, url) {
  return onRequest({ request: incoming(options, url), env: config })
}

async function failure(response, status) {
  assert.equal(response.status, status)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  for (const header of ['Set-Cookie', 'Location', 'Authorization', 'Access-Control-Allow-Origin', 'X-AskM6-Proxy-Secret', 'X-Private']) {
    assert.equal(response.headers.get(header), null)
  }
  const text = await response.text()
  for (const privateText of [secret, token, 'private']) assert.equal(text.includes(privateText), false)
}

for (const [label, value] of [['empty', undefined], ['object', {}], ['null proof', { turnstile_token: null }],
  ['proof', { turnstile_token: 'synthetic-proof' }], ['maximum proof', { turnstile_token: 'é'.repeat(2048) }]]) {
  test(`forwards ${label} with only the trusted IP and secure guest cookie`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
      assert.equal(url.href, env.API_ORIGIN + endpoint)
      assert.equal(options.method, 'POST')
      assert.equal(options.redirect, 'manual')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.credentials, 'omit')
      assert.equal(options.body, value === undefined ? undefined : JSON.stringify(value))
      assert.deepEqual(Object.fromEntries(options.headers), {
        accept: 'application/json', 'accept-encoding': 'identity', origin: site,
        cookie: `${name}=${token}`, 'x-askm6-client-ip': '198.51.100.20', 'x-askm6-proxy-secret': secret,
        ...(value === undefined ? {} : { 'content-type': 'application/json' }),
      })
      return upstream(metadata, { headers: {
        'Content-Type': 'application/json', 'Set-Cookie': cookie,
        'X-AskM6-Proxy-Secret': secret, 'X-Private': 'private', 'Access-Control-Allow-Origin': '*',
      } })
    })
    const headers = {
      Origin: site, 'CF-Connecting-IP': '198.51.100.20',
      Cookie: `askm6_guest=private; __Host-askm6_account=private; ${name}=${token}; unrelated=private`,
      Authorization: 'Bearer private', 'X-Forwarded-For': '203.0.113.99',
      'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
    }
    const response = await dispatch(value === undefined ? { headers } : jsonBody(value, headers))
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), metadata)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    assert.equal(response.headers.get('Set-Cookie'), `${name}=${token}; Expires=${expiry}; Path=/; Secure; HttpOnly; SameSite=Lax`)
    for (const header of ['X-AskM6-Proxy-Secret', 'X-Private', 'Access-Control-Allow-Origin']) assert.equal(response.headers.get(header), null)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const candidate of [undefined, 'false', 'TRUE', ' true ', '1']) {
  test(`guest forwarding is closed for flag ${JSON.stringify(candidate)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({}, { ...env, GUEST_SESSION_PROXY_ENABLED: candidate }), 404)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const [label, config, options, url, status] of [
  ['missing backend', { API_ORIGIN: undefined }, {}, undefined, 503],
  ['HTTP backend', { API_ORIGIN: 'http://backend.example' }, {}, undefined, 503],
  ['backend path', { API_ORIGIN: 'https://backend.example/private' }, {}, undefined, 503],
  ['backend credentials', { API_ORIGIN: 'https://private@backend.example' }, {}, undefined, 503],
  ['same backend origin', { API_ORIGIN: site }, {}, undefined, 503],
  ['missing public origin', { AUTH_PUBLIC_ORIGIN: undefined }, {}, undefined, 503],
  ['wrong method', {}, { method: 'GET' }, undefined, 405],
  ['foreign Origin', {}, { headers: { Origin: 'https://other.example' } }, undefined, 403],
  ['missing Origin', {}, { headers: {} }, undefined, 403],
  ['combined Origin', {}, { headers: { Origin: `${site}, ${site}` } }, undefined, 403],
  ['foreign Fetch Metadata', {}, { headers: { Origin: site, 'Sec-Fetch-Site': 'cross-site' } }, undefined, 403],
  ['preview URL', {}, {}, 'https://preview.example' + endpoint, 403],
  ['query', {}, {}, site + endpoint + '?destination=private', 400],
  ['fragment', {}, {}, site + endpoint + '#private', 400],
  ['untrusted mode', { AUTH_PROXY_TRUST_ENABLED: 'false' }, {}, undefined, 503],
  ['missing proxy key', { AUTH_PROXY_SHARED_SECRET: undefined }, {}, undefined, 503],
  ['invalid proxy key', { AUTH_PROXY_SHARED_SECRET: 'private' }, {}, undefined, 503],
  ['missing edge IP', {}, { headers: { Origin: site, 'X-Forwarded-For': '198.51.100.20' } }, undefined, 503],
  ['combined edge IP', {}, { headers: { Origin: site, 'CF-Connecting-IP': '198.51.100.20, 203.0.113.30' } }, undefined, 503],
  ['duplicate guest cookie', {}, jsonBody({}, { Cookie: `${name}=${token}; ${name}=${token}` }), undefined, 400],
  ['oversized cookie header', {}, jsonBody({}, { Cookie: 'unrelated=' + 'x'.repeat(8192) }), undefined, 400],
  ['ambiguous length', {}, jsonBody({}, { 'Content-Length': '2, 2' }), undefined, 400],
  ['wrong actual length', {}, jsonBody({}, { 'Content-Length': '0' }), undefined, 400],
  ['declared oversized body', {}, jsonBody({}, { 'Content-Length': '16385' }), undefined, 413],
  ['compressed input', {}, jsonBody({}, { 'Content-Encoding': 'gzip' }), undefined, 400],
  ['ambiguous transfer encoding', {}, jsonBody({}, { 'Transfer-Encoding': 'chunked, gzip' }), undefined, 400],
  ['conflicting framing', {}, jsonBody({}, { 'Transfer-Encoding': 'chunked', 'Content-Length': '2' }), undefined, 400],
]) {
  test(`rejects ${label} before contacting backend`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const response = await dispatch(options, { ...env, ...config }, url)
    if (status === 405) assert.equal(response.headers.get('Allow'), 'POST')
    await failure(response, status)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const body of [null, [], 'private', 1, true, { user_id: 'private' }, { turnstile_token: 'ok', destination: 'private' },
  { turnstile_token: '' }, { turnstile_token: 'x'.repeat(2049) }, { turnstile_token: 1 }, { turnstile_token: {} },
  { turnstile_token: '\ud800' }]) {
  test(`rejects invalid JSON schema ${JSON.stringify(body)?.slice(0, 55)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch(jsonBody(body)), 400)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const [body, contentType, status] of [['{', 'application/json', 400], ['{}', 'text/plain', 415],
  [' '.repeat(16385), 'application/json', 413], [new Uint8Array([0xff]), 'application/json', 400]]) {
  test(`rejects malformed/type/byte-bound input (${status}, ${String(body).length})`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({ body, headers: { Origin: site, 'CF-Connecting-IP': '198.51.100.20', 'Content-Type': contentType } }), status)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('actual UTF-8 bytes determine the body limit and an exact-limit document is accepted', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.body, '{}')
    return upstream()
  })
  const options = jsonBody({})
  options.body = '{}' + ' '.repeat(16382)
  options.headers['Content-Length'] = '16384'
  const response = await dispatch(options)
  assert.equal(response.status, 200)
  await response.arrayBuffer()
  assert.equal(fetch.mock.callCount(), 1)
  const tooLarge = jsonBody({ turnstile_token: '😀'.repeat(2048) })
  tooLarge.body += ' '.repeat(9000)
  await failure(await dispatch(tooLarge), 413)
  assert.equal(fetch.mock.callCount(), 1)
})

test('decoded chunked input is bounded and reconstructed without forwarding its framing', async (t) => {
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.body, '{}')
    assert.equal(options.headers.get('Transfer-Encoding'), null)
    assert.equal(options.headers.get('Content-Length'), null)
    return upstream()
  })
  const response = await dispatch(jsonBody({}, { 'Transfer-Encoding': 'chunked' }))
  assert.equal(response.status, 200)
  await response.arrayBuffer()
})

for (const cookieHeader of [undefined, 'askm6_guest=private', `${name}=invalid`]) {
  test(`omits missing/malformed/development cookies (${cookieHeader?.slice(0, 25)}) and accepts a newly issued token`, async (t) => {
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
      assert.equal(options.headers.get('Cookie'), null)
      return upstream()
    })
    const response = await dispatch(jsonBody({ turnstile_token: 'proof' }, cookieHeader ? { Cookie: cookieHeader } : {}))
    assert.equal(response.status, 200)
    assert.ok(response.headers.get('Set-Cookie')?.startsWith(`${name}=${token};`))
    await response.arrayBuffer()
  })
}

for (const [status, headers, retry, verification] of [
  [400, {}, null, null], [413, {}, null, null], [415, {}, null, null],
  [403, {}, null, null], [403, { 'X-Guest-Verification': 'required' }, null, 'required'],
  [403, { 'X-Guest-Verification': 'required, required' }, null, null],
  [503, { 'X-Guest-Verification': 'required', 'Retry-After': '30' }, null, null],
  ...['1', '86400', '0030', '0', '86401', '-1', '1.5', 'Wed, 21 Oct 2030 07:28:00 GMT', undefined]
    .map((raw) => [429, raw === undefined ? {} : { 'Retry-After': raw }, ['1', '86400', '0030'].includes(raw) ? String(Number(raw)) : null, null]),
]) {
  test(`preserves only safe error signals (${status}, ${JSON.stringify(headers)})`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('private backend detail', {
      status, headers: { ...headers, 'Set-Cookie': cookie, Location: 'https://private.example', 'X-Private': 'private' },
    }))
    const response = await dispatch()
    assert.equal(response.headers.get('Retry-After'), retry)
    assert.equal(response.headers.get('X-Guest-Verification'), verification)
    await failure(response, status)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const status of [201, 204, 301, 302, 303, 307, 308, 401, 418, 500]) {
  test(`masks unexpected status/redirect ${status} without retry or cookies`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(status === 204 ? null : 'private', {
      status, headers: { Location: 'https://private.example', 'Set-Cookie': cookie },
    }))
    await failure(await dispatch(), 502)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const body of [null, [], {}, { ...metadata, status: 'other' }, { ...metadata, user_id: 'private' },
  { ...metadata, expires_at: '2020-01-01T00:00:00Z' }, { ...metadata, expires_at: '2030-02-30T00:00:00Z' },
  { ...metadata, expires_at: '2030-01-01' }, { ...metadata, expires_at: 1 }]) {
  test(`rejects invalid success metadata ${JSON.stringify(body)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(body))
    await failure(await dispatch(), 502)
  })
}

for (const headers of [
  { 'Content-Type': 'text/plain', 'Set-Cookie': cookie },
  { 'Content-Type': 'application/json', 'Set-Cookie': cookie, 'Content-Encoding': 'gzip' },
  { 'Content-Type': 'application/json', 'Set-Cookie': cookie, 'Content-Length': '4097' },
  { 'Content-Type': 'application/json', 'Set-Cookie': cookie, 'Content-Length': '0' },
]) {
  test(`rejects invalid response framing ${JSON.stringify(headers)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(metadata, { headers }))
    await failure(await dispatch(), 502)
  })
}

for (const candidate of [null, cookie.replace(name, 'askm6_guest'), cookie.replace(token, 'invalid'),
  cookie.replace('; Secure', ''), cookie.replace('; HttpOnly', ''), cookie.replace('Path=/', 'Path=/api'),
  cookie.replace('SameSite=lax', 'SameSite=none'), cookie + '; Domain=site.example', cookie + '; Max-Age=3600',
  cookie + '; Secure', cookie + '; Priority=High', cookie.replace(expiry, 'Wed, 02 Jan 2030 12:00:00 GMT'),
  cookie + ', unrelated=private']) {
  test(`rejects unsafe guest Set-Cookie ${candidate?.slice(-70)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(metadata, { headers: {
      'Content-Type': 'application/json', ...(candidate === null ? {} : { 'Set-Cookie': candidate }),
    } }))
    await failure(await dispatch(), 502)
  })
}

test('rejects multiple cookies and supports Workers getAll without comma splitting', async (t) => {
  let multiple = false
  t.mock.method(globalThis, 'fetch', async () => {
    const response = upstream()
    response.headers.getAll = () => multiple ? [cookie, 'unrelated=private'] : [cookie]
    response.headers.getSetCookie = () => { throw new Error('Must use Workers API') }
    return response
  })
  const response = await dispatch()
  assert.equal(response.status, 200)
  await response.arrayBuffer()
  multiple = true
  await failure(await dispatch(), 502)
})

test('invalid UTF-8, malformed JSON and actual oversized response bytes are rejected', async (t) => {
  let body = new Uint8Array([0xff])
  t.mock.method(globalThis, 'fetch', async () => new Response(body, {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie },
  }))
  for (const bytes of [body, new TextEncoder().encode('{'), new TextEncoder().encode(' '.repeat(4097))]) {
    body = bytes
    await failure(await dispatch(), 502)
  }
})

test('network failures remain private without automatic retry', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('private network error') })
  await failure(await dispatch(), 502)
  assert.equal(fetch.mock.callCount(), 1)
})

test('an already cancelled request does not contact backend', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await dispatch({ signal: AbortSignal.abort() }), 502)
  assert.equal(fetch.mock.callCount(), 0)
})

for (const cancellation of ['deadline', 'client']) {
  test(`${cancellation} cancels a stalled incoming body before fetch`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let cancelled = false
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const pending = dispatch({ body, duplex: 'half', signal: controller.signal })
    if (cancellation === 'deadline') t.mock.timers.tick(20_000)
    else controller.abort()
    await failure(await pending, 502)
    assert.equal(cancelled, true)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('late fetch completion after cancellation cannot issue a guest cookie', async (t) => {
  const controller = new AbortController()
  let release
  let signal
  let began
  const started = new Promise((resolve) => { began = resolve })
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    signal = options.signal
    began()
    return new Promise((resolve) => { release = resolve })
  })
  const pending = dispatch({ signal: controller.signal })
  await started
  controller.abort()
  await failure(await pending, 502)
  assert.equal(signal.aborted, true)
  release(upstream())
  await new Promise((resolve) => setImmediate(resolve))
})

test('deadline includes upstream response consumption and cancels its stream', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let cancelled = false
  let began
  const started = new Promise((resolve) => { began = resolve })
  t.mock.method(globalThis, 'fetch', async () => {
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const original = body.getReader.bind(body)
    t.mock.method(body, 'getReader', () => { began(); return original() })
    return new Response(body, { headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie } })
  })
  const pending = dispatch()
  await started
  t.mock.timers.tick(20_000)
  await failure(await pending, 502)
  assert.equal(cancelled, true)
})
