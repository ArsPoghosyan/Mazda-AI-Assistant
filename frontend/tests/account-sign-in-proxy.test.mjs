import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'

const site = 'https://site.example'
const endpoint = '/api/v1/account/sign-in'
const cookieName = '__Host-askm6_account'
const token = 'B'.repeat(43)
const secret = 'ab'.repeat(32) // Public synthetic fixture.
const credentials = { email: ' Owner@Example.test ', password: '  synthetic-password-é  ', captcha_token: 'synthetic-proof' }
const metadata = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00.123456Z', absolute_expires_at: '2030-01-30T12:00:00Z',
}
const expiry = 'Tue, 01 Jan 2030 12:00:00 GMT'
const cookie = `${cookieName}=${token}; expires=${expiry}; HttpOnly; Path=/; SameSite=lax; Secure`
const env = { API_ORIGIN: 'https://backend.example', AUTH_PUBLIC_ORIGIN: site,
  ACCOUNT_SIGN_IN_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: secret }

function incoming(options = {}, url = site + endpoint) {
  return new Request(url, { method: 'POST', body: JSON.stringify(credentials), ...options, headers: {
    Origin: site, 'CF-Connecting-IP': '198.51.100.20', 'Content-Type': 'application/json', ...options.headers,
  } })
}

function dispatch(options = {}, config = env, url) {
  return onRequest({ request: incoming(options, url), env: config })
}

function upstream(body = metadata, options = {}) {
  return Response.json(body, { headers: { 'Set-Cookie': cookie }, ...options })
}

async function failure(response, status) {
  assert.equal(response.status, status)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  for (const name of ['Set-Cookie', 'Location', 'Authorization', 'Access-Control-Allow-Origin', 'X-Private', 'X-AskM6-Proxy-Secret']) {
    assert.equal(response.headers.get(name), null)
  }
  const text = await response.text()
  for (const value of [token, secret, credentials.email, credentials.password, credentials.captcha_token, metadata.user_id, 'private']) {
    assert.equal(text.includes(value), false)
  }
}

for (const [label, input] of [
  ['unchanged credentials', credentials],
  ['Unicode and leading BOM characters', { email: '\ufeffOwner@Example.test', password: '\ufeff e\u0301 😀 ', captcha_token: 'proof' }],
  ['maximum field lengths', { email: 'é'.repeat(320), password: '😀'.repeat(1024), captcha_token: 'x'.repeat(2048) }],
]) {
  test(`submits ${label} once and validates newly issued account metadata/cookie`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
      assert.equal(url.href, env.API_ORIGIN + endpoint)
      assert.equal(options.body, JSON.stringify(input))
      assert.equal(options.method, 'POST')
      assert.equal(options.redirect, 'manual')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.credentials, 'omit')
      assert.deepEqual(Object.fromEntries(options.headers), {
        accept: 'application/json', 'accept-encoding': 'identity', 'content-type': 'application/json', origin: site,
        'x-askm6-proxy-secret': secret, 'x-askm6-client-ip': '198.51.100.20',
      })
      return upstream(metadata, { headers: {
        'Content-Type': 'application/json', 'Set-Cookie': cookie,
        'X-Private': 'private', 'X-AskM6-Proxy-Secret': secret, 'Access-Control-Allow-Origin': '*',
      } })
    })
    const response = await dispatch({ body: JSON.stringify(input), headers: {
      Cookie: '__Host-askm6_guest=private; __Host-askm6_google=private; askm6_account=private',
      Authorization: 'Bearer private', 'X-Forwarded-For': '203.0.113.99',
      'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
    } })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), metadata)
    assert.equal(response.headers.get('Set-Cookie'), `${cookieName}=${token}; Expires=${expiry}; Path=/; Secure; HttpOnly; SameSite=Lax`)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    for (const name of ['X-Private', 'X-AskM6-Proxy-Secret', 'Access-Control-Allow-Origin']) assert.equal(response.headers.get(name), null)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const value of [undefined, 'false', 'TRUE', ' true ', '1']) {
  test(`sign-in forwarding stays closed for flag ${JSON.stringify(value)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({}, { ...env, ACCOUNT_SIGN_IN_PROXY_ENABLED: value }), 404)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const value of [token, '', '""', 'malformed', 'expired-but-shaped'.padEnd(43, '_')]) {
  test(`requires sign-out for account cookie presence (${JSON.stringify(value)}) before body parsing`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const request = incoming({ headers: { Cookie: `${cookieName}=${value}` } })
    t.mock.method(request.body, 'getReader', () => { throw new Error('Must not parse credentials') })
    const response = await onRequest({ request, env })
    await failure(response, 409)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const [label, config, options, url, status] of [
  ['missing API origin', { API_ORIGIN: undefined }, {}, undefined, 503],
  ['HTTP backend', { API_ORIGIN: 'http://backend.example' }, {}, undefined, 503],
  ['backend path', { API_ORIGIN: 'https://backend.example/private' }, {}, undefined, 503],
  ['backend credentials', { API_ORIGIN: 'https://private@backend.example' }, {}, undefined, 503],
  ['same origin backend', { API_ORIGIN: site }, {}, undefined, 503],
  ['missing public origin', { AUTH_PUBLIC_ORIGIN: undefined }, {}, undefined, 503],
  ['disabled IP trust', { AUTH_PROXY_TRUST_ENABLED: 'false' }, {}, undefined, 503],
  ['missing shared key', { AUTH_PROXY_SHARED_SECRET: undefined }, {}, undefined, 503],
  ['invalid shared key', { AUTH_PROXY_SHARED_SECRET: 'private' }, {}, undefined, 503],
  ['wrong method', {}, { method: 'GET', body: undefined }, undefined, 405],
  ['foreign Origin', {}, { headers: { Origin: 'https://other.example' } }, undefined, 403],
  ['empty Origin', {}, { headers: { Origin: '' } }, undefined, 403],
  ['combined Origin', {}, { headers: { Origin: `${site}, ${site}` } }, undefined, 403],
  ['cross-site Fetch Metadata', {}, { headers: { 'Sec-Fetch-Site': 'cross-site' } }, undefined, 403],
  ['preview deployment', {}, {}, 'https://preview.example' + endpoint, 403],
  ['query parameters', {}, {}, site + endpoint + '?destination=private', 400],
  ['fragment', {}, {}, site + endpoint + '#private', 400],
  ['missing ingress IP', {}, { headers: { 'CF-Connecting-IP': '' } }, undefined, 503],
  ['combined ingress IP', {}, { headers: { 'CF-Connecting-IP': '198.51.100.20, 203.0.113.30' } }, undefined, 503],
  ['ambiguous cookies', {}, { headers: { Cookie: `${cookieName}=${token}; ${cookieName}=${token}` } }, undefined, 400],
  ['oversized cookies', {}, { headers: { Cookie: 'other=' + 'x'.repeat(8192) } }, undefined, 400],
  ['wrong content type', {}, { headers: { 'Content-Type': 'text/plain' } }, undefined, 415],
  ['ambiguous length', {}, { headers: { 'Content-Length': '12, 12' } }, undefined, 400],
  ['wrong actual length', {}, { headers: { 'Content-Length': '0' } }, undefined, 400],
  ['declared oversized body', {}, { headers: { 'Content-Length': '16385' } }, undefined, 413],
  ['compressed input', {}, { headers: { 'Content-Encoding': 'gzip' } }, undefined, 400],
  ['combined framing', {}, { headers: { 'Transfer-Encoding': 'chunked', 'Content-Length': '1' } }, undefined, 400],
  ['unsupported transfer encoding', {}, { headers: { 'Transfer-Encoding': 'gzip, chunked' } }, undefined, 400],
]) {
  test(`rejects ${label} without contacting backend`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const response = await dispatch(options, { ...env, ...config }, url)
    if (status === 405) assert.equal(response.headers.get('Allow'), 'POST')
    await failure(response, status)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const [label, input] of [
  ['null', null], ['array', []], ['scalar', 'private'], ['missing credentials', {}],
  ['missing email', { password: 'x' }], ['missing password', { email: 'x' }],
  ['extra field', { ...credentials, user_id: 'private' }],
  ['empty email', { ...credentials, email: '' }], ['nonstring email', { ...credentials, email: 1 }],
  ['oversized email', { ...credentials, email: 'x'.repeat(321) }],
  ['oversized password', { ...credentials, password: 'x'.repeat(1025) }],
  ['empty password', { ...credentials, password: '' }], ['nonstring password', { ...credentials, password: [] }],
  ['invalid Unicode email', { ...credentials, email: '\ud800' }], ['invalid Unicode password', { ...credentials, password: '\udfff' }],
  ['empty proof', { ...credentials, captcha_token: '' }], ['oversized proof', { ...credentials, captcha_token: 'x'.repeat(2049) }],
  ['nonstring proof', { ...credentials, captcha_token: false }], ['non-ASCII proof', { ...credentials, captcha_token: 'é' }],
  ['trailing proof newline', { ...credentials, captcha_token: 'proof\n' }], ['proof whitespace', { ...credentials, captcha_token: ' proof' }],
]) {
  test(`rejects ${label} input schema before provider forwarding`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({ body: JSON.stringify(input) }), 400)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const body of [undefined, '{', new Uint8Array([0xff])]) {
  test(`rejects empty/malformed/invalid UTF-8 JSON ${String(body)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({ body }), 400)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('accepts decoded chunked input at the exact byte limit and rejects one extra byte', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.body, JSON.stringify(credentials))
    assert.equal(options.headers.get('Transfer-Encoding'), null)
    assert.equal(options.headers.get('Content-Length'), null)
    return upstream()
  })
  const serialized = JSON.stringify(credentials)
  const padding = 16384 - new TextEncoder().encode(serialized).byteLength
  const body = serialized + ' '.repeat(padding)
  const response = await dispatch({ body, headers: { 'Transfer-Encoding': 'chunked' } })
  assert.equal(response.status, 200)
  await response.arrayBuffer()
  await failure(await dispatch({ body: body + ' ' }), 413)
  assert.equal(fetch.mock.callCount(), 1)
})

for (const proof of [undefined, null]) {
  test(`keeps missing/null CAPTCHA decisions with backend (${proof})`, async (t) => {
    const body = { email: credentials.email, password: credentials.password, ...(proof === undefined ? {} : { captcha_token: proof }) }
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
      assert.equal(options.body, JSON.stringify(body))
      return new Response('private', { status: 403, headers: { 'X-Account-Verification': 'required' } })
    })
    const response = await dispatch({ body: JSON.stringify(body) })
    assert.equal(response.headers.get('X-Account-Verification'), 'required')
    await failure(response, 403)
  })
}

for (const [status, headers, retry, verification] of [
  [400, {}, null, null], [401, {}, null, null], [409, {}, null, null], [413, {}, null, null], [415, {}, null, null],
  [403, {}, null, null], [403, { 'X-Account-Verification': 'required' }, null, 'required'],
  [403, { 'X-Account-Verification': 'required, required' }, null, null],
  [503, { 'X-Account-Verification': 'required', 'Retry-After': '20' }, null, null],
  ...['1', '86400', '0030', '0', '86401', '-1', '1.5', 'Wed, 21 Oct 2030 07:28:00 GMT', undefined]
    .map((value) => [429, value === undefined ? {} : { 'Retry-After': value }, ['1', '86400', '0030'].includes(value) ? String(Number(value)) : null, null]),
]) {
  test(`preserves safe error semantics (${status}, ${JSON.stringify(headers)}) without accepting cookies`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response('private provider detail', {
      status, headers: { ...headers, 'Set-Cookie': cookie, 'X-Private': 'private', Location: 'https://private.example' },
    }))
    const response = await dispatch()
    assert.equal(response.headers.get('Retry-After'), retry)
    assert.equal(response.headers.get('X-Account-Verification'), verification)
    await failure(response, status)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const status of [201, 204, 301, 302, 303, 307, 308, 418, 500]) {
  test(`masks unexpected response ${status} and does not follow redirects`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(status === 204 ? null : 'private', {
      status, headers: { 'Set-Cookie': cookie, Location: 'https://private.example' },
    }))
    await failure(await dispatch(), 502)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const [label, body] of [
  ['null', null], ['array', []], ['missing fields', {}], ['provider token', { ...metadata, access_token: 'private' }],
  ['invalid UUID', { ...metadata, user_id: 'invalid' }], ['missing idle', { user_id: metadata.user_id, absolute_expires_at: metadata.absolute_expires_at }],
  ['UUID trailing newline', { ...metadata, user_id: metadata.user_id + '\n' }],
  ['invalid timestamp', { ...metadata, expires_at: '2030-02-30T00:00:00Z' }],
  ['non-UTC timestamp', { ...metadata, expires_at: '2030-01-01T12:00:00+01:00' }],
  ['past idle expiry', { ...metadata, expires_at: '2020-01-01T00:00:00Z' }],
  ['idle beyond absolute', { ...metadata, absolute_expires_at: '2029-01-01T00:00:00Z' }],
]) {
  test(`rejects ${label} success metadata without issuing account cookie`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(body))
    await failure(await dispatch(), 502)
  })
}

for (const candidate of [null, cookie.replace(cookieName, 'askm6_account'), cookie.replace(cookieName, '__Host-askm6_guest'),
  cookie.replace(token, 'malformed'), cookie.replace('; Secure', ''), cookie.replace('; HttpOnly', ''),
  cookie.replace('Path=/', 'Path=/api'), cookie.replace('SameSite=lax', 'SameSite=none'),
  cookie + '; Domain=site.example', cookie + '; Secure', cookie + '; Max-Age=0', cookie + '; Priority=High',
  cookie.replace(expiry, 'Wed, 02 Jan 2030 12:00:00 GMT')]) {
  test(`rejects unsafe newly issued account cookie ${candidate?.slice(-65)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(metadata, { headers: {
      'Content-Type': 'application/json', ...(candidate === null ? {} : { 'Set-Cookie': candidate }),
    } }))
    await failure(await dispatch(), 502)
  })
}

test('multiple cookies cannot change guest/OAuth identities and folded cookies are not split', async (t) => {
  let folded = false
  t.mock.method(globalThis, 'fetch', async () => {
    const headers = new Headers({ 'Content-Type': 'application/json' })
    if (folded) headers.set('Set-Cookie', cookie + ', __Host-askm6_guest=private')
    else { headers.append('Set-Cookie', cookie); headers.append('Set-Cookie', '__Host-askm6_guest=private') }
    return upstream(metadata, { headers })
  })
  await failure(await dispatch(), 502)
  folded = true
  await failure(await dispatch(), 502)
})

for (const headers of [
  { 'Content-Type': 'text/plain', 'Set-Cookie': cookie },
  { 'Content-Type': 'application/json', 'Set-Cookie': cookie, 'Content-Encoding': 'gzip' },
  { 'Content-Type': 'application/json', 'Set-Cookie': cookie, 'Content-Length': '4097' },
  { 'Content-Type': 'application/json', 'Set-Cookie': cookie, 'Content-Length': '0' },
]) {
  test(`rejects invalid success framing ${JSON.stringify(headers)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(metadata, { headers }))
    await failure(await dispatch(), 502)
  })
}

test('malformed/invalid UTF-8/oversized response bodies never issue a credential', async (t) => {
  let content
  t.mock.method(globalThis, 'fetch', async () => new Response(content, {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie },
  }))
  for (const body of ['{', new Uint8Array([0xff]), ' '.repeat(4097)]) {
    content = body
    await failure(await dispatch(), 502)
  }
})

test('network failures remain private and never retry credentials', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('private network error') })
  await failure(await dispatch(), 502)
  assert.equal(fetch.mock.callCount(), 1)
})

test('already cancelled sign-in never contacts the backend', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await dispatch({ signal: AbortSignal.abort() }), 502)
  assert.equal(fetch.mock.callCount(), 0)
})

for (const kind of ['deadline', 'client']) {
  test(`${kind} cancels stalled credentials before forwarding`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let cancelled = false
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const pending = dispatch({ body, duplex: 'half', signal: controller.signal })
    if (kind === 'deadline') t.mock.timers.tick(20_000)
    else controller.abort()
    await failure(await pending, 502)
    assert.equal(cancelled, true)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const kind of ['deadline', 'client']) {
  test(`${kind} cancels a pending provider request and discards late account cookies`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let began, release, signal
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
    await failure(await pending, 502)
    assert.equal(signal.aborted, true)
    assert.equal(fetch.mock.callCount(), 1)
    release(upstream())
    await new Promise((resolve) => setImmediate(resolve))
  })
}

test('the total deadline covers response consumption and cancels its stream', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let began, cancelled = false
  const reading = new Promise((resolve) => { began = resolve })
  t.mock.method(globalThis, 'fetch', async () => {
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const original = body.getReader.bind(body)
    t.mock.method(body, 'getReader', () => { began(); return original() })
    return new Response(body, { headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie } })
  })
  const pending = dispatch()
  await reading
  t.mock.timers.tick(20_000)
  await failure(await pending, 502)
  assert.equal(cancelled, true)
})
