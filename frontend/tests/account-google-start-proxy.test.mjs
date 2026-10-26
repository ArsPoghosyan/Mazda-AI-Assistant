import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'

const site = 'https://site.example'
const path = '/api/v1/account/google/start'
const issuer = 'https://auth.example/auth/v1'
const name = '__Host-askm6_oauth'
const token = 'O'.repeat(43)
const previous = 'P'.repeat(43)
const challenge = 'C'.repeat(43)
const secret = 'ab'.repeat(32) // Public synthetic fixture.
const expiry = new Date(Date.now() + 600_000).toISOString()
const cookie = `${name}=${token}; expires=${new Date(expiry).toUTCString()}; HttpOnly; Path=/; SameSite=lax; Secure`
const clear = `${name}=""; expires=Thu, 01 Jan 2026 00:00:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=lax; Secure`
const canonicalClear = `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`
function authorization(overrides = {}) {
  return issuer + '/authorize?' + new URLSearchParams({ provider: 'google', redirect_to: site + '/api/v1/account/google/callback',
    code_challenge: challenge, code_challenge_method: 's256', ...overrides })
}
const metadata = { authorization_url: authorization(), expires_at: expiry }
const env = { API_ORIGIN: 'https://backend.example', AUTH_PUBLIC_ORIGIN: site, SUPABASE_AUTH_ISSUER: issuer,
  ACCOUNT_GOOGLE_START_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: secret }
function incoming(options = {}, url = site + path) {
  return new Request(url, { method: 'POST', ...options, headers: {
    Origin: site, 'CF-Connecting-IP': '198.51.100.20', ...options.headers,
  } })
}
function dispatch(options = {}, config = env, url) { return onRequest({ request: incoming(options, url), env: config }) }
function upstream(body = metadata, selectedCookie = cookie, headers = {}) {
  return Response.json(body, { headers: { ...(selectedCookie === null ? {} : { 'Set-Cookie': selectedCookie }), ...headers } })
}
async function failure(response, status = 502, allowedCookie = null, retry = null) {
  assert.equal(response.status, status)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer')
  assert.equal(response.headers.get('Set-Cookie'), allowedCookie)
  assert.equal(response.headers.get('Retry-After'), retry)
  for (const header of ['Location', 'Authorization', 'Access-Control-Allow-Origin', 'X-Private', 'X-AskM6-Proxy-Secret', 'X-Account-Verification']) {
    assert.equal(response.headers.get(header), null)
  }
  const text = await response.text()
  for (const value of [token, previous, challenge, secret, 'private']) assert.equal(text.includes(value), false)
}

for (const oldCookie of [null, `${name}=${previous}`]) {
  test(`creates/replaces only the OAuth binding (${oldCookie === null ? 'new' : 'replacement'}) without forwarding other credentials`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
      assert.equal(url.href, env.API_ORIGIN + path)
      assert.equal(options.body, undefined)
      assert.equal(options.method, 'POST')
      assert.equal(options.redirect, 'manual')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.credentials, 'omit')
      assert.deepEqual(Object.fromEntries(options.headers), { accept: 'application/json', 'accept-encoding': 'identity', origin: site,
        'x-askm6-client-ip': '198.51.100.20', 'x-askm6-proxy-secret': secret, ...(oldCookie ? { cookie: oldCookie } : {}) })
      return upstream(metadata, cookie, { 'X-Private': 'private', Location: 'https://private.example', 'X-AskM6-Proxy-Secret': secret })
    })
    const response = await dispatch({ headers: {
      Cookie: `__Host-askm6_guest=private; askm6_account=private; askm6_oauth=private; unrelated=private${oldCookie ? '; ' + oldCookie : ''}`,
      Authorization: 'Bearer private', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
    } })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), metadata)
    assert.equal(response.headers.get('Set-Cookie'), `${name}=${token}; Expires=${new Date(expiry).toUTCString()}; Path=/; Secure; HttpOnly; SameSite=Lax`)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer')
    for (const header of ['Location', 'X-Private', 'X-AskM6-Proxy-Secret']) assert.equal(response.headers.get(header), null)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const flag of [undefined, 'false', 'TRUE', ' true ', '1']) {
  test(`Google start stays closed for ${JSON.stringify(flag)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({}, { ...env, ACCOUNT_GOOGLE_START_PROXY_ENABLED: flag }), 404)
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const [label, config, options, url, status] of [
  ['missing API', { API_ORIGIN: undefined }, {}, undefined, 503],
  ['HTTP API', { API_ORIGIN: 'http://backend.example' }, {}, undefined, 503],
  ['backend path', { API_ORIGIN: 'https://backend.example/private' }, {}, undefined, 503],
  ['same origins', { API_ORIGIN: site }, {}, undefined, 503],
  ['missing public origin', { AUTH_PUBLIC_ORIGIN: undefined }, {}, undefined, 503],
  ['missing issuer', { SUPABASE_AUTH_ISSUER: undefined }, {}, undefined, 503],
  ...['http://auth.example/auth/v1', issuer + '/', 'https://user@auth.example/auth/v1', issuer + '?x=1', issuer + '#x', 'https://auth.example', 'invalid']
    .map((value) => ['invalid issuer ' + value, { SUPABASE_AUTH_ISSUER: value }, {}, undefined, 503]),
  ['wrong method', {}, { method: 'GET' }, undefined, 405],
  ['wrong origin', {}, { headers: { Origin: 'https://other.example' } }, undefined, 403],
  ['empty origin', {}, { headers: { Origin: '' } }, undefined, 403],
  ['combined origin', {}, { headers: { Origin: `${site}, ${site}` } }, undefined, 403],
  ['cross-site', {}, { headers: { 'Sec-Fetch-Site': 'cross-site' } }, undefined, 403],
  ['preview URL', {}, {}, 'https://preview.example' + path, 403],
  ['query', {}, {}, site + path + '?redirect_to=private', 400],
  ['fragment', {}, {}, site + path + '#private', 400],
  ['body', {}, { body: '{}' }, undefined, 400],
  ['false zero length', {}, { body: '{}', headers: { 'Content-Length': '0' } }, undefined, 400],
  ['nonzero length', {}, { headers: { 'Content-Length': '1' } }, undefined, 400],
  ['combined length', {}, { headers: { 'Content-Length': '0, 0' } }, undefined, 400],
  ['transfer encoding', {}, { headers: { 'Transfer-Encoding': 'chunked' } }, undefined, 400],
  ['compression', {}, { headers: { 'Content-Encoding': 'gzip' } }, undefined, 400],
  ['cookie size', {}, { headers: { Cookie: 'x'.repeat(8193) } }, undefined, 400],
  ['disabled trust', { AUTH_PROXY_TRUST_ENABLED: 'false' }, {}, undefined, 503],
  ['missing key', { AUTH_PROXY_SHARED_SECRET: undefined }, {}, undefined, 503],
  ['empty IP', {}, { headers: { 'CF-Connecting-IP': '' } }, undefined, 503],
  ['combined IP', {}, { headers: { 'CF-Connecting-IP': '198.51.100.20, 203.0.113.99' } }, undefined, 503],
]) {
  test(`rejects ${label} before backend work`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const response = await dispatch(options, { ...env, ...config }, url)
    if (status === 405) assert.equal(response.headers.get('Allow'), 'POST')
    await failure(response, status)
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const value of ['', '""', 'bad', 'A'.repeat(43)]) {
  test(`any account cookie requires explicit sign-out (${value.length})`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({ headers: { Cookie: `__Host-askm6_account=${value}; ${name}=${previous}` } }), 409)
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const binding of [`${name}=bad`, `${name}=`, name, `${name}=${previous}; ${name}=${previous}`, `${name}=${previous} `]) {
  test(`preserves malformed/duplicate binding for backend-confirmed clearing (${binding.length})`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
      assert.equal(options.headers.get('Cookie'), /[ \t]$/.test(binding) ? binding + ';' : binding)
      return new Response('private', { status: 400, headers: { 'Set-Cookie': clear } })
    })
    await failure(await dispatch({ headers: { Cookie: binding + '; unrelated=private' } }), 400, canonicalClear)
    assert.equal(fetch.mock.callCount(), 1)
  })
}
for (const [field, value] of [['provider', 'github'], ['redirect_to', 'https://foreign.example/callback'],
  ['redirect_to', site + '/api/v1/account/google/callback?x=1'], ['code_challenge_method', 'S256'],
  ['code_challenge', 'x'.repeat(42)], ['code_challenge', challenge + '\n']]) {
  test(`rejects unsafe authorization ${field}=${JSON.stringify(value)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream({ ...metadata, authorization_url: authorization({ [field]: value }) }))
    await failure(await dispatch())
  })
}
for (const url of [authorization() + '&provider=google', authorization() + '&access_token=private',
  authorization().replace('auth.example', 'foreign.example'), authorization().replace('https:', 'http:'),
  authorization().replace('/authorize?', '/authorize/extra?'), authorization().replace('https://', 'https://user@'),
  authorization() + '#private', '//auth.example/auth/v1/authorize', 'invalid']) {
  test(`rejects untrusted authorization destination ${url.slice(0, 62)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream({ ...metadata, authorization_url: url }))
    await failure(await dispatch())
  })
}
for (const body of [null, [], {}, { ...metadata, access_token: 'private' }, { ...metadata, expires_at: '2020-01-01T00:00:00Z' },
  { ...metadata, expires_at: expiry + '\n' }, { ...metadata, expires_at: 123 }, { ...metadata, authorization_url: 123 }]) {
  test(`rejects malformed/private metadata ${JSON.stringify(body).slice(0, 60)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(body))
    await failure(await dispatch())
  })
}
for (const selectedCookie of [null, '', cookie.replace(name, '__Host-askm6_account'), cookie.replace(name, 'askm6_oauth'),
  cookie.replace('HttpOnly; ', ''), cookie.replace('; Secure', ''), cookie.replace('Path=/', 'Path=/api'),
  cookie + '; Domain=site.example', cookie + '; Secure', cookie + '; Max-Age=600', cookie.replace(token, 'short'),
  cookie.replace(new Date(expiry).toUTCString(), new Date(Date.parse(expiry) + 1000).toUTCString()),
  [cookie, cookie], [cookie, clear]]) {
  test(`rejects unsafe success cookie ${JSON.stringify(selectedCookie).slice(0, 65)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(metadata, selectedCookie))
    await failure(await dispatch())
  })
}
for (const badCookie of [cookie, clear.replace(name, '__Host-askm6_account'), clear.replace('Max-Age=0', 'Max-Age=1'),
  [clear, clear], clear + '; Domain=site.example']) {
  test(`rejects unsafe 400 clearing ${JSON.stringify(badCookie).slice(0, 65)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response('private', { status: 400, headers: { 'Set-Cookie': badCookie } }))
    await failure(await dispatch())
  })
}
for (const [status, raw, expected] of [[400, undefined, null], [403, undefined, null], [409, undefined, null], [503, '5', null],
  ...['1', '86400', '0030', '0', '86401', '-1', '1.5', undefined].map((raw) => [429, raw,
    ['1', '86400', '0030'].includes(raw) ? String(Number(raw)) : null])]) {
  test(`keeps only safe error/retry signals ${status}/${raw}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response('private', { status, headers: {
      ...(status !== 400 ? { 'Set-Cookie': clear } : {}), ...(raw === undefined ? {} : { 'Retry-After': raw }),
      Location: 'https://private.example', 'X-Account-Verification': 'required',
    } }))
    await failure(await dispatch(), status, null, expected)
  })
}
for (const status of [201, 202, 204, 301, 302, 303, 307, 308, 401, 500]) {
  test(`never follows or exposes unexpected status ${status}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(status === 204 ? null : 'private', { status, headers: { 'Set-Cookie': cookie } }))
    await failure(await dispatch())
    assert.equal(fetch.mock.callCount(), 1)
  })
}
for (const headers of [{ 'Content-Type': 'text/plain' }, { 'Content-Encoding': 'gzip' }, { 'Content-Length': '0' },
  { 'Content-Length': '4097' }, { 'Content-Length': '1, 1' }]) {
  test(`rejects unsafe metadata framing ${JSON.stringify(headers)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(metadata, cookie, headers))
    await failure(await dispatch())
  })
}
test('bounds actual response bytes and rejects malformed JSON/UTF-8', async (t) => {
  let body
  t.mock.method(globalThis, 'fetch', async () => new Response(body, { headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie } }))
  for (const value of ['{', new Uint8Array([0xff]), ' '.repeat(4097)]) { body = value; await failure(await dispatch()) }
})
test('transport failure and pre-cancellation never retry or modify browser cookies', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('private') })
  await failure(await dispatch({ signal: AbortSignal.abort() }))
  assert.equal(fetch.mock.callCount(), 0)
  await failure(await dispatch())
  assert.equal(fetch.mock.callCount(), 1)
})
for (const kind of ['deadline', 'client']) {
  test(`${kind} cancels stalled declared-zero request without backend work`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let cancelled = false
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const pending = dispatch({ body, duplex: 'half', headers: { 'Content-Length': '0' }, signal: controller.signal })
    if (kind === 'deadline') t.mock.timers.tick(20_000)
    else controller.abort()
    await failure(await pending)
    assert.equal(cancelled, true)
    assert.equal(fetch.mock.callCount(), 0)
  })
  test(`${kind} rejects late Google start URL/cookie without retry`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let signal, release, began
    const started = new Promise((resolve) => { began = resolve })
    const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
      signal = options.signal; began()
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
test('deadline covers response consumption and cancels the metadata stream', async (t) => {
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
  await failure(await pending)
  assert.equal(cancelled, true)
})
