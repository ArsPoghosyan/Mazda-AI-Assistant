import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'

const site = 'https://site.example'
const endpoint = '/api/v1/account/sign-out'
const name = '__Host-askm6_account'
const token = 'A'.repeat(43)
const secret = 'ab'.repeat(32) // Public synthetic fixture.
const deletion = `${name}=""; expires=Thu, 01 Jan 2026 00:00:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=lax; Secure`
const canonical = `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`
const env = { API_ORIGIN: 'https://backend.example', AUTH_PUBLIC_ORIGIN: site, ACCOUNT_SIGN_OUT_PROXY_ENABLED: 'true' }

function incoming(options = {}, url = site + endpoint) {
  return new Request(url, { method: 'POST', headers: { Origin: site, Cookie: `${name}=${token}` }, ...options })
}

function dispatch(options = {}, config = env, url) {
  return onRequest({ request: incoming(options, url), env: config })
}

function upstream(cookie = deletion, extra = {}) {
  return new Response(null, { status: 204, headers: { ...(cookie === null ? {} : { 'Set-Cookie': cookie }), ...extra } })
}

async function failure(response, status = 502) {
  assert.equal(response.status, status)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  for (const header of ['Set-Cookie', 'Location', 'Authorization', 'Retry-After', 'Access-Control-Allow-Origin', 'X-AskM6-Proxy-Secret', 'X-Private']) {
    assert.equal(response.headers.get(header), null)
  }
  const text = await response.text()
  for (const value of [token, secret, 'private']) assert.equal(text.includes(value), false)
}

test('signs out only the secure account credential and clears it after backend confirmation', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url.href, env.API_ORIGIN + endpoint)
    assert.equal(options.method, 'POST')
    assert.equal(options.body, undefined)
    assert.equal(options.redirect, 'manual')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.credentials, 'omit')
    assert.deepEqual(Object.fromEntries(options.headers), {
      accept: 'application/json', 'accept-encoding': 'identity', cookie: `${name}=${token}`, origin: site,
    })
    return upstream(deletion, { Location: 'https://private.example', 'Access-Control-Allow-Origin': '*', 'X-Private': 'private' })
  })
  const response = await dispatch({ headers: {
    Origin: site, Cookie: `__Host-askm6_guest=private; __Host-askm6_google=private; askm6_account=private; ${name}=${token}`,
    Authorization: 'Bearer private', 'CF-Connecting-IP': '198.51.100.20', 'X-Forwarded-For': '203.0.113.99',
    'X-AskM6-Proxy-Secret': 'forged', 'X-AskM6-Client-IP': '203.0.113.99',
  } })
  assert.equal(response.status, 204)
  assert.equal(await response.text(), '')
  assert.equal(response.headers.get('Content-Type'), null)
  assert.equal(response.headers.get('Set-Cookie'), canonical)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  for (const header of ['Location', 'Access-Control-Allow-Origin', 'X-Private']) assert.equal(response.headers.get(header), null)
  assert.equal(fetch.mock.callCount(), 1)
})

for (const cookie of [null, 'unrelated=private', 'askm6_account=private', `${name}=bad`, `${name}=`, `${name}=""`]) {
  test(`omits absent/development/malformed credentials and waits for confirmed deletion (${cookie?.slice(0, 24)})`, async (t) => {
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
      assert.equal(options.headers.get('Cookie'), null)
      return upstream()
    })
    const response = await dispatch({ headers: { Origin: site, ...(cookie === null ? {} : { Cookie: cookie }) } })
    assert.equal(response.status, 204)
    assert.equal(response.headers.get('Set-Cookie'), canonical)
    assert.equal(await response.text(), '')
  })
}

for (const flag of [undefined, 'false', 'TRUE', ' true ', '1']) {
  test(`sign-out stays closed for flag ${JSON.stringify(flag)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await dispatch({}, { ...env, ACCOUNT_SIGN_OUT_PROXY_ENABLED: flag }), 404)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const [label, config, options, url, status] of [
  ['missing API origin', { API_ORIGIN: undefined }, {}, undefined, 503],
  ['HTTP API origin', { API_ORIGIN: 'http://backend.example' }, {}, undefined, 503],
  ['backend URL path', { API_ORIGIN: 'https://backend.example/private' }, {}, undefined, 503],
  ['backend credentials', { API_ORIGIN: 'https://private@backend.example' }, {}, undefined, 503],
  ['same backend origin', { API_ORIGIN: site }, {}, undefined, 503],
  ['missing public origin', { AUTH_PUBLIC_ORIGIN: undefined }, {}, undefined, 503],
  ['wrong method', {}, { method: 'GET' }, undefined, 405],
  ['missing Origin', {}, { headers: {} }, undefined, 403],
  ['foreign Origin', {}, { headers: { Origin: 'https://foreign.example' } }, undefined, 403],
  ['combined Origin', {}, { headers: { Origin: `${site}, ${site}` } }, undefined, 403],
  ['cross-site metadata', {}, { headers: { Origin: site, 'Sec-Fetch-Site': 'cross-site' } }, undefined, 403],
  ['preview deployment', {}, {}, 'https://preview.example' + endpoint, 403],
  ['query', {}, {}, site + endpoint + '?scope=global', 400],
  ['fragment', {}, {}, site + endpoint + '#private', 400],
  ['undeclared payload', {}, { body: '{}' }, undefined, 400],
  ['false zero length', {}, { body: '{}', headers: { Origin: site, 'Content-Length': '0' } }, undefined, 400],
  ['nonzero length', {}, { headers: { Origin: site, 'Content-Length': '1' } }, undefined, 400],
  ['ambiguous length', {}, { headers: { Origin: site, 'Content-Length': '0, 0' } }, undefined, 400],
  ['transfer encoding', {}, { headers: { Origin: site, 'Transfer-Encoding': 'chunked' } }, undefined, 400],
  ['compressed input', {}, { headers: { Origin: site, 'Content-Encoding': 'gzip' } }, undefined, 400],
  ['duplicate account cookies', {}, { headers: { Origin: site, Cookie: `${name}=${token}; ${name}=${token}` } }, undefined, 400],
  ['oversized cookies', {}, { headers: { Origin: site, Cookie: 'unrelated=' + 'x'.repeat(8192) } }, undefined, 400],
]) {
  test(`rejects ${label} without deleting a session or clearing cookies`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const response = await dispatch(options, { ...env, ...config }, url)
    if (status === 405) assert.equal(response.headers.get('Allow'), 'POST')
    await failure(response, status)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('optional trusted-IP mode overwrites assertions using only verified ingress and server secret', async (t) => {
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.headers.get('X-AskM6-Proxy-Secret'), secret)
    assert.equal(options.headers.get('X-AskM6-Client-IP'), '2001:db8::1')
    for (const header of ['CF-Connecting-IP', 'X-Forwarded-For', 'Forwarded']) assert.equal(options.headers.get(header), null)
    return upstream()
  })
  const response = await dispatch({ headers: {
    Origin: site, 'CF-Connecting-IP': '2001:db8::1', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
  } }, { ...env, AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: secret })
  assert.equal(response.status, 204)
  assert.equal(response.headers.get('Set-Cookie'), canonical)
  await response.arrayBuffer()
})

test('enabled but invalid trusted-IP configuration fails without fetch or cookie clearing', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await dispatch({}, { ...env, AUTH_PROXY_TRUST_ENABLED: 'true' }), 503)
  assert.equal(fetch.mock.callCount(), 0)
})

for (const [status, expected] of [[403, 403], [503, 503], [200, 502], [201, 502], [301, 502], [302, 502], [303, 502],
  [307, 502], [308, 502], [400, 502], [401, 502], [409, 502], [429, 502], [500, 502]]) {
  test(`HTTP ${status} cannot authorize local cookie deletion or trigger retries`, async (t) => {
    let cancelled = false
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({ cancel() { cancelled = true } }), {
      status, headers: { 'Set-Cookie': deletion, Location: 'https://private.example', 'X-Private': 'private', 'Retry-After': '20' },
    }))
    await failure(await dispatch(), expected)
    assert.equal(fetch.mock.callCount(), 1)
    assert.equal(cancelled, true)
  })
}

for (const candidate of [null, deletion.replace(name, 'askm6_account'), deletion.replace(name, '__Host-askm6_guest'),
  deletion.replace('""', token), deletion.replace('; Secure', ''), deletion.replace('; HttpOnly', ''),
  deletion.replace('Max-Age=0;', ''), deletion.replace('Max-Age=0', 'Max-Age=1'),
  deletion.replace('Path=/', 'Path=/api'), deletion.replace('SameSite=lax', 'SameSite=none'),
  deletion + '; Domain=site.example', deletion + '; Secure', deletion + '; Max-Age=0', deletion + '; Priority=High',
  deletion.replace('Thu, 01 Jan 2026 00:00:00 GMT', 'invalid-date')]) {
  test(`rejects malformed or incorrectly scoped deletion cookie ${candidate?.slice(-65)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(candidate))
    await failure(await dispatch())
  })
}

test('supports native Workers cookie fields and rejects multiple or folded identity cookies', async (t) => {
  let mode = 'single'
  t.mock.method(globalThis, 'fetch', async () => {
    const response = upstream()
    response.headers.getAll = () => mode === 'single' ? [deletion] : mode === 'multiple'
      ? [deletion, '__Host-askm6_guest=private'] : [deletion + ', __Host-askm6_guest=private']
    response.headers.getSetCookie = () => { throw new Error('Must use Workers API') }
    return response
  })
  const response = await dispatch()
  assert.equal(response.status, 204)
  assert.equal(response.headers.get('Set-Cookie'), canonical)
  await response.arrayBuffer()
  for (const value of ['multiple', 'folded']) { mode = value; await failure(await dispatch()) }
})

for (const headers of [{ 'Content-Length': '1' }, { 'Content-Length': '0, 0' }, { 'Transfer-Encoding': 'chunked' }, { 'Content-Encoding': 'gzip' }]) {
  test(`rejects malformed 204 framing ${JSON.stringify(headers)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(deletion, headers))
    await failure(await dispatch())
  })
}

test('accepts actual EOF on zero-length request and response streams', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => {
    const response = upstream(deletion, { 'Content-Length': '0' })
    Object.defineProperty(response, 'body', { value: new ReadableStream({ start(controller) { controller.close() } }) })
    return response
  })
  const body = new ReadableStream({ start(controller) { controller.close() } })
  const response = await dispatch({ body, duplex: 'half', headers: { Origin: site, 'Content-Length': '0' } })
  assert.equal(response.status, 204)
  assert.equal(response.headers.get('Set-Cookie'), canonical)
  assert.equal(fetch.mock.callCount(), 1)
  await response.arrayBuffer()
})

for (const bytes of [new Uint8Array(), new TextEncoder().encode('private')]) {
  test(`a non-EOF 204 stream chunk cannot clear cookies (${bytes.byteLength} bytes)`, async (t) => {
    let cancelled = false
    t.mock.method(globalThis, 'fetch', async () => {
      const response = upstream()
      Object.defineProperty(response, 'body', { value: new ReadableStream({
        start(controller) { controller.enqueue(bytes) }, cancel() { cancelled = true },
      }) })
      return response
    })
    await failure(await dispatch())
    assert.equal(cancelled, true)
  })
}

test('an unfinished zero-byte input chunk is rejected before the backend', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  const body = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array()) } })
  await failure(await dispatch({ body, duplex: 'half', headers: { Origin: site, 'Content-Length': '0' } }), 400)
  assert.equal(fetch.mock.callCount(), 0)
})

test('transport failure preserves browser credentials without retry', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('private transport failure') })
  await failure(await dispatch())
  assert.equal(fetch.mock.callCount(), 1)
})

test('already cancelled requests never contact the backend', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await dispatch({ signal: AbortSignal.abort() }))
  assert.equal(fetch.mock.callCount(), 0)
})

for (const kind of ['deadline', 'client']) {
  test(`${kind} stops stalled empty-body confirmation without backend contact`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let cancelled = false
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const pending = dispatch({ body, duplex: 'half', signal: controller.signal, headers: { Origin: site, 'Content-Length': '0' } })
    if (kind === 'deadline') t.mock.timers.tick(20_000)
    else controller.abort()
    await failure(await pending)
    assert.equal(fetch.mock.callCount(), 0)
    assert.equal(cancelled, true)
  })
}

for (const kind of ['deadline', 'client']) {
  test(`${kind} discards a late backend deletion confirmation`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let signal, release
    const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
      signal = options.signal
      return new Promise((resolve) => { release = resolve })
    })
    const pending = dispatch({ signal: controller.signal })
    if (kind === 'deadline') t.mock.timers.tick(20_000)
    else controller.abort()
    await failure(await pending)
    assert.equal(signal.aborted, true)
    assert.equal(fetch.mock.callCount(), 1)
    release(upstream())
    await new Promise((resolve) => setImmediate(resolve))
  })
}

test('the deadline includes checking a stalled 204 response stream', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let began, cancelled = false
  const reading = new Promise((resolve) => { began = resolve })
  t.mock.method(globalThis, 'fetch', async () => {
    const response = upstream()
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const original = body.getReader.bind(body)
    t.mock.method(body, 'getReader', () => { began(); return original() })
    Object.defineProperty(response, 'body', { value: body })
    return response
  })
  const pending = dispatch()
  await reading
  t.mock.timers.tick(20_000)
  await failure(await pending)
  assert.equal(cancelled, true)
})
