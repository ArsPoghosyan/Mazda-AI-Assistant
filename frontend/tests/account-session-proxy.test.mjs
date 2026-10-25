import assert from 'node:assert/strict'
import { test } from 'node:test'
import { forwardAccountSession } from '../server/account-session-proxy.ts'
import { ACCOUNT_COOKIE } from '../server/account-session-proxy-cookies.ts'

const site = 'https://site.example'
const path = '/api/v1/account/session'
const token = 'A'.repeat(43)
const metadata = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00.123456Z',
  absolute_expires_at: '2030-01-30T12:00:00+00:00',
}
const expiry = new Date(metadata.expires_at).toUTCString()
const renewal = `${ACCOUNT_COOKIE}=${token}; expires=${expiry}; HttpOnly; Path=/; SameSite=lax; Secure`
const deletion = `${ACCOUNT_COOKIE}=""; expires=${expiry}; HttpOnly; Max-Age=0; Path=/; SameSite=lax; Secure`
const env = { API_ORIGIN: 'https://backend.example', AUTH_PUBLIC_ORIGIN: site, AUTH_SESSION_PROXY_ENABLED: 'true' }

function incoming(options = {}) {
  return new Request(site + path, {
    method: 'POST', headers: { Origin: site, Cookie: `${ACCOUNT_COOKIE}=${token}` }, ...options,
  })
}

function upstream(body = metadata, cookie = renewal, options = {}) {
  const headers = new Headers({ 'Content-Type': 'application/json' })
  if (cookie !== null) headers.set('Set-Cookie', cookie)
  return new Response(JSON.stringify(body), { headers, ...options })
}

async function failure(response, status = 502) {
  assert.equal(response.status, status)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  for (const header of ['Set-Cookie', 'Location', 'Authorization', 'Retry-After', 'Access-Control-Allow-Origin']) {
    assert.equal(response.headers.get(header), null)
  }
  const text = await response.text()
  for (const privateText of [token, 'private', metadata.user_id]) assert.equal(text.includes(privateText), false)
}

test('forwards only the secure account credential and fixed origin, then validates renewal', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url.href, env.API_ORIGIN + path)
    assert.equal(options.method, 'POST')
    assert.equal(options.redirect, 'manual')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.credentials, 'omit')
    assert.equal(options.body, undefined)
    assert.deepEqual(Object.fromEntries(options.headers), {
      accept: 'application/json', 'accept-encoding': 'identity',
      cookie: `${ACCOUNT_COOKIE}=${token}`, origin: site,
    })
    return upstream(metadata, renewal, { headers: {
      'Content-Type': 'application/json', 'Set-Cookie': renewal,
      Location: 'https://private.example', 'Access-Control-Allow-Origin': '*',
      'X-Private': 'private', 'Cache-Control': 'public, max-age=3600',
    } })
  })
  const response = await forwardAccountSession(incoming({ headers: {
    Origin: site, Cookie: `guest=private; ${ACCOUNT_COOKIE}=${token}; askm6_account=private`,
    Authorization: 'Bearer private', 'X-Forwarded-For': '192.0.2.1',
    'CF-Connecting-IP': '192.0.2.2', Forwarded: 'for=private', 'X-Private': 'private',
  } }), env)
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), metadata)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  assert.equal(response.headers.get('Set-Cookie'), `${ACCOUNT_COOKIE}=${token}; Expires=${expiry}; Path=/; Secure; HttpOnly; SameSite=Lax`)
  assert.equal(response.headers.get('Location'), null)
  assert.equal(response.headers.get('X-Private'), null)
  assert.equal(response.headers.get('Access-Control-Allow-Origin'), null)
  assert.equal(fetch.mock.callCount(), 1)
})

for (const cookie of [null, 'unrelated=private', `${ACCOUNT_COOKIE}=malformed`, 'askm6_account=private']) {
  test(`omits missing/invalid credentials and accepts only a confirmed clearing cookie (${cookie === null ? 'missing' : cookie.split('=')[0]})`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
      assert.equal(options.headers.has('Cookie'), false)
      return upstream({ detail: 'private-provider-detail' }, deletion, { status: 401 })
    })
    const response = await forwardAccountSession(incoming({ headers: {
      Origin: site, ...(cookie === null ? {} : { Cookie: cookie }),
    } }), env)
    assert.equal(response.status, 401)
    assert.deepEqual(await response.json(), { detail: 'Invalid or expired account session.' })
    assert.equal(response.headers.get('Set-Cookie'), `${ACCOUNT_COOKIE}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const [label, header] of [
  ['duplicate', `${ACCOUNT_COOKIE}=${token}; ${ACCOUNT_COOKIE}=${'B'.repeat(43)}`],
  ['oversized', 'unrelated=' + 'x'.repeat(8192)],
]) {
  test(`rejects ${label} incoming cookie headers without network access`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await failure(await forwardAccountSession(incoming({ headers: { Origin: site, Cookie: header } }), env), 400)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('request policy rejection happens before cookie handling or network access', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await forwardAccountSession(incoming(), { ...env, AUTH_SESSION_PROXY_ENABLED: 'false' }), 404)
  await failure(await forwardAccountSession(incoming({ headers: { Origin: 'https://other.example' } }), env), 403)
  assert.equal(fetch.mock.callCount(), 0)
})

for (const status of [201, 204, 301, 302, 303, 307, 308, 400, 429, 500]) {
  test(`masks unexpected HTTP ${status} and never follows or forwards redirects`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(status === 204 ? null : 'private', {
      status, headers: { Location: 'https://private.example', 'Set-Cookie': renewal },
    }))
    await failure(await forwardAccountSession(incoming(), env))
    assert.equal(fetch.mock.callCount(), 1)
  })
}

for (const status of [403, 503]) {
  test(`returns fixed HTTP ${status} without forwarding its body or cookies`, async (t) => {
    let cancelled = false
    t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({
      cancel() { cancelled = true },
    }), { status, headers: { 'Set-Cookie': renewal, 'X-Private': 'private' } }))
    await failure(await forwardAccountSession(incoming(), env), status)
    assert.equal(cancelled, true)
  })
}

for (const [label, change] of [
  ['missing secure', renewal.replace('; Secure', '')],
  ['missing httponly', renewal.replace('; HttpOnly', '')],
  ['wrong path', renewal.replace('Path=/', 'Path=/api')],
  ['wrong samesite', renewal.replace('SameSite=lax', 'SameSite=None')],
  ['domain', renewal + '; Domain=site.example'],
  ['partitioned', renewal + '; Partitioned'],
  ['duplicate path', renewal + '; Path=/'],
  ['duplicate secure', renewal + '; Secure'],
  ['new token', renewal.replace(token, 'B'.repeat(43))],
  ['insecure name', renewal.replace(ACCOUNT_COOKIE, 'askm6_account')],
  ['max age', renewal + '; Max-Age=600'],
  ['different expiry', renewal.replace(expiry, 'Tue, 01 Jan 2030 12:01:00 GMT')],
  ['invalid expiry', renewal.replace(expiry, 'private')],
  ['folded cookies', renewal + ', guest=private'],
  ['missing cookie', null],
]) {
  test(`rejects renewal with ${label}, preserving the browser credential`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(metadata, change))
    await failure(await forwardAccountSession(incoming(), env))
  })
}

for (const [label, cookie] of [
  ['missing deletion', null], ['renewal on rejection', renewal],
  ['missing max age', deletion.replace('; Max-Age=0', '')],
  ['positive max age', deletion.replace('Max-Age=0', 'Max-Age=1')],
  ['missing secure', deletion.replace('; Secure', '')],
]) {
  test(`does not clear browser credentials on ${label}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream({}, cookie, { status: 401 }))
    await failure(await forwardAccountSession(incoming(), env))
  })
}

test('rejects multiple separate cookies instead of folding or choosing one', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => {
    const response = upstream()
    response.headers.append('Set-Cookie', 'unrelated=private')
    return response
  })
  await failure(await forwardAccountSession(incoming(), env))
})

test('uses the Workers getAll method without splitting Expires commas', async (t) => {
  const response = upstream()
  Object.defineProperty(response.headers, 'getAll', { value: (name) => {
    assert.equal(name, 'Set-Cookie')
    return [renewal]
  } })
  Object.defineProperty(response.headers, 'getSetCookie', { value: () => { throw new Error('Must use Workers method') } })
  t.mock.method(globalThis, 'fetch', async () => response)
  assert.equal((await forwardAccountSession(incoming(), env)).status, 200)
})

for (const [label, body] of [
  ['null', null], ['array', []], ['missing field', { user_id: metadata.user_id }],
  ['invalid user', { ...metadata, user_id: 'private' }],
  ['provider token', { ...metadata, access_token: 'private' }],
  ['invalid expiry', { ...metadata, expires_at: 'private' }],
  ['nonstring expiry', { ...metadata, expires_at: 42 }],
  ['date without zone', { ...metadata, expires_at: '2030-01-01T12:00:00' }],
  ['invalid calendar date', { ...metadata, expires_at: '2030-02-30T12:00:00Z' }],
  ['expired', { ...metadata, expires_at: '2000-01-01T12:00:00Z' }],
  ['expiry beyond absolute', { ...metadata, absolute_expires_at: '2029-01-01T12:00:00Z' }],
]) {
  test(`masks ${label} success metadata without forwarding cookies`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(body))
    await failure(await forwardAccountSession(incoming(), env))
  })
}

for (const [name, value] of [
  ['Content-Type', 'text/html'], ['Content-Encoding', 'gzip'],
  ['Content-Length', '4097'], ['Content-Length', '-1'],
  ['Content-Length', '1'],
]) {
  test(`rejects invalid upstream ${name}=${value}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => {
      const response = upstream()
      response.headers.set(name, value)
      return response
    })
    await failure(await forwardAccountSession(incoming(), env))
  })
}

for (const [label, bytes] of [
  ['invalid json', new TextEncoder().encode('{private')],
  ['invalid UTF-8', new Uint8Array([0xff])],
  ['oversized bytes', new TextEncoder().encode(' '.repeat(4097))],
]) {
  test(`rejects ${label} using actual bytes, even without Content-Length`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response(bytes, {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
    }))
    await failure(await forwardAccountSession(incoming(), env))
  })
}

test('rejects a success response when no account credential was forwarded', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await forwardAccountSession(incoming({ headers: { Origin: site } }), env))
})

test('network failures remain private and do not trigger retries', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('private network details') })
  await failure(await forwardAccountSession(incoming(), env))
  assert.equal(fetch.mock.callCount(), 1)
})

test('confirms a Workers-style zero-length POST stream before fetching', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  const body = new ReadableStream({ start(controller) { controller.close() } })
  const request = incoming({ body, duplex: 'half', headers: {
    Origin: site, Cookie: `${ACCOUNT_COOKIE}=${token}`, 'Content-Length': '0',
  } })
  assert.equal((await forwardAccountSession(request, env)).status, 200)
  assert.equal(request.bodyUsed, true)
  assert.equal(fetch.mock.callCount(), 1)
})

test('a false zero-length declaration cannot bypass payload rejection', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await forwardAccountSession(incoming({ body: 'private', headers: {
    Origin: site, 'Content-Length': '0',
  } }), env), 400)
  assert.equal(fetch.mock.callCount(), 0)
})

test('the deadline also covers a stalled zero-length request stream', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let cancelled = false
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  const body = new ReadableStream({ cancel() { cancelled = true } })
  const request = incoming({ body, duplex: 'half', headers: { Origin: site, 'Content-Length': '0' } })
  const pending = forwardAccountSession(request, env)
  t.mock.timers.tick(20_000)
  await failure(await pending)
  assert.equal(fetch.mock.callCount(), 0)
  assert.equal(cancelled, true)
})

test('already-cancelled requests never contact the backend', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
  await failure(await forwardAccountSession(incoming({ signal: AbortSignal.abort() }), env))
  assert.equal(fetch.mock.callCount(), 0)
})

test('cancellation returns no cookies even when a late fetch ignores its signal', async (t) => {
  const controller = new AbortController()
  let release
  let upstreamSignal
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    upstreamSignal = options.signal
    return new Promise((resolve) => { release = resolve })
  })
  const pending = forwardAccountSession(incoming({ signal: controller.signal }), env)
  controller.abort()
  await failure(await pending)
  assert.equal(upstreamSignal.aborted, true)
  release(upstream())
  await new Promise((resolve) => setImmediate(resolve))
})

test('the total 20-second deadline includes reading a stalled response body', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let cancelled = false
  let upstreamSignal
  let bodyStarted
  const reading = new Promise((resolve) => { bodyStarted = resolve })
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    upstreamSignal = options.signal
    const body = new ReadableStream({
      pull() { return new Promise(() => {}) },
      cancel() { cancelled = true },
    })
    const getReader = body.getReader.bind(body)
    t.mock.method(body, 'getReader', (...args) => { bodyStarted(); return getReader(...args) })
    return new Response(body, { headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal } })
  })
  const pending = forwardAccountSession(incoming(), env)
  await reading
  t.mock.timers.tick(20_000)
  await failure(await pending)
  assert.equal(upstreamSignal.aborted, true)
  assert.equal(cancelled, true)
})

test('the deadline cancels a fetch that has not returned headers', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let release
  let signal
  const fetch = t.mock.method(globalThis, 'fetch', async (_url, options) => {
    signal = options.signal
    return new Promise((resolve) => { release = resolve })
  })
  const pending = forwardAccountSession(incoming(), env)
  t.mock.timers.tick(20_000)
  await failure(await pending)
  assert.equal(signal.aborted, true)
  assert.equal(fetch.mock.callCount(), 1)
  release(upstream())
})

test('client cancellation while reading cancels the stream and preserves cookies', async (t) => {
  const controller = new AbortController()
  let beginReading
  let cancelled = false
  const reading = new Promise((resolve) => { beginReading = resolve })
  t.mock.method(globalThis, 'fetch', async () => {
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const getReader = body.getReader.bind(body)
    t.mock.method(body, 'getReader', (...args) => { beginReading(); return getReader(...args) })
    return new Response(body, { headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal } })
  })
  const pending = forwardAccountSession(incoming({ signal: controller.signal }), env)
  await reading
  controller.abort()
  await failure(await pending)
  assert.equal(cancelled, true)
})
