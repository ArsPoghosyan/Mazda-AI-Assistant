import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'

const site = 'https://site.example'
const endpoint = '/api/v1/account/session'
const token = 'A'.repeat(43)
const name = '__Host-askm6_account'
const env = {
  API_ORIGIN: 'https://backend.example',
  AUTH_PUBLIC_ORIGIN: site,
  AUTH_SESSION_PROXY_ENABLED: 'true',
}
const metadata = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}
const renewal = `${name}=${token}; expires=Tue, 01 Jan 2030 12:00:00 GMT; HttpOnly; Path=/; SameSite=lax; Secure`
const deletion = `${name}=""; expires=Tue, 01 Jan 2030 12:00:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=lax; Secure`

function context(options = {}, configuration = env, url = site + endpoint) {
  return { request: new Request(url, {
    method: 'POST', headers: { Origin: site, Cookie: `${name}=${token}` }, ...options,
  }), env: configuration }
}

async function blocked(response, status) {
  assert.equal(response.status, status)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  for (const header of ['Set-Cookie', 'Location', 'Access-Control-Allow-Origin', 'X-Private']) {
    assert.equal(response.headers.get(header), null)
  }
  const text = await response.text()
  for (const secret of [token, metadata.user_id, 'private']) assert.equal(text.includes(secret), false)
}

for (const [label, flag] of [
  ['unset', undefined], ['false', 'false'], ['uppercase', 'TRUE'], ['padded', ' true '],
]) {
  test(`session handler stays closed when flag is ${label}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('Must not fetch') })
    await blocked(await onRequest(context({}, { AUTH_SESSION_PROXY_ENABLED: flag })), 404)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('enabled handler applies policy, cookie filtering, metadata checks and renewal together', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url.href, env.API_ORIGIN + endpoint)
    assert.equal(options.method, 'POST')
    assert.equal(options.redirect, 'manual')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.body, undefined)
    assert.deepEqual(Object.fromEntries(options.headers), {
      accept: 'application/json', 'accept-encoding': 'identity',
      cookie: `${name}=${token}`, origin: site,
    })
    return Response.json(metadata, { headers: {
      'Set-Cookie': renewal, 'X-Private': 'private', 'Access-Control-Allow-Origin': '*',
    } })
  })
  const response = await onRequest(context({ headers: {
    Origin: site, Cookie: `guest=private; ${name}=${token}; askm6_account=private`,
    Authorization: 'Bearer private', 'X-Forwarded-For': '192.0.2.1',
  } }))
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), metadata)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  assert.equal(response.headers.get('Set-Cookie'), `${name}=${token}; Expires=Tue, 01 Jan 2030 12:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax`)
  assert.equal(response.headers.get('X-Private'), null)
  assert.equal(response.headers.get('Access-Control-Allow-Origin'), null)
  assert.equal(fetch.mock.callCount(), 1)
})

test('enabled signed-out check clears only the secure account cookie after backend confirmation', async (t) => {
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.headers.has('Cookie'), false)
    return Response.json({ detail: 'private provider details' }, { status: 401, headers: { 'Set-Cookie': deletion } })
  })
  const response = await onRequest(context({ headers: { Origin: site, Cookie: 'guest=private' } }))
  assert.equal(response.status, 401)
  assert.deepEqual(await response.json(), { detail: 'Invalid or expired account session.' })
  assert.equal(response.headers.get('Set-Cookie'), `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`)
})

for (const origin of [null, 'https://other.example', site + ', ' + site]) {
  test(`handler rejects untrusted or missing Origin ${JSON.stringify(origin)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('Must not fetch') })
    await blocked(await onRequest(context({ headers: origin === null ? {} : { Origin: origin } })), 403)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('a preview deployment cannot authorize itself using forwarded headers', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('Must not fetch') })
  await blocked(await onRequest(context({ headers: {
    Origin: site, Host: 'site.example', 'X-Forwarded-Host': 'site.example',
  } }, env, 'https://preview.example' + endpoint)), 403)
  assert.equal(fetch.mock.callCount(), 0)
})

for (const method of ['GET', 'OPTIONS']) {
  test(`handler rejects ${method} without network access`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('Must not fetch') })
    const response = await onRequest(context({ method }))
    assert.equal(response.headers.get('Allow'), 'POST')
    await blocked(response, 405)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

for (const path of [
  '/api/v1/account/sign-in', '/api/v1/account/sign-up', '/api/v1/account/sign-out',
  '/api/v1/guest/session', '/api/v1/account/google/start', '/api/v1/account/google/callback',
  endpoint + '/', '/api/v1/account/%73ession',
]) {
  test(`enabling session checks does not expose ${path}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('Must not fetch') })
    await blocked(await onRequest(context({}, env, site + path)), 404)
    assert.equal(fetch.mock.callCount(), 0)
  })
}

test('missing backend configuration fails without contacting an upstream', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('Must not fetch') })
  await blocked(await onRequest(context({}, { ...env, API_ORIGIN: undefined })), 503)
  assert.equal(fetch.mock.callCount(), 0)
})

test('payloads are rejected before network access and are not consumed', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('Must not fetch') })
  const input = context({ body: '{"access_token":"private"}' })
  await blocked(await onRequest(input), 400)
  assert.equal(input.request.bodyUsed, false)
  assert.equal(fetch.mock.callCount(), 0)
})

for (const [label, status, body, cookie] of [
  ['extra provider data', 200, { ...metadata, access_token: 'private' }, renewal],
  ['cookie rotation', 200, metadata, renewal.replace(token, 'B'.repeat(43))],
  ['unconfirmed deletion', 401, { detail: 'private' }, null],
  ['redirect', 302, { detail: 'private' }, renewal],
  ['temporary failure', 503, { detail: 'private' }, renewal],
]) {
  test(`handler preserves the browser credential on ${label}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json(body, {
      status, headers: { ...(cookie ? { 'Set-Cookie': cookie } : {}), Location: 'https://private.example' },
    }))
    await blocked(await onRequest(context()), status === 503 ? 503 : 502)
    assert.equal(fetch.mock.callCount(), 1)
  })
}

test('incoming cancellation reaches the forwarding helper through the handler', async (t) => {
  const controller = new AbortController()
  let signal
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    signal = options.signal
    return new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(new Error('private transport detail')), { once: true })
    })
  })
  const pending = onRequest(context({ signal: controller.signal }))
  controller.abort()
  await blocked(await pending, 502)
  assert.equal(signal.aborted, true)
})

test('health routing is independent of the auth flag/config and never forwards cookies', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url.href, env.API_ORIGIN + '/api/v1/health')
    assert.deepEqual(options.headers, { Accept: 'application/json' })
    return Response.json({ status: 'ok' }, { headers: { 'Set-Cookie': renewal } })
  })
  const response = await onRequest(context({ method: 'GET' }, {
    API_ORIGIN: env.API_ORIGIN, AUTH_SESSION_PROXY_ENABLED: 'true', AUTH_PUBLIC_ORIGIN: 'invalid',
  }, site + '/api/v1/health'))
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal(fetch.mock.callCount(), 1)
})
