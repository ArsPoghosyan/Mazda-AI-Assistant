import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'
import { CURRENT_TERMS_VERSION as version } from '../shared/account-terms.ts'

const site = 'https://site.example'
const backend = 'https://backend.example'
const token = 'A'.repeat(43)
const name = '__Host-askm6_account'
const env = { API_ORIGIN: backend, AUTH_PUBLIC_ORIGIN: site, ACCOUNT_TERMS_PROXY_ENABLED: 'true' }
const cookie = `${name}=${token}; Expires=Tue, 01 Jan 2030 12:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax`
const clear = `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`
const time = new Date(Date.now() - 1000).toISOString()

for (const operation of ['status', 'accept']) {
  const path = `/api/v1/account/terms/${operation}`
  const metadata = operation === 'status' ? { terms_version: version, accepted_at: null, acceptance_required: true }
    : { terms_version: version, accepted_at: time }
  function incoming(options = {}, url = site + path) {
    return new Request(url, { method: 'POST',
      ...(operation === 'accept' ? { body: JSON.stringify({ accepted: true, terms_version: version }) } : {}),
      ...options, headers: { Origin: site, Cookie: `${name}=${token}`, 'X-Account-Subject': '563128d6-22fd-464f-a3bd-31018fdf1b3c',
        ...(operation === 'accept' ? { 'Content-Type': 'application/json' } : {}), ...options.headers } })
  }
  function dispatch(options = {}, config = env, url) { return onRequest({ request: incoming(options, url), env: config }) }
  function upstream(payload = metadata, renewal = cookie) { return Response.json(payload, { headers: { 'Set-Cookie': renewal, 'X-Private': 'private-detail' } }) }

  test(`${operation} forwards only the account cookie, bounded input and safe fixed response`, async (t) => {
    const mock = t.mock.method(globalThis, 'fetch', async (url, options) => {
      assert.equal(url.href, backend + path)
      assert.equal(options.headers.get('Cookie'), `${name}=${token}`)
      assert.equal(options.headers.get('Authorization'), null)
      assert.equal(options.headers.get('X-Forwarded-For'), null)
      assert.equal(options.headers.get('Origin'), site)
      assert.equal(options.redirect, 'manual')
      assert.equal(options.credentials, 'omit')
      assert.equal(options.body, operation === 'status' ? undefined : JSON.stringify({ accepted: true, terms_version: version }))
      return upstream()
    })
    const response = await dispatch({ headers: { Cookie: `${name}=${token}; guest=private`, Authorization: 'Bearer private' } })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), metadata)
    assert.equal(response.headers.get('Set-Cookie'), cookie)
    assert.equal(response.headers.get('X-Private'), null)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    assert.equal(mock.mock.callCount(), 1)
  })
  for (const flag of [undefined, 'false', 'TRUE', '1']) {
    test(`${operation} is independently closed for ${flag}`, async (t) => {
      const mock = t.mock.method(globalThis, 'fetch', async () => upstream())
      const result = await dispatch({}, { ...env, ACCOUNT_TERMS_PROXY_ENABLED: flag })
      assert.equal(result.status, 404)
      assert.equal(result.headers.get('Set-Cookie'), null)
      assert.equal(mock.mock.callCount(), 0)
    })
  }
  for (const [options, config, suffix, code] of [
    [{ method: 'GET', body: undefined }, {}, '', 405], [{ headers: { Origin: 'https://foreign.example' } }, {}, '', 403],
    [{ headers: { 'Sec-Fetch-Site': 'cross-site' } }, {}, '', 403], [{}, { API_ORIGIN: site }, '', 503],
    [{}, {}, '?user_id=private', 400], [{}, {}, '#private', 400],
    [{ headers: { 'Content-Encoding': 'gzip' } }, {}, '', 400],
    [{ headers: { 'Transfer-Encoding': 'chunked', 'Content-Length': '2' } }, {}, '', 400],
    [{ headers: { 'Content-Length': '0, 0' } }, {}, '', 400],
    [{ headers: { Cookie: `${name}=${token}; ${name}=${token}` } }, {}, '', 400],
    [{ headers: { 'Content-Length': '1025' } }, {}, '', 413],
    [{ headers: { 'X-Account-Subject': 'bad' } }, {}, '', 400],
    [{}, { AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32) }, '', 503],
  ]) {
    test(`${operation} rejects request ${JSON.stringify(options)} ${suffix} with ${code}`, async (t) => {
      const mock = t.mock.method(globalThis, 'fetch', async () => upstream())
      const response = await dispatch(options, { ...env, ...config }, site + path + suffix)
      assert.equal(response.status, code)
      assert.equal(response.headers.get('Set-Cookie'), null)
      assert.equal(mock.mock.callCount(), 0)
    })
  }
  for (const payload of [null, {}, { ...metadata, user_id: 'private' }, { ...metadata, terms_version: 'old' },
    { ...metadata, accepted_at: 'invalid' }, ...(operation === 'status' ? [{ ...metadata, acceptance_required: false }] : [{ ...metadata, accepted_at: null }]),
  ]) {
    test(`${operation} rejects invalid upstream metadata ${JSON.stringify(payload)}`, async (t) => {
      t.mock.method(globalThis, 'fetch', async () => upstream(payload))
      const response = await dispatch()
      assert.equal(response.status, 502)
      assert.equal(response.headers.get('Set-Cookie'), null)
      assert.equal((await response.text()).includes('private'), false)
    })
  }
  for (const renewal of [null, cookie.replace(token, 'B'.repeat(43)), cookie + '; Domain=site.example', cookie.replace('; Secure', ''), cookie.replace('2030', '2020')]) {
    test(`${operation} rejects missing or invalid renewal ${renewal?.slice(-30)}`, async (t) => {
      t.mock.method(globalThis, 'fetch', async () => Response.json(metadata, { headers: renewal === null ? {} : { 'Set-Cookie': renewal } }))
      const response = await dispatch()
      assert.equal(response.status, 502)
      assert.equal(response.headers.get('Set-Cookie'), null)
    })
  }
  test(`${operation} clears only a backend-confirmed invalid session`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json({ detail: 'private' }, { status: 401, headers: { 'Set-Cookie': clear } }))
    const response = await dispatch()
    assert.equal(response.status, 401)
    assert.equal(response.headers.get('Set-Cookie'), clear)
    assert.equal((await response.text()).includes('private'), false)
  })
  for (const code of [302, 403, 503, 500]) {
    test(`${operation} handles backend ${code} without leaking cookies or details`, async (t) => {
      t.mock.method(globalThis, 'fetch', async () => new Response('private', { status: code, headers: { 'Set-Cookie': cookie, Location: 'https://private.example' } }))
      const response = await dispatch()
      assert.equal(response.status, [403, 503].includes(code) ? code : 502)
      assert.equal(response.headers.get('Set-Cookie'), null)
      assert.equal(response.headers.get('Location'), null)
      assert.equal((await response.text()).includes('private'), false)
    })
  }
  test(`${operation} times out even when upstream ignores cancellation`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    t.mock.method(globalThis, 'fetch', () => new Promise(() => {}))
    const pending = dispatch()
    for (let i = 0; i < 12; i++) await Promise.resolve()
    t.mock.timers.tick(20_000)
    const response = await pending
    assert.equal(response.status, 502)
    assert.equal(response.headers.get('Set-Cookie'), null)
  })
  if (operation === 'accept') for (const payload of [{ accepted: false, terms_version: version }, { accepted: 'true', terms_version: version },
    { accepted: true, terms_version: 'old' }, { accepted: true, terms_version: version, user_id: 'private' }]) {
    test(`accept refuses unchecked, outdated or client-owned input ${JSON.stringify(payload)}`, async (t) => {
      const mock = t.mock.method(globalThis, 'fetch', async () => upstream())
      assert.equal((await dispatch({ body: JSON.stringify(payload) })).status, 400)
      assert.equal(mock.mock.callCount(), 0)
    })
  }
}
