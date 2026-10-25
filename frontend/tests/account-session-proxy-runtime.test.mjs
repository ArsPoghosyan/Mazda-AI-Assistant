import assert from 'node:assert/strict'
import { before, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { Miniflare, createFetchMock } from 'miniflare'
import { build } from 'vite'

const site = 'https://site.example'
const endpoint = '/api/v1/account/session'
const backend = 'https://backend.example'
const token = 'A'.repeat(43)
const name = '__Host-askm6_account'
const metadata = {
  user_id: '563128d6-22fd-464f-a3bd-31018fdf1b3c',
  expires_at: '2030-01-01T12:00:00Z',
  absolute_expires_at: '2030-01-30T12:00:00Z',
}
const renewal = `${name}=${token}; expires=Tue, 01 Jan 2030 12:00:00 GMT; HttpOnly; Path=/; SameSite=lax; Secure`
const bindings = { API_ORIGIN: backend, AUTH_PUBLIC_ORIGIN: site, AUTH_SESSION_PROXY_ENABLED: 'true' }
let script

before(async () => {
  const entry = fileURLToPath(new URL('./fixtures/account-session-proxy-worker.mjs', import.meta.url))
  const bundle = await build({
    configFile: false, envFile: false, envDir: false, logLevel: 'silent',
    root: fileURLToPath(new URL('..', import.meta.url)),
    build: { write: false, minify: false, target: 'es2022', lib: { entry, formats: ['es'] } },
  })
  const chunks = (Array.isArray(bundle) ? bundle : [bundle]).flatMap((output) =>
    output.output.filter((item) => item.type === 'chunk'),
  )
  assert.equal(chunks.length, 1)
  script = chunks[0].code
}, { timeout: 30_000 })

async function runtime(t, overrides = {}) {
  const mock = createFetchMock()
  mock.disableNetConnect()
  const mf = new Miniflare({
    host: '127.0.0.1', port: 0, modules: true, script,
    cf: false, compatibilityDate: '2026-07-30',
    compatibilityFlags: ['enable_request_signal'],
    bindings: { ...bindings, ...overrides }, fetchMock: mock,
  })
  t.after(async () => { await mf.dispose(); await mock.close() })
  await mf.ready
  return { mf, mock }
}

function options(headers = {}) {
  return { method: 'POST', headers: { Origin: site, Cookie: `${name}=${token}`, ...headers } }
}

test('actual Workers runtime accepts session forwarding and secure renewal', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t)
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
  })
  const response = await mf.dispatchFetch(site + endpoint, options())
  assert.equal(response.status, 200, await response.clone().text())
  assert.deepEqual(await response.json(), metadata)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  assert.equal(response.headers.get('Set-Cookie'), `${name}=${token}; Expires=Tue, 01 Jan 2030 12:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax`)
  mock.assertNoPendingInterceptors()
})

test('Workers default-off routing never makes a backend request', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t, { AUTH_SESSION_PROXY_ENABLED: 'false' })
  const response = await mf.dispatchFetch(site + endpoint, options())
  assert.equal(response.status, 404)
  assert.equal(response.headers.get('Set-Cookie'), null)
})

test('Workers forwards only the account cookie, not other credentials or spoofed IPs', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t)
  mock.get(backend).intercept({ method: 'POST', path: endpoint, headers: (headers) => {
    const sent = new Headers(headers)
    assert.equal(sent.get('Cookie'), `${name}=${token}`)
    assert.equal(sent.get('Authorization'), null)
    assert.equal(sent.get('X-Forwarded-For'), null)
    assert.equal(sent.get('Origin'), site)
    return true
  } }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
  })
  const response = await mf.dispatchFetch(site + endpoint, options({
    Cookie: `guest=private; ${name}=${token}; askm6_account=private`,
    Authorization: 'Bearer private', 'X-Forwarded-For': '192.0.2.1',
  }))
  assert.equal(response.status, 200, await response.clone().text())
  await response.arrayBuffer()
  mock.assertNoPendingInterceptors()
})

test('Workers handles the backend clearing cookie through its native Headers API', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t)
  const deletion = `${name}=""; expires=Tue, 01 Jan 2030 12:00:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=lax; Secure`
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(401, '{"detail":"private"}', {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': deletion },
  })
  const response = await mf.dispatchFetch(site + endpoint, options({ Cookie: '' }))
  assert.equal(response.status, 401)
  assert.equal(response.headers.get('Set-Cookie'), `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`)
  assert.deepEqual(await response.json(), { detail: 'Invalid or expired account session.' })
  mock.assertNoPendingInterceptors()
})

test('Workers preserves separate cookies rather than splitting Expires commas', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t)
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': [renewal, 'guest=private'] },
  })
  const response = await mf.dispatchFetch(site + endpoint, options())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal((await response.text()).includes('private'), false)
  mock.assertNoPendingInterceptors()
})

test('Workers rejects foreign/preview origins, bodies and other authentication routes', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t)
  for (const [url, init, status] of [
    [site + endpoint, options({ Origin: 'https://other.example' }), 403],
    ['https://preview.example' + endpoint, options(), 403],
    [site + endpoint, { ...options(), body: '{"access_token":"private"}' }, 400],
    [site + '/api/v1/account/sign-in', options(), 404],
    [site + '/api/v1/account/google/callback', { method: 'GET' }, 404],
  ]) {
    const response = await mf.dispatchFetch(url, init)
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal((await response.text()).includes('private'), false)
  }
})

test('Workers manual redirect mode prevents credential forwarding to another host', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t)
  let redirected = false
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(302, 'private', {
    headers: { Location: 'https://redirect.example/collect', 'Set-Cookie': renewal },
  })
  mock.get('https://redirect.example').intercept({ path: '/collect' }).reply(() => {
    redirected = true
    return { statusCode: 200, data: JSON.stringify(metadata), responseOptions: {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
    } }
  })
  const response = await mf.dispatchFetch(site + endpoint, options())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Location'), null)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
  assert.equal(redirected, false)
})

test('Workers masks private/unexpected response data and keeps the browser cookie', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t)
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(200, JSON.stringify({
    ...metadata, access_token: 'private',
  }), { headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal } })
  const response = await mf.dispatchFetch(site + endpoint, options())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal((await response.text()).includes('private'), false)
  mock.assertNoPendingInterceptors()
})

test('Workers health forwarding stays available when account forwarding is disabled', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { AUTH_SESSION_PROXY_ENABLED: 'false' })
  mock.get(backend).intercept({ method: 'GET', path: '/api/v1/health', headers: (headers) => {
    assert.equal(new Headers(headers).get('Cookie'), null)
    return true
  } }).reply(200, '{"status":"ok"}', { headers: { 'Content-Type': 'application/json' } })
  const response = await mf.dispatchFetch(site + '/api/v1/health', { headers: { Cookie: 'private' } })
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { status: 'ok' })
  mock.assertNoPendingInterceptors()
})

test('an explicit Workers abort signal cancels the handler without issuing cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
  }).delay(300)
  const response = await mf.dispatchFetch(site + endpoint, options())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

test('the real Workers deadline stops a stalled upstream without cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t)
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
  }).delay(21_000)
  const start = performance.now()
  const response = await mf.dispatchFetch(site + endpoint, options())
  const elapsed = performance.now() - start
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  await response.arrayBuffer()
  assert.ok(elapsed >= 19_000 && elapsed < 26_000, `Deadline completed after ${elapsed}ms`)
})
