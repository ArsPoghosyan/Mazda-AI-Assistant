import assert from 'node:assert/strict'
import { before, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { Miniflare, createFetchMock, fetch as mockFetch } from 'miniflare'
import { build } from 'vite'
import { CURRENT_TERMS_VERSION } from '../shared/account-terms.ts'

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
    bindings: { ...bindings, ...overrides },
    // Miniflare's default fetchMock Node adapter follows redirects. Preserve
    // manual handling at this hop too, so workerd sees the actual 303/cookies.
    outboundService: (request) => mockFetch(request, { dispatcher: mock, redirect: 'manual' }),
  })
  t.after(async () => { await mf.dispose(); await mock.close() })
  await mf.ready
  return { mf, mock }
}

function options(headers = {}) {
  return { method: 'POST', headers: { Origin: site, Cookie: `${name}=${token}`, ...headers } }
}

for (const operation of ['status', 'accept']) {
  test(`Workers Terms ${operation} validates ingress, cookie renewal and explicit metadata`, { timeout: 30_000 }, async (t) => {
    const secret = 'ab'.repeat(32)
    const { mf, mock } = await runtime(t, { ACCOUNT_TERMS_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: secret })
    const path = `/api/v1/account/terms/${operation}`
    const body = operation === 'status' ? { terms_version: CURRENT_TERMS_VERSION, accepted_at: null, acceptance_required: true }
      : { terms_version: CURRENT_TERMS_VERSION, accepted_at: new Date(Date.now() - 1000).toISOString() }
    let deliveredHeaders, deliveredBody
    mock.get(backend).intercept({ method: 'POST', path }).reply(request => {
      deliveredHeaders = new Headers(request.headers)
      deliveredBody = request.body
      return { statusCode: 200, data: JSON.stringify(body), responseOptions: { headers: {
        'Content-Type': 'application/json', 'Set-Cookie': renewal, 'X-Private': 'private',
      } } }
    })
    const response = await mf.dispatchFetch(site + path, { ...options({ 'CF-Connecting-IP': '198.51.100.20', 'X-Account-Subject': metadata.user_id,
      ...(operation === 'accept' ? { 'Content-Type': 'application/json' } : {}) }),
      ...(operation === 'accept' ? { body: JSON.stringify({ accepted: true, terms_version: CURRENT_TERMS_VERSION }) } : {}) })
    assert.equal(response.status, 200, await response.clone().text())
    assert.deepEqual(await response.json(), body)
    assert.equal(deliveredHeaders.get('Cookie'), `${name}=${token}`)
    assert.equal(deliveredHeaders.get('X-AskM6-Proxy-Secret'), secret)
    assert.equal(deliveredHeaders.get('X-AskM6-Client-IP'), '198.51.100.20')
    assert.equal(deliveredHeaders.get('X-Account-Subject'), metadata.user_id)
    assert.equal(deliveredHeaders.get('Authorization'), null)
    if (operation === 'accept') assert.equal(await new Response(deliveredBody).text(), JSON.stringify({ accepted: true, terms_version: CURRENT_TERMS_VERSION }))
    assert.equal(response.headers.get('X-Private'), null)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    mock.assertNoPendingInterceptors()
  })
  test(`Workers Terms ${operation} remains default-off`, { timeout: 30_000 }, async t => {
    const { mf } = await runtime(t)
    const response = await mf.dispatchFetch(site + `/api/v1/account/terms/${operation}`, options())
    assert.equal(response.status, 404)
    assert.equal(response.headers.get('Set-Cookie'), null)
  })
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

test('Workers authenticates only the edge IP assertion and strips echoed proxy secrets', { timeout: 30_000 }, async (t) => {
  const secret = 'ab'.repeat(32)
  const { mf, mock } = await runtime(t, { AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: secret })
  mock.get(backend).intercept({ method: 'POST', path: endpoint, headers: (headers) => {
    const sent = new Headers(headers)
    assert.equal(sent.get('X-AskM6-Proxy-Secret'), secret)
    assert.equal(sent.get('X-AskM6-Client-IP'), '2001:db8::1')
    assert.equal(sent.get('CF-Connecting-IP'), null)
    assert.equal(sent.get('X-Forwarded-For'), null)
    return true
  } }).reply(200, JSON.stringify(metadata), { headers: {
    'Content-Type': 'application/json', 'Set-Cookie': renewal, 'X-AskM6-Proxy-Secret': secret,
  } })
  const response = await mf.dispatchFetch(site + endpoint, options({
    'CF-Connecting-IP': '2001:db8::1', 'X-AskM6-Client-IP': '203.0.113.99',
    'X-AskM6-Proxy-Secret': 'browser-forged', 'X-Forwarded-For': '203.0.113.99',
  }))
  assert.equal(response.status, 200, await response.clone().text())
  assert.equal(response.headers.get('X-AskM6-Proxy-Secret'), null)
  assert.equal((await response.text()).includes(secret), false)
  mock.assertNoPendingInterceptors()
})

test('Workers rejects missing or combined edge IPs without contacting the backend', { timeout: 30_000 }, async (t) => {
  for (const mode of ['missing', 'empty', undefined]) {
    const { mf } = await runtime(t, { AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32),
      ...(mode === undefined ? {} : { TEST_CLIENT_IP_MODE: mode }),
    })
    const headers = { 'CF-Connecting-IP': mode === undefined ? '198.51.100.20, 203.0.113.30' : '198.51.100.20' }
    const response = await mf.dispatchFetch(site + endpoint, options(headers))
    assert.equal(response.status, 503)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    await response.arrayBuffer()
  }
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

const guestPath = '/api/v1/guest/session'
const guestCookie = '__Host-askm6_guest'
const guestMetadata = { status: 'ok', expires_at: metadata.expires_at }
const guestSetCookie = renewal.replace(name, guestCookie)
const guestBindings = { GUEST_SESSION_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32) }

test('Workers creates and refreshes a guest using only its secure cookie and verified ingress assertion', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, guestBindings)
  for (const existing of [false, true]) {
    let inspectionError
    let deliveredBody
    mock.get(backend).intercept({ method: 'POST', path: guestPath, headers: (headers) => {
      const sent = new Headers(headers)
      try {
        assert.equal(sent.get('Cookie'), existing ? `${guestCookie}=${token}` : null)
        assert.equal(sent.get('X-AskM6-Proxy-Secret'), guestBindings.AUTH_PROXY_SHARED_SECRET)
        assert.equal(sent.get('X-AskM6-Client-IP'), '198.51.100.20')
        assert.equal(sent.get('Authorization'), null)
        assert.equal(sent.get('X-Forwarded-For'), null)
        assert.equal(sent.get('Origin'), site)
        assert.equal(sent.get('Content-Type'), existing ? null : 'application/json')
      } catch (error) { inspectionError = error }
      return true
    } }).reply((request) => {
      deliveredBody = request.body
      return { statusCode: 200, data: JSON.stringify(guestMetadata), responseOptions: {
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': guestSetCookie },
      } }
    })
    const response = await mf.dispatchFetch(site + guestPath, {
      method: 'POST', headers: { Origin: site, 'CF-Connecting-IP': '198.51.100.20',
        Cookie: `${name}=${token}; ${existing ? `${guestCookie}=${token}` : 'askm6_guest=private'}`,
        Authorization: 'Bearer private', 'X-Forwarded-For': '203.0.113.99',
        'X-AskM6-Proxy-Secret': 'forged', 'X-AskM6-Client-IP': '203.0.113.99',
        ...(existing ? {} : { 'Content-Type': 'application/json' }),
      }, ...(existing ? {} : { body: JSON.stringify({ turnstile_token: 'synthetic-proof' }) }),
    })
    if (inspectionError) throw inspectionError
    assert.equal(response.status, 200, await response.clone().text())
    assert.equal(await new Response(deliveredBody).text(), existing ? '' : JSON.stringify({ turnstile_token: 'synthetic-proof' }))
    assert.deepEqual(await response.json(), guestMetadata)
    assert.equal(response.headers.get('Set-Cookie'), `${guestCookie}=${token}; Expires=Tue, 01 Jan 2030 12:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax`)
    assert.equal(response.headers.get('X-AskM6-Proxy-Secret'), null)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers guest routing is independently gated and requires an ingress assertion', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t)
  const closed = await mf.dispatchFetch(site + guestPath, options())
  assert.equal(closed.status, 404)
  await closed.arrayBuffer()
  for (const mode of ['missing', 'empty']) {
    const absent = await runtime(t, { ...guestBindings, TEST_CLIENT_IP_MODE: mode })
    const response = await absent.mf.dispatchFetch(site + guestPath, options({ 'CF-Connecting-IP': '198.51.100.20' }))
    assert.equal(response.status, 503)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
  const enabled = await runtime(t, guestBindings)
  for (const [url, init, status] of [
    [site + guestPath, options({ Origin: 'https://foreign.example' }), 403],
    [site + guestPath, { ...options({ 'CF-Connecting-IP': '198.51.100.20', 'Content-Type': 'application/json' }), body: ' '.repeat(16385) }, 413],
    [site + guestPath, { ...options({ 'CF-Connecting-IP': '198.51.100.20', 'Content-Type': 'application/json' }), body: '{"user_id":"private"}' }, 400],
  ]) {
    const response = await enabled.mf.dispatchFetch(url, init)
    assert.equal(response.status, status, await response.clone().text())
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
})

test('Workers guest errors preserve only CAPTCHA and bounded retry signals', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, guestBindings)
  for (const [status, headers] of [[403, { 'X-Guest-Verification': 'required' }], [429, { 'Retry-After': '37' }]]) {
    mock.get(backend).intercept({ method: 'POST', path: guestPath }).reply(status, 'private provider detail', {
      headers: { ...headers, 'Set-Cookie': guestSetCookie, Location: 'https://private.example' },
    })
    const response = await mf.dispatchFetch(site + guestPath, options({ 'CF-Connecting-IP': '198.51.100.20' }))
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal(response.headers.get('X-Guest-Verification'), status === 403 ? 'required' : null)
    assert.equal(response.headers.get('Retry-After'), status === 429 ? '37' : null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers rejects guest responses that set another identity cookie or multiple cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, guestBindings)
  for (const cookies of [renewal, [guestSetCookie, renewal]]) {
    mock.get(backend).intercept({ method: 'POST', path: guestPath }).reply(200, JSON.stringify(guestMetadata), {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookies },
    })
    const response = await mf.dispatchFetch(site + guestPath, options({ 'CF-Connecting-IP': '198.51.100.20' }))
    assert.equal(response.status, 502)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers guest abort cannot issue a late guest cookie', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...guestBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: guestPath }).reply(200, JSON.stringify(guestMetadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': guestSetCookie },
  }).delay(300)
  const response = await mf.dispatchFetch(site + guestPath, options({ 'CF-Connecting-IP': '198.51.100.20' }))
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

const signInPath = '/api/v1/account/sign-in'
const signInCredentials = { email: ' Owner@Example.test ', password: '  synthetic-password-é  ', captcha_token: 'synthetic-proof' }
const signInBindings = { ...guestBindings, ACCOUNT_SIGN_IN_PROXY_ENABLED: 'true' }
function signInOptions(headers = {}) {
  return { method: 'POST', body: JSON.stringify(signInCredentials), headers: {
    Origin: site, 'CF-Connecting-IP': '198.51.100.20', 'Content-Type': 'application/json', ...headers,
  } }
}

test('Workers email sign-in preserves credentials and accepts only a new secure account cookie', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signInBindings)
  let deliveredHeaders, deliveredBody
  mock.get(backend).intercept({ method: 'POST', path: signInPath }).reply((request) => {
    deliveredHeaders = new Headers(request.headers)
    deliveredBody = request.body
    return { statusCode: 200, data: JSON.stringify(metadata), responseOptions: { headers: {
      'Content-Type': 'application/json', 'Set-Cookie': renewal, 'X-AskM6-Proxy-Secret': signInBindings.AUTH_PROXY_SHARED_SECRET,
    } } }
  })
  const response = await mf.dispatchFetch(site + signInPath, signInOptions({
    Cookie: `${guestCookie}=${token}; askm6_account=private; __Host-askm6_google=private`,
    Authorization: 'Bearer private', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
  }))
  assert.equal(response.status, 200, await response.clone().text())
  assert.deepEqual(await response.json(), metadata)
  assert.equal(deliveredHeaders.get('Origin'), site)
  assert.equal(deliveredHeaders.get('X-AskM6-Proxy-Secret'), signInBindings.AUTH_PROXY_SHARED_SECRET)
  assert.equal(deliveredHeaders.get('X-AskM6-Client-IP'), '198.51.100.20')
  for (const header of ['Cookie', 'Authorization', 'CF-Connecting-IP', 'X-Forwarded-For', 'Transfer-Encoding']) {
    assert.equal(deliveredHeaders.get(header), null)
  }
  assert.equal(await new Response(deliveredBody).text(), JSON.stringify(signInCredentials))
  assert.equal(response.headers.get('Set-Cookie'), `${name}=${token}; Expires=Tue, 01 Jan 2030 12:00:00 GMT; Path=/; Secure; HttpOnly; SameSite=Lax`)
  assert.equal(response.headers.get('X-AskM6-Proxy-Secret'), null)
  mock.assertNoPendingInterceptors()
})

test('Workers email sign-in is independently gated and requires trusted ingress', { timeout: 30_000 }, async (t) => {
  const closed = await runtime(t, guestBindings)
  const response = await closed.mf.dispatchFetch(site + signInPath, signInOptions())
  assert.equal(response.status, 404)
  await response.arrayBuffer()
  for (const mode of ['missing', 'empty']) {
    const absent = await runtime(t, { ...signInBindings, TEST_CLIENT_IP_MODE: mode })
    const result = await absent.mf.dispatchFetch(site + signInPath, signInOptions())
    assert.equal(result.status, 503)
    assert.equal(result.headers.get('Set-Cookie'), null)
    await result.arrayBuffer()
  }
  const enabled = await runtime(t, signInBindings)
  for (const [url, init, status] of [
    [site + signInPath, signInOptions({ Origin: 'https://foreign.example' }), 403],
    ['https://preview.example' + signInPath, signInOptions(), 403],
    [site + signInPath, { ...signInOptions(), body: ' '.repeat(16385) }, 413],
    [site + signInPath, { ...signInOptions(), body: '{"email":"x","password":"x","user_id":"private"}' }, 400],
  ]) {
    const result = await enabled.mf.dispatchFetch(url, init)
    assert.equal(result.status, status, await result.clone().text())
    assert.equal(result.headers.get('Set-Cookie'), null)
    await result.arrayBuffer()
  }
})

test('Workers email sign-in requires explicit sign-out for valid, malformed and empty account cookies', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t, signInBindings)
  for (const value of [token, 'malformed', '', '""']) {
    const response = await mf.dispatchFetch(site + signInPath, signInOptions({ Cookie: `${name}=${value}` }))
    assert.equal(response.status, 409)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
})

test('Workers email errors preserve rejection, conflict, CAPTCHA and bounded retry signals without cookie changes', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signInBindings)
  for (const [status, headers] of [[401, {}], [409, {}], [403, { 'X-Account-Verification': 'required' }], [429, { 'Retry-After': '37' }]]) {
    mock.get(backend).intercept({ method: 'POST', path: signInPath }).reply(status, 'private provider detail', {
      headers: { ...headers, 'Set-Cookie': renewal, Location: 'https://private.example' },
    })
    const response = await mf.dispatchFetch(site + signInPath, signInOptions())
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal(response.headers.get('X-Account-Verification'), status === 403 ? 'required' : null)
    assert.equal(response.headers.get('Retry-After'), status === 429 ? '37' : null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers email sign-in rejects guest and multiple upstream cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signInBindings)
  for (const cookies of [guestSetCookie, [renewal, guestSetCookie]]) {
    mock.get(backend).intercept({ method: 'POST', path: signInPath }).reply(200, JSON.stringify(metadata), {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookies },
    })
    const response = await mf.dispatchFetch(site + signInPath, signInOptions())
    assert.equal(response.status, 502)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers email sign-in abort cannot issue a late account cookie', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...signInBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: signInPath }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
  }).delay(300)
  const response = await mf.dispatchFetch(site + signInPath, signInOptions())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

const signOutPath = '/api/v1/account/sign-out'
const signOutBindings = { ACCOUNT_SIGN_OUT_PROXY_ENABLED: 'true' }
const clearingCookie = `${name}=""; expires=Thu, 01 Jan 2026 00:00:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=lax; Secure`
const canonicalClear = `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`

test('Workers sign-out forwards only the account cookie and returns confirmed clearing with no body', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signOutBindings)
  let sent
  mock.get(backend).intercept({ method: 'POST', path: signOutPath }).reply((request) => {
    sent = new Headers(request.headers)
    return { statusCode: 204, data: '', responseOptions: { headers: { 'Set-Cookie': clearingCookie } } }
  })
  const response = await mf.dispatchFetch(site + signOutPath, options({
    Cookie: `${name}=${token}; ${guestCookie}=private; __Host-askm6_google=private; askm6_account=private`,
    Authorization: 'Bearer private', 'X-AskM6-Proxy-Secret': 'forged', 'X-AskM6-Client-IP': '203.0.113.99',
  }))
  assert.equal(response.status, 204, await response.clone().text())
  assert.equal(sent.get('Cookie'), `${name}=${token}`)
  assert.equal(sent.get('Origin'), site)
  for (const header of ['Authorization', 'X-AskM6-Proxy-Secret', 'X-AskM6-Client-IP', 'X-Forwarded-For']) assert.equal(sent.get(header), null)
  assert.equal(response.headers.get('Set-Cookie'), canonicalClear)
  assert.equal(response.headers.get('Content-Type'), null)
  assert.equal(await response.text(), '')
  mock.assertNoPendingInterceptors()
})

test('Workers sign-out omits missing/malformed credentials and still requires backend clearing confirmation', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signOutBindings)
  for (const header of [`${guestCookie}=private`, `${name}=malformed`, `${name}=""`]) {
    let sent
    mock.get(backend).intercept({ method: 'POST', path: signOutPath }).reply((request) => {
      sent = new Headers(request.headers)
      return { statusCode: 204, data: '', responseOptions: { headers: { 'Set-Cookie': clearingCookie } } }
    })
    const response = await mf.dispatchFetch(site + signOutPath, options({ Cookie: header }))
    assert.equal(response.status, 204, await response.clone().text())
    assert.equal(sent.get('Cookie'), null)
    assert.equal(response.headers.get('Set-Cookie'), canonicalClear)
    await response.arrayBuffer()
    mock.assertNoPendingInterceptors()
  }
})

test('Workers sign-out is independently gated and rejects invalid origins, bodies and ambiguous cookies', { timeout: 30_000 }, async (t) => {
  const closed = await runtime(t)
  const response = await closed.mf.dispatchFetch(site + signOutPath, options())
  assert.equal(response.status, 404)
  await response.arrayBuffer()
  const { mf } = await runtime(t, signOutBindings)
  for (const [url, init, status] of [
    [site + signOutPath, options({ Origin: 'https://foreign.example' }), 403],
    ['https://preview.example' + signOutPath, options(), 403],
    [site + signOutPath, { ...options(), body: '{}' }, 400],
    [site + signOutPath, options({ Cookie: `${name}=${token}; ${name}=${token}` }), 400],
  ]) {
    const result = await mf.dispatchFetch(url, init)
    assert.equal(result.status, status)
    assert.equal(result.headers.get('Set-Cookie'), null)
    await result.arrayBuffer()
  }
})

test('Workers sign-out errors and unsafe clearing cookies preserve all browser cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signOutBindings)
  for (const [status, cookie, expected] of [[403, clearingCookie, 403], [503, clearingCookie, 503], [302, clearingCookie, 502],
    [204, clearingCookie.replace(name, guestCookie), 502], [204, [clearingCookie, guestSetCookie], 502]]) {
    mock.get(backend).intercept({ method: 'POST', path: signOutPath }).reply(status, status === 204 ? '' : 'private', {
      headers: { 'Set-Cookie': cookie, Location: 'https://private.example' },
    })
    const response = await mf.dispatchFetch(site + signOutPath, options())
    assert.equal(response.status, expected)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers sign-out abort cannot return a late clearing cookie', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...signOutBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: signOutPath }).reply(204, '', {
    headers: { 'Set-Cookie': clearingCookie },
  }).delay(300)
  const response = await mf.dispatchFetch(site + signOutPath, options())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

test('Workers supports a complete mocked sign-in, session-check and sign-out cycle', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...signInBindings, ...signOutBindings })
  mock.get(backend).intercept({ method: 'POST', path: signInPath }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
  })
  const login = await mf.dispatchFetch(site + signInPath, signInOptions())
  assert.equal(login.status, 200, await login.clone().text())
  const accountCookie = login.headers.get('Set-Cookie').split(';', 1)[0]
  await login.arrayBuffer()
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
  })
  const session = await mf.dispatchFetch(site + endpoint, options({ Cookie: accountCookie, 'CF-Connecting-IP': '198.51.100.20' }))
  assert.equal(session.status, 200, await session.clone().text())
  assert.deepEqual(await session.json(), metadata)
  mock.get(backend).intercept({ method: 'POST', path: signOutPath }).reply(204, '', { headers: { 'Set-Cookie': clearingCookie } })
  const logout = await mf.dispatchFetch(site + signOutPath, options({ Cookie: `${accountCookie}; ${guestCookie}=private`, 'CF-Connecting-IP': '198.51.100.20' }))
  assert.equal(logout.status, 204, await logout.clone().text())
  assert.equal(logout.headers.get('Set-Cookie'), canonicalClear)
  assert.equal(await logout.text(), '')
  mock.assertNoPendingInterceptors()
})

const signUpPath = '/api/v1/account/sign-up'
function signUpOptions(...args) { const options = signInOptions(...args); return { ...options, body: JSON.stringify({ ...JSON.parse(options.body), accepted: true, terms_version: CURRENT_TERMS_VERSION }) } }
const signupReceiptCookie = () => `__Host-askm6_signup_terms=${'A'.repeat(120)}; Max-Age=3000; Expires=${new Date(Date.now() + 3_000_000).toUTCString()}; Path=/; Secure; HttpOnly; SameSite=Lax`
const registrationAccepted = { status: 'accepted', message: 'If registration can proceed, check your email for a verification code.' }
const signUpBindings = { ACCOUNT_SIGN_UP_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32) }

test('Workers sign-up forwards exact credentials and returns generic acceptance with only the temporary agreement receipt', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signUpBindings)
  let sent, deliveredBody
  mock.get(backend).intercept({ method: 'POST', path: signUpPath }).reply((request) => {
    sent = new Headers(request.headers)
    deliveredBody = request.body
    return { statusCode: 202, data: JSON.stringify(registrationAccepted), responseOptions: {
      headers: { 'Content-Type': 'application/json', 'X-AskM6-Proxy-Secret': signUpBindings.AUTH_PROXY_SHARED_SECRET, 'Set-Cookie': signupReceiptCookie() },
    } }
  })
  const response = await mf.dispatchFetch(site + signUpPath, signUpOptions({
    Cookie: `${name}=${token}; ${guestCookie}=private; __Host-askm6_google=private`,
    Authorization: 'Bearer private', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
  }))
  assert.equal(response.status, 202, await response.clone().text())
  assert.deepEqual(await response.json(), registrationAccepted)
  assert.equal(await new Response(deliveredBody).text(), JSON.stringify({ ...signInCredentials, accepted: true, terms_version: CURRENT_TERMS_VERSION }))
  assert.equal(sent.get('Origin'), site)
  assert.equal(sent.get('X-AskM6-Proxy-Secret'), signUpBindings.AUTH_PROXY_SHARED_SECRET)
  assert.equal(sent.get('X-AskM6-Client-IP'), '198.51.100.20')
  for (const header of ['Cookie', 'Authorization', 'X-Forwarded-For', 'CF-Connecting-IP']) assert.equal(sent.get(header), null)
  assert.match(response.headers.get('Set-Cookie'), /^__Host-askm6_signup_terms=/)
  assert.equal(response.headers.get('X-AskM6-Proxy-Secret'), null)
  mock.assertNoPendingInterceptors()
})

test('Workers sign-up is independently gated and rejects explicitly missing/empty edge IPs', { timeout: 30_000 }, async (t) => {
  const closed = await runtime(t)
  const response = await closed.mf.dispatchFetch(site + signUpPath, signUpOptions())
  assert.equal(response.status, 404)
  await response.arrayBuffer()
  for (const mode of ['missing', 'empty']) {
    const { mf } = await runtime(t, { ...signUpBindings, TEST_CLIENT_IP_MODE: mode })
    const result = await mf.dispatchFetch(site + signUpPath, signUpOptions())
    assert.equal(result.status, 503)
    assert.equal(result.headers.get('Set-Cookie'), null)
    await result.arrayBuffer()
  }
})

test('Workers sign-up rejects wrong origins and invalid/oversized registration input before fetching', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t, signUpBindings)
  for (const [url, init, status] of [
    [site + signUpPath, signUpOptions({ Origin: 'https://foreign.example' }), 403],
    ['https://preview.example' + signUpPath, signUpOptions(), 403],
    [site + signUpPath, { ...signUpOptions(), body: '{"email":"x","password":"x"}' }, 400],
    [site + signUpPath, { ...signUpOptions(), body: '{"email":"x","password":"x","captcha_token":null}' }, 400],
    [site + signUpPath, { ...signUpOptions(), body: ' '.repeat(16385) }, 413],
  ]) {
    const response = await mf.dispatchFetch(url, init)
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
})

test('Workers sign-up errors preserve only CAPTCHA/retry signals and mask provider details', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signUpBindings)
  for (const [status, headers] of [[400, {}], [403, { 'X-Account-Verification': 'required' }], [429, { 'Retry-After': '37' }], [503, {}]]) {
    mock.get(backend).intercept({ method: 'POST', path: signUpPath }).reply(status, 'private account information', {
      headers: { ...headers, 'Set-Cookie': clearingCookie, Location: 'https://private.example' },
    })
    const response = await mf.dispatchFetch(site + signUpPath, signUpOptions())
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal(response.headers.get('X-Account-Verification'), status === 403 ? 'required' : null)
    assert.equal(response.headers.get('Retry-After'), status === 429 ? '37' : null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers sign-up rejects unexpected success identity fields and unexpected success cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, signUpBindings)
  // Empty Set-Cookie fields may be discarded by the HTTP mock before the worker;
  // Node transport tests separately validate rejection when that field is exposed.
  for (const [body, headers] of [[{ ...registrationAccepted, user_id: 'private' }, {}],
    [registrationAccepted, { 'Set-Cookie': renewal }],
    [registrationAccepted, { 'Set-Cookie': [renewal, guestSetCookie] }]]) {
    mock.get(backend).intercept({ method: 'POST', path: signUpPath }).reply(202, JSON.stringify(body), {
      headers: { 'Content-Type': 'application/json', ...headers },
    })
    const response = await mf.dispatchFetch(site + signUpPath, signUpOptions())
    assert.equal(response.status, 502, JSON.stringify(headers))
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers sign-up abort never returns a late acceptance', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...signUpBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: signUpPath }).reply(202, JSON.stringify(registrationAccepted), {
    headers: { 'Content-Type': 'application/json' },
  }).delay(300)
  const response = await mf.dispatchFetch(site + signUpPath, signUpOptions())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

const confirmationPath = '/api/v1/account/confirm-email'
const confirmationCredentials = { email: ' Owner@Example.test ', code: '001234' }
const emailConfirmed = { status: 'confirmed', message: 'Email confirmed. You can now sign in.' }
const confirmationBindings = { ACCOUNT_EMAIL_CONFIRMATION_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32) }

function confirmationOptions(headers = {}) {
  return { ...signInOptions(headers), body: JSON.stringify(confirmationCredentials) }
}

test('Workers email confirmation preserves email and leading-zero code without signing in or changing cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, confirmationBindings)
  let sent, deliveredBody
  mock.get(backend).intercept({ method: 'POST', path: confirmationPath }).reply((request) => {
    sent = new Headers(request.headers)
    deliveredBody = request.body
    return { statusCode: 200, data: JSON.stringify(emailConfirmed), responseOptions: {
      headers: { 'Content-Type': 'application/json', 'X-AskM6-Proxy-Secret': confirmationBindings.AUTH_PROXY_SHARED_SECRET },
    } }
  })
  const response = await mf.dispatchFetch(site + confirmationPath, confirmationOptions({
    Cookie: `${name}=${token}; ${guestCookie}=private; __Host-askm6_google=private`,
    Authorization: 'Bearer private', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
  }))
  assert.equal(response.status, 200, await response.clone().text())
  assert.deepEqual(await response.json(), emailConfirmed)
  assert.equal(await new Response(deliveredBody).text(), JSON.stringify(confirmationCredentials))
  assert.equal(sent.get('Origin'), site)
  assert.equal(sent.get('X-AskM6-Proxy-Secret'), confirmationBindings.AUTH_PROXY_SHARED_SECRET)
  assert.equal(sent.get('X-AskM6-Client-IP'), '198.51.100.20')
  for (const header of ['Cookie', 'Authorization', 'X-Forwarded-For', 'CF-Connecting-IP']) assert.equal(sent.get(header), null)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal(response.headers.get('X-AskM6-Proxy-Secret'), null)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  mock.assertNoPendingInterceptors()
})

test('Workers email confirmation is independently gated and requires trusted ingress', { timeout: 30_000 }, async (t) => {
  const closed = await runtime(t, signUpBindings)
  const response = await closed.mf.dispatchFetch(site + confirmationPath, confirmationOptions())
  assert.equal(response.status, 404)
  await response.arrayBuffer()
  for (const overrides of [{ TEST_CLIENT_IP_MODE: 'missing' }, { TEST_CLIENT_IP_MODE: 'empty' },
    { AUTH_PROXY_TRUST_ENABLED: 'false' }, { AUTH_PROXY_SHARED_SECRET: '' }]) {
    const { mf } = await runtime(t, { ...confirmationBindings, ...overrides })
    const result = await mf.dispatchFetch(site + confirmationPath, confirmationOptions())
    assert.equal(result.status, 503)
    assert.equal(result.headers.get('Set-Cookie'), null)
    await result.arrayBuffer()
  }
})

test('Workers email confirmation rejects wrong origins, invalid codes and actual oversized input before fetching', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t, confirmationBindings)
  for (const [url, init, status] of [
    [site + confirmationPath, confirmationOptions({ Origin: 'https://foreign.example' }), 403],
    ['https://preview.example' + confirmationPath, confirmationOptions(), 403],
    [site + confirmationPath, { ...confirmationOptions(), body: '{"email":"x","code":123456}' }, 400],
    [site + confirmationPath, { ...confirmationOptions(), body: '{"email":"x","code":"123456\\n"}' }, 400],
    [site + confirmationPath, { ...confirmationOptions(), body: ' '.repeat(4097) }, 413],
    [site + confirmationPath, confirmationOptions({ 'CF-Connecting-IP': '198.51.100.20, 203.0.113.99' }), 503],
  ]) {
    const response = await mf.dispatchFetch(url, init)
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
})

test('Workers email confirmation masks provider errors, drops unrelated verification headers and preserves bounded retry seconds', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, confirmationBindings)
  for (const [status, headers] of [[400, {}], [403, { 'X-Account-Verification': 'required' }],
    [429, { 'Retry-After': '37' }], [429, { 'Retry-After': '86401' }], [503, {}]]) {
    mock.get(backend).intercept({ method: 'POST', path: confirmationPath }).reply(status, 'private account information', {
      headers: { ...headers, 'Set-Cookie': clearingCookie, Location: 'https://private.example' },
    })
    const response = await mf.dispatchFetch(site + confirmationPath, confirmationOptions())
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal(response.headers.get('X-Account-Verification'), null)
    assert.equal(response.headers.get('Retry-After'), headers['Retry-After'] === '37' ? '37' : null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers email confirmation rejects token-bearing success, cookies, redirects and wrong success status', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, confirmationBindings)
  for (const [status, body, headers] of [[200, { ...emailConfirmed, access_token: 'private' }, {}],
    [200, emailConfirmed, { 'Set-Cookie': renewal }], [200, emailConfirmed, { 'Set-Cookie': [renewal, guestSetCookie] }],
    [202, emailConfirmed, {}], [302, emailConfirmed, { Location: 'https://private.example' }]]) {
    mock.get(backend).intercept({ method: 'POST', path: confirmationPath }).reply(status, JSON.stringify(body), {
      headers: { 'Content-Type': 'application/json', ...headers },
    })
    const response = await mf.dispatchFetch(site + confirmationPath, confirmationOptions())
    assert.equal(response.status, 502)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers email confirmation abort never returns a late success', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...confirmationBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: confirmationPath }).reply(200, JSON.stringify(emailConfirmed), {
    headers: { 'Content-Type': 'application/json' },
  }).delay(300)
  const response = await mf.dispatchFetch(site + confirmationPath, confirmationOptions())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

const recoveryCredentials = { email: ' Owner@Example.test ', captcha_token: 'synthetic-proof' }
function recoveryOptions(headers = {}) {
  return { ...signInOptions(headers), body: JSON.stringify(recoveryCredentials) }
}

const recoveryPath = '/api/v1/account/password-recovery'
const recoveryAccepted = { status: 'accepted', message: 'If password recovery can proceed, check your email for the next steps.' }
const recoveryBindings = { ACCOUNT_PASSWORD_RECOVERY_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32) }

test('Workers password-recovery forwards exact credentials and returns generic acceptance without any browser cookie changes', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, recoveryBindings)
  let sent, deliveredBody
  mock.get(backend).intercept({ method: 'POST', path: recoveryPath }).reply((request) => {
    sent = new Headers(request.headers)
    deliveredBody = request.body
    return { statusCode: 202, data: JSON.stringify(recoveryAccepted), responseOptions: {
      headers: { 'Content-Type': 'application/json', 'X-AskM6-Proxy-Secret': recoveryBindings.AUTH_PROXY_SHARED_SECRET },
    } }
  })
  const response = await mf.dispatchFetch(site + recoveryPath, recoveryOptions({
    Cookie: `${name}=${token}; ${guestCookie}=private; __Host-askm6_google=private`,
    Authorization: 'Bearer private', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
  }))
  assert.equal(response.status, 202, await response.clone().text())
  assert.deepEqual(await response.json(), recoveryAccepted)
  assert.equal(await new Response(deliveredBody).text(), JSON.stringify(recoveryCredentials))
  assert.equal(sent.get('Origin'), site)
  assert.equal(sent.get('X-AskM6-Proxy-Secret'), recoveryBindings.AUTH_PROXY_SHARED_SECRET)
  assert.equal(sent.get('X-AskM6-Client-IP'), '198.51.100.20')
  for (const header of ['Cookie', 'Authorization', 'X-Forwarded-For', 'CF-Connecting-IP']) assert.equal(sent.get(header), null)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal(response.headers.get('X-AskM6-Proxy-Secret'), null)
  mock.assertNoPendingInterceptors()
})

test('Workers password-recovery is independently gated and rejects explicitly missing/empty edge IPs', { timeout: 30_000 }, async (t) => {
  const closed = await runtime(t, { ...signUpBindings, ...confirmationBindings })
  const response = await closed.mf.dispatchFetch(site + recoveryPath, recoveryOptions())
  assert.equal(response.status, 404)
  await response.arrayBuffer()
  for (const mode of ['missing', 'empty']) {
    const { mf } = await runtime(t, { ...recoveryBindings, TEST_CLIENT_IP_MODE: mode })
    const result = await mf.dispatchFetch(site + recoveryPath, recoveryOptions())
    assert.equal(result.status, 503)
    assert.equal(result.headers.get('Set-Cookie'), null)
    await result.arrayBuffer()
  }
})

test('Workers password-recovery rejects wrong origins and invalid/oversized recovery input before fetching', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t, recoveryBindings)
  for (const [url, init, status] of [
    [site + recoveryPath, recoveryOptions({ Origin: 'https://foreign.example' }), 403],
    ['https://preview.example' + recoveryPath, recoveryOptions(), 403],
    [site + recoveryPath, { ...recoveryOptions(), body: '{"email":"x"}' }, 400],
    [site + recoveryPath, { ...recoveryOptions(), body: '{"email":"x","captcha_token":null}' }, 400],
    [site + recoveryPath, { ...recoveryOptions(), body: ' '.repeat(16385) }, 413],
  ]) {
    const response = await mf.dispatchFetch(url, init)
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
})

test('Workers password-recovery errors preserve only CAPTCHA/retry signals and mask provider details', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, recoveryBindings)
  for (const [status, headers] of [[400, {}], [403, { 'X-Account-Verification': 'required' }], [429, { 'Retry-After': '37' }], [503, {}]]) {
    mock.get(backend).intercept({ method: 'POST', path: recoveryPath }).reply(status, 'private account information', {
      headers: { ...headers, 'Set-Cookie': clearingCookie, Location: 'https://private.example' },
    })
    const response = await mf.dispatchFetch(site + recoveryPath, recoveryOptions())
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal(response.headers.get('X-Account-Verification'), status === 403 ? 'required' : null)
    assert.equal(response.headers.get('Retry-After'), status === 429 ? '37' : null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers password-recovery rejects unexpected success identity fields and any success cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, recoveryBindings)
  // Empty Set-Cookie fields may be discarded by the HTTP mock before the worker;
  // Node transport tests separately validate rejection when that field is exposed.
  for (const [body, headers] of [[{ ...recoveryAccepted, user_id: 'private' }, {}],
    [recoveryAccepted, { 'Set-Cookie': renewal }],
    [recoveryAccepted, { 'Set-Cookie': [renewal, guestSetCookie] }]]) {
    mock.get(backend).intercept({ method: 'POST', path: recoveryPath }).reply(202, JSON.stringify(body), {
      headers: { 'Content-Type': 'application/json', ...headers },
    })
    const response = await mf.dispatchFetch(site + recoveryPath, recoveryOptions())
    assert.equal(response.status, 502, JSON.stringify(headers))
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers password-recovery abort never returns a late acceptance', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...recoveryBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: recoveryPath }).reply(202, JSON.stringify(recoveryAccepted), {
    headers: { 'Content-Type': 'application/json' },
  }).delay(300)
  const response = await mf.dispatchFetch(site + recoveryPath, recoveryOptions())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

const resetPath = '/api/v1/account/password-reset'
const resetCredentials = { email: ' Owner@Example.test ', code: '001234', new_password: '  synthetic-new-password-é  ' }
const passwordCompleted = { status: 'completed', message: 'Password reset completed. Sign in with your new password.' }
const resetBindings = { ACCOUNT_PASSWORD_RESET_PROXY_ENABLED: 'true', AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32) }

function resetOptions(headers = {}) {
  return { ...signInOptions(headers), body: JSON.stringify(resetCredentials) }
}

test('Workers password reset preserves email and leading-zero code without signing in or changing cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, resetBindings)
  let sent, deliveredBody
  mock.get(backend).intercept({ method: 'POST', path: resetPath }).reply((request) => {
    sent = new Headers(request.headers)
    deliveredBody = request.body
    return { statusCode: 200, data: JSON.stringify(passwordCompleted), responseOptions: {
      headers: { 'Content-Type': 'application/json', 'X-AskM6-Proxy-Secret': resetBindings.AUTH_PROXY_SHARED_SECRET },
    } }
  })
  const response = await mf.dispatchFetch(site + resetPath, resetOptions({
    Cookie: `${name}=${token}; ${guestCookie}=private; __Host-askm6_google=private`,
    Authorization: 'Bearer private', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
  }))
  assert.equal(response.status, 200, await response.clone().text())
  assert.deepEqual(await response.json(), passwordCompleted)
  assert.equal(await new Response(deliveredBody).text(), JSON.stringify(resetCredentials))
  assert.equal(sent.get('Origin'), site)
  assert.equal(sent.get('X-AskM6-Proxy-Secret'), resetBindings.AUTH_PROXY_SHARED_SECRET)
  assert.equal(sent.get('X-AskM6-Client-IP'), '198.51.100.20')
  for (const header of ['Cookie', 'Authorization', 'X-Forwarded-For', 'CF-Connecting-IP']) assert.equal(sent.get(header), null)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal(response.headers.get('X-AskM6-Proxy-Secret'), null)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  mock.assertNoPendingInterceptors()
})

test('Workers password reset is independently gated and requires trusted ingress', { timeout: 30_000 }, async (t) => {
  const closed = await runtime(t, { ...signUpBindings, ...confirmationBindings, ...recoveryBindings })
  const response = await closed.mf.dispatchFetch(site + resetPath, resetOptions())
  assert.equal(response.status, 404)
  await response.arrayBuffer()
  for (const overrides of [{ TEST_CLIENT_IP_MODE: 'missing' }, { TEST_CLIENT_IP_MODE: 'empty' },
    { AUTH_PROXY_TRUST_ENABLED: 'false' }, { AUTH_PROXY_SHARED_SECRET: '' }]) {
    const { mf } = await runtime(t, { ...resetBindings, ...overrides })
    const result = await mf.dispatchFetch(site + resetPath, resetOptions())
    assert.equal(result.status, 503)
    assert.equal(result.headers.get('Set-Cookie'), null)
    await result.arrayBuffer()
  }
})

test('Workers password reset rejects wrong origins, invalid codes and actual oversized input before fetching', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t, resetBindings)
  for (const [url, init, status] of [
    [site + resetPath, resetOptions({ Origin: 'https://foreign.example' }), 403],
    ['https://preview.example' + resetPath, resetOptions(), 403],
    [site + resetPath, { ...resetOptions(), body: JSON.stringify({ ...resetCredentials, code: 123456 }) }, 400],
    [site + resetPath, { ...resetOptions(), body: JSON.stringify({ ...resetCredentials, code: '123456\n' }) }, 400],
    [site + resetPath, { ...resetOptions(), body: ' '.repeat(16385) }, 413],
    [site + resetPath, { ...resetOptions(), body: JSON.stringify({ email: 'x', code: '001234' }) }, 400],
    [site + resetPath, { ...resetOptions(), body: JSON.stringify({ ...resetCredentials, new_password: '' }) }, 400],
    [site + resetPath, resetOptions({ 'CF-Connecting-IP': '198.51.100.20, 203.0.113.99' }), 503],
  ]) {
    const response = await mf.dispatchFetch(url, init)
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
})

test('Workers password reset masks provider errors, drops unrelated verification headers and preserves bounded retry seconds', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, resetBindings)
  for (const [status, headers] of [[400, {}], [403, { 'X-Account-Verification': 'required' }],
    [429, { 'Retry-After': '37' }], [429, { 'Retry-After': '86401' }], [503, {}]]) {
    mock.get(backend).intercept({ method: 'POST', path: resetPath }).reply(status, 'private account information', {
      headers: { ...headers, 'Set-Cookie': clearingCookie, Location: 'https://private.example' },
    })
    const response = await mf.dispatchFetch(site + resetPath, resetOptions())
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal(response.headers.get('X-Account-Verification'), null)
    assert.equal(response.headers.get('Retry-After'), headers['Retry-After'] === '37' ? '37' : null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers password reset rejects token-bearing success, cookies, redirects and wrong success status', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, resetBindings)
  for (const [status, body, headers] of [[200, { ...passwordCompleted, access_token: 'private' }, {}],
    [200, passwordCompleted, { 'Set-Cookie': renewal }], [200, passwordCompleted, { 'Set-Cookie': [renewal, guestSetCookie] }],
    [202, passwordCompleted, {}], [302, passwordCompleted, { Location: 'https://private.example' }]]) {
    mock.get(backend).intercept({ method: 'POST', path: resetPath }).reply(status, JSON.stringify(body), {
      headers: { 'Content-Type': 'application/json', ...headers },
    })
    const response = await mf.dispatchFetch(site + resetPath, resetOptions())
    assert.equal(response.status, 502)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers password reset abort never returns a late success', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...resetBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: resetPath }).reply(200, JSON.stringify(passwordCompleted), {
    headers: { 'Content-Type': 'application/json' },
  }).delay(300)
  const response = await mf.dispatchFetch(site + resetPath, resetOptions())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

test('Workers password reset leaves cookie clearing to a later backend-confirmed signed-out session check', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...resetBindings, ...recoveryBindings })
  mock.get(backend).intercept({ method: 'POST', path: recoveryPath }).reply(202, JSON.stringify(recoveryAccepted), {
    headers: { 'Content-Type': 'application/json' },
  })
  const recovery = await mf.dispatchFetch(site + recoveryPath, recoveryOptions())
  assert.equal(recovery.status, 202, await recovery.clone().text())
  assert.equal(recovery.headers.get('Set-Cookie'), null)
  await recovery.arrayBuffer()
  mock.get(backend).intercept({ method: 'POST', path: resetPath }).reply(200, JSON.stringify(passwordCompleted), {
    headers: { 'Content-Type': 'application/json' },
  })
  const reset = await mf.dispatchFetch(site + resetPath, resetOptions({ Cookie: `${name}=${token}; ${guestCookie}=private` }))
  assert.equal(reset.status, 200, await reset.clone().text())
  assert.equal(reset.headers.get('Set-Cookie'), null)
  assert.deepEqual(await reset.json(), passwordCompleted)
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(401, '{"detail":"private"}', {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearingCookie },
  })
  const session = await mf.dispatchFetch(site + endpoint, options({ Cookie: `${name}=${token}; ${guestCookie}=private`, 'CF-Connecting-IP': '198.51.100.20' }))
  assert.equal(session.status, 401, await session.clone().text())
  assert.equal(session.headers.get('Set-Cookie'), canonicalClear)
  assert.equal((await session.text()).includes('private'), false)
  mock.assertNoPendingInterceptors()
})

const googleStartPath = '/api/v1/account/google/start'
const googleIssuer = 'https://auth.example/auth/v1'
const googleCookie = '__Host-askm6_oauth'
const googleToken = 'O'.repeat(43)
const googlePrevious = 'P'.repeat(43)
const googleExpiry = new Date(Date.now() + 600_000).toISOString()
const googleStartMetadata = { authorization_url: googleIssuer + '/authorize?' + new URLSearchParams({
  provider: 'google', redirect_to: site + '/api/v1/account/google/callback', code_challenge: 'C'.repeat(43), code_challenge_method: 's256',
}), expires_at: googleExpiry }
const googleSetCookie = `${googleCookie}=${googleToken}; expires=${new Date(googleExpiry).toUTCString()}; HttpOnly; Path=/; SameSite=lax; Secure`
const googleClear = clearingCookie.replace(name, googleCookie)
const googleCanonicalClear = canonicalClear.replace(name, googleCookie)
const googleStartBindings = { ACCOUNT_GOOGLE_START_PROXY_ENABLED: 'true', SUPABASE_AUTH_ISSUER: googleIssuer,
  AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32) }
function googleStartOptions(headers = {}) {
  return { method: 'POST', headers: { Origin: site, 'CF-Connecting-IP': '198.51.100.20', ...headers } }
}

test('Workers Google start creates/replaces only the OAuth binding and returns validated authorization metadata', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, googleStartBindings)
  for (const binding of [null, `${googleCookie}=${googlePrevious}`]) {
    let sent
    mock.get(backend).intercept({ method: 'POST', path: googleStartPath }).reply((request) => {
      sent = new Headers(request.headers)
      return { statusCode: 200, data: JSON.stringify(googleStartMetadata), responseOptions: {
        headers: { 'Content-Type': 'application/json', 'Set-Cookie': googleSetCookie, 'X-Private': 'private' },
      } }
    })
    const response = await mf.dispatchFetch(site + googleStartPath, googleStartOptions({
      Cookie: `${guestCookie}=private; askm6_oauth=private${binding ? '; ' + binding : ''}`,
      Authorization: 'Bearer private', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
    }))
    assert.equal(response.status, 200, await response.clone().text())
    assert.deepEqual(await response.json(), googleStartMetadata)
    assert.equal(sent.get('Cookie'), binding)
    assert.equal(sent.get('Origin'), site)
    assert.equal(sent.get('X-AskM6-Client-IP'), '198.51.100.20')
    assert.equal(sent.get('X-AskM6-Proxy-Secret'), googleStartBindings.AUTH_PROXY_SHARED_SECRET)
    for (const header of ['Authorization', 'CF-Connecting-IP', 'X-Forwarded-For']) assert.equal(sent.get(header), null)
    assert.equal(response.headers.get('Set-Cookie'), `${googleCookie}=${googleToken}; Expires=${new Date(googleExpiry).toUTCString()}; Path=/; Secure; HttpOnly; SameSite=Lax`)
    assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer')
    assert.equal(response.headers.get('Location'), null)
    assert.equal(response.headers.get('X-Private'), null)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers Google start is independently gated and requires configured issuer and trusted ingress', { timeout: 30_000 }, async (t) => {
  const closed = await runtime(t, { ...signInBindings, ...signUpBindings })
  const response = await closed.mf.dispatchFetch(site + googleStartPath, googleStartOptions())
  assert.equal(response.status, 404)
  await response.arrayBuffer()
  for (const overrides of [{ TEST_CLIENT_IP_MODE: 'missing' }, { TEST_CLIENT_IP_MODE: 'empty' },
    { AUTH_PROXY_TRUST_ENABLED: 'false' }, { SUPABASE_AUTH_ISSUER: '' }]) {
    const { mf } = await runtime(t, { ...googleStartBindings, ...overrides })
    const result = await mf.dispatchFetch(site + googleStartPath, googleStartOptions())
    assert.equal(result.status, 503)
    assert.equal(result.headers.get('Set-Cookie'), null)
    await result.arrayBuffer()
  }
})

test('Workers Google start enforces origin, empty input and explicit account sign-out without enabling callbacks', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t, googleStartBindings)
  for (const [url, init, status] of [
    [site + googleStartPath, googleStartOptions({ Origin: 'https://foreign.example' }), 403],
    ['https://preview.example' + googleStartPath, googleStartOptions(), 403],
    [site + googleStartPath + '?provider=github', googleStartOptions(), 400],
    [site + googleStartPath, { ...googleStartOptions(), body: '{}' }, 400],
    ...['', 'bad', token].map((value) => [site + googleStartPath, googleStartOptions({ Cookie: `${name}=${value}; ${googleCookie}=${googlePrevious}` }), 409]),
    [site + '/api/v1/account/google/callback?code=synthetic', { method: 'GET' }, 404],
  ]) {
    const response = await mf.dispatchFetch(url, init)
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
})

test('Workers Google start preserves malformed/duplicate binding evidence and clears only after backend confirmation', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, googleStartBindings)
  for (const binding of [`${googleCookie}=bad`, `${googleCookie}=${googlePrevious}; ${googleCookie}=${googlePrevious}`, `${googleCookie}=${googlePrevious} `]) {
    mock.get(backend).intercept({ method: 'POST', path: googleStartPath }).reply((request) => {
      assert.equal(new Headers(request.headers).get('Cookie'), binding.endsWith(' ') ? binding + ';' : binding)
      return { statusCode: 400, data: 'private', responseOptions: { headers: { 'Set-Cookie': googleClear } } }
    })
    const response = await mf.dispatchFetch(site + googleStartPath, googleStartOptions({ Cookie: binding + '; unrelated=private' }))
    assert.equal(response.status, 400, await response.clone().text())
    assert.equal(response.headers.get('Set-Cookie'), googleCanonicalClear)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers Google start errors retain only bounded retry seconds and preserve browser cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, googleStartBindings)
  for (const [status, retry, expectedRetry] of [[403, undefined, null], [409, undefined, null],
    [429, '37', '37'], [429, '86401', null], [503, undefined, null]]) {
    mock.get(backend).intercept({ method: 'POST', path: googleStartPath }).reply(status, 'private', {
      headers: { 'Set-Cookie': googleClear, 'X-Account-Verification': 'required', ...(retry ? { 'Retry-After': retry } : {}) },
    })
    const response = await mf.dispatchFetch(site + googleStartPath, googleStartOptions())
    assert.equal(response.status, status)
    assert.equal(response.headers.get('Retry-After'), expectedRetry)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('X-Account-Verification'), null)
    assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer')
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('Workers Google start rejects unsafe URLs, extra metadata, account cookies and unsafe binding clearing', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, googleStartBindings)
  for (const [status, body, selectedCookie] of [
    [200, { ...googleStartMetadata, authorization_url: googleStartMetadata.authorization_url.replace('auth.example', 'foreign.example') }, googleSetCookie],
    [200, { ...googleStartMetadata, access_token: 'private' }, googleSetCookie],
    [200, googleStartMetadata, renewal], [200, googleStartMetadata, [googleSetCookie, guestSetCookie]],
    [200, googleStartMetadata, googleSetCookie.replace('HttpOnly; ', '')],
    [400, { detail: 'private' }, clearingCookie], [302, { detail: 'private' }, googleSetCookie],
  ]) {
    mock.get(backend).intercept({ method: 'POST', path: googleStartPath }).reply(status, JSON.stringify(body), {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': selectedCookie, Location: 'https://private.example' },
    })
    const response = await mf.dispatchFetch(site + googleStartPath, googleStartOptions())
    assert.equal(response.status, 502)
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(response.headers.get('Location'), null)
    assert.equal((await response.text()).includes('private'), false)
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers Google start abort never returns a late URL or OAuth cookie', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...googleStartBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'POST', path: googleStartPath }).reply(200, JSON.stringify(googleStartMetadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': googleSetCookie },
  }).delay(300)
  const response = await mf.dispatchFetch(site + googleStartPath, googleStartOptions())
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal((await response.text()).includes(googleIssuer), false)
})

const googleCallbackPath = '/api/v1/account/google/callback'
const googleCallbackQuery = '?code=synthetic-code'
const googleCallbackBindings = { ACCOUNT_GOOGLE_CALLBACK_PROXY_ENABLED: 'true' }
function googleCallbackOptions(headers = {}) {
  return { method: 'GET', redirect: 'manual', headers: { Cookie: `${googleCookie}=${googleToken}`, ...headers } }
}

test('Workers Google callback permits cross-site navigation and preserves separate validated account and OAuth cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, googleCallbackBindings)
  let sent
  mock.get(backend).intercept({ method: 'GET', path: googleCallbackPath + googleCallbackQuery }).reply((request) => {
    sent = new Headers(request.headers)
    return { statusCode: 303, data: '', responseOptions: { headers: {
      Location: site + '/#google-sign-in=success', 'Content-Length': '0', 'Set-Cookie': [renewal, googleClear], 'X-Private': 'private',
    } } }
  })
  const response = await mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions({
    Origin: 'https://accounts.google.com', 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate',
    Cookie: `${guestCookie}=private; ${googleCookie}=${googleToken}; askm6_account=private`, Authorization: 'Bearer private',
    'X-AskM6-Proxy-Secret': 'forged', 'X-AskM6-Client-IP': '203.0.113.99',
  }))
  assert.equal(response.status, 303, await response.clone().text())
  assert.equal(response.headers.get('Location'), site + '/#google-sign-in=success')
  const fields = response.headers.getSetCookie()
  assert.equal(fields.length, 2)
  assert.equal(fields[0], googleCanonicalClear)
  assert.ok(fields[1].startsWith(`${name}=${token}; Expires=`))
  assert.equal(sent.get('Cookie'), `${googleCookie}=${googleToken}`)
  for (const header of ['Origin', 'Authorization', 'X-AskM6-Proxy-Secret', 'X-AskM6-Client-IP', 'CF-Connecting-IP']) assert.equal(sent.get(header), null)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer')
  assert.equal(response.headers.get('X-Private'), null)
  assert.equal(await response.text(), '')
  mock.assertNoPendingInterceptors()
})

test('Workers Google callback is independently gated and rejects preview hosts, malformed queries and missing binding before exchange', { timeout: 30_000 }, async (t) => {
  const closed = await runtime(t, googleStartBindings)
  const hidden = await closed.mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions())
  assert.equal(hidden.status, 404)
  await hidden.arrayBuffer()
  const { mf } = await runtime(t, googleCallbackBindings)
  for (const [url, init, status] of [
    ['https://preview.example' + googleCallbackPath + googleCallbackQuery, googleCallbackOptions({ Host: 'site.example' }), 403],
    [site + googleCallbackPath + '?code=a&code=b', googleCallbackOptions(), 303],
    [site + googleCallbackPath + '?error=private', googleCallbackOptions(), 303],
    [site + googleCallbackPath + '/extra?code=synthetic', googleCallbackOptions(), 303],
    [site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions({ Cookie: `${guestCookie}=private` }), 303],
  ]) {
    const response = await mf.dispatchFetch(url, init)
    assert.equal(response.status, status)
    if (status === 303) assert.equal(response.headers.get('Location'), site + '/#google-sign-in=rejected')
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal((await response.text()).includes('private'), false)
  }
})

test('Workers Google callback requires explicit sign-out and preserves existing account and guest cookies', { timeout: 30_000 }, async (t) => {
  const { mf } = await runtime(t, googleCallbackBindings)
  for (const value of ['', 'bad', token]) {
    const response = await mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions({
      Cookie: `${name}=${value}; ${googleCookie}=${googleToken}; ${guestCookie}=private`,
    }))
    assert.equal(response.status, 303)
    assert.equal(response.headers.get('Location'), site + '/#google-sign-in=sign-out-required')
    assert.equal(response.headers.get('Set-Cookie'), null)
    await response.arrayBuffer()
  }
})

test('Workers Google callback returns only fixed failure outcomes and backend-confirmed OAuth clearing', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, googleCallbackBindings)
  for (const outcome of ['rejected', 'unavailable', 'sign-out-required']) {
    mock.get(backend).intercept({ method: 'GET', path: googleCallbackPath + googleCallbackQuery }).reply(303, '', {
      headers: { Location: `${site}/#google-sign-in=${outcome}`, 'Content-Length': '0', 'Set-Cookie': googleClear },
    })
    const response = await mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions())
    assert.equal(response.status, 303)
    assert.equal(response.headers.get('Location'), `${site}/#google-sign-in=${outcome}`)
    assert.deepEqual(response.headers.getSetCookie(), [googleCanonicalClear])
    await response.arrayBuffer()
    mock.assertNoPendingInterceptors()
  }
  mock.get(backend).intercept({ method: 'GET', path: googleCallbackPath + googleCallbackQuery }).reply(503, 'private', { headers: { 'Set-Cookie': googleClear } })
  const disabled = await mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions())
  assert.equal(disabled.status, 503)
  assert.equal(disabled.headers.get('Set-Cookie'), googleCanonicalClear)
  assert.equal(disabled.headers.get('Location'), null)
  assert.equal((await disabled.text()).includes('private'), false)
  mock.assertNoPendingInterceptors()
})

test('Workers Google callback rejects unsafe return URLs, wrong cookie sets and unexpected bodies/statuses', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, googleCallbackBindings)
  for (const [status, location, cookies, body] of [
    [303, 'https://private.example/#google-sign-in=success', [googleClear, renewal], ''],
    [303, site + '/#google-sign-in=success', [googleClear], ''],
    [303, site + '/#google-sign-in=rejected', [googleClear, renewal], ''],
    [303, site + '/#google-sign-in=success', [googleClear, guestSetCookie], ''],
    [303, site + '/#google-sign-in=success', [googleClear, renewal], 'private'],
    [302, site + '/#google-sign-in=success', [googleClear, renewal], ''],
  ]) {
    mock.get(backend).intercept({ method: 'GET', path: googleCallbackPath + googleCallbackQuery }).reply(status, body, {
      headers: { Location: location, 'Content-Length': String(new TextEncoder().encode(body).byteLength), 'Set-Cookie': cookies },
    })
    const response = await mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions())
    assert.equal(response.status, 303)
    assert.equal(response.headers.get('Location'), site + '/#google-sign-in=unavailable')
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(await response.text(), '')
    mock.assertNoPendingInterceptors()
  }
})

test('an explicit Workers Google callback abort never returns late account or clearing cookies', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...googleCallbackBindings, TEST_ABORT_MS: '30' })
  mock.get(backend).intercept({ method: 'GET', path: googleCallbackPath + googleCallbackQuery }).reply(303, '', {
    headers: { Location: site + '/#google-sign-in=success', 'Content-Length': '0', 'Set-Cookie': [googleClear, renewal] },
  }).delay(300)
  const response = await mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions())
  assert.equal(response.status, 303)
  assert.equal(response.headers.get('Location'), site + '/#google-sign-in=unavailable')
  assert.equal(response.headers.get('Set-Cookie'), null)
  await response.arrayBuffer()
})

test('Workers completes a mocked Google start, callback, account-session check and sign-out cycle', { timeout: 30_000 }, async (t) => {
  const { mf, mock } = await runtime(t, { ...googleStartBindings, ...googleCallbackBindings, ...signOutBindings })
  mock.get(backend).intercept({ method: 'POST', path: googleStartPath }).reply(200, JSON.stringify(googleStartMetadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': googleSetCookie },
  })
  const start = await mf.dispatchFetch(site + googleStartPath, googleStartOptions())
  assert.equal(start.status, 200, await start.clone().text())
  const bindingCookie = start.headers.get('Set-Cookie').split(';', 1)[0]
  await start.arrayBuffer()
  mock.get(backend).intercept({ method: 'GET', path: googleCallbackPath + googleCallbackQuery }).reply(303, '', {
    headers: { Location: site + '/#google-sign-in=success', 'Content-Length': '0', 'Set-Cookie': [googleClear, renewal] },
  })
  const callback = await mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, googleCallbackOptions({ Cookie: bindingCookie }))
  assert.equal(callback.status, 303)
  assert.equal(callback.headers.get('Location'), site + '/#google-sign-in=success')
  const accountCookie = callback.headers.getSetCookie().find((cookie) => cookie.startsWith(name + '=')).split(';', 1)[0]
  await callback.arrayBuffer()
  mock.get(backend).intercept({ method: 'POST', path: endpoint }).reply(200, JSON.stringify(metadata), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': renewal },
  })
  const session = await mf.dispatchFetch(site + endpoint, options({ Cookie: accountCookie, 'CF-Connecting-IP': '198.51.100.20' }))
  assert.equal(session.status, 200, await session.clone().text())
  assert.deepEqual(await session.json(), metadata)
  mock.get(backend).intercept({ method: 'POST', path: signOutPath }).reply(204, '', { headers: { 'Set-Cookie': clearingCookie } })
  const signOut = await mf.dispatchFetch(site + signOutPath, options({ Cookie: accountCookie, 'CF-Connecting-IP': '198.51.100.20' }))
  assert.equal(signOut.status, 204)
  assert.equal(signOut.headers.get('Set-Cookie'), canonicalClear)
  await signOut.arrayBuffer()
  mock.assertNoPendingInterceptors()
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


test('Workers carries only the Terms receipt through confirmation and clears it with committed signin', { timeout: 30_000 }, async t => {
  const { mf, mock } = await runtime(t, { ...signInBindings, ...confirmationBindings })
  const name = '__Host-askm6_signup_terms'
  const pending = 'A'.repeat(120)
  const confirmed = 'B'.repeat(120)
  let confirmationHeaders, signinHeaders
  mock.get(backend).intercept({ method: 'POST', path: confirmationPath }).reply(request => {
    confirmationHeaders = new Headers(request.headers)
    return { statusCode: 200, data: JSON.stringify({ status: 'confirmed', message: 'Email confirmed. You can now sign in.' }), responseOptions: { headers: {
      'Content-Type': 'application/json', 'Set-Cookie': signupReceiptCookie().replace(pending, confirmed),
    } } }
  })
  const confirmation = await mf.dispatchFetch(site + confirmationPath, { method: 'POST',
    body: JSON.stringify({ email: signInCredentials.email, code: '001234' }), headers: {
      Origin: site, 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.20',
      Cookie: `${name}=${pending}; __Host-askm6_guest=private; __Host-askm6_google=private`,
    } })
  assert.equal(confirmation.status, 200, await confirmation.clone().text())
  assert.equal(confirmationHeaders.get('Cookie'), `${name}=${pending}`)
  const rotated = confirmation.headers.getSetCookie()
  assert.equal(rotated.length, 1)
  assert.ok(rotated[0].startsWith(`${name}=${confirmed};`))
  mock.get(backend).intercept({ method: 'POST', path: signInPath }).reply(request => {
    signinHeaders = new Headers(request.headers)
    return { statusCode: 200, data: JSON.stringify(metadata), responseOptions: { headers: {
      'Content-Type': 'application/json', 'Set-Cookie': [renewal,
        `${name}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`],
    } } }
  })
  const signedIn = await mf.dispatchFetch(site + signInPath, signInOptions({ Cookie: `${name}=${confirmed}; __Host-askm6_guest=private` }))
  assert.equal(signedIn.status, 200, await signedIn.clone().text())
  assert.deepEqual(await signedIn.json(), metadata)
  assert.equal(signinHeaders.get('Cookie'), `${name}=${confirmed}`)
  const cookies = signedIn.headers.getSetCookie()
  assert.equal(cookies.length, 2)
  assert.ok(cookies[0].startsWith('__Host-askm6_account='))
  assert.ok(cookies[1].startsWith(`${name}=;`))
  assert.match(cookies[1], /Max-Age=0/)
  mock.assertNoPendingInterceptors()
})


test('Workers email-confirmed signup can complete Google first with three isolated cookies', { timeout: 30_000 }, async t => {
  const { mf, mock } = await runtime(t, { ...confirmationBindings, ...googleCallbackBindings })
  const receipt = '__Host-askm6_signup_terms'
  const pending = 'A'.repeat(120)
  const confirmed = 'B'.repeat(120)
  let forwarded
  mock.get(backend).intercept({ method: 'POST', path: confirmationPath }).reply(200, JSON.stringify(emailConfirmed), { headers: {
    'Content-Type': 'application/json', 'Set-Cookie': signupReceiptCookie().replace(pending, confirmed),
  } })
  const verified = await mf.dispatchFetch(site + confirmationPath, confirmationOptions({ Cookie: `${receipt}=${pending}` }))
  assert.equal(verified.status, 200, await verified.clone().text())
  assert.ok(verified.headers.getSetCookie()[0].startsWith(`${receipt}=${confirmed};`))
  mock.get(backend).intercept({ method: 'GET', path: googleCallbackPath + googleCallbackQuery }).reply(request => {
    forwarded = new Headers(request.headers)
    return { statusCode: 303, data: '', responseOptions: { headers: {
      Location: site + '/#google-sign-in=success', 'Content-Length': '0',
      'Set-Cookie': [googleClear, renewal, `${receipt}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`],
    } } }
  })
  const response = await mf.dispatchFetch(site + googleCallbackPath + googleCallbackQuery, { redirect: 'manual', headers: {
    Cookie: `${googleCookie}=${googleToken}; ${receipt}=${confirmed}; ${guestCookie}=private`,
    Authorization: 'Bearer private', Origin: 'https://accounts.google.com',
  } })
  assert.equal(response.status, 303)
  assert.equal(response.headers.get('Location'), site + '/#google-sign-in=success')
  assert.equal(forwarded.get('Cookie'), `${googleCookie}=${googleToken}; ${receipt}=${confirmed}`)
  assert.equal(forwarded.get('Authorization'), null)
  const cookies = response.headers.getSetCookie()
  assert.equal(cookies.length, 3)
  assert.equal(cookies[0], googleCanonicalClear)
  assert.ok(cookies[1].startsWith(`${name}=${token};`))
  assert.ok(cookies[2].startsWith(`${receipt}=;`))
  assert.match(cookies[2], /Max-Age=0/)
  mock.assertNoPendingInterceptors()
})
