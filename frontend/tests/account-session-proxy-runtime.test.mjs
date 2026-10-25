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
  const { mf } = await runtime(t, { AUTH_PROXY_TRUST_ENABLED: 'true', AUTH_PROXY_SHARED_SECRET: 'ab'.repeat(32) })
  for (const headers of [{}, { 'CF-Connecting-IP': '198.51.100.20, 203.0.113.30' }]) {
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
  const enabled = await runtime(t, guestBindings)
  for (const [url, init, status] of [
    [site + guestPath, options(), 503],
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
  const enabled = await runtime(t, signInBindings)
  for (const [url, init, status] of [
    [site + signInPath, signInOptions({ 'CF-Connecting-IP': '' }), 503],
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
