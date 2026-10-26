import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'

const site = 'https://site.example'
const path = '/api/v1/account/google/callback'
const oauth = '__Host-askm6_oauth'
const account = '__Host-askm6_account'
const binding = 'O'.repeat(43)
const token = 'A'.repeat(43)
const code = 'synthetic-code+&='
const expiry = new Date(Date.now() + 1_800_000).toUTCString()
const clear = `${oauth}=""; expires=Thu, 01 Jan 2026 00:00:00 GMT; HttpOnly; Max-Age=0; Path=/; SameSite=lax; Secure`
const canonicalClear = `${oauth}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`
const created = `${account}=${token}; expires=${expiry}; HttpOnly; Path=/; SameSite=lax; Secure`
const canonicalCreated = `${account}=${token}; Expires=${expiry}; Path=/; Secure; HttpOnly; SameSite=Lax`
const env = { API_ORIGIN: 'https://backend.example', AUTH_PUBLIC_ORIGIN: site, ACCOUNT_GOOGLE_CALLBACK_PROXY_ENABLED: 'true' }
const url = site + path + '?' + new URLSearchParams({ code })
function incoming(options = {}, destination = url) {
  return new Request(destination, { method: 'GET', ...options, headers: { Cookie: `${oauth}=${binding}`, ...options.headers } })
}
function dispatch(options = {}, configuration = env, destination) { return onRequest({ request: incoming(options, destination), env: configuration }) }
function upstream(outcome = 'success', cookies = outcome === 'success' ? [clear, created] : [clear], options = {}) {
  const headers = new Headers({ Location: `${site}/#google-sign-in=${outcome}`, ...options.headers })
  for (const cookie of cookies) headers.append('Set-Cookie', cookie)
  return new Response(options.body ?? null, { status: options.status ?? 303, headers })
}
async function returned(response, outcome = 'unavailable', cookies = []) {
  assert.equal(response.status, 303)
  assert.equal(response.headers.get('Location'), `${site}/#google-sign-in=${outcome}`)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer')
  assert.deepEqual(response.headers.getSetCookie(), cookies)
  for (const header of ['Authorization', 'Access-Control-Allow-Origin', 'X-Private', 'X-AskM6-Proxy-Secret', 'Retry-After']) {
    assert.equal(response.headers.get(header), null)
  }
  assert.equal(await response.text(), '')
}
async function blocked(response, status) {
  assert.equal(response.status, status)
  assert.equal(response.headers.get('Location'), null)
  assert.equal(response.headers.get('Set-Cookie'), null)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer')
  const text = await response.text()
  for (const value of [code, token, binding, 'private']) assert.equal(text.includes(value), false)
}

for (const origin of [undefined, 'https://accounts.google.com']) {
  test(`accepts top-level cross-site callback without a trusted Origin (${origin === undefined ? 'absent' : 'provider'}) and forwards only binding/code`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async (target, options) => {
      assert.equal(target.origin, env.API_ORIGIN)
      assert.equal(target.pathname, path)
      assert.deepEqual([...target.searchParams], [['code', code]])
      assert.equal(options.method, 'GET')
      assert.equal(options.body, undefined)
      assert.equal(options.redirect, 'manual')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.credentials, 'omit')
      assert.deepEqual(Object.fromEntries(options.headers), {
        accept: 'application/json', 'accept-encoding': 'identity', cookie: `${oauth}=${binding}`,
      })
      return upstream('success', [created, clear], { headers: { 'X-Private': 'private', 'Access-Control-Allow-Origin': '*' } })
    })
    await returned(await dispatch({ headers: {
      ...(origin ? { Origin: origin } : {}), 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate',
      Cookie: `__Host-askm6_guest=private; ${oauth}=${binding}; askm6_account=private; askm6_oauth=private`,
      Authorization: 'Bearer private', 'X-AskM6-Client-IP': '203.0.113.99', 'X-AskM6-Proxy-Secret': 'forged',
    } }), 'success', [canonicalClear, canonicalCreated])
    assert.equal(fetch.mock.callCount(), 1)
  })
}
for (const flag of [undefined, 'false', 'TRUE', ' true ', '1']) {
  test(`callback is independently gated for ${JSON.stringify(flag)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await blocked(await dispatch({}, { ...env, ACCOUNT_GOOGLE_START_PROXY_ENABLED: 'true', ACCOUNT_GOOGLE_CALLBACK_PROXY_ENABLED: flag }), 404)
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const [label, configuration, options, destination, status] of [
  ['wrong method', {}, { method: 'POST' }, undefined, 405],
  ['missing backend', { API_ORIGIN: undefined }, {}, undefined, 503],
  ['HTTP backend', { API_ORIGIN: 'http://backend.example' }, {}, undefined, 503],
  ['backend path', { API_ORIGIN: 'https://backend.example/private' }, {}, undefined, 503],
  ['backend credentials', { API_ORIGIN: 'https://user@backend.example' }, {}, undefined, 503],
  ['same origins', { API_ORIGIN: site }, {}, undefined, 503],
  ['missing public origin', { AUTH_PUBLIC_ORIGIN: undefined }, {}, undefined, 503],
  ['preview host', {}, { headers: { Host: 'site.example', 'X-Forwarded-Host': 'site.example' } }, url.replace('site.example', 'preview.example'), 403],
]) {
  test(`rejects ${label} before code exchange`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    const response = await dispatch(options, { ...env, ...configuration }, destination)
    if (status === 405) assert.equal(response.headers.get('Allow'), 'GET')
    await blocked(response, status)
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const query of ['', 'code=', 'code', 'code=a&code=b', 'code=a&', 'error=private', 'code=a&state=private',
  'code=a+b', 'code=%0A', 'code=%20', 'code=%7F', 'code=%C3%A9', 'code=%FF', 'code=%', 'code=%GG',
  'wrong=x', 'code=' + 'x'.repeat(1025), 'code=' + '%41'.repeat(1400)]) {
  test(`rejects malformed callback query case ${query.length}/${query.slice(0, 14)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await returned(await dispatch({}, env, site + path + '?' + query), 'rejected')
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const destination of [url + '#private', site + path + '/extra?code=synthetic', site + path + '/?code=synthetic']) {
  test(`rejects callback fragment/suffix without forwarding ${destination.length}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await returned(await dispatch({}, env, destination), 'rejected')
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const raw of ['%63ode=synthetic%2Bcode', 'code=a=b', 'code=' + 'x'.repeat(1024)]) {
  test(`preserves accepted opaque code after safe query rebuilding (${raw.length})`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async (target) => {
      assert.equal(target.searchParams.get('code'), raw.startsWith('%63') ? 'synthetic+code' : raw.slice(5))
      return upstream('rejected')
    })
    await returned(await dispatch({}, env, site + path + '?' + raw), 'rejected', [canonicalClear])
    assert.equal(fetch.mock.callCount(), 1)
  })
}
for (const value of ['', '""', 'bad', token]) {
  test(`account cookie presence prevents replacement (${value.length})`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await returned(await dispatch({ headers: { Cookie: `${account}=${value}; ${oauth}=${binding}` } }), 'sign-out-required')
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const header of ['', 'askm6_oauth=private', 'x'.repeat(8193), `${account}=a; ${account}=b; ${oauth}=${binding}`]) {
  test(`missing/ambiguous cookies cannot exchange code (${header.length})`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream())
    await returned(await dispatch({ headers: { Cookie: header } }), 'rejected')
    assert.equal(fetch.mock.callCount(), 0)
  })
}
for (const selected of [`${oauth}=bad`, `${oauth}=${binding}; ${oauth}=${binding}`, `${oauth}=${binding} `]) {
  test(`malformed binding remains backend-verifiable (${selected.length})`, async (t) => {
    t.mock.method(globalThis, 'fetch', async (_target, options) => {
      assert.equal(options.headers.get('Cookie'), selected.endsWith(' ') ? selected + ';' : selected)
      return upstream('rejected')
    })
    await returned(await dispatch({ headers: { Cookie: selected + '; unrelated=private' } }), 'rejected', [canonicalClear])
  })
}
for (const outcome of ['rejected', 'unavailable', 'sign-out-required']) {
  test(`returns fixed ${outcome} with only confirmed binding deletion`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(outcome))
    await returned(await dispatch(), outcome, [canonicalClear])
  })
}
for (const destination of ['https://foreign.example/#google-sign-in=success', site + '/other#google-sign-in=success',
  site + '/?code=private#google-sign-in=success', site + '/#google-sign-in=success&code=private',
  '/#google-sign-in=success', site + '/#google-sign-in=unknown', site + '/#google-sign-in=%73uccess']) {
  test(`rejects an untrusted backend return destination (${destination.length})`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream('success', [clear, created], { headers: { Location: destination } }))
    await returned(await dispatch())
  })
}
for (const [outcome, cookies] of [
  ['success', []], ['success', [clear]], ['success', [created]], ['success', [clear, clear]],
  ['success', [clear, created, created]], ['success', [clear, created.replace(account, '__Host-askm6_guest')]],
  ['success', [clear, created.replace('HttpOnly; ', '')]], ['success', [clear, created + '; Domain=site.example']],
  ['success', [clear, created.replace(expiry, 'Wed, 01 Jan 2020 00:00:00 GMT')]],
  ['success', [clear, created + '; Max-Age=1800']], ['success', [clear, created.replace(token, 'bad')]],
  ['success', [clear.replace('Max-Age=0', 'Max-Age=1'), created]], ['success', [clear.replace(oauth, 'askm6_oauth'), created]],
  ['rejected', []], ['rejected', [clear, created]], ['rejected', [created]], ['rejected', [clear + '; Domain=site.example']],
]) {
  test(`rejects unsafe ${outcome} cookie set (${JSON.stringify(cookies).length})`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => upstream(outcome, cookies))
    await returned(await dispatch())
  })
}
for (const options of [{ body: 'private' }, { headers: { 'Content-Length': '1' } },
  { headers: { 'Content-Length': '0, 0' } }, { headers: { 'Transfer-Encoding': 'chunked' } },
  { headers: { 'Content-Encoding': 'gzip' } }, ...[200, 201, 302, 307, 308, 400, 401, 500].map((status) => ({ status }))]) {
  test(`rejects unsafe backend callback framing/status ${JSON.stringify(options)}`, async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => upstream('success', [clear, created], options))
    await returned(await dispatch())
    assert.equal(fetch.mock.callCount(), 1)
  })
}
test('disabled backend may clear only a confirmed OAuth cookie with a private 503 body discarded', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => upstream('unavailable', [clear], { status: 503, body: 'private' }))
  const response = await dispatch()
  assert.equal(response.status, 503)
  assert.equal(response.headers.get('Set-Cookie'), canonicalClear)
  assert.equal(response.headers.get('Location'), null)
  assert.equal((await response.text()).includes('private'), false)
})
test('a malformed 503 cannot clear any browser cookie', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => upstream('unavailable', [created], { status: 503 }))
  await returned(await dispatch())
})
test('network errors and pre-cancellation never replay code or change cookies', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('private callback ' + code) })
  await returned(await dispatch({ signal: AbortSignal.abort() }))
  assert.equal(fetch.mock.callCount(), 0)
  await returned(await dispatch())
  assert.equal(fetch.mock.callCount(), 1)
})
for (const kind of ['deadline', 'client']) {
  test(`${kind} rejects late callback login and clearing cookies without retry`, async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] })
    const controller = new AbortController()
    let began, release, signal
    const started = new Promise((resolve) => { began = resolve })
    const fetch = t.mock.method(globalThis, 'fetch', async (_target, options) => {
      signal = options.signal; began()
      return new Promise((resolve) => { release = resolve })
    })
    const pending = dispatch({ signal: controller.signal })
    await started
    if (kind === 'deadline') t.mock.timers.tick(20_000)
    else controller.abort()
    await returned(await pending)
    assert.equal(signal.aborted, true)
    assert.equal(fetch.mock.callCount(), 1)
    release(upstream())
    await new Promise((resolve) => setImmediate(resolve))
  })
}
test('deadline bounds stalled redirect-body EOF and cancels its reader', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  let began, cancelled = false
  const reading = new Promise((resolve) => { began = resolve })
  t.mock.method(globalThis, 'fetch', async () => {
    const body = new ReadableStream({ cancel() { cancelled = true } })
    const original = body.getReader.bind(body)
    t.mock.method(body, 'getReader', () => { began(); return original() })
    return upstream('success', [clear, created], { body })
  })
  const pending = dispatch()
  await reading
  t.mock.timers.tick(20_000)
  await returned(await pending)
  assert.equal(cancelled, true)
})
