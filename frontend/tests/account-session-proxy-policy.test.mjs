import assert from 'node:assert/strict'
import { test } from 'node:test'
import { planAccountSessionProxy } from '../server/account-session-proxy-policy.ts'
import { onRequest } from '../functions/api/[[path]].ts'

const site = 'https://site.example'
const path = '/api/v1/account/session'
const env = {
  API_ORIGIN: 'https://backend.example',
  AUTH_PUBLIC_ORIGIN: site,
  AUTH_SESSION_PROXY_ENABLED: 'true',
}

function request(options = {}) {
  return new Request(site + path, {
    method: 'POST', headers: { Origin: site, 'Sec-Fetch-Site': 'same-origin' },
    ...options,
  })
}

function rejected(result, status) {
  assert.ok(result instanceof Response)
  assert.equal(result.status, status)
  assert.equal(result.headers.get('Cache-Control'), 'no-store')
  for (const name of ['Set-Cookie', 'Location', 'Access-Control-Allow-Origin']) {
    assert.equal(result.headers.get(name), null)
  }
}

test('plans only the fixed session destination without forwarding browser credentials', (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('Policy must not make network requests')
  })
  const result = planAccountSessionProxy(request({ headers: {
    Origin: site, 'Sec-Fetch-Site': 'same-origin',
    Cookie: '__Host-askm6_account=private-browser-token; unrelated=private-cookie',
    Authorization: 'Bearer private-provider-token',
    'X-Forwarded-For': '192.0.2.1',
  } }), env)
  assert.ok(!(result instanceof Response))
  assert.deepEqual(Object.keys(result).sort(), ['publicOrigin', 'upstreamUrl'])
  assert.equal(result.upstreamUrl.href, 'https://backend.example' + path)
  assert.equal(result.publicOrigin, site)
  assert.equal(JSON.stringify(result).includes('private'), false)
  assert.equal(fetch.mock.callCount(), 0)
})

for (const [label, flag] of [
  ['missing', undefined], ['false', 'false'], ['empty', ''], ['uppercase', 'TRUE'],
  ['number', '1'], ['whitespace', ' true '],
]) {
  test(`fails closed with ${label} enable flag`, () => {
    rejected(planAccountSessionProxy(request(), { ...env, AUTH_SESSION_PROXY_ENABLED: flag }), 404)
  })
}

for (const route of [
  '/api/v1/account/sign-in', '/api/v1/account/sign-up',
  '/api/v1/account/sign-out', '/api/v1/account/google/start',
  '/api/v1/account/google/callback', '/api/v1/guest/session',
  path + '/', '/api/v1/account/%73ession', '/api/v1/unknown',
]) {
  test(`does not authorize ${route}`, () => {
    rejected(planAccountSessionProxy(new Request(site + route, {
      method: 'POST', headers: { Origin: site },
    }), env), 404)
  })
}

for (const method of ['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']) {
  test(`rejects ${method} without providing CORS access`, () => {
    const result = planAccountSessionProxy(request({ method }), env)
    rejected(result, 405)
    assert.equal(result.headers.get('Allow'), 'POST')
  })
}

for (const key of ['AUTH_PUBLIC_ORIGIN', 'API_ORIGIN']) {
  for (const [label, value] of [
    ['missing', undefined], ['invalid', 'not-a-url'], ['http', 'http://host.example'],
    ['credentials', 'https://user:private@host.example'],
    ['path', 'https://host.example/private'], ['query', 'https://host.example/?private=1'],
    ['fragment', 'https://host.example/#private'], ['spaces', ' https://host.example '],
  ]) {
    test(`rejects ${key} with ${label} configuration`, async () => {
      const result = planAccountSessionProxy(request(), { ...env, [key]: value })
      rejected(result, 503)
      assert.equal((await result.text()).includes('private'), false)
    })
  }
}

test('rejects a backend origin pointing back to the frontend', () => {
  rejected(planAccountSessionProxy(request(), { ...env, API_ORIGIN: site + '/' }), 503)
})

test('accepts a trailing slash in configured origins without broadening their scope', () => {
  const result = planAccountSessionProxy(request(), {
    ...env, AUTH_PUBLIC_ORIGIN: site + '/', API_ORIGIN: env.API_ORIGIN + '/',
  })
  assert.ok(!(result instanceof Response))
  assert.equal(result.publicOrigin, site)
  assert.equal(result.upstreamUrl.href, env.API_ORIGIN + path)
})

for (const origin of [null, '', 'null', 'https://other.example', site + '/', site + ', ' + site]) {
  test(`rejects missing or untrusted Origin ${JSON.stringify(origin)}`, () => {
    rejected(planAccountSessionProxy(request({
      headers: origin === null ? {} : { Origin: origin },
    }), env), 403)
  })
}

test('rejects duplicate Origin headers', () => {
  rejected(planAccountSessionProxy(request({
    headers: [['Origin', site], ['Origin', site]],
  }), env), 403)
})

for (const fetchSite of ['cross-site', 'same-site', 'none', 'private']) {
  test(`rejects contradictory Fetch Metadata ${fetchSite}`, () => {
    rejected(planAccountSessionProxy(request({
      headers: { Origin: site, 'Sec-Fetch-Site': fetchSite },
    }), env), 403)
  })
}

test('allows absent Fetch Metadata only with exact origin checks still satisfied', () => {
  assert.ok(!(planAccountSessionProxy(request({ headers: { Origin: site } }), env) instanceof Response))
})

test('does not authorize a preview host through forged forwarding headers', () => {
  const forged = new Request('https://preview.example' + path, { method: 'POST', headers: {
    Origin: site, Host: 'site.example', 'X-Forwarded-Host': 'site.example',
    Forwarded: 'host=site.example;proto=https', 'X-Forwarded-Proto': 'https',
  } })
  rejected(planAccountSessionProxy(forged, env), 403)
})

test('rejects query parameters without echoing their contents', async () => {
  const incoming = new Request(site + path + '?target=https://private.example', {
    method: 'POST', headers: { Origin: site },
  })
  const result = planAccountSessionProxy(incoming, env)
  rejected(result, 400)
  assert.equal((await result.text()).includes('private'), false)
})

test('rejects provider credentials in a body without reading or returning them', async () => {
  const incoming = request({ body: '{"access_token":"private-provider-token"}' })
  const result = planAccountSessionProxy(incoming, env)
  rejected(result, 400)
  assert.equal(incoming.bodyUsed, false)
  assert.equal((await result.text()).includes('private'), false)
})

for (const length of ['1', '-1', '00', 'private']) {
  test(`rejects nonempty or ambiguous Content-Length ${length}`, () => {
    rejected(planAccountSessionProxy(request({
      headers: { Origin: site, 'Content-Length': length },
    }), env), 400)
  })
}

test('rejects Transfer-Encoding even without an exposed body', () => {
  rejected(planAccountSessionProxy(request({
    headers: { Origin: site, 'Transfer-Encoding': 'chunked' },
  }), env), 400)
})

test('accepts an explicit zero-length request without reading data', () => {
  assert.ok(!(planAccountSessionProxy(request({
    headers: { Origin: site, 'Content-Length': '0' },
  }), env) instanceof Response))
})

test('the production Pages handler rejects sessions unless explicitly enabled', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('Disabled session routing must not fetch')
  })
  rejected(await onRequest({ request: request(), env: { ...env, AUTH_SESSION_PROXY_ENABLED: undefined } }), 404)
  assert.equal(fetch.mock.callCount(), 0)
})
