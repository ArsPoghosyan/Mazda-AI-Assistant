import assert from 'node:assert/strict'
import { test } from 'node:test'
import { onRequest } from '../functions/api/[[path]].ts'

const health = {
  status: 'ok',
  service: 'mazda6-assistant-api',
}

function context(path = '/api/v1/health', method = 'GET') {
  return {
    request: new Request(`https://site.example${path}`, { method }),
    env: { API_ORIGIN: 'https://backend.example' },
  }
}

test('forwards health requests to the configured backend', async (t) => {
  const upstream = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(url.toString(), 'https://backend.example/api/v1/health')
    assert.equal(options.redirect, 'manual')
    assert.ok(options.signal instanceof AbortSignal)
    return Response.json(health)
  })

  const response = await onRequest(
    context('/api/v1/health?target=https://untrusted.example'),
  )

  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), health)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  assert.equal(upstream.mock.callCount(), 1)
})

test('rejects backend redirects without forwarding their location', async (t) => {
  const statuses = [301, 302, 303, 307, 308]
  let redirectStatus
  const upstream = t.mock.method(globalThis, 'fetch', async () => {
    return new Response('Redirecting', {
      status: redirectStatus,
      headers: { Location: 'https://untrusted.example' },
    })
  })

  for (const status of statuses) {
    redirectStatus = status
    const response = await onRequest(context())

    assert.equal(response.status, 502)
    assert.deepEqual(await response.json(), {
      error: 'Unexpected backend redirect.',
    })
    assert.equal(response.headers.get('Location'), null)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
  }

  assert.equal(upstream.mock.callCount(), statuses.length)
})

test('unknown API routes never contact the backend', async (t) => {
  const upstream = t.mock.method(
    globalThis, 'fetch', async () => Response.json(health),
  )

  const response = await onRequest(context('/api/v1/unknown'))

  assert.equal(response.status, 404)
  assert.equal(upstream.mock.callCount(), 0)
})

test('unsupported methods never contact the backend', async (t) => {
  const upstream = t.mock.method(
    globalThis, 'fetch', async () => Response.json(health),
  )

  const response = await onRequest(context('/api/v1/health', 'POST'))

  assert.equal(response.status, 405)
  assert.equal(response.headers.get('Allow'), 'GET')
  assert.equal(upstream.mock.callCount(), 0)
})

test('missing or invalid origins fail without network requests', async (t) => {
  const upstream = t.mock.method(
    globalThis, 'fetch', async () => Response.json(health),
  )

  const invalidOrigins = [
    undefined,
    'not-a-url',
    'http://backend.example',
    'https://user:password@backend.example',
    'https://backend.example/api',
    'https://backend.example?query=1',
    'https://backend.example#fragment',
  ]

  for (const API_ORIGIN of invalidOrigins) {
    const response = await onRequest({
      ...context(),
      env: { API_ORIGIN },
    })

    assert.equal(response.status, 503)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
  }

  assert.equal(upstream.mock.callCount(), 0)
})

test('preserves backend error responses', async (t) => {
  const body = { error: 'Service temporarily unavailable.' }

  t.mock.method(
    globalThis,
    'fetch',
    async () => Response.json(body, { status: 503 }),
  )

  const response = await onRequest(context())

  assert.equal(response.status, 503)
  assert.deepEqual(await response.json(), body)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
})

test('network failures return a controlled JSON error', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => {
    throw new TypeError('Connection failed')
  })

  const response = await onRequest(context())

  assert.equal(response.status, 502)
  assert.deepEqual(await response.json(), {
    error: 'Backend unavailable. Please try again.',
  })
})

test('uses a bounded timeout and handles cancellation', async (t) => {
  const timer = t.mock.method(
    AbortSignal, 'timeout', () => AbortSignal.abort(),
  )

  t.mock.method(globalThis, 'fetch', async (url, options) => {
    options.signal.throwIfAborted()
    return Response.json(health)
  })

  const response = await onRequest(context())

  assert.equal(timer.mock.callCount(), 1)
  assert.equal(timer.mock.calls[0].arguments[0], 65_000)
  assert.equal(response.status, 502)
})
