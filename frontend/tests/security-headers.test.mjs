import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFile } from 'node:fs/promises'
import { onRequest } from '../functions/api/[[path]].ts'

const expected = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
}

test('static header rules and Functions use the same minimal browser baseline', async () => {
  const rules = await readFile(new URL('../public/_headers', import.meta.url), 'utf8')
  assert.match(rules, /^\/\*$/m)
  for (const [name, value] of Object.entries(expected)) assert(rules.includes(`  ${name}: ${value}`))
})

for (const [path, method, status] of [
  ['/api/v1/missing', 'GET', 404],
  ['/api/v1/health', 'POST', 405],
  ['/api/v1/health', 'GET', 503],
  ['/api/v1/account/sign-up', 'POST', 404],
]) {
  test(`Functions add headers without changing ${method} ${path}: ${status}`, async () => {
    const response = await onRequest({request:new Request('https://site.example'+path,{method}),env:{}})
    assert.equal(response.status,status)
    assert.equal(response.headers.get('Cache-Control'),'no-store')
    assert.equal(response.headers.get('Access-Control-Allow-Origin'),null)
    for (const [name,value] of Object.entries(expected)) assert.equal(response.headers.get(name),value)
  })
}
