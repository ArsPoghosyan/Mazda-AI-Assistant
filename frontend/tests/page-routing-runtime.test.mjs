import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Miniflare } from 'miniflare'
import { build } from 'vite'

const root = fileURLToPath(new URL('..', import.meta.url))
let directory, mf

before(async () => {
  directory = await mkdtemp(resolve(tmpdir(), 'askm6-page-routing-'))
  await build({ root, envFile: false, logLevel: 'silent', build: { outDir: directory, emptyOutDir: true } })
  const bundled = await build({ root, configFile: false, envFile: false, logLevel: 'silent', build: {
    write: false, minify: false, lib: {
      entry: fileURLToPath(new URL('./fixtures/page-routing-worker.mjs', import.meta.url)), formats: ['es'],
    },
  } })
  const chunks = (Array.isArray(bundled) ? bundled : [bundled]).flatMap(output => output.output.filter(item => item.type === 'chunk'))
  assert.equal(chunks.length, 1)
  mf = new Miniflare({ name: 'pages-routing', host: '127.0.0.1', port: 0, modules: true, script: chunks[0].code,
    cf: false, compatibilityDate: '2026-07-30', assets: {
      directory, binding: 'ASSETS', routerConfig: { invoke_user_worker_ahead_of_assets: true, has_user_worker: true },
      assetConfig: { not_found_handling: '404-page' },
    },
    outboundService: () => { throw new Error('Page routing must never contact an upstream') },
  })
  await mf.ready
}, { timeout: 60_000 })

after(async () => {
  await mf?.dispose()
  if (directory) {
    const target = resolve(directory)
    assert(target.startsWith(resolve(tmpdir()) + sep) && basename(target).startsWith('askm6-page-routing-'))
    await rm(target, { recursive: true, force: true })
  }
})

test('the build emits a not-found entry and only exact policy rewrites', async () => {
  const html = await readFile(resolve(directory, '404.html'), 'utf8')
  assert.match(html, /Page not found \| askm6/)
  assert.match(html, /noindex,follow/)
  const rules = (await readFile(resolve(directory, '_redirects'), 'utf8')).split(/\r?\n/).filter(line => line && !line.startsWith('#'))
  assert.deepEqual(rules, ['/privacy / 200', '/privacy/ / 200', '/terms / 200', '/terms/ / 200'])
  assert.deepEqual(JSON.parse(await readFile(resolve(directory, '_routes.json'), 'utf8')), { version: 1, include: ['/api/*'], exclude: [] })
})

for (const path of ['/', '/privacy', '/privacy/', '/terms', '/terms/']) {
  test(`asset routing preserves ${path} as HTTP 200`, async () => {
    const response = await mf.dispatchFetch('https://site.example' + path, { redirect: 'manual' })
    assert.equal(response.status, 200, (await response.clone().text()).slice(0, 1200))
    assert.equal(response.headers.get('X-Frame-Options'), 'DENY')
    assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff')
    assert.match(response.headers.get('Content-Type'), /text\/html/)
    assert.match(await response.text(), /<title>askm6<\/title>/)
  })
}

for (const path of ['/missing', '/privacy-other', '/nested/missing', '/missing?code=synthetic-private']) {
  test(`asset routing returns the branded HTTP 404 for ${path}`, async () => {
    const response = await mf.dispatchFetch('https://site.example' + path)
    assert.equal(response.status, 404)
    assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer')
    assert.match(response.headers.get('Content-Security-Policy'), /frame-ancestors 'none'/)
    assert.match(response.headers.get('Content-Type'), /text\/html/)
    const html = await response.text()
    assert.match(html, /Page not found \| askm6/)
    assert.doesNotMatch(html, /synthetic-private/)
    assert.equal(response.headers.get('Set-Cookie'), null)
  })
}

for (const path of ['/api/v1/missing', '/api/v1/account/google/callback', '/api/v1/guest/session']) {
  test(`API routing preserves JSON 404 for ${path}`, async () => {
    const response = await mf.dispatchFetch('https://site.example' + path)
    assert.equal(response.status, 404)
    assert.match(response.headers.get('Content-Type'), /application\/json/)
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    assert.equal(response.headers.get('Set-Cookie'), null)
    assert.equal(typeof await response.json(), 'object')
  })
}

test('the health API keeps its method response instead of a website error', async () => {
  const response = await mf.dispatchFetch('https://site.example/api/v1/health', { method: 'POST' })
  assert.equal(response.status, 405)
  assert.equal(response.headers.get('Allow'), 'GET')
})
