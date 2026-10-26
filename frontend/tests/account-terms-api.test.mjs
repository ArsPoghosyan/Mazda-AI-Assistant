import assert from 'node:assert/strict'
import { test } from 'node:test'
import { checkAccountTerms, acceptAccountTerms, SetupSessionExpired } from '../src/api/accountTerms.ts'
import { CURRENT_TERMS_VERSION as version } from '../shared/account-terms.ts'

const accepted_at = new Date(Date.now() - 1000).toISOString()
const accepted = { terms_version: version, accepted_at }
const missing = { terms_version: version, accepted_at: null, acceptance_required: true }

for (const operation of ['status', 'accept']) {
  const call = signal => (operation === 'status' ? checkAccountTerms : acceptAccountTerms)(signal, '563128d6-22fd-464f-a3bd-31018fdf1b3c')
  test(`${operation} sends only the exact cookie-authenticated request and returns validated metadata`, async (t) => {
    const controller = new AbortController()
    const mock = t.mock.method(globalThis, 'fetch', async (url, options) => {
      assert.equal(url, `/api/v1/account/terms/${operation}`)
      assert.equal(options.method, 'POST')
      assert.equal(options.credentials, 'same-origin')
      assert.equal(options.redirect, 'error')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.signal, controller.signal)
      assert.equal(options.headers['X-Account-Subject'], '563128d6-22fd-464f-a3bd-31018fdf1b3c')
      assert.equal(options.body, operation === 'status' ? undefined : JSON.stringify({ accepted: true, terms_version: version }))
      return Response.json(operation === 'status' ? missing : accepted)
    })
    const result = await call(controller.signal)
    assert.equal(result.acceptance_required, operation === 'status')
    assert.equal(mock.mock.callCount(), 1)
  })
  for (const status of [400, 403, 404, 429, 500, 502, 503]) {
    test(`${operation} masks HTTP ${status} without retry`, async (t) => {
      const mock = t.mock.method(globalThis, 'fetch', async () => new Response('private-detail', { status }))
      await assert.rejects(call(new AbortController().signal), /^Error: Account setup could not be completed/)
      assert.equal(mock.mock.callCount(), 1)
    })
  }
  test(`${operation} recognizes verified session expiry`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json({}, { status: 401 }))
    await assert.rejects(call(new AbortController().signal), SetupSessionExpired)
  })
  for (const payload of [null, [], {}, { ...accepted, terms_version: 'old' }, { ...accepted, accepted_at: 'invalid' },
    { ...accepted, user_id: 'private' }, { ...accepted, accepted_at: new Date(Date.now() + 120_000).toISOString() },
    ...(operation === 'status' ? [{ ...missing, acceptance_required: false }, { ...missing, acceptance_required: 'true' }] : [{ ...accepted, accepted_at: null }]),
  ]) {
    test(`${operation} rejects malformed or mismatched metadata ${JSON.stringify(payload)}`, async (t) => {
      t.mock.method(globalThis, 'fetch', async () => Response.json(payload))
      await assert.rejects(call(new AbortController().signal), /Account setup could not be completed/)
    })
  }
  test(`${operation} preserves cancellation and masks ordinary network errors`, async (t) => {
    const controller = new AbortController()
    t.mock.method(globalThis, 'fetch', async () => { controller.abort(); throw controller.signal.reason })
    await assert.rejects(call(controller.signal), { name: 'AbortError' })
  })
  test(`${operation} never exposes network details`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => { throw new Error('private-detail') })
    await assert.rejects(call(new AbortController().signal), /^Error: Account setup could not be completed/)
  })
}


test('account changes require fresh session verification and never expose backend details', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => Response.json({ detail: 'private' }, { status: 409 }))
  await assert.rejects(checkAccountTerms(new AbortController().signal, '563128d6-22fd-464f-a3bd-31018fdf1b3c'), SetupSessionExpired)
})
