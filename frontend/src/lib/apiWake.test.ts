import { expect, test } from 'vitest'
import { apiWakeUrl } from './apiWake'

const WAKE = 'https://backend.example.test/api/v1/health'

test('an exact HTTPS health URL enables the wake request', () => {
  expect(apiWakeUrl(WAKE)).toBe(WAKE)
  expect(apiWakeUrl(`  ${WAKE}  `)).toBe(WAKE)
})

test.each([
  ['unset', undefined],
  ['empty', '   '],
  ['plain HTTP', 'http://backend.example.test/api/v1/health'],
  ['credentials', 'https://user:secret@backend.example.test/api/v1/health'],
  ['query', `${WAKE}?debug=1`],
  ['fragment', `${WAKE}#top`],
  ['other path', 'https://backend.example.test/api/v1/account/session'],
  ['origin only', 'https://backend.example.test'],
  ['not a URL', 'backend.example.test/api/v1/health'],
  ['script URL', 'javascript:alert(1)'],
] as const)('%s disables the wake request', (_name, value) => {
  expect(apiWakeUrl(value)).toBeNull()
})
