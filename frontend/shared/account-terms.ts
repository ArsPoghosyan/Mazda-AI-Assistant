// Keep this revision aligned with the published Terms and backend contract.
export const CURRENT_TERMS_VERSION = '2026-10-26'

export type TermsStatus = {
  terms_version: string
  accepted_at: string | null
  acceptance_required: boolean
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('Invalid Terms metadata')
  return value as Record<string, unknown>
}

function acceptanceTime(value: unknown): string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)) {
    throw new Error('Invalid acceptance time')
  }
  const time = Date.parse(value)
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== value.slice(0, 19) || time > Date.now() + 60_000) {
    throw new Error('Invalid acceptance time')
  }
  return value
}

export function readTermsMetadata(value: unknown, operation: 'status' | 'accept'): TermsStatus {
  const body = record(value)
  const fields = operation === 'status' ? 'acceptance_required,accepted_at,terms_version' : 'accepted_at,terms_version'
  if (Object.keys(body).sort().join(',') !== fields || body.terms_version !== CURRENT_TERMS_VERSION) {
    throw new Error('Invalid Terms revision or fields')
  }
  const time = body.accepted_at === null && operation === 'status' ? null : acceptanceTime(body.accepted_at)
  if (operation === 'status' && body.acceptance_required !== (time === null)) throw new Error('Inconsistent Terms status')
  return { terms_version: CURRENT_TERMS_VERSION, accepted_at: time, acceptance_required: time === null }
}
