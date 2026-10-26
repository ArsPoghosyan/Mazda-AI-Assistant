import { CURRENT_TERMS_VERSION, readTermsMetadata, type TermsStatus } from '../../shared/account-terms.ts'

export class SetupSessionExpired extends Error {
  constructor(message = 'Your session expired. Please sign in again.') { super(message); this.name = 'SetupSessionExpired' }
}

async function exchange(operation: 'status' | 'accept', signal: AbortSignal, subject: string): Promise<TermsStatus> {
  try {
    const response = await fetch(`/api/v1/account/terms/${operation}`, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
      headers: { 'X-Account-Subject': subject, ...(operation === 'accept' ? { 'Content-Type': 'application/json' } : {}) },
      ...(operation === 'accept' ? {
        body: JSON.stringify({ accepted: true, terms_version: CURRENT_TERMS_VERSION }) } : {}),
    })
    signal.throwIfAborted()
    if (response.status === 401) throw new SetupSessionExpired()
    if (response.status === 409) throw new SetupSessionExpired('Your account session changed. Please check it again.')
    if (response.status !== 200) throw new Error('Setup unavailable')
    const value: unknown = await response.json()
    signal.throwIfAborted()
    return readTermsMetadata(value, operation)
  } catch (error) {
    if (signal.aborted || (error instanceof Error && error.name === 'AbortError') || error instanceof SetupSessionExpired) throw error
    // eslint-disable-next-line preserve-caught-error -- Never expose transport, provider or parser details.
    throw new Error('Account setup could not be completed. Please try again.')
  }
}

export function checkAccountTerms(signal: AbortSignal, subject: string): Promise<TermsStatus> { return exchange('status', signal, subject) }
export function acceptAccountTerms(signal: AbortSignal, subject: string): Promise<TermsStatus> { return exchange('accept', signal, subject) }
