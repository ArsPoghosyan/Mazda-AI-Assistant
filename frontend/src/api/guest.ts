export type GuestSessionResponse = {
  status: 'ok'
  expires_at: string
}

export class GuestVerificationRequiredError extends Error {
  constructor() {
    super('Please complete human verification.')
    this.name = 'GuestVerificationRequiredError'
  }
}

export async function ensureGuestSession(
  signal?: AbortSignal,
  turnstileToken?: string,
): Promise<GuestSessionResponse> {
  const response = await fetch('/api/v1/guest/session', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    signal,
    ...(turnstileToken === undefined
      ? {}
      : {
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ turnstile_token: turnstileToken }),
        }),
  })

  if (!response.ok) {
    if (response.status === 403) {
      if (response.headers.get('X-Guest-Verification') === 'required') {
        throw new GuestVerificationRequiredError()
      }

      throw new Error('Guest access could not be verified.')
    }

    if (response.status === 503) {
      throw new Error('Guest access is temporarily unavailable.')
    }

    throw new Error('Guest access could not be started.')
  }

  let body: unknown

  try {
    body = await response.json()
  } catch {
    throw new Error('Unexpected guest session response.')
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    !('status' in body) ||
    body.status !== 'ok' ||
    !('expires_at' in body) ||
    typeof body.expires_at !== 'string' ||
    Number.isNaN(Date.parse(body.expires_at))
  ) {
    throw new Error('Unexpected guest session response.')
  }

  return {
    status: 'ok',
    expires_at: body.expires_at,
  }
}