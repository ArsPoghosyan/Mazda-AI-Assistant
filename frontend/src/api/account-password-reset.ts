export type AccountPasswordResetCredentials = {
  email: string
  code: string
  new_password: string
}

export type AccountPasswordResetResponse = {
  status: 'completed'
}

export class AccountPasswordResetRejectedError extends Error {
  constructor() {
    super('Password reset was rejected. Check your email, code and new password, then try again.')
    this.name = 'AccountPasswordResetRejectedError'
  }
}

export class AccountPasswordResetRateLimitedError extends Error {
  constructor() {
    super('Too many password-reset attempts. Please try again later.')
    this.name = 'AccountPasswordResetRateLimitedError'
  }
}

export async function resetAccountPassword(
  credentials: AccountPasswordResetCredentials,
  signal?: AbortSignal,
): Promise<AccountPasswordResetResponse> {
  let response: Response

  try {
    response = await fetch('/api/v1/account/password-reset', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      signal,
      body: JSON.stringify({
        email: credentials.email,
        code: credentials.code,
        new_password: credentials.new_password,
      }),
    })
  } catch (error) {
    if (
      signal?.aborted ||
      (error instanceof Error && error.name === 'AbortError')
    ) {
      throw error
    }

    // eslint-disable-next-line preserve-caught-error -- Discard untrusted transport details at the UI boundary.
    throw new Error('Password reset could not be confirmed. Try signing in with your new password before starting recovery again.')
  }

  if (response.status !== 200) {
    if (response.status === 400) {
      throw new AccountPasswordResetRejectedError()
    }

    if (response.status === 429) {
      throw new AccountPasswordResetRateLimitedError()
    }

    if (response.status === 503) {
      throw new Error('Password reset is temporarily unavailable. Try signing in with your new password before starting recovery again.')
    }

    throw new Error('Password reset could not be confirmed. Try signing in with your new password before starting recovery again.')
  }

  let body: unknown

  try {
    body = await response.json()
  } catch (error) {
    if (
      signal?.aborted ||
      (error instanceof Error && error.name === 'AbortError')
    ) {
      throw error
    }

    // eslint-disable-next-line preserve-caught-error -- Parser errors may contain private response content.
    throw new Error('Unexpected password-reset response. Try signing in with your new password before starting recovery again.')
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    Array.isArray(body) ||
    !('status' in body) ||
    body.status !== 'completed'
  ) {
    throw new Error('Unexpected password-reset response. Try signing in with your new password before starting recovery again.')
  }

  return { status: 'completed' }
}
