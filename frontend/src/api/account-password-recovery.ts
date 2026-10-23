export type AccountPasswordRecoveryCredentials = {
  email: string
  captcha_token: string
}

export type AccountPasswordRecoveryResponse = {
  status: 'accepted'
}

export class AccountPasswordRecoveryRejectedError extends Error {
  constructor() {
    super('Password recovery was rejected. Check your details and try again.')
    this.name = 'AccountPasswordRecoveryRejectedError'
  }
}

export class AccountPasswordRecoveryVerificationRequiredError extends Error {
  constructor() {
    super('Please complete human verification.')
    this.name = 'AccountPasswordRecoveryVerificationRequiredError'
  }
}

export class AccountPasswordRecoveryRateLimitedError extends Error {
  constructor() {
    super('Too many recovery requests. Please try again later.')
    this.name = 'AccountPasswordRecoveryRateLimitedError'
  }
}

export async function requestAccountPasswordRecovery(
  credentials: AccountPasswordRecoveryCredentials,
  signal?: AbortSignal,
): Promise<AccountPasswordRecoveryResponse> {
  let response: Response

  try {
    response = await fetch('/api/v1/account/password-recovery', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      signal,
      body: JSON.stringify({
        email: credentials.email,
        captcha_token: credentials.captcha_token,
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
    throw new Error('Password recovery could not be requested. Please try again.')
  }

  if (response.status !== 202) {
    if (response.status === 400) {
      throw new AccountPasswordRecoveryRejectedError()
    }

    if (
      response.status === 403 &&
      response.headers.get('X-Account-Verification') === 'required'
    ) {
      throw new AccountPasswordRecoveryVerificationRequiredError()
    }

    if (response.status === 429) {
      throw new AccountPasswordRecoveryRateLimitedError()
    }

    if (response.status === 503) {
      throw new Error('Password recovery is temporarily unavailable.')
    }

    throw new Error('Password recovery could not be requested. Please try again.')
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
    throw new Error('Unexpected password-recovery response.')
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    Array.isArray(body) ||
    !('status' in body) ||
    body.status !== 'accepted'
  ) {
    throw new Error('Unexpected password-recovery response.')
  }

  return { status: 'accepted' }
}
