export type AccountSignInCredentials = {
  email: string
  password: string
  captcha_token: string
}

export type AccountSessionResponse = {
  user_id: string
  expires_at: string
  absolute_expires_at: string
}

export class AccountVerificationRequiredError extends Error {
  constructor() {
    super('Please complete human verification.')
    this.name = 'AccountVerificationRequiredError'
  }
}

export class AccountSignInRejectedError extends Error {
  constructor() {
    super('Sign-in was rejected. Please try again.')
    this.name = 'AccountSignInRejectedError'
  }
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export async function signInAccount(
  credentials: AccountSignInCredentials,
  signal?: AbortSignal,
): Promise<AccountSessionResponse> {
  let response: Response

  try {
    response = await fetch('/api/v1/account/sign-in', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      signal,
      body: JSON.stringify({
        email: credentials.email,
        password: credentials.password,
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
    throw new Error('Sign-in could not be completed. Please try again.')
  }

  if (!response.ok) {
    if (response.status === 401) {
      throw new AccountSignInRejectedError()
    }

    if (response.status === 403) {
      if (response.headers.get('X-Account-Verification') === 'required') {
        throw new AccountVerificationRequiredError()
      }

      throw new Error('Sign-in could not be verified. Please try again.')
    }

    if (response.status === 503) {
      throw new Error('Sign-in is temporarily unavailable. Please try again.')
    }

    throw new Error('Sign-in could not be completed. Please try again.')
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
    throw new Error('Unexpected sign-in response.')
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    !('user_id' in body) ||
    typeof body.user_id !== 'string' ||
    !UUID_PATTERN.test(body.user_id) ||
    !('expires_at' in body) ||
    typeof body.expires_at !== 'string' ||
    !('absolute_expires_at' in body) ||
    typeof body.absolute_expires_at !== 'string'
  ) {
    throw new Error('Unexpected sign-in response.')
  }

  const expiry = Date.parse(body.expires_at)
  const absoluteExpiry = Date.parse(body.absolute_expires_at)

  if (
    !Number.isFinite(expiry) ||
    !Number.isFinite(absoluteExpiry) ||
    expiry > absoluteExpiry
  ) {
    throw new Error('Unexpected sign-in response.')
  }

  return {
    user_id: body.user_id,
    expires_at: body.expires_at,
    absolute_expires_at: body.absolute_expires_at,
  }
}