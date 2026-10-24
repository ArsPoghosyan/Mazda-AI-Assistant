export type AccountSignUpCredentials = {
  email: string
  password: string
  captcha_token: string
}

export type AccountSignUpResponse = {
  status: 'accepted'
}

export class AccountSignUpRejectedError extends Error {
  constructor() {
    super('Registration was rejected. Check your details and try again.')
    this.name = 'AccountSignUpRejectedError'
  }
}

export class AccountSignUpVerificationRequiredError extends Error {
  constructor() {
    super('Please complete human verification.')
    this.name = 'AccountSignUpVerificationRequiredError'
  }
}

export class AccountSignUpRateLimitedError extends Error {
  readonly retryAfterSeconds: number | null

  constructor(retryAfter: string | null = null) {
    super('Too many sign-up attempts. Please try again later.')
    this.name = 'AccountSignUpRateLimitedError'

    // Accept only the backend's bounded delta-seconds, never raw header text.
    const seconds = retryAfter !== null && /^[0-9]{1,5}$/.test(retryAfter)
      ? Number(retryAfter)
      : NaN
    this.retryAfterSeconds = seconds >= 1 && seconds <= 86_400 ? seconds : null
  }
}

export async function signUpAccount(
  credentials: AccountSignUpCredentials,
  signal?: AbortSignal,
): Promise<AccountSignUpResponse> {
  let response: Response

  try {
    response = await fetch('/api/v1/account/sign-up', {
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
    throw new Error('Registration could not be completed. Please try again.')
  }

  if (response.status !== 202) {
    if (response.status === 429) {
      throw new AccountSignUpRateLimitedError(response.headers.get('Retry-After'))
    }

    if (response.status === 400) {
      throw new AccountSignUpRejectedError()
    }

    if (
      response.status === 403 &&
      response.headers.get('X-Account-Verification') === 'required'
    ) {
      throw new AccountSignUpVerificationRequiredError()
    }

    if (response.status === 503) {
      throw new Error(
        'Registration is temporarily unavailable. Please try again.',
      )
    }

    throw new Error('Registration could not be completed. Please try again.')
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
    throw new Error('Unexpected registration response.')
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    !('status' in body) ||
    body.status !== 'accepted'
  ) {
    throw new Error('Unexpected registration response.')
  }

  return { status: 'accepted' }
}

export type AccountEmailConfirmationCredentials = {
  email: string
  code: string
}

export type AccountEmailConfirmationResponse = {
  status: 'confirmed'
}

export class AccountEmailConfirmationRejectedError extends Error {
  constructor() {
    super(
      'Email confirmation was rejected. Check your email and code, then try again.',
    )
    this.name = 'AccountEmailConfirmationRejectedError'
  }
}

export class AccountEmailConfirmationRateLimitedError extends Error {
  readonly retryAfterSeconds: number | null

  constructor(retryAfter: string | null = null) {
    super('Too many email confirmation attempts. Please try again later.')
    this.name = 'AccountEmailConfirmationRateLimitedError'

    // Accept only bounded delta-seconds; never expose untrusted header text.
    const seconds = retryAfter !== null && /^[0-9]{1,5}$/.test(retryAfter)
      ? Number(retryAfter)
      : NaN
    this.retryAfterSeconds = seconds >= 1 && seconds <= 86_400 ? seconds : null
  }
}

export async function confirmAccountEmail(
  credentials: AccountEmailConfirmationCredentials,
  signal?: AbortSignal,
): Promise<AccountEmailConfirmationResponse> {
  let response: Response

  try {
    response = await fetch('/api/v1/account/confirm-email', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      signal,
      body: JSON.stringify({
        email: credentials.email,
        code: credentials.code,
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
    throw new Error(
      'Email confirmation could not be completed. Please try again.',
    )
  }

  if (response.status !== 200) {
    if (response.status === 429) {
      throw new AccountEmailConfirmationRateLimitedError(response.headers.get('Retry-After'))
    }

    if (response.status === 400) {
      throw new AccountEmailConfirmationRejectedError()
    }

    if (response.status === 503) {
      throw new Error(
        'Email confirmation is temporarily unavailable. Please try again.',
      )
    }

    throw new Error(
      'Email confirmation could not be completed. Please try again.',
    )
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
    throw new Error('Unexpected email-confirmation response.')
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    !('status' in body) ||
    body.status !== 'confirmed'
  ) {
    throw new Error('Unexpected email-confirmation response.')
  }

  return { status: 'confirmed' }
}
