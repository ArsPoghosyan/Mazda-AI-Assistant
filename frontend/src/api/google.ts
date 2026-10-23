export type GoogleLoginStartResponse = {
  authorization_url: string
  expires_at: string
}

const FAILURE = 'Google sign-in could not be started. Please try again.'
const INVALID = 'Unexpected Google sign-in response.'

function isCancelled(error: unknown, signal?: AbortSignal): boolean {
  return (
    signal?.aborted === true ||
    (error instanceof Error && error.name === 'AbortError')
  )
}

export async function startGoogleSignIn(
  expectedIssuer: string,
  expectedCallbackUrl: string,
  signal?: AbortSignal,
): Promise<GoogleLoginStartResponse> {
  let response: Response

  try {
    response = await fetch('/api/v1/account/google/start', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal,
    })
  } catch (error) {
    if (isCancelled(error, signal)) throw error

    // eslint-disable-next-line preserve-caught-error -- Transport errors may contain private details.
    throw new Error(FAILURE)
  }

  if (response.status === 400) {
    throw new Error('Please start Google sign-in again.')
  }

  if (response.status === 409) {
    throw new Error('Sign out before starting another account login.')
  }

  if (response.status === 503) {
    throw new Error('Google sign-in is temporarily unavailable.')
  }

  if (response.status !== 200) {
    throw new Error(FAILURE)
  }

  let body: unknown

  try {
    body = await response.json()
  } catch (error) {
    if (isCancelled(error, signal)) throw error

    // eslint-disable-next-line preserve-caught-error -- Parser errors may contain private response content.
    throw new Error(INVALID)
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    !('authorization_url' in body) ||
    typeof body.authorization_url !== 'string' ||
    body.authorization_url.length > 8192 ||
    !('expires_at' in body) ||
    typeof body.expires_at !== 'string'
  ) {
    throw new Error(INVALID)
  }

  const expiry = Date.parse(body.expires_at)
  if (!Number.isFinite(expiry) || expiry <= Date.now()) {
    throw new Error(INVALID)
  }

  try {
    const issuer = new URL(expectedIssuer)
    const destination = new URL(body.authorization_url)
    const parameters = destination.searchParams
    const keys = [...parameters.keys()]

    if (
      issuer.protocol !== 'https:' ||
      issuer.username ||
      issuer.password ||
      issuer.pathname !== '/auth/v1' ||
      issuer.search ||
      issuer.hash ||
      destination.protocol !== 'https:' ||
      destination.origin !== issuer.origin ||
      destination.pathname !== '/auth/v1/authorize' ||
      destination.username ||
      destination.password ||
      destination.hash ||
      keys.length !== 4 ||
      new Set(keys).size !== 4 ||
      !keys.every((key) =>
        [
          'provider',
          'redirect_to',
          'code_challenge',
          'code_challenge_method',
        ].includes(key),
      ) ||
      parameters.get('provider') !== 'google' ||
      parameters.get('redirect_to') !== expectedCallbackUrl ||
      parameters.get('code_challenge_method') !== 's256' ||
      !/^[A-Za-z0-9_-]{43}$/.test(
        parameters.get('code_challenge') ?? '',
      )
    ) {
      throw new Error(INVALID)
    }

    return {
      authorization_url: destination.href,
      expires_at: body.expires_at,
    }
  } catch {
    throw new Error(INVALID)
  }
}