import { forwardAccountSession } from '../../server/account-session-proxy.ts'
import type { AccountSessionProxyEnvironment } from '../../server/account-session-proxy-policy.ts'
import { forwardGuestSession, type GuestSessionProxyEnvironment } from '../../server/guest-session-proxy.ts'
import { forwardAccountSignIn, type AccountSignInProxyEnvironment } from '../../server/account-sign-in-proxy.ts'
import { forwardAccountSignOut, type AccountSignOutProxyEnvironment } from '../../server/account-sign-out-proxy.ts'
import { forwardAccountSignUp, type AccountSignUpProxyEnvironment } from '../../server/account-sign-up-proxy.ts'
import { forwardAccountEmailConfirmation, type AccountEmailConfirmationProxyEnvironment } from '../../server/account-email-confirmation-proxy.ts'
import { forwardAccountPasswordRecovery, type AccountPasswordRecoveryProxyEnvironment } from '../../server/account-password-recovery-proxy.ts'
import { forwardAccountPasswordReset, type AccountPasswordResetProxyEnvironment } from '../../server/account-password-reset-proxy.ts'
import { forwardAccountGoogleStart, type AccountGoogleStartProxyEnvironment } from '../../server/account-google-start-proxy.ts'
import { forwardAccountGoogleCallback, type AccountGoogleCallbackProxyEnvironment } from '../../server/account-google-callback-proxy.ts'

type ProxyContext = {
  request: Request
  env: AccountSessionProxyEnvironment & GuestSessionProxyEnvironment & AccountSignInProxyEnvironment & AccountSignOutProxyEnvironment & AccountSignUpProxyEnvironment & AccountEmailConfirmationProxyEnvironment & AccountPasswordRecoveryProxyEnvironment & AccountPasswordResetProxyEnvironment & AccountGoogleStartProxyEnvironment & AccountGoogleCallbackProxyEnvironment
}

function errorResponse(message: string, status: number): Response {
  return Response.json(
    { error: message },
    { status, headers: { 'Cache-Control': 'no-store' } },
  )
}

export async function onRequest({
  request,
  env,
}: ProxyContext): Promise<Response> {
  const pathname = new URL(request.url).pathname

  if (pathname === '/api/v1/account/session') {
    return forwardAccountSession(request, env)
  }
  if (pathname === '/api/v1/guest/session') {
    return forwardGuestSession(request, env)
  }
  if (pathname === '/api/v1/account/sign-in') {
    return forwardAccountSignIn(request, env)
  }
  if (pathname === '/api/v1/account/sign-out') {
    return forwardAccountSignOut(request, env)
  }
  if (pathname === '/api/v1/account/sign-up') {
    return forwardAccountSignUp(request, env)
  }
  if (pathname === '/api/v1/account/confirm-email') {
    return forwardAccountEmailConfirmation(request, env)
  }
  if (pathname === '/api/v1/account/password-recovery') {
    return forwardAccountPasswordRecovery(request, env)
  }
  if (pathname === '/api/v1/account/password-reset') {
    return forwardAccountPasswordReset(request, env)
  }
  if (pathname === '/api/v1/account/google/start') {
    return forwardAccountGoogleStart(request, env)
  }
  if (pathname === '/api/v1/account/google/callback' || pathname.startsWith('/api/v1/account/google/callback/')) {
    return forwardAccountGoogleCallback(request, env)
  }

  if (pathname !== '/api/v1/health') {
    return errorResponse('API route not found.', 404)
  }

  if (request.method !== 'GET') {
    return new Response(null, {
      status: 405,
      headers: {
        Allow: 'GET',
        'Cache-Control': 'no-store',
      },
    })
  }

  let origin: URL

  try {
    origin = new URL(env.API_ORIGIN ?? '')

    if (
      origin.protocol !== 'https:' ||
      origin.username ||
      origin.password ||
      origin.pathname !== '/' ||
      origin.search ||
      origin.hash
    ) {
      return errorResponse('API origin is not configured correctly.', 503)
    }
  } catch {
    return errorResponse('API origin is not configured correctly.', 503)
  }

  try {
    const upstream = await fetch(new URL('/api/v1/health', origin), {
      headers: { Accept: 'application/json' },
      redirect: 'manual',
      signal: AbortSignal.timeout(65_000),
    })

    if (upstream.status >= 300 && upstream.status < 400) {
      await upstream.body?.cancel()
      return errorResponse('Unexpected backend redirect.', 502)
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        'Content-Type':
          upstream.headers.get('Content-Type') ?? 'application/json',
        'Cache-Control': 'no-store',
      },
    })
  } catch {
    return errorResponse('Backend unavailable. Please try again.', 502)
  }
}
