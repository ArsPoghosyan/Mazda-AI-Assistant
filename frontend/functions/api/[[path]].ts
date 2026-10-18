type ProxyContext = {
  request: Request
  env: {
    API_ORIGIN?: string
  }
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
      redirect: 'error',
      signal: AbortSignal.timeout(65_000),
    })

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