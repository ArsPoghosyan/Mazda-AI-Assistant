// Server-only Pages bindings. Never expose the shared secret through VITE_*.
export type ProxyClientIPEnvironment = {
  AUTH_PROXY_TRUST_ENABLED?: string
  AUTH_PROXY_SHARED_SECRET?: string
}

export class ProxyClientIPUnavailable extends Error {
  constructor() { super('Client address is unavailable.') }
}

function validIP(value: string): boolean {
  if (value.length > 45 || !/^[0-9a-fA-F:.]+$/.test(value)) return false
  if (!value.includes(':')) {
    const octets = value.split('.')
    return octets.length === 4 && octets.every((octet) =>
      /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255,
    )
  }
  try {
    // URL's bracketed-host parser validates IPv6, including embedded IPv4.
    return new URL(`http://[${value}]/`).hostname.startsWith('[')
  } catch { return false }
}

export function proxyClientIPHeaders(request: Request, env: ProxyClientIPEnvironment): Headers {
  const headers = new Headers()
  if (env.AUTH_PROXY_TRUST_ENABLED === undefined || env.AUTH_PROXY_TRUST_ENABLED === 'false') {
    return headers
  }
  // A misspelled flag must not silently turn off an intended trust boundary.
  const secret = env.AUTH_PROXY_SHARED_SECRET
  // Use only at verified Cloudflare ingress, where the edge supplies this header.
  // A generic server must not authenticate a browser's CF header with our key.
  const address = request.headers.get('CF-Connecting-IP')
  if (
    env.AUTH_PROXY_TRUST_ENABLED !== 'true' ||
    !secret || !/^[0-9a-fA-F]{64}$/.test(secret) ||
    !address || !validIP(address)
  ) {
    throw new ProxyClientIPUnavailable()
  }
  headers.set('X-AskM6-Proxy-Secret', secret)
  headers.set('X-AskM6-Client-IP', address)
  return headers
}
