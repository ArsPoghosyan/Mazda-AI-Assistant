import { onRequest } from '../../functions/api/[[path]].ts'

// Adapt the real Pages handler to a workerd module for isolated runtime tests.
export default {
  async fetch(request, env) {
    // Miniflare may populate CF-Connecting-IP from its platform-specific local
    // socket. Apply explicit negative cases after that ingress normalization.
    // This hook exists only in this isolated fixture, never in the Pages handler.
    if (env.TEST_CLIENT_IP_MODE) {
      request = new Request(request)
      if (env.TEST_CLIENT_IP_MODE === 'missing') request.headers.delete('CF-Connecting-IP')
      else if (env.TEST_CLIENT_IP_MODE === 'empty') request.headers.set('CF-Connecting-IP', '')
      else throw new Error('Invalid test client-IP mode')
    }
    // Explicit test-only signal injection checks the runtime's cancellation
    // APIs without claiming automatic client-disconnect delivery was verified.
    if (env.TEST_ABORT_MS) {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), Number(env.TEST_ABORT_MS))
      try {
        return await onRequest({ request: new Request(request, { signal: controller.signal }), env })
      } finally { clearTimeout(timer) }
    }
    return onRequest({ request, env })
  },
}
