import { onRequest } from '../../functions/api/[[path]].ts'

// Adapt the real Pages handler to a workerd module for isolated runtime tests.
export default {
  async fetch(request, env) {
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
