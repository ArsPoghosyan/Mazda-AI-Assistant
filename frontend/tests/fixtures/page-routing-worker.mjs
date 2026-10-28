import { onRequest } from '../../functions/api/[[path]].ts'

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname.startsWith('/api/')) return onRequest({ request, env })
    return env.ASSETS.fetch(request)
  },
}
