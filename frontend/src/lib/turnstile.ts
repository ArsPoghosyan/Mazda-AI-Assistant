export type TurnstileOptions = {
  sitekey: string
  action: string
  theme?: 'auto' | 'light' | 'dark'
  size?: 'normal' | 'flexible' | 'compact'
  retry?: 'auto' | 'never'
  'response-field'?: boolean
  callback: (token: string) => void
  'error-callback': (errorCode: string) => void
  'expired-callback': () => void
  'timeout-callback'?: () => void
  'refresh-expired'?: 'auto' | 'manual' | 'never'
  'refresh-timeout'?: 'auto' | 'manual' | 'never'
}

export type TurnstileApi = {
  ready: (callback: () => void) => void
  render: (
    container: HTMLElement,
    options: TurnstileOptions,
  ) => string | undefined
  reset: (widgetId: string) => void
  remove: (widgetId: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

const SCRIPT_URL =
  'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

const LOAD_TIMEOUT_MS = 10_000

let loading: Promise<TurnstileApi> | null = null

function availableApi(): TurnstileApi | undefined {
  const api = window.turnstile

  if (
    api &&
    typeof api.ready === 'function' &&
    typeof api.render === 'function' &&
    typeof api.reset === 'function' &&
    typeof api.remove === 'function'
  ) {
    return api
  }

  return undefined
}

export function loadTurnstile(): Promise<TurnstileApi> {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return Promise.reject(new Error('Human verification is unavailable.'))
  }

  if (loading) {
    return loading
  }

  const attempt = new Promise<TurnstileApi>((resolve, reject) => {
    const script = document.createElement('script')
    let finished = false

    const timeoutId = window.setTimeout(fail, LOAD_TIMEOUT_MS)

    function cleanup() {
      window.clearTimeout(timeoutId)
      script.onload = null
      script.onerror = null
    }

    function fail() {
      if (finished) return

      finished = true
      cleanup()
      script.remove()
      reject(new Error('Human verification could not be loaded.'))
    }

    function waitForReady(api: TurnstileApi) {
      try {
        api.ready(() => {
          if (finished) return

          finished = true
          cleanup()
          resolve(api)
        })
      } catch {
        fail()
      }
    }

    const existing = availableApi()

    if (existing) {
      waitForReady(existing)
      return
    }


    script.src = SCRIPT_URL
    // Cloudflare's ready() rejects scripts marked async or defer.
    script.async = false

    script.onload = () => {
      const api = availableApi()

      if (!api) {
        fail()
        return
      }

      waitForReady(api)
    }

    script.onerror = fail

    try {
      document.head.append(script)
    } catch {
      fail()
    }
  })

  loading = attempt

  void attempt.catch(() => {
    if (loading === attempt) {
      loading = null
    }
  })

  return attempt
}
