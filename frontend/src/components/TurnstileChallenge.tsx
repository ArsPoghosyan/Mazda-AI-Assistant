import { useEffect, useEffectEvent, useId, useRef, useState } from 'react'
import { loadTurnstile, type TurnstileApi } from '../lib/turnstile'

type TurnstileChallengeProps = {
  siteKey: string
  onToken: (token: string) => void
  onInvalidated: () => void
}

type Feedback = {
  status: 'loading' | 'ready' | 'complete' | 'error'
  message: string
}

export default function TurnstileChallenge({
  siteKey,
  onToken,
  onInvalidated,
}: TurnstileChallengeProps) {
  const container = useRef<HTMLDivElement>(null)
  const titleId = useId()
  const messageId = useId()
  const [attempt, setAttempt] = useState(0)
  const [feedback, setFeedback] = useState<Feedback>({
    status: 'loading',
    message: 'Loading verification…',
  })

  const receiveToken = useEffectEvent((token: string) => {
    setFeedback({
      status: 'complete',
      message: 'Check completed.',
    })
    onToken(token)
  })

  const reportFailure = useEffectEvent((message: string) => {
    setFeedback({ status: 'error', message })
    onInvalidated()
  })

  useEffect(() => {
    const host = container.current
    if (!host) return

    let disposed = false
    let failed = false
    let delivered = false
    let api: TurnstileApi | undefined
    let widgetId: string | undefined

    function fail(message: string) {
      if (disposed || failed) return

      failed = true
      reportFailure(message)
    }

    const pending = siteKey.trim()
      ? loadTurnstile()
      : Promise.reject(new Error('Missing verification configuration.'))

    void pending
      .then((loaded) => {
        if (disposed) return

        api = loaded
        setFeedback({
          status: 'ready',
          message: 'Complete the check to continue.',
        })

        widgetId = loaded.render(host, {
          sitekey: siteKey,
          action: 'guest_start',
          theme: 'dark',
          size: 'compact',
          retry: 'never',
          'refresh-expired': 'never',
          'refresh-timeout': 'never',
          'response-field': false,

          callback: (token) => {
            if (disposed || failed || delivered) return

            if (!token || token.length > 2048) {
              fail('Verification could not be completed. Please try again.')
              return
            }

            delivered = true
            receiveToken(token)
          },

          'error-callback': () => {
            fail('Verification could not be completed. Please try again.')
          },

          'expired-callback': () => {
            fail('Verification expired. Please try again.')
          },

          'timeout-callback': () => {
            fail('Verification took too long. Please try again.')
          },
        })

        if (widgetId === undefined) {
          fail('Verification could not be loaded. Please try again.')
        }
      })
      .catch(() => {
        fail('Verification could not be loaded. Please try again.')
      })

    return () => {
      disposed = true

      try {
        if (api && widgetId !== undefined) {
          api.remove(widgetId)
        }
      } catch {
        // Clear the container below even if SDK cleanup fails.
      }

      host.replaceChildren()
    }
  }, [siteKey, attempt])

  function retry() {
    onInvalidated()
    setFeedback({
      status: 'loading',
      message: 'Loading verification…',
    })
    setAttempt((current) => current + 1)
  }

  return (
    <section
      aria-labelledby={titleId}
      aria-describedby={messageId}
      className="order-last basis-full space-y-3 text-sm"
    >
      <p id={titleId} className="font-medium text-foreground">
        Human verification
      </p>

      <div ref={container} className="min-h-36" />

      <p
        id={messageId}
        role="status"
        aria-atomic="true"
        className="max-w-sm text-muted"
      >
        {feedback.message}
      </p>

      {feedback.status === 'error' && (
        <button
          type="button"
          onClick={retry}
          className="inline-flex min-h-11 items-center justify-center rounded-control border border-control-border px-4 py-2 font-medium text-foreground hover:bg-surface-raised"
        >
          Retry verification
        </button>
      )}
    </section>
  )
}