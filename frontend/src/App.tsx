import LandingPage from './components/LandingPage'
import { useApiHealth, type ApiStatus } from './hooks/useApiHealth'
import { useGuestSession } from './hooks/useGuestSession'
import TurnstileChallenge from './components/TurnstileChallenge'


const statusMessages: Record<ApiStatus, string> = {
  checking: 'Checking API connection…',
  connected: 'API connected',
  unavailable: 'API unavailable',
}

export default function App() {
  const { status, retry } = useApiHealth()
  const guest = useGuestSession()

  const guestDisabled =
    !guest.enabled ||
    guest.status === 'loading' ||
    guest.status === 'verification' ||
    guest.status === 'ready'

  const guestLabel =
    guest.status === 'loading'
      ? 'Starting…'
      : guest.status === 'verification'
        ? 'Complete verification'
        : guest.status === 'ready'
          ? 'Guest session ready'
          : guest.status === 'error'
            ? 'Try again'
            : 'Try as Guest'

  return (
    <LandingPage
      guestAction={
        <>
          <button
            type="button"
            disabled={guestDisabled}
            aria-busy={guest.status === 'loading'}
            aria-describedby="guest-status development-notice"
            onClick={() => {
              void guest.start()
            }}
            className="inline-flex min-h-11 items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60"
          >
            {guestLabel}
          </button>
          {guest.enabled && guest.status === 'verification' && (
            <TurnstileChallenge
              siteKey={import.meta.env.VITE_TURNSTILE_SITE_KEY?.trim() ?? ''}
              onToken={(token) => {
                void guest.start(token)
              }}
              onInvalidated={guest.invalidateVerification}
            />
          )}

          <p
            id="guest-status"
            role="status"
            aria-atomic="true"
            className="order-last min-h-6 basis-full text-sm text-muted"
          >
            {guest.message}
          </p>
        </>
      }
      serviceStatus={
        <div className="flex flex-wrap items-center gap-3">
          <p role="status">{statusMessages[status]}</p>

          {status === 'unavailable' && (
            <button
              type="button"
              onClick={retry}
              className="inline-flex min-h-11 items-center px-2 text-accent hover:text-accent-hover"
            >
              Try again
            </button>
          )}
        </div>
      }
    />
  )
}
