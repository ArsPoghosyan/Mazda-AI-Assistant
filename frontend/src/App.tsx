import { useRef, useState } from 'react'
import AccountSignInDialog from './components/AccountSignInDialog'
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

  const [signInOpen, setSignInOpen] = useState(false)
  const signInButton = useRef<HTMLButtonElement>(null)

  const signInDisabled =
    !import.meta.env.DEV ||
    guest.status === 'loading' ||
    guest.status === 'verification'

  const guestDisabled =
    signInOpen ||
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
      accountAction={
        <button
          ref={signInButton}
          type="button"
          disabled={signInDisabled}
          aria-expanded={signInOpen}
          aria-haspopup="dialog"
          aria-controls="account-sign-in-panel"
          aria-describedby="development-notice"
          onClick={() => setSignInOpen(true)}
          className="inline-flex min-h-11 items-center justify-center rounded-control border border-control-border px-6 py-3 font-medium text-foreground enabled:hover:bg-surface-raised disabled:opacity-60"
        >
          Sign In
        </button>
      }
      accountPanel={
        <AccountSignInDialog
          open={signInOpen}
          siteKey={import.meta.env.VITE_TURNSTILE_SITE_KEY?.trim() ?? ''}
          returnFocusRef={signInButton}
          onClose={() => setSignInOpen(false)}
        />
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
