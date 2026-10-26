import { useEffect, useRef, useState } from 'react'
import AccountSignInDialog from './components/AccountSignInDialog'
import LandingPage from './components/LandingPage'
import TurnstileChallenge from './components/TurnstileChallenge'
import { useAccountSession } from './hooks/useAccountSession'
import { useAccountSignOut } from './hooks/useAccountSignOut'
import { useApiHealth, type ApiStatus } from './hooks/useApiHealth'
import { useGuestSession } from './hooks/useGuestSession'

const statusMessages: Record<ApiStatus, string> = {
  checking: 'Checking API connection…',
  connected: 'API connected',
  unavailable: 'API unavailable',
}

export default function App() {
  const { status, retry } = useApiHealth()
  const backendReady = status === 'connected'
  const account = useAccountSession(backendReady)
  const signOut = useAccountSignOut()
  const guest = useGuestSession()

  const [signInOpen, setSignInOpen] = useState(false)
  const signInButton = useRef<HTMLButtonElement>(null)
  const accessStatus = useRef<HTMLParagraphElement>(null)

  const signingOut = signOut.status === 'loading'
  const sessionMessage =
    account.status === 'signed_in' &&
    (signOut.status === 'loading' || signOut.status === 'error')
      ? signOut.message
      : account.status === 'signed_out' && guest.message
        ? guest.message
        : account.message || guest.message
  const accessMessage = backendReady
    ? sessionMessage
    : status === 'checking'
      ? 'Starting the service… This may take about a minute.'
      : 'Service unavailable. Use “Try again” below to reconnect.'

  useEffect(() => {
    if (account.status === 'signed_out' && signOut.status === 'ready') {
      signInButton.current?.focus()
    }
  }, [account.status, signOut.status])

  async function handleSignOut() {
    if (account.status !== 'signed_in') return

    const confirmed = await signOut.start()

    if (confirmed) account.acceptSignOut()
  }

  const signInDisabled =
    !backendReady ||
    !account.enabled ||
    account.status === 'checking' ||
    account.status === 'signed_in' ||
    guest.status === 'loading' ||
    guest.status === 'verification'

  const accountLabel =
    !backendReady && account.enabled
      ? status === 'checking'
        ? 'Waiting for service…'
        : 'Service unavailable'
      : account.status === 'checking'
        ? 'Checking account…'
        : account.status === 'signed_in'
          ? 'Signed in'
          : account.status === 'unavailable'
            ? 'Retry session check'
            : 'Sign In'

  const guestDisabled =
    !backendReady ||
    signInOpen ||
    (account.enabled && account.status !== 'signed_out') ||
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
            aria-describedby="access-status development-notice"
            onClick={() => {
              if (!backendReady) return
              void guest.start()
            }}
            className="inline-flex min-h-11 items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60"
          >
            {guestLabel}
          </button>

          {backendReady && guest.enabled && guest.status === 'verification' && (
            <TurnstileChallenge
              siteKey={import.meta.env.VITE_TURNSTILE_SITE_KEY?.trim() ?? ''}
              onToken={(token) => {
                void guest.start(token)
              }}
              onInvalidated={guest.invalidateVerification}
            />
          )}

          <p
            ref={accessStatus}
            id="access-status"
            tabIndex={-1}
            role="status"
            aria-atomic="true"
            className="order-last min-h-6 basis-full text-sm text-muted"
          >
            {accessMessage}
          </p>
        </>
      }
      accountAction={
        <>
          <button
            ref={signInButton}
            type="button"
            disabled={signInDisabled}
            aria-busy={
              account.enabled &&
              (status === 'checking' || (backendReady && account.status === 'checking'))
            }
            aria-expanded={
              account.status === 'signed_out' ? signInOpen : undefined
            }
            aria-haspopup={
              account.status === 'signed_out' ? 'dialog' : undefined
            }
            aria-controls={
              account.status === 'signed_out'
                ? 'account-sign-in-panel'
                : undefined
            }
            aria-describedby="access-status development-notice"
            onClick={() => {
              if (!backendReady) return
              if (account.status === 'unavailable') {
                account.refresh()
              } else if (account.status === 'signed_out') {
                setSignInOpen(true)
              }
            }}
            className="inline-flex min-h-11 items-center justify-center rounded-control border border-control-border px-6 py-3 font-medium text-foreground enabled:hover:bg-surface-raised disabled:opacity-60"
          >
            {accountLabel}
          </button>

          {account.status === 'signed_in' && (
            <button
              type="button"
              disabled={!signOut.enabled || signingOut}
              aria-busy={signingOut}
              aria-describedby="access-status development-notice"
              onClick={() => {
                void handleSignOut()
              }}
              className="inline-flex min-h-11 items-center justify-center rounded-control border border-control-border px-6 py-3 font-medium text-foreground enabled:hover:bg-surface-raised disabled:opacity-60"
            >
              {signingOut ? 'Signing out…' : 'Sign out'}
            </button>
          )}
        </>
      }
      accountPanel={
        <AccountSignInDialog
          open={signInOpen}
          siteKey={import.meta.env.VITE_TURNSTILE_SITE_KEY?.trim() ?? ''}
          returnFocusRef={signInButton}
          fallbackFocusRef={accessStatus}
          onSignedIn={(session) => {
            account.acceptSignIn(session)
            setSignInOpen(false)
          }}
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
