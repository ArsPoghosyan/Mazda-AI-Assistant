import {
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
} from 'react'
import type { AccountSessionResponse } from '../api/account'
import { useAccountSignIn } from '../hooks/useAccountSignIn'
import { useGoogleSignIn } from '../hooks/useGoogleSignIn'
import GoogleAccessOption from './GoogleAccessOption'
import TurnstileChallenge from './TurnstileChallenge'

type AccountSignInFormProps = {
  siteKey: string
  titleId?: string
  initialEmail?: string
  onCreateAccount?: () => void
  onForgotPassword?: (email: string) => void
  onClose: () => void
  onSignedIn?: (session: AccountSessionResponse) => void
}

export default function AccountSignInForm({
  siteKey,
  titleId,
  initialEmail = '',
  onCreateAccount,
  onForgotPassword,
  onClose,
  onSignedIn,
}: AccountSignInFormProps) {
  const signIn = useAccountSignIn()
  const google = useGoogleSignIn()
  const id = useId()
  const headingId = titleId ?? `${id}-title`
  const emailInput = useRef<HTMLInputElement>(null)
  const proof = useRef<string | null>(null)
  const generation = useRef(0)
  const active = useRef(false)
  const formElement = useRef<HTMLFormElement>(null)
  const accessOperation = useRef<'email' | 'google' | 'navigation' | null>(null)

  const [verified, setVerified] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const [showPassword, setShowPassword] = useState(false)

  const loading = signIn.status === 'loading'
  const ready = signIn.status === 'ready'
  const googleBusy = google.status === 'loading' || google.status === 'redirecting'
  const fieldsDisabled = !signIn.enabled || loading || ready || googleBusy
  const statusMessage = googleBusy
    ? ''
    : !signIn.enabled
      ? 'Account sign-in is not available here yet.'
      : signIn.message

  useEffect(() => {
    active.current = true
    emailInput.current?.focus()

    return () => {
      active.current = false
    }
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (fieldsDisabled || !proof.current || accessOperation.current) return

    const form = event.currentTarget
    const data = new FormData(form)
    const email = data.get('email')
    const password = data.get('password')

    if (typeof email !== 'string' || typeof password !== 'string') return

    accessOperation.current = 'email'

    const captchaToken = proof.current

    // Consume this proof immediately, before React renders again.
    proof.current = null
    setVerified(false)

    generation.current += 1
    setAttempt(generation.current)
    setShowPassword(false)

    const passwordInput = form.elements.namedItem('password')

    if (passwordInput instanceof HTMLInputElement) {
      passwordInput.value = ''
    }

    let completed = false
    try {
      const session = await signIn.start({
        email,
        password,
        captcha_token: captchaToken,
      })
      completed = session !== null
      if (session && active.current) onSignedIn?.(session)
    } finally {
      if (!completed && accessOperation.current === 'email') {
        accessOperation.current = null
      }
    }
  }

  async function startGoogle() {
    if (!google.enabled || loading || ready || googleBusy || accessOperation.current) return

    accessOperation.current = 'google'
    proof.current = null
    setVerified(false)
    generation.current += 1
    setAttempt(generation.current)
    setShowPassword(false)

    const passwordInput = formElement.current?.elements.namedItem('password')
    if (passwordInput instanceof HTMLInputElement) passwordInput.value = ''

    try {
      await google.start()
    } finally {
      if (accessOperation.current === 'google') accessOperation.current = null
    }
  }

  return (
    <section
      aria-labelledby={headingId}
      className="w-full max-w-md rounded-panel border border-divider bg-surface p-2 min-[360px]:p-5 sm:p-6"
    >
      <div className="flex items-center justify-between gap-4">
        <h2 id={headingId} className="text-xl font-semibold">
          Sign in
        </h2>

        <button
          type="button"
          onClick={onClose}
          aria-label="Close sign-in"
          className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-foreground"
        >
          Close
        </button>
      </div>

      <p id={`${id}-help`} className="mt-2 text-sm text-muted">
        {google.enabled
          ? 'Choose Google or use your email and password.'
          : 'Use your email and password to sign in.'}
      </p>

      {google.enabled && (
        <GoogleAccessOption
          statusId={`${id}-google-status`}
          disabled={loading || ready || googleBusy}
          busy={googleBusy}
          message={google.message}
          onContinue={() => { void startGoogle() }}
        />
      )}

      <form
        ref={formElement}
        method="post"
        onSubmit={submit}
        aria-labelledby={headingId}
        aria-describedby={`${id}-help ${id}-status`}
        className="mt-6 space-y-5"
      >
        <fieldset disabled={fieldsDisabled} className="space-y-5">
          <legend className="sr-only">Account credentials</legend>

          <div className="space-y-2">
            <label
              htmlFor={`${id}-email`}
              className="block text-sm font-medium"
            >
              Email
            </label>

            <input
              ref={emailInput}
              id={`${id}-email`}
              name="email"
              type="email"
              defaultValue={initialEmail}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              maxLength={320}
              className="min-h-11 w-full rounded-control border border-control-border bg-background px-3 py-2 text-base text-foreground disabled:opacity-60"
            />
          </div>

          <div className="space-y-2">
            <label
              htmlFor={`${id}-password`}
              className="block text-sm font-medium"
            >
              Password
            </label>

            <input
              id={`${id}-password`}
              name="password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              required
              maxLength={1024}
              className="min-h-11 w-full rounded-control border border-control-border bg-background px-3 py-2 text-base text-foreground disabled:opacity-60"
            />

            <div className="flex flex-wrap items-center justify-between gap-3">
              <button
                type="button"
                aria-controls={`${id}-password`}
                aria-pressed={showPassword}
                onClick={() => setShowPassword((current) => !current)}
                className="inline-flex min-h-11 items-center text-sm text-accent hover:text-accent-hover"
              >
                Show password
              </button>
              {signIn.enabled && onForgotPassword && (
                <button type="button" disabled={fieldsDisabled} onClick={() => {
                  if (fieldsDisabled || accessOperation.current) return
                  accessOperation.current = 'navigation'
                  const email = emailInput.current?.value ?? ''
                  const password = formElement.current?.elements.namedItem('password')
                  if (password instanceof HTMLInputElement) password.value = ''
                  proof.current = null
                  generation.current += 1
                  setVerified(false)
                  setShowPassword(false)
                  onForgotPassword(email)
                }} className="inline-flex min-h-11 items-center text-sm text-accent enabled:hover:text-accent-hover disabled:opacity-60">Forgot password?</button>
              )}
            </div>
          </div>
        </fieldset>

        {signIn.enabled && !loading && !ready && !googleBusy && (
          <TurnstileChallenge
            key={attempt}
            siteKey={siteKey}
            action="account_sign_in"
            onToken={(token) => {
              if (attempt !== generation.current) return

              proof.current = token
              setVerified(true)
            }}
            onInvalidated={() => {
              if (attempt !== generation.current) return

              proof.current = null
              setVerified(false)
            }}
          />
        )}

        <p
          id={`${id}-status`}
          role="status"
          aria-atomic="true"
          className={statusMessage ? 'text-sm text-muted' : 'sr-only'}
        >
          {statusMessage}
        </p>

        <button
          type="submit"
          disabled={fieldsDisabled || !verified}
          aria-busy={loading}
          aria-describedby={`${id}-status`}
          className="inline-flex min-h-11 w-full items-center justify-center rounded-control bg-accent px-6 py-3 font-semibold text-on-accent enabled:hover:bg-accent-hover disabled:opacity-60"
        >
          {loading ? 'Signing in…' : ready ? 'Signed in' : 'Sign in'}
        </button>
      </form>
      {signIn.enabled && onCreateAccount && (
        <p className="mt-4 text-sm text-muted">
          New here?{' '}
          <button
            type="button"
            onClick={() => {
              if (!fieldsDisabled && !accessOperation.current) onCreateAccount()
            }}
            disabled={fieldsDisabled}
            className="inline-flex min-h-11 items-center font-medium text-accent enabled:hover:text-accent-hover disabled:opacity-60"
          >
            Create account
          </button>
        </p>
      )}
    </section>
  )
}
